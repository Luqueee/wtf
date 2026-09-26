//! Atomic, pinned model provisioning. No command, output, or diagnostic context is sent.
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const REVISION: &str = "68f27dfe5a27a54fb2b1fefc432f43f972e90868";
const REPOSITORY: &str = "https://huggingface.co/receptron/laya-onnx/resolve";
const READY: &str = ".verified-revision";

struct Asset {
    path: &'static str,
    size: u64,
    sha256: &'static str,
}

const ASSETS: &[Asset] = &[
    Asset {
        path: "laya.onnx",
        size: 3_807_291,
        sha256: "a874eb254b58b0fcb1e7ad56fbb188c29d64e08c9a46b689433e1f52c66dba1e",
    },
    Asset {
        path: "laya.onnx.data",
        size: 1_685_258_240,
        sha256: "487746363a8da57bcadb4345352997d22a0fb90d70aa22c6856668d023242aba",
    },
    Asset {
        path: "laya_config.json",
        size: 369,
        sha256: "5049005dc6ae3ca5e82cc7d85c421357d5c543817300c8e8c5281ddbc69bb561",
    },
    Asset {
        path: "tokenizer/tokenizer.json",
        size: 3_583_228,
        sha256: "6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30",
    },
    Asset {
        path: "tokenizer/tokenizer_config.json",
        size: 308,
        sha256: "50044de60daaa73df97d262e15a40d4faf0160e7d742df64b377877a1320dd12",
    },
];

pub fn default_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or("XDG_CACHE_HOME or HOME is required for the local model cache")?;
    if !base.is_absolute() {
        return Err("the model cache base must be an absolute path".into());
    }
    Ok(base.join("wtf").join("laya").join(REVISION))
}

fn private_dir(path: &Path) -> Result<(), String> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(path)
                .map_err(|error| format!("cannot inspect model cache: {error}"))?;
            if !meta.file_type().is_dir() {
                return Err(format!(
                    "model cache path is not a directory: {}",
                    path.display()
                ));
            }
            if meta.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("cannot secure model cache directory: {error}"))?;
            }
            Ok(())
        }
        Err(error) => Err(format!("cannot create model cache: {error}")),
    }
}

fn prepare_dir(dir: &Path) -> Result<(), String> {
    let parent = dir.parent().ok_or("invalid model cache directory")?;
    let grandparent = parent.parent().ok_or("invalid model cache directory")?;
    fs::create_dir_all(grandparent.parent().ok_or("invalid model cache root")?)
        .map_err(|error| format!("cannot create model cache base: {error}"))?;
    private_dir(grandparent)?;
    private_dir(parent)?;
    private_dir(dir)?;
    private_dir(&dir.join("tokenizer"))
}

fn file_size_matches(path: &Path, size: u64) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file() && meta.len() == size)
}

fn verified_file(path: &Path, asset: &Asset) -> Result<bool, String> {
    if !file_size_matches(path, asset.size) {
        return Ok(false);
    }
    let mut file =
        File::open(path).map_err(|error| format!("cannot inspect cached model: {error}"))?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|error| format!("cannot hash cached model: {error}"))?;
        if read == 0 {
            break;
        }
        hash.update(&buf[..read]);
    }
    Ok(format!("{:x}", hash.finalize()) == asset.sha256)
}

struct PartialFile(PathBuf);
impl Drop for PartialFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn download(agent: &ureq::Agent, base: &str, dir: &Path, asset: &Asset) -> Result<(), String> {
    let url = format!("{base}/{}", asset.path);
    let response = agent
        .get(&url)
        .call()
        .map_err(|error| format!("cannot download {}: {error}", asset.path))?;
    if response.status() != 200 {
        return Err(format!(
            "unexpected response for {}: {}",
            asset.path,
            response.status()
        ));
    }
    let target = dir.join(asset.path);
    let partial = PartialFile(dir.join(format!(
        ".download-{}-{}.tmp",
        std::process::id(),
        asset.path.replace('/', "-")
    )));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&partial.0)
        .map_err(|error| format!("cannot stage {}: {error}", asset.path))?;
    let mut hash = Sha256::new();
    let mut reader = response.into_reader().take(asset.size + 1);
    let mut received = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buf)
            .map_err(|error| format!("incomplete {}: {error}", asset.path))?;
        if read == 0 {
            break;
        }
        received += read as u64;
        if received > asset.size {
            return Err(format!("{} exceeded pinned size", asset.path));
        }
        file.write_all(&buf[..read])
            .map_err(|error| format!("cannot write {}: {error}", asset.path))?;
        hash.update(&buf[..read]);
    }
    if received != asset.size || format!("{:x}", hash.finalize()) != asset.sha256 {
        return Err(format!(
            "{} failed pinned size/SHA-256 verification",
            asset.path
        ));
    }
    file.sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", asset.path))?;
    fs::rename(&partial.0, &target)
        .map_err(|error| format!("cannot publish {}: {error}", asset.path))?;
    Ok(())
}

fn ready(dir: &Path, assets: &[Asset]) -> bool {
    let marker = dir.join(READY);
    fs::symlink_metadata(&marker).is_ok_and(|meta| meta.file_type().is_file())
        && fs::read_to_string(marker).is_ok_and(|content| content == REVISION)
        && assets
            .iter()
            .all(|asset| file_size_matches(&dir.join(asset.path), asset.size))
}

fn mark_ready(dir: &Path) -> Result<(), String> {
    let path = dir.join(READY);
    let temp = PartialFile(dir.join(format!(".verified-{}.tmp", std::process::id())));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp.0)
        .map_err(|error| format!("cannot stage model marker: {error}"))?;
    file.write_all(REVISION.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("cannot sync model marker: {error}"))?;
    fs::rename(&temp.0, path).map_err(|error| format!("cannot publish model marker: {error}"))
}

fn ensure_at(dir: &Path, base: &str, assets: &[Asset]) -> Result<(), String> {
    prepare_dir(dir)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(".download.lock"))
        .map_err(|error| format!("cannot lock model cache: {error}"))?;
    let until = Instant::now() + Duration::from_secs(900);
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(fs::TryLockError::WouldBlock) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(200))
            }
            Err(error) => return Err(format!("cannot obtain model cache lock: {error:?}")),
        }
    }
    if ready(dir, assets) {
        return Ok(());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(60))
        .timeout(Duration::from_secs(900))
        .build();
    for asset in assets {
        let target = dir.join(asset.path);
        if verified_file(&target, asset)? {
            continue;
        }
        eprintln!("Downloading Laya model: {}", asset.path);
        download(&agent, base, dir, asset)?;
    }
    mark_ready(dir)
}

pub fn ensure_default() -> Result<PathBuf, String> {
    let dir = default_dir()?;
    ensure_at(&dir, &format!("{REPOSITORY}/{REVISION}"), ASSETS)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const FIXTURE: Asset = Asset {
        path: "laya.onnx",
        size: 4,
        sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    };

    #[test]
    fn downloads_verified_bytes_once_and_reuses_private_cache() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("wtf/laya/revision");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest")
                .unwrap();
        });
        ensure_at(&dir, &base, &[FIXTURE]).unwrap();
        server.join().unwrap();
        assert_eq!(fs::read(dir.join("laya.onnx")).unwrap(), b"test");
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o077, 0);
        // No listener now: using the verified cache must not contact the network.
        ensure_at(&dir, &base, &[FIXTURE]).unwrap();
    }

    #[test]
    fn bad_download_cannot_publish_file_or_ready_marker() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("wtf/laya/revision");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil")
                .unwrap();
        });
        assert!(ensure_at(&dir, &base, &[FIXTURE]).is_err());
        server.join().unwrap();
        assert!(!dir.join("laya.onnx").exists());
        assert!(!dir.join(READY).exists());
    }
}
