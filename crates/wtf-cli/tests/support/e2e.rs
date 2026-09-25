use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

pub struct Sandbox {
    _temp: TempDir,
    pub home: PathBuf,
    pub work: PathBuf,
    pub runtime: PathBuf,
    pub bin: PathBuf,
}

impl Sandbox {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().expect("create isolated E2E directory");
        let home = temp.path().join("home");
        let work = temp.path().join("work");
        let config = home.join(".config");
        let runtime = temp.path().join("runtime");
        for directory in [&home, &work, &config, &runtime] {
            fs::create_dir_all(directory).expect("create isolated E2E directory");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("secure isolated E2E directory");
        }
        let bin = std::env::var_os("WTF_E2E_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_wtf")));
        Self {
            _temp: temp,
            home,
            work,
            runtime,
            bin,
        }
    }

    pub fn install_bash(&self) {
        let output = self
            .command("install", &[])
            .output()
            .expect("run wtf install");
        assert!(
            output.status.success(),
            "wtf install failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub fn run_bash(&self, cwd: &Path, script: &str, extra_env: &[(&str, &str)]) -> Output {
        let mut command = Command::new("/bin/bash");
        command
            .args(["--noprofile", "--rcfile"])
            .arg(self.home.join(".bashrc"))
            .arg("-i")
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("RUSTUP_HOME", self.rustup_home())
            .env("SHELL", "/bin/bash")
            .env("PATH", self.path())
            .env("TERM", "dumb")
            .env("LC_ALL", "C")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let mut child = command.spawn().expect("launch isolated interactive Bash");
        let stdout = child.stdout.take().expect("Bash stdout");
        let stderr = child.stderr.take().expect("Bash stderr");
        let stdout_reader = thread::spawn(|| bounded_capture(stdout));
        let stderr_reader = thread::spawn(|| bounded_capture(stderr));
        let mut stdin = child.stdin.take().expect("Bash stdin");
        stdin
            .write_all(script.as_bytes())
            .expect("write Bash script");
        stdin.write_all(b"\nexit 0\n").expect("finish Bash script");
        drop(stdin);

        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = child.try_wait().expect("check Bash process") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("terminate timed-out E2E Bash");
                panic!("isolated Bash exceeded its 120-second timeout");
            }
            thread::sleep(Duration::from_millis(20));
        };
        Output {
            status,
            stdout: stdout_reader.join().expect("read bounded Bash stdout"),
            stderr: stderr_reader.join().expect("read bounded Bash stderr"),
        }
    }

    pub fn read_json(&self, path: &Path, output: &Output) -> Value {
        let context = format!(
            "Bash stdout: {}\nBash stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(path).unwrap_or_else(|error| {
            panic!("missing JSON result {}: {error}\n{context}", path.display())
        });
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "invalid JSON result ({error}): {}\n{context}",
                String::from_utf8_lossy(&bytes)
            )
        })
    }

    fn command(&self, subcommand: &str, args: &[&str]) -> Command {
        let mut command = Command::new(&self.bin);
        command
            .arg(subcommand)
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("RUSTUP_HOME", self.rustup_home())
            .env("SHELL", "/bin/bash")
            .env("PATH", self.path())
            .env("TERM", "dumb")
            .env("LC_ALL", "C")
            .current_dir(&self.work);
        command
    }

    fn path(&self) -> OsString {
        let binary_dir = self.bin.parent().expect("wtf binary has a parent");
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
        let mut paths = vec![binary_dir.to_path_buf()];
        if let Some(cargo_home) = cargo_home {
            paths.push(cargo_home.join("bin"));
        }
        paths.extend(std::env::split_paths(std::ffi::OsStr::new(
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )));
        std::env::join_paths(paths).expect("construct isolated PATH")
    }

    fn rustup_home(&self) -> PathBuf {
        std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
            .expect("host HOME or RUSTUP_HOME is required for Rust E2E tools")
    }
}
fn bounded_capture(mut reader: impl Read) -> Vec<u8> {
    const MAX_CAPTURE: usize = 1024 * 1024;
    let mut captured = Vec::with_capacity(MAX_CAPTURE.min(16 * 1024));
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer).expect("read Bash output");
        if count == 0 {
            break;
        }
        let remaining = MAX_CAPTURE.saturating_sub(captured.len());
        captured.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    captured
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
