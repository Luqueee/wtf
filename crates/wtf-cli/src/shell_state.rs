use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use wtf_core::capture::{CommandExecution, ProcessExit};

const FILE_NAME: &str = "last-failure.json";
const MAX_COMMAND_LINE: usize = 16 * 1024;
const MAX_CWD: usize = 4096;
const MAX_SHELL: usize = 64;
const MAX_FILE: u64 = 64 * 1024;
const DEFAULT_TTL_SECS: u64 = 900;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize)]
struct FailureRecord {
    command_line: String,
    cwd: String,
    exit_code: i32,
    started_at: u64,
    finished_at: u64,
    shell: String,
}

/// Store only bounded command metadata for the most recent failed shell command.
pub fn record_failure(
    command_line: &str,
    cwd: &str,
    exit_code: i32,
    started_at: u64,
    finished_at: u64,
    shell: &str,
) -> io::Result<()> {
    if exit_code == 0 || is_wtf_command(command_line) || unsafe_shell_context(command_line) {
        return Ok(());
    }

    let record = FailureRecord {
        command_line: redact_and_bound(command_line, MAX_COMMAND_LINE),
        cwd: bounded(cwd, MAX_CWD),
        exit_code,
        started_at,
        finished_at,
        shell: bounded(shell, MAX_SHELL),
    };
    let dir = state_directory(true)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no secure state directory available",
        )
    })?;
    write_record(&dir, &record, current_uid())
}

fn write_record(dir: &Path, record: &FailureRecord, uid: u32) -> io::Result<()> {
    let data = serde_json::to_vec(record).map_err(io::Error::other)?;
    let path = dir.join(FILE_NAME);
    if fs::symlink_metadata(&path).is_ok() {
        check_private_file(&path, uid)?;
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_path = dir.join(format!(
        ".last-failure-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nofollow_flag());
    let result = (|| {
        let mut file = options.open(&temp_path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        fs::rename(&temp_path, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}

#[cfg(target_os = "linux")]
fn nofollow_flag() -> i32 {
    0x20000
}
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn nofollow_flag() -> i32 {
    0x100
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn nofollow_flag() -> i32 {
    0
}

fn read_record(path: &Path, uid: u32, now: u64, ttl: u64) -> Option<FailureRecord> {
    check_private_file(path, uid).ok()?;
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.len() == 0 || metadata.len() > MAX_FILE {
        return None;
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(nofollow_flag());
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    options
        .open(path)
        .ok()?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_FILE {
        return None;
    }
    let record: FailureRecord = serde_json::from_slice(&bytes).ok()?;
    if record.exit_code == 0
        || record.finished_at > now
        || now.saturating_sub(record.finished_at) > ttl
        || record.command_line.is_empty()
        || record.command_line.len() > MAX_COMMAND_LINE
        || record.cwd.len() > MAX_CWD
        || record.shell.len() > MAX_SHELL
        || is_wtf_command(&record.command_line)
    {
        return None;
    }
    Some(record)
}

fn execution(record: FailureRecord) -> Option<CommandExecution> {
    let (command, args) = command_and_args(&record.command_line);
    if command.is_empty() {
        return None;
    }
    Some(CommandExecution {
        command,
        args,
        cwd: PathBuf::from(record.cwd),
        exit_status: ProcessExit {
            code: Some(record.exit_code),
            signal: None,
        },
        stdout: String::new(),
        stderr: String::new(),
        duration: Duration::from_secs(record.finished_at.saturating_sub(record.started_at)),
        timestamp: UNIX_EPOCH + Duration::from_secs(record.finished_at),
        spawn_error: None,
    })
}

/// Read a still-valid secure record as an output-free command execution.
pub fn load_recent() -> Option<CommandExecution> {
    let dir = state_directory(false).ok().flatten()?;
    execution(read_record(
        &dir.join(FILE_NAME),
        current_uid(),
        epoch_seconds(),
        ttl_secs(),
    )?)
}

fn state_directory(create: bool) -> io::Result<Option<PathBuf>> {
    let uid = current_uid();
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let base = PathBuf::from(runtime);
        if secure_base(&base, uid) {
            if let Some(path) = prepare_private_dir(&base.join("wtf"), uid, create) {
                return Ok(Some(path));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let base = PathBuf::from(format!("/run/user/{uid}"));
        if secure_base(&base, uid) {
            if let Some(path) = prepare_private_dir(&base.join("wtf"), uid, create) {
                return Ok(Some(path));
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if secure_base(&home, uid) {
            let cache = home.join(".cache");
            if ensure_cache_dir(&cache, uid, create) {
                if let Some(path) = prepare_private_dir(&cache.join("wtf"), uid, create) {
                    return Ok(Some(path));
                }
            }
        }
    }
    let temp = std::env::temp_dir().join(format!("wtf-{uid}"));
    if let Some(path) = prepare_private_dir(&temp, uid, create) {
        return Ok(Some(path));
    }
    Ok(None)
}

fn prepare_private_dir(path: &Path, uid: u32, create: bool) -> Option<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != uid
                || meta.mode() & 0o777 != 0o700
            {
                return None;
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(false).mode(0o700);
            if builder.create(path).is_err() {
                return None;
            }
            let meta = fs::symlink_metadata(path).ok()?;
            if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
                return None;
            }
        }
        _ => return None,
    }
    Some(path.to_path_buf())
}

fn ensure_cache_dir(path: &Path, uid: u32, create: bool) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == uid
                && meta.mode() & 0o022 == 0
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(path).is_ok() && ensure_cache_dir(path, uid, false)
        }
        _ => false,
    }
}

fn secure_base(path: &Path, uid: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| {
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == uid
            // Runtime and HOME bases may be readable by others, but not writable.
            && meta.mode() & 0o022 == 0
    })
}

fn check_private_file(path: &Path, uid: u32) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing insecure failure record",
        ));
    }
    Ok(())
}

fn current_uid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: getuid has no arguments and no side effects.
    unsafe { getuid() }
}

fn ttl_secs() -> u64 {
    std::env::var("WTF_FAILURE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_TTL_SECS)
}

fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn bounded(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_string();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn is_wtf_command(line: &str) -> bool {
    shell_tokens(line).into_iter().any(|token| {
        unquote(&line[token.start..token.end])
            .rsplit('/')
            .next()
            .is_some_and(|part| part == "wtf")
    })
}

fn unsafe_shell_context(line: &str) -> bool {
    line.contains('\n') || line.contains('\r') || line.contains("<<")
}

fn redact_and_bound(line: &str, limit: usize) -> String {
    // Bound before tokenization so all spans are UTF-8 boundaries and scanning stays cheap.
    let line = bounded(line, limit);
    let tokens = shell_tokens(&line);
    let mut output = String::with_capacity(line.len());
    let mut source_end = 0;
    let mut redact_next = 0usize;
    for token in tokens {
        let raw = &line[token.start..token.end];
        let value = unquote(raw);
        let lower = value.to_ascii_lowercase();
        let key = lower
            .trim_start_matches('-')
            .split(['=', ':'])
            .next()
            .unwrap_or("");
        let payload_flag = key == "d"
            || key == "f"
            || key.starts_with("data")
            || key == "form"
            || key == "form-string";
        let sensitive = payload_flag
            || matches!(key, "env" | "build-arg")
            || [
                "password",
                "passwd",
                "token",
                "secret",
                "api_key",
                "api-key",
                "apikey",
                "authorization",
                "auth",
                "credential",
                "client_secret",
                "cookie",
                "user",
            ]
            .iter()
            .any(|needle| {
                key.contains(needle) || (*needle == "user" && matches!(key, "u" | "user"))
            });
        let replacement = if redact_next > 0 {
            redact_next -= 1;
            "[REDACTED]".to_string()
        } else if sensitive {
            let split = raw.find(['=', ':']);
            if key == "authorization" && value.contains(' ') {
                "[REDACTED]".to_string()
            } else if let Some(split) = split {
                if key == "authorization" {
                    redact_next = 2;
                }
                let suffix = if raw.ends_with(['\'', '"']) {
                    &raw[raw.len() - 1..]
                } else {
                    ""
                };
                format!("{}=[REDACTED]{}", &raw[..split], suffix)
            } else {
                // `--password value`; Authorization headers also include `Bearer value`.
                redact_next = if key == "authorization" { 2 } else { 1 };
                raw.to_string()
            }
        } else if matches!(
            value.as_str(),
            "-H" | "--header" | "-e" | "--env" | "--env-file" | "--build-arg"
        ) {
            redact_next = 1;
            raw.to_string()
        } else if value.contains("://") {
            redact_url(raw)
        } else {
            raw.to_string()
        };
        output.push_str(&line[source_end..token.start]);
        output.push_str(&replacement);
        source_end = token.end;
    }
    output.push_str(&line[source_end..]);
    bounded(&output, limit)
}

#[derive(Clone, Copy)]
struct Token {
    start: usize,
    end: usize,
}
fn shell_tokens(line: &str) -> Vec<Token> {
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == bytes.len() {
            break;
        }
        let start = i;
        let mut quote = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if quote == 0 && b.is_ascii_whitespace() {
                break;
            }
            if b == b'\\' && quote != b'\'' {
                i = (i + 2).min(bytes.len());
                continue;
            }
            if quote == 0 && (b == b'\'' || b == b'"') {
                quote = b;
                i += 1;
                continue;
            }
            if quote == b && quote != 0 {
                quote = 0;
                i += 1;
                continue;
            }
            i += 1;
        }
        tokens.push(Token { start, end: i });
    }
    tokens
}

fn redact_url(token: &str) -> String {
    let mut value = token.to_string();
    if let Some(scheme_end) = value.find("://") {
        let authority_start = scheme_end + 3;
        if let Some(at) = value[authority_start..].find('@') {
            let at = authority_start + at;
            value.replace_range(authority_start..at, "[REDACTED]");
        }
    }
    if let Some(query) = value.find('?') {
        let (prefix, query_value) = value.split_at(query + 1);
        let mut parts = Vec::new();
        for pair in query_value.split('&') {
            let (key, _) = pair.split_once('=').unwrap_or((pair, ""));
            let key_lower = key.to_ascii_lowercase();
            if [
                "password",
                "passwd",
                "token",
                "secret",
                "key",
                "auth",
                "credential",
            ]
            .iter()
            .any(|k| key_lower.contains(k))
            {
                parts.push(format!("{key}=[REDACTED]"));
            } else {
                parts.push(pair.to_string());
            }
        }
        value = format!("{prefix}{}", parts.join("&"));
    }
    value
}

fn command_and_args(line: &str) -> (String, Vec<String>) {
    let tokens = shell_tokens(line);
    let Some(first) = tokens.first() else {
        return (String::new(), Vec::new());
    };
    let command = unquote(&line[first.start..first.end]);
    let args = tokens
        .iter()
        .skip(1)
        .map(|t| unquote(&line[t.start..t.end]))
        .collect();
    (command, args)
}

fn unquote(token: &str) -> String {
    let mut output = String::new();
    let mut quote = None;
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' && quote != Some('\'') {
            if let Some(next) = chars.next() {
                output.push(next);
            }
        } else if matches!(ch, '\'' | '"') && quote.is_none() {
            quote = Some(ch);
        } else if Some(ch) == quote {
            quote = None;
        } else {
            output.push(ch);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn record(line: &str, finished_at: u64) -> FailureRecord {
        FailureRecord {
            command_line: redact_and_bound(line, MAX_COMMAND_LINE),
            cwd: "/work/project".into(),
            exit_code: 7,
            started_at: finished_at.saturating_sub(3),
            finished_at,
            shell: "bash".into(),
        }
    }

    #[test]
    fn replacement_and_execution_preserve_metadata_without_output() {
        let dir = private_dir();
        let uid = current_uid();
        assert!(secure_base(dir.path(), uid));
        assert!(read_record(
            &dir.path().join(FILE_NAME),
            uid,
            epoch_seconds(),
            DEFAULT_TTL_SECS
        )
        .is_none());
        let empty_path = dir.path().join(FILE_NAME);
        fs::write(&empty_path, b"").unwrap();
        assert!(read_record(&empty_path, uid, epoch_seconds(), DEFAULT_TTL_SECS).is_none());
        fs::remove_file(empty_path).unwrap();
        let now = epoch_seconds();
        write_record(dir.path(), &record("git push origin main", now), uid).unwrap();
        write_record(dir.path(), &record("cargo test --workspace", now), uid).unwrap();

        let loaded = execution(
            read_record(&dir.path().join(FILE_NAME), uid, now, DEFAULT_TTL_SECS).unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.command, "cargo");
        assert_eq!(
            loaded.args,
            vec!["test".to_string(), "--workspace".to_string()]
        );
        assert_eq!(loaded.cwd, PathBuf::from("/work/project"));
        assert_eq!(loaded.exit_code(), Some(7));
        assert_eq!(loaded.duration, Duration::from_secs(3));
        assert!(loaded.stdout.is_empty());
        assert!(loaded.stderr.is_empty());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn expiration_corruption_and_insecure_files_are_rejected() {
        let dir = private_dir();
        let uid = current_uid();
        let path = dir.path().join(FILE_NAME);
        write_record(dir.path(), &record("cargo test", 100), uid).unwrap();
        assert!(read_record(&path, uid, 111, 10).is_none());
        assert!(read_record(&path, uid, 109, 10).is_some());

        fs::write(&path, b"{").unwrap();
        assert!(read_record(&path, uid, 109, 10).is_none());
        write_record(dir.path(), &record("cargo test", 100), uid).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_record(&path, uid, 109, 10).is_none());
    }

    #[test]
    fn sensitive_arguments_headers_and_url_secrets_are_redacted() {
        let line = "curl -H 'Authorization: Bearer abc123' 'https://user:pass@example.test/api?token=secret&ok=yes' --password hunter2 --token=more --user admin:password -H 'X-Api-Key: keysecret' -H 'Cookie: sid=private'";
        let safe = redact_and_bound(line, MAX_COMMAND_LINE);
        for secret in [
            "abc123",
            "user:pass",
            "secret",
            "hunter2",
            "more",
            "admin:password",
            "keysecret",
            "private",
        ] {
            assert!(!safe.contains(secret), "{safe}");
        }
        assert!(safe.contains("[REDACTED]"));
    }

    #[test]
    fn multiline_history_is_skipped_and_payloads_are_not_persisted() {
        assert!(unsafe_shell_context("cat <<EOF\nprivate body\nEOF"));
        assert!(unsafe_shell_context("command\r\nsecond"));
        assert!(!unsafe_shell_context("curl --data value"));

        let dir = private_dir();
        let line = "curl --data 'body=data-secret' --data-custom custom-secret --form 'file=form-secret' -F 'x=f-secret' -d d-secret";
        let safe = redact_and_bound(line, MAX_COMMAND_LINE);
        let record = record(&safe, 100);
        write_record(dir.path(), &record, current_uid()).unwrap();
        let persisted = fs::read_to_string(dir.path().join(FILE_NAME)).unwrap();
        for secret in [
            "data-secret",
            "custom-secret",
            "form-secret",
            "f-secret",
            "d-secret",
        ] {
            assert!(!persisted.contains(secret), "{persisted}");
        }
    }

    #[test]
    fn docker_environment_values_are_not_stored_in_shell_records() {
        let safe = redact_and_bound(
            "docker run --name api -e DATABASE_URL=postgres-value --env API_ENDPOINT=private-value --env=ANOTHER=value --build-arg BUILD_TOKEN=build-value image",
            MAX_COMMAND_LINE,
        );
        for secret in [
            "postgres-value",
            "private-value",
            "ANOTHER=value",
            "build-value",
        ] {
            assert!(!safe.contains(secret), "{safe}");
        }
        assert!(safe.contains("--name api"));
    }

    #[test]
    fn wtf_commands_and_successes_are_excluded() {
        assert!(is_wtf_command("wtf --verbose"));
        assert!(is_wtf_command("/opt/bin/wtf -- cat"));
        assert!(is_wtf_command("command wtf -- cat"));
        assert!(!is_wtf_command("cargo test"));
    }
}
