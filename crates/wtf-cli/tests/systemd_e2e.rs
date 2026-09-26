#![cfg(target_os = "linux")]

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

const INVOCATION_ID: &str = "0123456789abcdef0123456789abcdef";
const JOURNAL_SECRET: &str = "SYSTEMD_JOURNAL_SECRET_MUST_NOT_BE_DISCLOSED";

struct Fixture {
    _temp: TempDir,
    home: PathBuf,
    work: PathBuf,
    runtime: PathBuf,
    bin: PathBuf,
    calls: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create private systemd E2E directory");
        let home = temp.path().join("home");
        let work = temp.path().join("work");
        let runtime = temp.path().join("runtime");
        let bin = temp.path().join("bin");
        let calls = temp.path().join("calls.log");
        for directory in [&home, &work, &runtime, &bin] {
            fs::create_dir(directory).expect("create private E2E directory");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("secure private E2E directory");
        }
        fs::create_dir(home.join(".config")).expect("create private XDG config directory");
        fs::write(&calls, "").expect("create fake command call log");
        for tool in [
            "curl", "wget", "nc", "ncat", "ping", "docker", "podman", "getent", "ip", "ss",
        ] {
            write_executable(&bin.join(tool), BLOCKED_EXTERNAL_SHIM);
        }
        write_executable(&bin.join("systemctl"), SYSTEMCTL_SHIM);
        write_executable(&bin.join("journalctl"), JOURNALCTL_SHIM);

        Self {
            _temp: temp,
            home,
            work,
            runtime,
            bin,
            calls,
        }
    }

    fn path(&self) -> std::ffi::OsString {
        let executable_dir = Path::new(env!("CARGO_BIN_EXE_wtf"))
            .parent()
            .expect("wtf executable has a parent directory");
        std::env::join_paths([
            self.bin.as_path(),
            executable_dir,
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])
        .expect("construct isolated systemd E2E PATH")
    }

    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("WTF_NO_MODEL", "1")
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("SHELL", "/bin/bash")
            .env("PATH", self.path())
            .env("TERM", "dumb")
            .env("LC_ALL", "C")
            .current_dir(&self.work);
        command
    }

    fn install_bash_hook(&self) {
        let output = self
            .command(env!("CARGO_BIN_EXE_wtf"))
            .arg("install")
            .output()
            .expect("install isolated Bash hook");
        assert!(
            output.status.success(),
            "wtf install failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run_explicit(
        &self,
        args: &[&str],
        show_mode: &str,
        journal_mode: &str,
        start_stderr: &str,
    ) -> Output {
        let mut command = self.command(env!("CARGO_BIN_EXE_wtf"));
        command
            .args(["--json", "--", "systemctl"])
            .args(args)
            .env("FAKE_CALL_LOG", &self.calls)
            .env("SYSTEMD_SHOW_MODE", show_mode)
            .env("SYSTEMD_LOG_MODE", journal_mode)
            .env("SYSTEMD_START_STDERR", start_stderr);
        command
            .output()
            .expect("run explicit systemctl E2E command")
    }

    fn run_interactive_bash(
        &self,
        script: &str,
        show_mode: &str,
        journal_mode: &str,
        start_stderr: &str,
    ) -> Output {
        let mut command = Command::new("/bin/bash");
        command
            .args(["--noprofile", "--rcfile"])
            .arg(self.home.join(".bashrc"))
            .arg("-i")
            .env_clear()
            .env("WTF_NO_MODEL", "1")
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("SHELL", "/bin/bash")
            .env("PATH", self.path())
            .env("TERM", "dumb")
            .env("LC_ALL", "C")
            .env("FAKE_CALL_LOG", &self.calls)
            .env("SYSTEMD_SHOW_MODE", show_mode)
            .env("SYSTEMD_LOG_MODE", journal_mode)
            .env("SYSTEMD_START_STDERR", start_stderr)
            .current_dir(&self.work)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("launch interactive isolated Bash");
        child
            .stdin
            .take()
            .expect("interactive Bash stdin")
            .write_all(script.as_bytes())
            .expect("write interactive Bash script");
        child
            .wait_with_output()
            .expect("wait for interactive isolated Bash")
    }

    fn read_json(&self, path: &Path, output: &Output) -> Value {
        let bytes = fs::read(path).unwrap_or_else(|error| {
            panic!(
                "missing diagnosis JSON {}: {error}; Bash stdout={} stderr={}",
                path.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "invalid diagnosis JSON ({error}): {}",
                String::from_utf8_lossy(&bytes)
            )
        })
    }

    fn calls(&self) -> Vec<Vec<String>> {
        fs::read_to_string(&self.calls)
            .expect("read isolated fake command log")
            .lines()
            .map(|line| line.split('\t').map(str::to_owned).collect())
            .collect()
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fake systemd executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make fake systemd executable runnable");
}

fn assert_json_failure(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(1),
        "failed systemctl diagnosis should return the command's status: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "wtf emitted invalid JSON ({error}): stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(json["exit_status"]["code"], 1, "{json}");
    assert!(
        !format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .contains(JOURNAL_SECRET),
        "raw journal contents must not be disclosed"
    );
    json
}

fn assert_confirmed_journal_cause(json: &Value) {
    assert_eq!(json["status"], "Confirmed", "{json}");
    assert_eq!(json["category"], "service/failed", "{json}");
    let root = json["investigation"]["root_cause"]
        .as_str()
        .expect("confirmed root cause is present");
    assert!(
        root.contains("api.service"),
        "root should name the unit: {json}"
    );
    assert!(
        root.to_ascii_lowercase()
            .contains("no space left on device"),
        "root should state the journal-confirmed cause: {json}"
    );
    assert_probe_evidence(json, "SystemdShow");
    assert_probe_evidence(json, "SystemdLogs");
    assert_probe_attempts(json, &[("SystemdShow", "ok"), ("SystemdLogs", "ok")]);
}

fn assert_probe_evidence(json: &Value, expected: &str) {
    let evidence = json["investigation"]["evidence"]
        .as_array()
        .expect("investigation evidence is present");
    assert!(
        evidence.iter().any(|item| item["probe"] == expected),
        "expected {expected} evidence: {json}"
    );
}

fn assert_probe_attempts(json: &Value, expected: &[(&str, &str)]) {
    let attempts = json["investigation"]["attempts"]
        .as_array()
        .expect("probe attempts are present");
    let actual: Vec<(&str, &str)> = attempts
        .iter()
        .map(|attempt| {
            (
                attempt["probe"].as_str().expect("probe id is a string"),
                attempt["result"]
                    .as_str()
                    .expect("probe result is a string"),
            )
        })
        .collect();
    assert_eq!(actual, expected, "unexpected probe attempts: {json}");
}

fn assert_initial_calls(calls: &[Vec<String>], before: u64, after: u64) {
    assert_eq!(
        calls.len(),
        3,
        "only the original start and two fixed probes run: {calls:?}"
    );
    assert_eq!(calls[0], ["systemctl", "start", "api"], "{calls:?}");
    assert_eq!(
        calls[1],
        [
            "systemctl",
            "show",
            "--no-pager",
            "--property=Id,LoadState,ActiveState,Result,InvocationID",
            "--",
            "api.service"
        ],
        "systemctl show must use the fixed, unit-scoped argv: {calls:?}"
    );
    assert_eq!(
        calls[2].first().map(String::as_str),
        Some("journalctl"),
        "{calls:?}"
    );
    assert_journal_argv_and_window(&calls[2], before, after);
}

fn assert_journal_argv_and_window(call: &[String], before: u64, after: u64) {
    assert_eq!(
        call.len(),
        9,
        "journalctl must receive only the fixed argv: {call:?}"
    );
    assert_eq!(call[0], "journalctl", "{call:?}");
    assert_eq!(call[1], "--unit=api.service", "{call:?}");
    let start = call[2]
        .strip_prefix("--since=@")
        .expect("journal window has a fixed since argument")
        .parse::<u64>()
        .expect("journal start timestamp is numeric");
    let end = call[3]
        .strip_prefix("--until=@")
        .expect("journal window has a fixed until argument")
        .parse::<u64>()
        .expect("journal end timestamp is numeric");
    assert!(end >= start, "journal window is ordered: {call:?}");
    assert!(
        end - start <= 3600,
        "journal window is bounded to one hour: {call:?}"
    );
    assert!(
        start >= before.saturating_sub(3),
        "journal window starts near the failed command: {call:?}"
    );
    assert!(
        start <= before.saturating_add(1),
        "journal window starts near the failed command: {call:?}"
    );
    assert!(
        end >= before.saturating_sub(2),
        "journal window covers the failed command: {call:?}"
    );
    assert!(
        end <= after.saturating_add(2),
        "journal window ends near the failed command: {call:?}"
    );
    let expected: Vec<String> = vec![
        "--lines=40".into(),
        "--no-pager".into(),
        "--output=cat".into(),
        "--quiet".into(),
        format!("_SYSTEMD_INVOCATION_ID={INVOCATION_ID}"),
    ];
    assert_eq!(
        &call[4..],
        expected.as_slice(),
        "journal must be bounded and filtered to the failed invocation: {call:?}"
    );
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_secs()
}

fn assert_no_unexpected_commands(calls: &[Vec<String>]) {
    assert!(
        calls.iter().all(|call| matches!(
            call.first().map(String::as_str),
            Some("systemctl" | "journalctl")
        )),
        "no network tools or real daemon commands should be used: {calls:?}"
    );
}

const SYSTEMCTL_SHIM: &str = r##"#!/bin/sh
{
    printf 'systemctl'
    for arg in "$@"; do printf '\t%s' "$arg"; done
    printf '\n'
} >> "$FAKE_CALL_LOG"
if [ "$1" = show ]; then
    case "${SYSTEMD_SHOW_MODE:-failed}" in
        failed)
            printf '%s\n' 'Id=api.service' 'LoadState=loaded' 'ActiveState=failed' 'Result=exit-code' 'InvocationID=0123456789abcdef0123456789abcdef'
            exit 0
            ;;
        missing)
            printf '%s\n' 'Id=api.service' 'LoadState=not-found' 'ActiveState=inactive' 'Result=success' 'InvocationID='
            exit 0
            ;;
        mismatch)
            printf '%s\n' 'Id=other.service' 'LoadState=loaded' 'ActiveState=failed' 'Result=exit-code' 'InvocationID=0123456789abcdef0123456789abcdef'
            exit 0
            ;;
        unavailable)
            printf '%s\n' 'fake show unavailable' >&2
            exit 1
            ;;
    esac
fi
printf '%s\n' "${SYSTEMD_START_STDERR:-synthetic systemctl failure}" >&2
exit 1
"##;

const BLOCKED_EXTERNAL_SHIM: &str = r##"#!/bin/sh
{
    printf '%s' "${0##*/}"
    for arg in "$@"; do printf '\t%s' "$arg"; done
    printf '\n'
} >> "$FAKE_CALL_LOG"
printf '%s\n' 'blocked unexpected external probe' >&2
exit 97
"##;

const JOURNALCTL_SHIM: &str = r##"#!/bin/sh
{
    printf 'journalctl'
    for arg in "$@"; do printf '\t%s' "$arg"; done
    printf '\n'
} >> "$FAKE_CALL_LOG"
case "${SYSTEMD_LOG_MODE:-known}" in
    known)
        printf '%s\n' 'api.service: No space left on device; SYSTEMD_JOURNAL_SECRET_MUST_NOT_BE_DISCLOSED'
        exit 0
        ;;
    inconclusive)
        printf '%s\n' 'api.service exited after an unclassified startup error'
        exit 0
        ;;
    unavailable)
        printf '%s\n' 'fake journal unavailable' >&2
        exit 1
        ;;
esac
exit 1
"##;

#[test]
fn explicit_start_confirms_only_the_matching_failed_invocation_journal_cause() {
    let fixture = Fixture::new();
    let before = current_epoch_seconds();
    let output = fixture.run_explicit(
        &["start", "api"],
        "failed",
        "known",
        "synthetic start failure",
    );
    let after = current_epoch_seconds();
    let json = assert_json_failure(&output);

    assert_eq!(json["command"], "systemctl start api", "{json}");
    assert_confirmed_journal_cause(&json);
    let calls = fixture.calls();
    assert_initial_calls(&calls, before, after);
    assert_no_unexpected_commands(&calls);
}

#[test]
fn interactive_bash_hook_reconstructs_failed_start_without_replaying_it() {
    let fixture = Fixture::new();
    fixture.install_bash_hook();
    let json_path = fixture.home.join("systemd.json");
    let script = format!(
        "systemctl start api\nwtf --json > {}\nexit 0\n",
        shell_quote(&json_path)
    );
    let before = current_epoch_seconds();
    let output =
        fixture.run_interactive_bash(&script, "failed", "known", "synthetic start failure");
    let after = current_epoch_seconds();
    assert!(
        output.status.success(),
        "isolated Bash failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = fixture.read_json(&json_path, &output);

    assert_eq!(json["command"], "systemctl start api", "{json}");
    assert_eq!(json["exit_status"]["code"], 1, "{json}");
    assert_confirmed_journal_cause(&json);
    assert!(
        !json.to_string().contains(JOURNAL_SECRET),
        "raw journal contents must not be disclosed in shell-hook JSON"
    );
    let calls = fixture.calls();
    assert_initial_calls(&calls, before, after);
    assert_no_unexpected_commands(&calls);
    assert!(
        !format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .contains(JOURNAL_SECRET),
        "raw journal contents must not be disclosed by the Bash path"
    );
}

#[test]
fn missing_unit_is_confirmed_without_reading_journal_logs() {
    let fixture = Fixture::new();
    let output = fixture.run_explicit(
        &["start", "api"],
        "missing",
        "known",
        "synthetic start failure",
    );
    let json = assert_json_failure(&output);

    assert_eq!(json["status"], "Confirmed", "{json}");
    assert_eq!(json["category"], "service/not-found", "{json}");
    assert!(
        json["investigation"]["root_cause"]
            .as_str()
            .is_some_and(|root| root.contains("api.service")),
        "missing-unit root should name the normalized unit: {json}"
    );
    assert_probe_evidence(&json, "SystemdShow");
    assert_probe_attempts(&json, &[("SystemdShow", "ok")]);
    let calls = fixture.calls();
    assert_eq!(
        calls.len(),
        2,
        "a missing unit must not trigger journalctl: {calls:?}"
    );
    assert_eq!(calls[0], ["systemctl", "start", "api"], "{calls:?}");
    assert_eq!(calls[1][0], "systemctl", "{calls:?}");
    assert_eq!(calls[1][1], "show", "{calls:?}");
    assert_no_unexpected_commands(&calls);
}

#[test]
fn stderr_alone_does_not_confirm_when_journal_is_inconclusive_or_unavailable() {
    for journal_mode in ["inconclusive", "unavailable"] {
        let fixture = Fixture::new();
        let output = fixture.run_explicit(
            &["start", "api"],
            "failed",
            journal_mode,
            "No space left on device (reported only by systemctl stderr)",
        );
        let json = assert_json_failure(&output);

        assert_eq!(
            json["status"], "Likely",
            "stderr alone must not confirm root cause: {json}"
        );
        assert_eq!(json["category"], "service/failed", "{json}");
        assert!(json["investigation"]["root_cause"].is_null(), "{json}");
        assert_probe_evidence(&json, "SystemdShow");
        assert_probe_attempts(
            &json,
            &[
                ("SystemdShow", "ok"),
                (
                    "SystemdLogs",
                    if journal_mode == "unavailable" {
                        "exit 1"
                    } else {
                        "ok"
                    },
                ),
            ],
        );
        let calls = fixture.calls();
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert_eq!(calls[0], ["systemctl", "start", "api"], "{calls:?}");
        assert_eq!(
            calls[2].first().map(String::as_str),
            Some("journalctl"),
            "{calls:?}"
        );
        assert_no_unexpected_commands(&calls);
    }
}

#[test]
fn unavailable_or_mismatched_show_state_is_unknown_and_skips_journal() {
    for show_mode in ["unavailable", "mismatch"] {
        let fixture = Fixture::new();
        let output = fixture.run_explicit(
            &["start", "api"],
            show_mode,
            "known",
            "synthetic start failure",
        );
        let json = assert_json_failure(&output);

        assert_eq!(json["category"], "unknown", "{json}");
        assert_eq!(
            json["investigation"]["evidence"].as_array().map(Vec::len),
            Some(0),
            "{json}"
        );
        assert!(json["investigation"]["root_cause"].is_null(), "{json}");
        assert_probe_attempts(
            &json,
            &[(
                "SystemdShow",
                if show_mode == "unavailable" {
                    "exit 1"
                } else {
                    "ok"
                },
            )],
        );
        let calls = fixture.calls();
        assert_eq!(
            calls.len(),
            2,
            "invalid state must not trigger journalctl: {calls:?}"
        );
        assert_eq!(calls[1][0], "systemctl", "{calls:?}");
        assert_eq!(calls[1][1], "show", "{calls:?}");
        assert_no_unexpected_commands(&calls);
    }
}

#[test]
fn unsupported_systemctl_action_flags_and_multiple_units_do_not_probe() {
    let cases: &[&[&str]] = &[
        &["restart", "api"],
        &["--user", "start", "api"],
        &["start", "--no-block", "api"],
        &["start", "api", "worker"],
    ];
    for args in cases {
        let fixture = Fixture::new();
        let output = fixture.run_explicit(args, "failed", "known", "synthetic unsupported failure");
        let json = assert_json_failure(&output);
        assert!(json["investigation"]["root_cause"].is_null(), "{json}");
        assert_eq!(
            json["investigation"]["attempts"].as_array().map(Vec::len),
            Some(0),
            "unsupported invocation must not probe systemd: {json}"
        );
        let calls = fixture.calls();
        assert_eq!(
            calls.len(),
            1,
            "only the original command may run: {calls:?}"
        );
        assert_eq!(calls[0][0], "systemctl", "{calls:?}");
        assert_eq!(
            &calls[0][1..],
            *args,
            "the fake records the exact original argv: {calls:?}"
        );
        assert_no_unexpected_commands(&calls);
    }
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}
