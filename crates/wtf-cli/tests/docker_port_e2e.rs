#![cfg(any(target_os = "linux", target_os = "macos"))]

#[path = "support/e2e.rs"]
mod support;

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::{shell_quote, Sandbox};

const RUN_ARGS: &[&str] = &["run", "-p", "8080:80", "fixture-image"];
const DAEMON_ERROR: &str = "Error response from daemon: driver failed programming external connectivity on endpoint attempted-api (id): Bind for 0.0.0.0:8080 failed: port is already allocated";
const OWNER_ROWS: &str = r#"{"ID":"decoy","Names":"other-service","Ports":"0.0.0.0:9090->90/tcp","Status":"Up 3 minutes","CreatedAt":"2020-01-01 00:00:00 +0000 UTC"}
{"ID":"owner","Names":"port-owner","Ports":"0.0.0.0:8080->80/tcp","Status":"Up 2 minutes","CreatedAt":"2020-01-01 00:00:00 +0000 UTC"}"#;

struct Fixture {
    sandbox: Sandbox,
    fake_bin: PathBuf,
    docker_calls: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sandbox = Sandbox::new();
        let fake_bin = sandbox.home.join("fake-bin");
        fs::create_dir(&fake_bin).expect("create private fake-command directory");
        let docker_calls = sandbox.home.join("docker-args.log");
        fs::write(&docker_calls, "").expect("create fake Docker argument log");
        write_executable(&fake_bin.join("docker"), DOCKER_SHIM);
        Self {
            sandbox,
            fake_bin,
            docker_calls,
        }
    }

    fn path(&self) -> std::ffi::OsString {
        let executable_dir = self.sandbox.bin.parent().expect("wtf binary has a parent");
        std::env::join_paths([
            self.fake_bin.as_path(),
            executable_dir,
            Path::new("/usr/bin"),
            Path::new("/bin"),
            Path::new("/usr/sbin"),
            Path::new("/sbin"),
        ])
        .expect("construct private fake-command PATH")
    }

    fn run_explicit(
        &self,
        daemon_error: &str,
        run_exit: i32,
        ps_mode: &str,
        ps_stdout: &str,
    ) -> Output {
        let mut command = Command::new(&self.sandbox.bin);
        command
            .args(["--json", "--", "docker"])
            .args(RUN_ARGS)
            .env_clear()
            .env("WTF_NO_MODEL", "1")
            .env("HOME", &self.sandbox.home)
            .env("XDG_CONFIG_HOME", self.sandbox.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &self.sandbox.runtime)
            .env("SHELL", "/bin/bash")
            .env("PATH", self.path())
            .env("TERM", "dumb")
            .env("LC_ALL", "C")
            .env("FAKE_DOCKER_ARGS", &self.docker_calls)
            .env("FAKE_DOCKER_RUN_EXIT", run_exit.to_string())
            .env("FAKE_DOCKER_RUN_STDERR", daemon_error)
            .env("FAKE_DOCKER_PS_MODE", ps_mode)
            .env("FAKE_DOCKER_PS_STDOUT", ps_stdout)
            .current_dir(&self.sandbox.work);
        command.output().expect("run WTF with private fake Docker")
    }

    fn calls(&self) -> Vec<Vec<String>> {
        fs::read_to_string(&self.docker_calls)
            .expect("read fake Docker argument log")
            .split("\n\n")
            .filter(|call| !call.trim().is_empty())
            .map(|call| call.lines().map(str::to_owned).collect())
            .collect()
    }

    fn expected_calls(&self, include_probe: bool) -> Vec<Vec<String>> {
        let mut calls = vec![RUN_ARGS.iter().map(|arg| (*arg).to_owned()).collect()];
        if include_probe {
            calls.push(vec!["ps".into(), "--format".into(), "{{json .}}".into()]);
        }
        calls
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write private fake Docker");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make fake Docker executable");
}

fn parse_json(output: &Output, expected_exit: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "CLI output: {output:?}"
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "WTF did not emit JSON ({error}): stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_unknown(json: &Value) {
    assert_ne!(json["status"], "Confirmed", "diagnosis: {json}");
    assert!(
        json["investigation"]["root_cause"].is_null(),
        "uncorroborated Docker port failure must not have a root cause: {json}"
    );
}

fn assert_probe_attempt(json: &Value, expected: &str) {
    let attempts = json["investigation"]["attempts"]
        .as_array()
        .expect("investigation attempts are present");
    assert!(
        attempts.iter().any(|item| item["probe"] == expected),
        "expected {expected} attempt: {json}"
    );
}

fn assert_no_raw_daemon_error(json: &Value) {
    let evidence = json["investigation"]["evidence"].to_string();
    assert!(
        !evidence.contains(DAEMON_ERROR),
        "raw Docker daemon error leaked into investigation evidence: {json}"
    );
}

#[test]
fn explicit_port_allocation_failure_names_the_running_owner_without_replaying_run() {
    let fixture = Fixture::new();
    let json = parse_json(
        &fixture.run_explicit(DAEMON_ERROR, 125, "ok", OWNER_ROWS),
        125,
    );

    assert_eq!(json["status"], "Confirmed", "diagnosis: {json}");
    assert_eq!(
        json["category"], "container/port-conflict",
        "diagnosis: {json}"
    );
    let root = json["investigation"]["root_cause"]
        .as_str()
        .expect("confirmed port-conflict diagnosis has a root cause");
    assert!(
        root.contains("8080"),
        "root must name the host port: {json}"
    );
    assert!(
        root.contains("port-owner"),
        "root must name the exact running container owner: {json}"
    );
    assert_probe_attempt(&json, "DockerRunning");
    assert_no_raw_daemon_error(&json);
    assert_eq!(fixture.calls(), fixture.expected_calls(true));
}

#[test]
fn daemon_error_for_a_different_host_port_does_not_confirm_or_probe_running_containers() {
    let fixture = Fixture::new();
    let mismatched_error = DAEMON_ERROR.replace("0.0.0.0:8080", "0.0.0.0:8081");
    let json = parse_json(
        &fixture.run_explicit(&mismatched_error, 125, "ok", OWNER_ROWS),
        125,
    );

    assert_unknown(&json);
    assert_eq!(fixture.calls(), fixture.expected_calls(false));
}

#[test]
fn unavailable_running_container_probe_cannot_confirm_the_port_owner() {
    let fixture = Fixture::new();
    let json = parse_json(
        &fixture.run_explicit(DAEMON_ERROR, 125, "unavailable", ""),
        125,
    );

    assert_unknown(&json);
    assert_probe_attempt(&json, "DockerRunning");
    assert_no_raw_daemon_error(&json);
    assert_eq!(fixture.calls(), fixture.expected_calls(true));
}

#[test]
fn running_containers_without_the_conflicting_binding_do_not_confirm_an_owner() {
    let fixture = Fixture::new();
    let no_owner = r#"{"ID":"other","Names":"other-service","Ports":"0.0.0.0:9090->90/tcp","Status":"Up 3 minutes"}"#;
    let json = parse_json(
        &fixture.run_explicit(DAEMON_ERROR, 125, "ok", no_owner),
        125,
    );

    assert_unknown(&json);
    assert_probe_attempt(&json, "DockerRunning");
    assert_no_raw_daemon_error(&json);
    assert_eq!(fixture.calls(), fixture.expected_calls(true));
}

#[test]
fn daemon_error_text_with_non_docker_run_exit_status_is_not_trusted() {
    let fixture = Fixture::new();
    let json = parse_json(&fixture.run_explicit(DAEMON_ERROR, 1, "ok", OWNER_ROWS), 1);

    assert_unknown(&json);
    assert_eq!(fixture.calls(), fixture.expected_calls(false));
}

#[test]
fn shell_metadata_cannot_prove_a_docker_port_owner() {
    let fixture = Fixture::new();
    fixture.sandbox.install_bash();
    let json_path = fixture.sandbox.work.join("metadata-port.json");
    let script = format!(
        "docker run -p 8080:80 fixture-image\nwtf --json > {}",
        shell_quote(&json_path.to_string_lossy())
    );
    let path = fixture.path().to_string_lossy().into_owned();
    let calls = fixture.docker_calls.to_string_lossy().into_owned();
    let output = fixture.sandbox.run_bash(
        &fixture.sandbox.work,
        &script,
        &[
            ("PATH", path.as_str()),
            ("FAKE_DOCKER_ARGS", calls.as_str()),
            ("FAKE_DOCKER_RUN_EXIT", "125"),
            ("FAKE_DOCKER_RUN_STDERR", DAEMON_ERROR),
        ],
    );
    assert!(output.status.success(), "isolated shell failed: {output:?}");
    let json = fixture.sandbox.read_json(&json_path, &output);
    assert_unknown(&json);
    assert_eq!(json["command"], "docker run -p 8080:80 fixture-image");
    assert_eq!(fixture.calls(), fixture.expected_calls(false));
}

const DOCKER_SHIM: &str = r#"#!/bin/sh
for arg do
    printf '%s\n' "$arg" >> "$FAKE_DOCKER_ARGS"
done
printf '\n' >> "$FAKE_DOCKER_ARGS"
case "$1" in
    run)
        printf '%s\n' "$FAKE_DOCKER_RUN_STDERR" >&2
        exit "$FAKE_DOCKER_RUN_EXIT"
        ;;
    ps)
        if [ "${FAKE_DOCKER_PS_MODE:-ok}" = unavailable ]; then
            printf '%s\n' 'fake Docker running-container probe unavailable' >&2
            exit 1
        fi
        printf '%s\n' "$FAKE_DOCKER_PS_STDOUT"
        exit 0
        ;;
    *)
        printf '%s\n' 'unexpected fake Docker command' >&2
        exit 64
        ;;
esac
"#;
