#![cfg(target_os = "linux")]

#[path = "support/e2e.rs"]
mod support;

use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::{shell_quote, Sandbox};

const SOURCE: &str = "/sandbox/missing";
const DOCKER_ERROR_PREFIX: &str = "bind source path does not exist: ";

#[derive(Clone, Copy)]
enum StatBehavior {
    Missing,
    Exists,
    Unavailable,
}

struct Fixture {
    sandbox: Sandbox,
    fake_bin: PathBuf,
    docker_args: PathBuf,
    stat_args: PathBuf,
    stat_behavior: StatBehavior,
}

impl Fixture {
    fn new(stat_behavior: StatBehavior) -> Self {
        let sandbox = Sandbox::new();
        let fake_bin = sandbox.home.join("fake-bin");
        fs::create_dir(&fake_bin).expect("create private fake-command directory");
        let docker_args = sandbox.home.join("docker-args.log");
        let stat_args = sandbox.home.join("stat-args.log");
        fs::write(&docker_args, "").expect("create fake Docker argument log");
        fs::write(&stat_args, "").expect("create fake stat argument log");
        write_executable(&fake_bin.join("docker"), DOCKER_SHIM);
        write_executable(&fake_bin.join("stat"), STAT_SHIM);
        Self {
            sandbox,
            fake_bin,
            docker_args,
            stat_args,
            stat_behavior,
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

    fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("WTF_NO_MODEL", "1")
            .env("HOME", &self.sandbox.home)
            .env("XDG_CONFIG_HOME", self.sandbox.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &self.sandbox.runtime)
            .env("SHELL", "/bin/bash")
            .env("PATH", self.path())
            .env("TERM", "dumb")
            .env("LC_ALL", "C")
            .env("FAKE_DOCKER_ARGS", &self.docker_args)
            .env("FAKE_STAT_ARGS", &self.stat_args)
            .env("FAKE_STAT_SOURCE", SOURCE)
            .env(
                "FAKE_STAT_BEHAVIOR",
                match self.stat_behavior {
                    StatBehavior::Missing => "missing",
                    StatBehavior::Exists => "exists",
                    StatBehavior::Unavailable => "unavailable",
                },
            )
            .current_dir(&self.sandbox.work);
        command
    }

    fn run_explicit(&self, source: &str, daemon_error: &str) -> Output {
        let mount = format!("type=bind,source={source},target=/config");
        self.command(&self.sandbox.bin)
            .args([
                "--json",
                "--",
                "docker",
                "run",
                "--name",
                "app",
                "--mount",
                mount.as_str(),
                "image",
            ])
            .env("FAKE_DOCKER_STDERR", daemon_error)
            .output()
            .expect("run the isolated WTF CLI with fake Docker")
    }

    fn argument_calls(&self, path: &Path) -> Vec<Vec<String>> {
        let log = fs::read_to_string(path).expect("read fake command argument log");
        log.split("\n\n")
            .filter(|call| !call.trim().is_empty())
            .map(|call| call.lines().map(str::to_owned).collect())
            .collect()
    }

    fn docker_calls(&self) -> Vec<Vec<String>> {
        self.argument_calls(&self.docker_args)
    }

    fn stat_calls(&self) -> Vec<Vec<String>> {
        self.argument_calls(&self.stat_args)
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write private fake command");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make private fake command executable");
}

fn parse_json(output: &Output) -> Value {
    assert_eq!(output.status.code(), Some(1), "CLI output: {output:?}");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "WTF did not emit JSON ({error}): stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_unconfirmed_without_root(json: &Value) {
    assert_ne!(json["status"], "Confirmed", "diagnosis: {json}");
    assert!(
        json["investigation"]["root_cause"].is_null(),
        "an uncorroborated bind source must not have a root cause: {json}"
    );
}

fn assert_source_redacted_from_investigation(json: &Value, source: &str) {
    let root = json["investigation"]["root_cause"]
        .as_str()
        .unwrap_or_default();
    assert!(
        !root.contains(source),
        "raw mount source in root cause: {json}"
    );
    let investigation_evidence = json["investigation"]["evidence"].to_string();
    assert!(
        !investigation_evidence.contains(source),
        "raw mount source in investigation evidence: {json}"
    );
    let diagnosis_evidence = json["evidence"].to_string();
    assert!(
        !diagnosis_evidence.contains(source),
        "raw mount source in diagnosis evidence: {json}"
    );
}

fn has_probe(json: &Value, probe: &str) -> bool {
    json["investigation"]["attempts"]
        .as_array()
        .is_some_and(|attempts| attempts.iter().any(|attempt| attempt["probe"] == probe))
}

fn assert_stat_arguments(fixture: &Fixture, source: &str) {
    assert_eq!(
        fixture.stat_calls(),
        vec![vec![
            "-c".to_owned(),
            "%F|%a|%U|%G|%n".to_owned(),
            "--".to_owned(),
            source.to_owned(),
        ]],
        "stat must use the fixed catalogue argv"
    );
}

fn expected_run(source: &str) -> Vec<String> {
    vec![
        "run".into(),
        "--name".into(),
        "app".into(),
        "--mount".into(),
        format!("type=bind,source={source},target=/config"),
        "image".into(),
    ]
}

fn assert_no_container_inspection_probes(json: &Value) {
    for probe in ["DockerAll", "DockerInspect", "DockerLogs"] {
        assert!(
            !has_probe(json, probe),
            "bind-source diagnosis must not run {probe}: {json}"
        );
    }
}

#[test]
fn missing_explicit_bind_source_is_confirmed_without_exposing_path_or_replaying_docker() {
    let fixture = Fixture::new(StatBehavior::Missing);
    let error = format!("{DOCKER_ERROR_PREFIX}{SOURCE}");
    let output = fixture.run_explicit(SOURCE, &error);
    let json = parse_json(&output);

    assert_eq!(json["status"], "Confirmed", "diagnosis: {json}");
    assert_eq!(json["category"], "container/mount", "diagnosis: {json}");
    let root = json["investigation"]["root_cause"]
        .as_str()
        .expect("confirmed bind diagnosis has a root cause");
    assert!(
        root.contains("app"),
        "root should name the container: {json}"
    );
    assert_source_redacted_from_investigation(&json, SOURCE);
    assert!(has_probe(&json, "Stat"), "diagnosis: {json}");
    assert_no_container_inspection_probes(&json);
    assert_stat_arguments(&fixture, SOURCE);
    assert_eq!(fixture.docker_calls(), vec![expected_run(SOURCE)]);
}

#[test]
fn mismatched_daemon_bind_path_is_not_confirmed_or_stat_probed() {
    let fixture = Fixture::new(StatBehavior::Missing);
    let error = format!("{DOCKER_ERROR_PREFIX}/sandbox/other");
    let output = fixture.run_explicit(SOURCE, &error);
    let json = parse_json(&output);

    assert_unconfirmed_without_root(&json);
    assert!(
        !has_probe(&json, "Stat"),
        "mismatched source was stat-probed: {json}"
    );
    assert_source_redacted_from_investigation(&json, SOURCE);
    assert_source_redacted_from_investigation(&json, "/sandbox/other");
    assert!(
        fixture.stat_calls().is_empty(),
        "stat argv: {:?}",
        fixture.stat_calls()
    );
    assert_eq!(
        fixture.docker_calls().first(),
        Some(&expected_run(SOURCE)),
        "the explicit Docker command is run once"
    );
}

#[test]
fn existing_bind_source_is_not_confirmed_as_missing() {
    let fixture = Fixture::new(StatBehavior::Exists);
    let error = format!("{DOCKER_ERROR_PREFIX}{SOURCE}");
    let output = fixture.run_explicit(SOURCE, &error);
    let json = parse_json(&output);

    assert_unconfirmed_without_root(&json);
    assert!(has_probe(&json, "Stat"), "diagnosis: {json}");
    assert_source_redacted_from_investigation(&json, SOURCE);
    assert_stat_arguments(&fixture, SOURCE);
    assert_eq!(fixture.docker_calls(), vec![expected_run(SOURCE)]);
}

#[test]
fn unavailable_stat_result_does_not_confirm_a_missing_bind_source() {
    let fixture = Fixture::new(StatBehavior::Unavailable);
    let error = format!("{DOCKER_ERROR_PREFIX}{SOURCE}");
    let output = fixture.run_explicit(SOURCE, &error);
    let json = parse_json(&output);

    assert_unconfirmed_without_root(&json);
    assert!(has_probe(&json, "Stat"), "diagnosis: {json}");
    assert_source_redacted_from_investigation(&json, SOURCE);
    assert_stat_arguments(&fixture, SOURCE);
    assert_eq!(fixture.docker_calls(), vec![expected_run(SOURCE)]);
}

#[test]
fn shell_metadata_without_daemon_error_does_not_confirm_missing_bind_source() {
    let fixture = Fixture::new(StatBehavior::Missing);
    fixture.sandbox.install_bash();
    let json_path = fixture.sandbox.home.join("metadata-only.json");
    let path = fixture.path().to_string_lossy().into_owned();
    let script = format!(
        "docker run --name app --mount type=bind,source={SOURCE},target=/config image\nwtf --json > {}",
        shell_quote(&json_path.to_string_lossy())
    );
    let docker_args = fixture.docker_args.to_string_lossy().into_owned();
    let stat_args = fixture.stat_args.to_string_lossy().into_owned();
    let output = fixture.sandbox.run_bash(
        &fixture.sandbox.work,
        &script,
        &[
            ("PATH", path.as_str()),
            ("FAKE_DOCKER_ARGS", docker_args.as_str()),
            ("FAKE_STAT_ARGS", stat_args.as_str()),
            ("FAKE_STAT_SOURCE", SOURCE),
            ("FAKE_STAT_BEHAVIOR", "missing"),
            ("FAKE_DOCKER_STDERR", ""),
        ],
    );
    assert!(
        output.status.success(),
        "isolated Bash failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = fixture.sandbox.read_json(&json_path, &output);
    assert_eq!(
        json["command"],
        format!("docker run --name app --mount type=bind,source={SOURCE},target=/config image"),
        "the shell-hook diagnosis must be for the failed Docker command: {json}"
    );
    assert_eq!(json["exit_status"]["code"], 1, "diagnosis: {json}");

    assert_unconfirmed_without_root(&json);
    assert!(
        !has_probe(&json, "Stat"),
        "metadata-only failure ran stat: {json}"
    );
    assert_source_redacted_from_investigation(&json, SOURCE);
    let docker_calls = fixture.docker_calls();
    assert_eq!(
        docker_calls
            .iter()
            .filter(|call| call.first().is_some_and(|arg| arg == "run"))
            .count(),
        1,
        "the recorded failed Docker run must not be replayed: {docker_calls:?}"
    );
    assert!(
        fixture.stat_calls().is_empty(),
        "stat argv: {:?}",
        fixture.stat_calls()
    );
}

const DOCKER_SHIM: &str = r#"#!/bin/sh
for arg do
    printf '%s\n' "$arg" >> "$FAKE_DOCKER_ARGS"
done
printf '\n' >> "$FAKE_DOCKER_ARGS"
if [ "$1" = run ]; then
    if [ -n "${FAKE_DOCKER_STDERR:-}" ]; then
        printf '%s\n' "$FAKE_DOCKER_STDERR" >&2
    fi
    exit 1
fi
exit 0
"#;

const STAT_SHIM: &str = r#"#!/bin/sh
for arg do
    printf '%s\n' "$arg" >> "$FAKE_STAT_ARGS"
done
printf '\n' >> "$FAKE_STAT_ARGS"
case "${FAKE_STAT_BEHAVIOR:-missing}" in
    missing)
        printf "stat: cannot stat '%s': No such file or directory\n" "$FAKE_STAT_SOURCE" >&2
        exit 1
        ;;
    exists)
        printf 'directory|700|root|root|%s\n' "$FAKE_STAT_SOURCE"
        exit 0
        ;;
    unavailable)
        printf '%s\n' 'stat fixture unavailable' >&2
        exit 127
        ;;
esac
exit 2
"#;
