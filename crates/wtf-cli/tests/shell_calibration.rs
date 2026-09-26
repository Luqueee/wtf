#[path = "support/e2e.rs"]
mod support;

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use support::{shell_quote, Sandbox};

fn assert_shell_finished(output: &Output) {
    assert!(
        output.status.success(),
        "isolated Bash failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_diagnosis(json: &Value, command: &str, exit_code: i32, status: &str, category: &str) {
    assert_eq!(json["command"], command);
    assert_eq!(json["exit_status"]["code"], exit_code);
    assert_eq!(json["status"], status);
    assert_eq!(json["category"], category);
    assert!(json["investigation"].is_object(), "diagnosis: {json}");
}

fn write_cargo_fixture(sandbox: &Sandbox, source: &str) {
    fs::create_dir_all(sandbox.work.join("src")).expect("create Cargo fixture source");
    fs::write(
        sandbox.work.join("Cargo.toml"),
        "[package]\nname = \"e2e_shell_calibration\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write dependency-free Cargo manifest");
    fs::write(sandbox.work.join("src/lib.rs"), source).expect("write Cargo fixture source");
}

fn run_git(sandbox: &Sandbox, cwd: &Path, args: &[&str]) -> Output {
    let binary_dir = Path::new(env!("CARGO_BIN_EXE_wtf")).parent().unwrap();
    let output = Command::new("git")
        .args(args)
        .env_clear()
        .env("HOME", &sandbox.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env(
            "PATH",
            std::env::join_paths([binary_dir, Path::new("/usr/bin"), Path::new("/bin")]).unwrap(),
        )
        .current_dir(cwd)
        .output()
        .expect("run local Git fixture command");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn init_repository(sandbox: &Sandbox, repository: &Path) {
    fs::create_dir_all(repository).expect("create local Git fixture");
    run_git(sandbox, repository, &["init", "-b", "main"]);
    run_git(sandbox, repository, &["config", "user.name", "E2E Fixture"]);
    run_git(
        sandbox,
        repository,
        &["config", "user.email", "e2e@example.invalid"],
    );
    fs::write(repository.join("fixture.txt"), "base\n").expect("write committed fixture");
    run_git(sandbox, repository, &["add", "fixture.txt"]);
    run_git(sandbox, repository, &["commit", "-m", "base fixture"]);
}

fn assert_confirmed_root(json: &Value, category: &str, root_cause: &str) {
    assert_eq!(json["status"], "Confirmed");
    assert_eq!(json["category"], category);
    assert_eq!(json["investigation"]["root_cause"], root_cause);
    assert!(
        json["investigation"]["cause"].is_null(),
        "unexpected secondary cause: {json}"
    );
}

#[test]
fn cargo_test_runtime_failure_stays_unknown_without_automatic_check() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    write_cargo_fixture(
        &sandbox,
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn runtime_assertion_fails() { assert_eq!(1, 2); }\n}\n",
    );
    let json_path = sandbox.home.join("cargo-runtime.json");
    let failed_status = sandbox.home.join("cargo-runtime-failed-status");
    let script = format!(
        "cargo test\nfailed=$?\nprintf '%s' \"$failed\" > {}\nwtf --json > {}",
        shell_quote(&failed_status.to_string_lossy()),
        shell_quote(&json_path.to_string_lossy()),
    );

    let output = sandbox.run_bash(&sandbox.work, &script, &[("CARGO_NET_OFFLINE", "true")]);
    assert_shell_finished(&output);
    assert_eq!(
        fs::read_to_string(failed_status).unwrap(),
        "101",
        "Cargo test failure transcript: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json = sandbox.read_json(&json_path, &output);
    assert_diagnosis(&json, "cargo test", 101, "Unknown", "unknown");
    assert!(
        json["investigation"]["root_cause"].is_null(),
        "diagnosis: {json}"
    );
    assert!(
        json["investigation"]["cause"].is_null(),
        "diagnosis: {json}"
    );
    assert!(
        json["investigation"]["reconstruction_note"]
            .as_str()
            .is_some_and(|note| note.contains("automatic Cargo checks are not run")),
        "diagnosis must explain why the uncaptured Cargo failure stays unknown: {json}"
    );
    assert_eq!(
        json["investigation"]["attempts"].as_array().map(Vec::len),
        Some(0),
        "automatic investigation must not run cargo check: {json}"
    );
    assert_eq!(
        json["investigation"]["evidence"].as_array().map(Vec::len),
        Some(0),
        "an uncaptured failure must not fabricate Cargo compiler evidence: {json}"
    );
}

#[test]
fn unsupported_cargo_flags_remain_unknown_without_compile_probes() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    write_cargo_fixture(&sandbox, "pub fn fixture() {}\n");
    let json_path = sandbox.home.join("cargo-flags.json");
    let failed_status = sandbox.home.join("cargo-flags-failed-status");
    let script = format!(
        "cargo build --wtf-calibration-invalid-flag\nfailed=$?\nprintf '%s' \"$failed\" > {}\nwtf --json > {}",
        shell_quote(&failed_status.to_string_lossy()),
        shell_quote(&json_path.to_string_lossy()),
    );

    let output = sandbox.run_bash(&sandbox.work, &script, &[("CARGO_NET_OFFLINE", "true")]);
    assert_shell_finished(&output);
    assert_eq!(
        fs::read_to_string(failed_status).unwrap(),
        "1",
        "invalid Cargo flag transcript: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json = sandbox.read_json(&json_path, &output);
    assert_diagnosis(
        &json,
        "cargo build --wtf-calibration-invalid-flag",
        1,
        "Unknown",
        "unknown",
    );
    assert!(
        json["investigation"]["root_cause"].is_null(),
        "diagnosis: {json}"
    );
    assert!(
        json["investigation"]["cause"].is_null(),
        "diagnosis: {json}"
    );
    assert!(
        json["investigation"]["reconstruction_note"]
            .as_str()
            .is_some_and(|note| note.contains("automatic Cargo checks are not run")),
        "unsupported arguments must not be converted into a compile diagnosis: {json}"
    );
    assert_eq!(
        json["investigation"]["attempts"].as_array().map(Vec::len),
        Some(0),
        "no fixed cargo check applies to this invocation: {json}"
    );
}

#[test]
fn git_push_from_detached_head_is_confirmed_from_local_repository_state() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    let repository = sandbox.work.join("detached-repo");
    let remote = sandbox.work.join("local-remote.git");
    run_git(
        &sandbox,
        &sandbox.work,
        &["init", "--bare", remote.to_str().unwrap()],
    );
    init_repository(&sandbox, &repository);
    run_git(
        &sandbox,
        &repository,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    run_git(&sandbox, &repository, &["checkout", "--detach", "HEAD"]);
    let current_branch = run_git(&sandbox, &repository, &["branch", "--show-current"]);
    assert!(
        String::from_utf8_lossy(&current_branch.stdout)
            .trim()
            .is_empty(),
        "fixture must be detached before the failed push"
    );
    let status = run_git(
        &sandbox,
        &repository,
        &["status", "--porcelain=v2", "--branch"],
    );
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("# branch.head (detached)"),
        "fixture must expose detached HEAD: {}",
        String::from_utf8_lossy(&status.stdout)
    );

    let json_path = sandbox.home.join("git-detached.json");
    let failed_status = sandbox.home.join("git-detached-failed-status");
    let script = format!(
        "git push\nfailed=$?\nprintf '%s' \"$failed\" > {}\nwtf --json > {}",
        shell_quote(&failed_status.to_string_lossy()),
        shell_quote(&json_path.to_string_lossy()),
    );
    let output = sandbox.run_bash(
        &repository,
        &script,
        &[
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ],
    );
    assert_shell_finished(&output);
    assert_eq!(
        fs::read_to_string(failed_status).unwrap(),
        "128",
        "detached Git failure transcript: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json = sandbox.read_json(&json_path, &output);
    assert_diagnosis(&json, "git push", 128, "Confirmed", "git/detached");
    assert_confirmed_root(
        &json,
        "git/detached",
        "HEAD is detached; no branch is checked out.",
    );
    let attempts = json["investigation"]["attempts"]
        .as_array()
        .expect("Git probe attempts");
    assert!(attempts
        .iter()
        .any(|attempt| attempt["probe"] == "GitBranch"));
    assert!(attempts
        .iter()
        .any(|attempt| attempt["probe"] == "GitPorcelain"));
    assert!(attempts.iter().all(|attempt| attempt["result"] == "ok"));
    assert!(
        json["investigation"]["evidence"]
            .as_array()
            .is_some_and(|evidence| evidence.iter().any(|item| {
                item["probe"] == "GitBranch" && item["observation"] == "HEAD is detached"
            })),
        "detached diagnosis should identify branch-probe evidence: {json}"
    );
}

#[test]
fn git_merge_conflict_is_confirmed_from_unmerged_index_entries() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    let repository = sandbox.work.join("conflict-repo");
    init_repository(&sandbox, &repository);
    fs::write(repository.join("fixture.txt"), "side change\n").expect("write side change");
    run_git(&sandbox, &repository, &["checkout", "-b", "side"]);
    run_git(&sandbox, &repository, &["add", "fixture.txt"]);
    run_git(&sandbox, &repository, &["commit", "-m", "side change"]);
    run_git(&sandbox, &repository, &["checkout", "main"]);
    fs::write(repository.join("fixture.txt"), "main change\n").expect("write main change");
    run_git(&sandbox, &repository, &["add", "fixture.txt"]);
    run_git(&sandbox, &repository, &["commit", "-m", "main change"]);

    let json_path = sandbox.home.join("git-conflict.json");
    let failed_status = sandbox.home.join("git-conflict-failed-status");
    let script = format!(
        "git merge side\nfailed=$?\nprintf '%s' \"$failed\" > {}\nwtf --json > {}",
        shell_quote(&failed_status.to_string_lossy()),
        shell_quote(&json_path.to_string_lossy()),
    );
    let output = sandbox.run_bash(
        &repository,
        &script,
        &[
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ],
    );
    assert_shell_finished(&output);
    assert_eq!(
        fs::read_to_string(failed_status).unwrap(),
        "1",
        "conflicted merge transcript: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let conflicted_status = run_git(&sandbox, &repository, &["status", "--porcelain"]);
    assert!(
        String::from_utf8_lossy(&conflicted_status.stdout).contains("UU fixture.txt"),
        "fixture must have an unresolved index conflict: {}",
        String::from_utf8_lossy(&conflicted_status.stdout)
    );

    let json = sandbox.read_json(&json_path, &output);
    assert_diagnosis(&json, "git merge side", 1, "Confirmed", "git/conflicts");
    assert_confirmed_root(
        &json,
        "git/conflicts",
        "Unresolved merge conflicts are present.",
    );
    let attempts = json["investigation"]["attempts"]
        .as_array()
        .expect("Git probe attempts");
    assert_eq!(
        attempts.len(),
        1,
        "conflict evidence should stop further probes: {json}"
    );
    assert_eq!(attempts[0]["probe"], "GitPorcelain");
    assert_eq!(attempts[0]["result"], "ok");
    assert!(
        json["investigation"]["evidence"]
            .as_array()
            .is_some_and(|evidence| evidence.iter().any(|item| {
                item["probe"] == "GitPorcelain"
                    && item["observation"] == "repository status contains unmerged paths"
            })),
        "conflict diagnosis should identify unmerged-status evidence: {json}"
    );
}
