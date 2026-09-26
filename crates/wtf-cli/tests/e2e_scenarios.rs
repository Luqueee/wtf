#[path = "support/e2e.rs"]
mod support;

use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};
use support::{shell_quote, Sandbox};

fn assert_shell_finished(output: &Output) {
    assert!(
        output.status.success(),
        "isolated Bash failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_diagnosed(json: &Value, command: &str, exit_code: i32, category: &str) {
    assert_eq!(json["command"], command);
    assert_eq!(json["exit_status"]["code"], exit_code);
    assert_eq!(json["status"], "Confirmed");
    assert_eq!(json["category"], category);
    assert!(
        json["investigation"].is_object(),
        "diagnosis should include investigation data: {json}"
    );
}

#[test]
fn interactive_cat_failure_checks_current_path_without_replaying_cat() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    let absent = sandbox.work.join("absent");
    let report = sandbox.home.join("cat-report.txt");
    let script = format!(
        "cat {}\nwtf --no-color > {}",
        shell_quote(&absent.to_string_lossy()),
        shell_quote(&report.to_string_lossy()),
    );
    let output = sandbox.run_bash(&sandbox.work, &script, &[]);
    assert_shell_finished(&output);
    let text = fs::read_to_string(report).unwrap();
    assert!(text.contains("Now:"), "{text}");
    assert!(
        text.contains(&format!("{} does not exist", absent.display())),
        "{text}"
    );
    assert!(
        text.contains("Original stdout/stderr was not recorded."),
        "{text}"
    );
    assert!(text.contains("1 check"), "{text}");
}

#[test]
fn cargo_build_failure_stays_unknown_and_explicit_builds_still_execute() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    let source_dir = sandbox.work.join("src");
    fs::create_dir_all(&source_dir).expect("create Rust fixture source");
    fs::write(
        sandbox.work.join("Cargo.toml"),
        "[package]\nname = \"e2e_compile_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write dependency-free Cargo manifest");
    let source = source_dir.join("main.rs");
    fs::write(&source, "fn main() { let _: u32 = \"wrong type\"; }\n")
        .expect("write failing Rust source");

    let json_path = sandbox.home.join("cargo.json");
    let failed_status = sandbox.home.join("cargo-failed-status");
    let fixed_status = sandbox.home.join("cargo-fixed-status");
    let script = format!(
        "cargo build\nfailed=$?\nprintf '%s' \"$failed\" > {}\nwtf --json > {}\ncat > {} <<'RS'\nfn main() {{ let _: &str = \"correct type\"; }}\nRS\ncargo build\nprintf '%s' \"$?\" > {}",
        shell_quote(&failed_status.to_string_lossy()),
        shell_quote(&json_path.to_string_lossy()),
        shell_quote(&source.to_string_lossy()),
        shell_quote(&fixed_status.to_string_lossy()),
    );
    let output = sandbox.run_bash(&sandbox.work, &script, &[]);
    assert_shell_finished(&output);
    assert_eq!(
        fs::read_to_string(failed_status).unwrap(),
        "101",
        "Cargo failure transcript: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(fixed_status).unwrap(), "0");
    let json = sandbox.read_json(&json_path, &output);
    assert_eq!(json["command"], "cargo build");
    assert_eq!(json["exit_status"]["code"], 101);
    assert_eq!(json["status"], "Unknown");
    assert_eq!(json["category"], "unknown");
    assert!(
        json["investigation"]["root_cause"].is_null(),
        "diagnosis: {json}"
    );
    assert_eq!(
        json["investigation"]["attempts"].as_array().map(Vec::len),
        Some(0),
        "failure reconstruction must not execute cargo check: {json}"
    );
    assert_eq!(
        json["investigation"]["evidence"].as_array().map(Vec::len),
        Some(0),
        "no compiler cause may be fabricated without captured evidence: {json}"
    );
}

#[test]
fn explicit_cargo_command_runs_once_without_automatic_check() {
    let sandbox = Sandbox::new();
    let cargo_dir = sandbox.work.join("bin");
    fs::create_dir_all(&cargo_dir).expect("create fake Cargo executable directory");
    let calls = sandbox.home.join("cargo-calls");
    let cargo = cargo_dir.join("cargo");
    fs::write(
        &cargo,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexit 101\n",
            shell_quote(&calls.to_string_lossy())
        ),
    )
    .expect("write fake Cargo executable");
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))
        .expect("make fake Cargo executable");

    let output = Command::new(env!("CARGO_BIN_EXE_wtf"))
        .args(["--json", "--", "cargo", "build"])
        .env_clear()
        .env("HOME", &sandbox.home)
        .env("XDG_CONFIG_HOME", sandbox.home.join(".config"))
        .env("XDG_RUNTIME_DIR", &sandbox.runtime)
        .env("WTF_NO_MODEL", "1")
        .env("PATH", &cargo_dir)
        .current_dir(&sandbox.work)
        .output()
        .expect("run explicit Cargo command through wtf");

    assert_eq!(
        output.status.code(),
        Some(101),
        "explicit command result: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(calls).unwrap(), "build\n");
}

#[test]
fn git_push_without_upstream_is_diagnosed_and_corrected_locally() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    let repository = sandbox.work.join("repo");
    let remote = sandbox.work.join("remote.git");
    fs::create_dir_all(&repository).expect("create repository fixture");
    let run_git = |cwd: &Path, args: &[&str]| {
        let output = std::process::Command::new("git")
            .args(args)
            .env_clear()
            .env("HOME", &sandbox.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("PATH", {
                let parent = Path::new(env!("CARGO_BIN_EXE_wtf")).parent().unwrap();
                std::env::join_paths([parent, Path::new("/usr/bin"), Path::new("/bin")]).unwrap()
            })
            .current_dir(cwd)
            .output()
            .expect("run local git fixture command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run_git(&sandbox.work, &["init", "--bare", remote.to_str().unwrap()]);
    run_git(&repository, &["init", "-b", "main"]);
    run_git(&repository, &["config", "user.name", "E2E Fixture"]);
    run_git(
        &repository,
        &["config", "user.email", "e2e@example.invalid"],
    );
    fs::write(repository.join("README"), "fixture\n").expect("write committed fixture");
    run_git(&repository, &["add", "README"]);
    run_git(&repository, &["commit", "-m", "fixture"]);
    run_git(
        &repository,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );

    let json_path = sandbox.home.join("git.json");
    let failed_status = sandbox.home.join("git-failed-status");
    let fixed_status = sandbox.home.join("git-fixed-status");
    let script = format!(
        "git push\nfailed=$?\nprintf '%s' \"$failed\" > {}\nwtf --json > {}\ngit push --set-upstream origin HEAD\nprintf '%s' \"$?\" > {}",
        shell_quote(&failed_status.to_string_lossy()),
        shell_quote(&json_path.to_string_lossy()),
        shell_quote(&fixed_status.to_string_lossy()),
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
        "Git failure transcript: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(fixed_status).unwrap(), "0");
    let json = sandbox.read_json(&json_path, &output);
    assert_diagnosed(&json, "git push", 128, "git/upstream");
    assert!(
        json["investigation"]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["observation"]
                    .as_str()
                    .is_some_and(|text| text.to_lowercase().contains("upstream"))
            }),
        "Git diagnosis should show missing-upstream probe evidence: {json}"
    );
}

#[test]
fn curl_to_unbound_loopback_port_is_diagnosed_with_uncertainty_and_corrected() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve dynamic loopback port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let start_server = sandbox.home.join("start-http-server");
    let server_ready = sandbox.home.join("http-server-ready");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(120);
        while !start_server.exists() {
            assert!(
                Instant::now() < deadline,
                "Bash did not request fixture server"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let listener =
            TcpListener::bind(("127.0.0.1", port)).expect("bind correction fixture server");
        listener
            .set_nonblocking(true)
            .expect("configure fixture listener");
        fs::write(server_ready, "ready").expect("signal fixture server readiness");
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    respond_http(&mut stream);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "curl did not connect to fixture server"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept curl correction request: {error}"),
            }
        }
    });

    let json_path = sandbox.home.join("curl.json");
    let failed_status = sandbox.home.join("curl-failed-status");
    let fixed_status = sandbox.home.join("curl-fixed-status");
    let script = format!(
        "curl --noproxy '*' --connect-timeout 2 --max-time 3 -sS -o /dev/null http://127.0.0.1:{port}/\nfailed=$?\nprintf '%s' \"$failed\" > {}\nwtf --json > {}\ntouch {}\nfor _ in {{1..300}}; do [[ -e {} ]] && break; sleep 0.01; done\n[[ -e {} ]] || exit 1\ncurl --max-time 3 -sS -o /dev/null http://127.0.0.1:{port}/\nprintf '%s' \"$?\" > {}",
        shell_quote(&failed_status.to_string_lossy()),
        shell_quote(&json_path.to_string_lossy()),
        shell_quote(&sandbox.home.join("start-http-server").to_string_lossy()),
        shell_quote(&sandbox.home.join("http-server-ready").to_string_lossy()),
        shell_quote(&sandbox.home.join("http-server-ready").to_string_lossy()),
        shell_quote(&fixed_status.to_string_lossy()),
    );
    let output = sandbox.run_bash(&sandbox.work, &script, &[]);
    assert_shell_finished(&output);
    server.join().expect("fixture HTTP server thread");
    assert_eq!(
        fs::read_to_string(failed_status).unwrap(),
        "7",
        "curl failure transcript: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(fixed_status).unwrap(), "0");
    let json = sandbox.read_json(&json_path, &output);
    assert_eq!(
        json["command"],
        format!("curl --noproxy * --connect-timeout 2 --max-time 3 -sS -o /dev/null http://127.0.0.1:{port}/")
    );
    assert_eq!(json["exit_status"]["code"], 7);
    assert_eq!(json["status"], "Likely");
    assert_eq!(json["category"], "network/no-local-listener");
    let attempts = json["investigation"]["attempts"].as_array().unwrap();
    assert_eq!(
        attempts.len(),
        1,
        "curl alone must not start Docker discovery: {json}"
    );
    assert_eq!(attempts[0]["probe"], "Listeners");
    assert!(
        json["investigation"]["hypotheses"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["id"] != "container_exited" && item["id"] != "missing_env"),
        "unlinked containers are not candidate explanations: {json}"
    );
    assert!(
        json["report"]["claims"]
            .as_array()
            .unwrap()
            .iter()
            .all(|claim| claim["kind"] != "next"),
        "an arbitrary local port has no justified next action: {json}"
    );
    assert!(
        json["investigation"]["evidence"]
            .as_array()
            .is_some_and(|evidence| evidence.iter().any(|item| {
                item["probe"]
                    .to_string()
                    .to_lowercase()
                    .contains("listener")
                    && item["observation"]
                        .as_str()
                        .is_some_and(|observation| observation.to_lowercase().contains("listener"))
            })),
        "no-listener diagnosis should expose listener probe evidence: {json}"
    );
    assert!(
        json["entities"]["ports"]
            .as_array()
            .is_some_and(|ports| ports.iter().any(|p| p.as_u64() == Some(u64::from(port)))),
        "diagnosis should retain the attempted port: {json}"
    );
    assert_eq!(json["report"]["source_mode"], "shell_record");
    assert_eq!(json["report"]["capture"], "unavailable");
    let claims = json["report"]["claims"].as_array().unwrap();
    assert!(
        claims.iter().any(|claim| claim["kind"] == "observed"
            && claim["source"]["id"] == "Listeners"
            && claim["source"]["observed_at"].as_u64().is_some()),
        "{json}"
    );
}

fn respond_http(stream: &mut TcpStream) {
    let mut request = [0; 1024];
    let _ = stream.read(&mut request).expect("read HTTP request");
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .expect("write HTTP response");
}
