use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn wtf_bin() -> &'static str {
    env!("CARGO_BIN_EXE_wtf")
}

#[test]
fn replay_uses_saved_execution_without_running_its_program_and_preserves_status() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("must-not-exist");
    let snapshot = dir.path().join("snapshot.json");
    let execution = serde_json::json!({
        "execution": {
            "command": "/usr/bin/touch", "args": [marker.to_str().unwrap()],
            "cwd": dir.path(), "exit_status": {"code": 37, "signal": null},
            "stdout": "", "stderr": "cannot create output: configuration conflict",
            "duration": {"secs": 0, "nanos": 0}, "timestamp": {"secs_since_epoch": 1700000000, "nanos_since_epoch": 0},
            "spawn_error": null
        },
        "capture_truncated": false
    });
    std::fs::write(&snapshot, serde_json::to_vec(&execution).unwrap()).unwrap();
    let output = Command::new(wtf_bin())
        .args(["--json", "--replay-snapshot", snapshot.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37));
    assert!(!marker.exists());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["report"]["claims"][0]["source"]["field"], "stderr");
    assert_eq!(json["report"]["checks"], 0);
}

#[test]
fn known_failure_reports_origin_and_exit_status_without_fixing_it() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let output = Command::new(wtf_bin())
        .args(["--json", "--", "cat", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["report"]["source_mode"], "explicit");
    assert_eq!(json["report"]["outcome"], "1");
    assert_eq!(json["report"]["capture"], "captured");
    assert_eq!(json["report"]["claims"][0]["kind"], "observed");
    assert_eq!(json["report"]["claims"][0]["source"]["type"], "execution");
    assert_eq!(json["report"]["claims"][0]["source"]["field"], "stderr");
    assert_eq!(json["report"]["claims"][1]["source"]["type"], "probe");
    assert_eq!(json["category"], "filesystem/not-found");
    assert!(!missing.exists());
}

#[test]
fn arbitrary_command_reports_evidence_without_inventing_a_missing_fact() {
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "sh",
            "-c",
            "echo 'unexpected mystery failure' >&2; exit 42",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(42));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("sh  42"), "{text}");
    assert!(text.contains("unexpected mystery failure"), "{text}");
    assert!(!text.contains("MISSING"), "{text}");
    assert!(!text.contains("Root cause"), "{text}");
}

#[test]
fn diff_exit_one_reports_differences_without_claiming_failure() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    std::fs::write(&first, "before\n").unwrap();
    std::fs::write(&second, "after\n").unwrap();

    let output = Command::new(wtf_bin())
        .args([
            "--json",
            "--",
            "diff",
            first.to_str().unwrap(),
            second.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["report"]["outcome"], "1");
    assert_eq!(json["report"]["summary"], "Command result: exit code 1.");
    assert_eq!(json["summary"], json["report"]["summary"]);
    assert_eq!(json["report"]["claims"][0]["source"]["field"], "stdout");
    assert!(json["report"]["claims"][0]["text"]
        .as_str()
        .unwrap()
        .contains("1c1"));

    let plain = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "diff",
            first.to_str().unwrap(),
            second.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(plain.status.code(), Some(1));
    let text = String::from_utf8(plain.stdout).unwrap();
    assert!(text.starts_with("?  diff  1\n"), "{text}");
    assert!(
        text.contains("RESULT    Command result: exit code 1."),
        "{text}"
    );
}

#[test]
fn real_git_failure_shows_reported_error_without_generic_missing_claim() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(wtf_bin())
        .args([
            "--json",
            "--",
            "git",
            "-C",
            dir.path().to_str().unwrap(),
            "status",
            "--short",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(128));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json["report"]["checks"], 0,
        "the surrounding repository is not the git -C target"
    );
    assert_eq!(json["report"]["claims"][0]["kind"], "observed");
    assert_eq!(json["report"]["claims"][0]["source"]["field"], "stderr");
    assert!(json["report"]["claims"][0]["text"]
        .as_str()
        .unwrap()
        .contains("not a git repository"));
    assert!(!json["report"]["claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim["kind"] == "missing"));
    assert!(json["investigation"]["root_cause"].is_null());
}

#[test]
fn shell_record_discloses_missing_output_without_replaying_failed_action() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("would-be-replayed");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let command = format!("sh -c 'touch {}'", marker.display());
    let recorded = Command::new(wtf_bin())
        .env("XDG_RUNTIME_DIR", dir.path())
        .args([
            "__record",
            "bash",
            "23",
            &now.to_string(),
            &now.to_string(),
            dir.path().to_str().unwrap(),
            &command,
        ])
        .output()
        .unwrap();
    assert!(recorded.status.success());
    let output = Command::new(wtf_bin())
        .env("XDG_RUNTIME_DIR", dir.path())
        .args(["--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["report"]["source_mode"], "shell_record");
    assert_eq!(json["report"]["capture"], "unavailable");
    assert_eq!(
        json["report"]["summary"],
        "Recent command result: exit code 23; original output unavailable."
    );
    assert_eq!(json["summary"], "Command result: exit code 23.");
    assert!(json["report"]["claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim["kind"] == "missing"
            && claim["text"].as_str().unwrap().contains("not recorded")));
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn shell_cat_checks_only_an_unambiguous_literal_path_at_inspection_time() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    fs::create_dir(&bin).unwrap();
    symlink("/usr/bin/stat", bin.join("stat")).unwrap();
    let path = dir.path().join("target");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    for (command, present, expected) in [
        (format!("cat {}", path.display()), false, "does not exist"),
        (format!("cat {}", path.display()), true, "exists"),
        ("cat $PATH".to_owned(), true, ""),
        (format!("cat {} /other", path.display()), true, ""),
    ] {
        if present {
            fs::write(&path, b"present").unwrap();
        }
        let recorded = Command::new(wtf_bin())
            .env("XDG_RUNTIME_DIR", dir.path())
            .args([
                "__record",
                "bash",
                "1",
                &now,
                &now,
                dir.path().to_str().unwrap(),
                &command,
            ])
            .output()
            .unwrap();
        assert!(recorded.status.success(), "{recorded:?}");
        let output = Command::new(wtf_bin())
            .env("XDG_RUNTIME_DIR", dir.path())
            .env("PATH", &bin)
            .args(["--json"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let claims = json["report"]["claims"].as_array().unwrap();
        assert_eq!(json["report"]["capture"], "unavailable");
        assert!(json["investigation"]["root_cause"].is_null(), "{json}");
        assert!(claims.iter().any(|claim| claim["kind"] == "missing"));
        if expected.is_empty() {
            assert_eq!(json["report"]["checks"], 0, "{json}");
            assert!(!claims.iter().any(|claim| claim["kind"] == "observed"));
        } else {
            assert_eq!(json["report"]["checks"], 1, "{json}");
            assert!(
                claims.iter().any(|claim| {
                    claim["kind"] == "observed"
                        && claim["text"].as_str().unwrap().contains(expected)
                        && claim["source"]["id"] == "Stat"
                }),
                "{json}"
            );
        }
    }
    assert_eq!(fs::read(path).unwrap(), b"present");
}

#[test]
fn captured_terminal_controls_and_credentials_cannot_format_default_report() {
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "sh",
            "-c",
            "printf '\\033[31mAuthorization: Bearer SHHH\\033[0m\\n' >&2; exit 3",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(!text.contains("SHHH"), "{text}");
    assert!(text.contains("OBSERVED"), "{text}");
}

#[test]
fn structured_and_explicit_output_redact_secret_bearing_capture() {
    for option in ["--json", "--show-output"] {
        let output = Command::new(wtf_bin())
            .args([
                option,
                "--",
                "sh",
                "-c",
                "printf 'Authorization: Bearer SHHH\\n' >&2; exit 4",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(4));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SHHH"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SHHH"));
    }
}

#[test]
fn successful_command_is_reported_and_output_requires_explicit_request() {
    let quiet = Command::new(wtf_bin())
        .args(["--no-color", "--", "echo", "private-payload"])
        .output()
        .unwrap();
    assert_eq!(quiet.status.code(), Some(0));
    let text = String::from_utf8(quiet.stdout).unwrap();
    assert!(text.contains("completed successfully"), "{text}");
    assert!(!text.contains("private-payload"), "{text}");
    let shown = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--show-output",
            "--",
            "echo",
            "private-payload",
        ])
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0));
    assert!(String::from_utf8(shown.stdout)
        .unwrap()
        .contains("private-payload"));
}

#[test]
fn live_capture_streams_once_and_preserves_command_status() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("launch-count");
    let script = "printf x >> \"$1\"; printf 'visible child stdout\\n'; printf 'child failed: fixture\\n' >&2; exit 23";
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--live",
            "--",
            "sh",
            "-c",
            script,
            "sh",
            marker.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(std::fs::read(&marker).unwrap(), b"x");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("visible child stdout\n"), "{stdout}");
    assert_eq!(stdout.matches("visible child stdout").count(), 1);
    assert!(stdout.contains("sh  23"), "{stdout}");
    assert!(stdout.contains("child failed: fixture"), "{stdout}");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "child failed: fixture\n"
    );
}

#[test]
fn spawn_failure_and_signal_keep_distinct_outcomes() {
    let absent = Command::new(wtf_bin())
        .args(["--json", "--", "definitely-absent-wtf-command-93850"])
        .output()
        .unwrap();
    assert_eq!(absent.status.code(), Some(127));
    let json: serde_json::Value = serde_json::from_slice(&absent.stdout).unwrap();
    assert_eq!(json["report"]["outcome"], "127");
    assert_eq!(
        json["report"]["claims"][0]["source"]["field"],
        "spawn_error"
    );

    let signaled = Command::new(wtf_bin())
        .args(["--json", "--", "sh", "-c", "kill -TERM $$"])
        .output()
        .unwrap();
    assert_eq!(signaled.status.code(), Some(143));
    let json: serde_json::Value = serde_json::from_slice(&signaled.stdout).unwrap();
    assert_eq!(json["report"]["outcome"], "signal 15");
    assert_eq!(json["exit_status"]["signal"], 15);
}

#[test]
fn truncated_output_is_marked_without_losing_exit_status() {
    let output = Command::new(wtf_bin())
        .args(["--json", "--", "python3", "-c", "import sys; sys.stderr.write('x' * 1100000); sys.stderr.write('\\ntrailing reason\\n'); sys.exit(19)"])
        .output().unwrap();
    assert_eq!(output.status.code(), Some(19));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["report"]["capture"], "truncated");
    assert_eq!(json["report"]["outcome"], "19");
    assert_eq!(json["report"]["source_mode"], "explicit");
}

#[test]
fn process_output_cannot_forge_a_capture_truncation_marker() {
    let output = Command::new(wtf_bin())
        .args([
            "--json",
            "--",
            "sh",
            "-c",
            "printf '[... 12 bytes omitted ...]\\n' >&2; exit 6",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(6));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["report"]["capture"], "captured");
}

#[test]
fn recognizable_credentials_are_redacted_from_json_and_text_channels() {
    let script = r#"printf 'Authorization: Bearer HEADER_SECRET\nAuthorization:\n Bearer FOLDED_HEADER_SECRET\nhttps://user:URL_PASSWORD@example.invalid/resource?access_token=URL_QUERY_SECRET\nCookie: session=COOKIE_SECRET\n\033]52;c;OSC_SECRET\a\nsafe trailing line\n'; printf 'X-API-Key: STDERR_API_SECRET\n' >&2; exit 37"#;
    let modes: Vec<Vec<&str>> = vec![
        vec!["--json"],
        vec!["--no-color"],
        vec!["--no-color", "--verbose"],
        vec!["--no-color", "--show-output"],
    ];
    let secrets = [
        "HEADER_SECRET",
        "FOLDED_HEADER_SECRET",
        "URL_PASSWORD",
        "URL_QUERY_SECRET",
        "COOKIE_SECRET",
        "OSC_SECRET",
        "STDERR_API_SECRET",
        "ARG_PASSWORD_SECRET",
        "ARG_HEADER_SECRET",
    ];

    for mode in modes {
        let mut command = Command::new(wtf_bin());
        command.args(&mode).args([
            "--",
            "sh",
            "-c",
            script,
            "--password=ARG_PASSWORD_SECRET",
            "--header",
            "X-Private: ARG_HEADER_SECRET",
        ]);
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(37));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for secret in secrets {
            assert!(!stdout.contains(secret), "stdout leaked {secret}: {stdout}");
            assert!(!stderr.contains(secret), "stderr leaked {secret}: {stderr}");
        }
        assert!(
            !stdout.contains('\u{1b}'),
            "terminal control survived: {stdout:?}"
        );
        assert!(
            !stderr.contains('\u{1b}'),
            "terminal control survived: {stderr:?}"
        );

        if mode.contains(&"--json") {
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["schema_version"], 1);
            assert_eq!(json["report"]["source_mode"], "explicit");
            let claims = json["report"]["claims"].as_array().unwrap();
            assert!(!claims.is_empty());
            assert!(claims.iter().all(|claim| {
                let source = &claim["source"];
                match source["type"].as_str() {
                    Some("execution" | "metadata") => source["field"].is_string(),
                    Some("probe") => {
                        source["outcome"].is_string() && source["observed_at"].is_number()
                    }
                    Some("suggestion") => true,
                    _ => false,
                }
            }));
            assert!(json["normalized"]["clean_stdout"]
                .as_str()
                .unwrap()
                .contains("safe trailing line"));
        }
    }
    let arguments_only = Command::new(wtf_bin())
        .args([
            "--json",
            "--",
            "sh",
            "-c",
            "exit 38",
            "--password=ARG_ONLY_PASSWORD_SECRET",
            "--header",
            "X-Private: ARG_ONLY_HEADER_SECRET",
        ])
        .output()
        .unwrap();
    assert_eq!(arguments_only.status.code(), Some(38));
    let arguments_stdout = String::from_utf8_lossy(&arguments_only.stdout);
    let arguments_stderr = String::from_utf8_lossy(&arguments_only.stderr);
    for secret in ["ARG_ONLY_PASSWORD_SECRET", "ARG_ONLY_HEADER_SECRET"] {
        assert!(!arguments_stdout.contains(secret), "{arguments_stdout}");
        assert!(!arguments_stderr.contains(secret), "{arguments_stderr}");
    }
}

#[test]
fn command_labels_cannot_inject_terminal_controls_or_multiline_text() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let command_path = dir
        .path()
        .join("report-tool\nLABEL_INJECTION_SECRET\u{1b}[31m");
    std::fs::write(&command_path, "#!/bin/sh\nprintf 'ok\\n'\n").unwrap();
    std::fs::set_permissions(&command_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let command_path = command_path.to_str().unwrap();

    let json_output = Command::new(wtf_bin())
        .args(["--json", "--", command_path])
        .output()
        .unwrap();
    assert!(json_output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(
        json["command"].as_str().unwrap(),
        command_path.split('\n').next().unwrap()
    );
    assert_eq!(json["report"]["command_label"], "report-tool");
    assert!(
        !String::from_utf8_lossy(&json_output.stdout).contains("LABEL_INJECTION_SECRET"),
        "{}",
        String::from_utf8_lossy(&json_output.stdout)
    );
    assert!(!String::from_utf8_lossy(&json_output.stdout).contains('\u{1b}'));

    let text_output = Command::new(wtf_bin())
        .args(["--no-color", "--verbose", "--", command_path])
        .output()
        .unwrap();
    assert!(text_output.status.success());
    let stdout = String::from_utf8_lossy(&text_output.stdout);
    assert!(stdout.contains("report-tool"));
    assert!(!stdout.contains("LABEL_INJECTION_SECRET"));
    assert!(!stdout.contains('\u{1b}'));
}

#[test]
fn json_diagnostic_lines_remain_bounded_after_sanitization() {
    let output = Command::new(wtf_bin())
        .args([
            "--json",
            "--",
            "python3",
            "-c",
            "import sys; sys.stdout.write('x' * 6000); sys.exit(5)",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let clean_stdout = json["normalized"]["clean_stdout"].as_str().unwrap();
    assert_eq!(clean_stdout.len(), 4096);
    assert!(clean_stdout.chars().all(|character| character == 'x'));
}
