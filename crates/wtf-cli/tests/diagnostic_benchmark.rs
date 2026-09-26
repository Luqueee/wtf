//! Reproducible CLI calibration cases. These exercise actual bounded probes in a private
//! directory; synthetic stderr cases deliberately separate a reported symptom from its cause.
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

struct Case<'a> {
    name: &'a str,
    argv: Vec<String>,
    category: &'a str,
    status: &'a str,
    cause: Option<String>,
    evidence: &'a str,
    expected_probes: &'a [&'a str],
    probe_evidence: Option<String>,
}

fn run_case(work: &Path, case: &Case<'_>) -> (Value, Duration) {
    let start = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_wtf"))
        .arg("--json")
        .arg("--")
        .args(&case.argv)
        .current_dir(work)
        .env_clear()
        .env("WTF_NO_MODEL", "1")
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", work)
        .env("XDG_RUNTIME_DIR", work)
        .output()
        .expect("run benchmark case");
    let elapsed = start.elapsed();
    assert!(!output.status.success(), "{} must fail", case.name);
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{}: {error}; stdout={:?}; stderr={:?}",
            case.name, output.stdout, output.stderr
        )
    });
    (json, elapsed)
}

#[cfg(unix)]
#[test]
fn diagnoses_distinguish_root_causes_from_reported_symptoms() {
    let sandbox = tempfile::tempdir().expect("create private benchmark directory");
    let work = sandbox.path();

    let absent = work.join("actual-missing.txt");
    let existing = work.join("reported-missing-but-present.txt");
    let mismatched_report = work.join("mismatched-reported-path.txt");
    let mismatched_argument = work.join("mismatched-argv-only-path.txt");
    let permission_target = work.join("permission-message-present.txt");
    let permission_missing = work.join("permission-message-missing.txt");
    let permission_argument = work.join("permission-argv-only-path.txt");
    let directory = work.join("directory-not-a-file");
    fs::write(&existing, "fixture").expect("create existing path");
    fs::write(&mismatched_report, "fixture").expect("create mismatched report path");
    fs::write(&permission_target, "fixture").expect("create permission target");
    fs::write(&permission_argument, "fixture").expect("create permission argv path");
    fs::create_dir(&directory).expect("create directory case");

    let mut cases = vec![
        Case {
            name: "missing executable: direct OS error",
            argv: vec!["wtf_fixture_nonexistent_executable".into()],
            category: "command/not-found",
            status: "Confirmed",
            cause: None,
            evidence: "failed to execute 'wtf_fixture_nonexistent_executable'",
            expected_probes: &[],
            probe_evidence: None,
        },
        Case {
            name: "missing file corroborated by stat",
            argv: vec!["cat".into(), absent.display().to_string()],
            category: "filesystem/not-found",
            status: "Confirmed",
            cause: Some(absent.display().to_string()),
            evidence: "No such file or directory",
            expected_probes: &["Stat"],
            probe_evidence: Some(absent.display().to_string()),
        },
        Case {
            name: "reported missing file actually exists",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "printf 'cat: %s: No such file or directory\\n' \"$1\" >&2; exit 1".into(),
                "_".into(),
                existing.display().to_string(),
            ],
            category: "filesystem/not-found",
            status: "Likely",
            cause: None,
            evidence: "No such file or directory",
            expected_probes: &["Stat"],
            probe_evidence: Some(existing.display().to_string()),
        },
        Case {
            name: "permission message without ownership proof",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "printf 'cat: %s: Permission denied\\n' \"$1\" >&2; exit 1".into(),
                "_".into(),
                permission_target.display().to_string(),
            ],
            category: "filesystem/permission-denied",
            status: "Likely",
            cause: None,
            evidence: "Permission denied",
            expected_probes: &["Stat"],
            probe_evidence: Some(permission_target.display().to_string()),
        },
        Case {
            name: "disk error without full filesystem",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "echo 'No space left on device' >&2; exit 1".into(),
            ],
            category: "filesystem/disk-full",
            status: "Likely",
            cause: None,
            evidence: "No space left on device",
            expected_probes: &["Filesystem", "FilesystemInodes"],
            probe_evidence: None,
        },
        Case {
            name: "conflict message without a port to verify",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "echo 'bind: address already in use' >&2; exit 1".into(),
            ],
            category: "network/port-conflict",
            status: "Likely",
            cause: None,
            evidence: "address already in use",
            expected_probes: &[],
            probe_evidence: None,
        },
        Case {
            name: "portless remote connection refusal avoids network probes",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "printf '%s\\n' 'curl: (7) Failed to connect to 192.0.2.1: Connection refused' >&2; exit 7".into(),
                "_".into(),
                "http://192.0.2.1/".into(),
            ],
            category: "network/connection-refused",
            status: "Likely",
            cause: None,
            evidence: "Connection refused",
            expected_probes: &[],
            probe_evidence: None,
        },
        Case {
            name: "unclassified failure",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "echo 'unclassified fixture failure' >&2; exit 42".into(),
            ],
            category: "unknown",
            status: "Unknown",
            cause: None,
            evidence: "unclassified fixture failure",
            expected_probes: &[],
            probe_evidence: None,
        },
        Case {
            name: "reported missing path disagrees with another argv path",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "printf 'cat: %s: No such file or directory\\n' \"$2\" >&2; exit 1".into(),
                "_".into(),
                mismatched_argument.display().to_string(),
                mismatched_report.display().to_string(),
            ],
            category: "filesystem/not-found",
            status: "Likely",
            cause: None,
            evidence: "No such file or directory",
            expected_probes: &["Stat"],
            probe_evidence: Some(mismatched_report.display().to_string()),
        },
        Case {
            name: "shell reports a missing child command",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "wtf_fixture_shell_missing_command".into(),
            ],
            category: "command/not-found",
            status: "Likely",
            cause: None,
            evidence: "wtf_fixture_shell_missing_command",
            expected_probes: &[],
            probe_evidence: None,
        },
        Case {
            name: "not-found message names a different command",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "echo 'unrelated_fixture_command: not found' >&2; exit 1".into(),
            ],
            category: "unknown",
            status: "Unknown",
            cause: None,
            evidence: "unrelated_fixture_command: not found",
            expected_probes: &[],
            probe_evidence: None,
        },
        Case {
            name: "permission message names a path that does not exist",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "printf 'cat: %s: Permission denied\\n' \"$2\" >&2; exit 1".into(),
                "_".into(),
                permission_argument.display().to_string(),
                permission_missing.display().to_string(),
            ],
            category: "filesystem/permission-denied",
            status: "Likely",
            cause: None,
            evidence: "Permission denied",
            expected_probes: &["Stat"],
            probe_evidence: Some(permission_missing.display().to_string()),
        },
        Case {
            name: "DNS-looking output from unrelated program stays unknown",
            argv: vec![
                "sh".into(),
                "-c".into(),
                "echo 'curl: (6) Could not resolve host: fixture.invalid' >&2; exit 6".into(),
            ],
            category: "unknown",
            status: "Unknown",
            cause: None,
            evidence: "Could not resolve host",
            expected_probes: &[],
            probe_evidence: None,
        },
        Case {
            name: "existing directory is not diagnosed as a missing file",
            argv: vec!["cat".into(), directory.display().to_string()],
            category: "unknown",
            status: "Unknown",
            cause: None,
            evidence: "Is a directory",
            expected_probes: &[],
            probe_evidence: None,
        },
    ];

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let non_executable = work.join("non-executable-script");
        fs::write(&non_executable, "#!/bin/sh\nexit 0\n")
            .expect("create non-executable command fixture");
        fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o644))
            .expect("remove executable permission");
        cases.push(Case {
            name: "permission error from a non-executable local file",
            argv: vec![non_executable.display().to_string()],
            category: "filesystem/permission-denied",
            status: "Confirmed",
            cause: None,
            evidence: "Permission denied",
            expected_probes: &["Stat"],
            probe_evidence: Some(non_executable.display().to_string()),
        });
    }

    assert!(
        (14..=18).contains(&cases.len()),
        "calibration matrix has {} cases, expected 14-18",
        cases.len()
    );
    let expected_unknown = cases.iter().filter(|case| case.status == "Unknown").count();
    let mut correct_categories = 0;
    let mut correct_statuses = 0;
    let mut correct_root_identities = 0;
    let mut correct_outcomes = 0;
    let mut false_confirmations = 0;
    let mut unknown = 0;
    let mut probes = 0;
    let mut latencies = Vec::with_capacity(cases.len());

    for case in &cases {
        let (json, elapsed) = run_case(work, case);
        let status = json["status"].as_str().expect("diagnosis status");
        let category_matches = json["category"] == case.category;
        let status_matches = status == case.status;
        let root = json["investigation"]["root_cause"].as_str();
        let root_matches = match (&case.cause, root) {
            (Some(expected), Some(actual)) => actual.contains(expected),
            (None, None) => true,
            _ => false,
        };
        let evidence = json["evidence"].as_array().expect("diagnosis evidence");
        assert!(
            evidence.iter().any(|line| {
                line.as_str()
                    .is_some_and(|line| line.contains(case.evidence))
            }),
            "{}: expected diagnosis evidence {:?}; got {evidence:?}",
            case.name,
            case.evidence
        );

        let attempts = json["investigation"]["attempts"]
            .as_array()
            .expect("investigation probe attempts");
        let actual_probes: Vec<_> = attempts
            .iter()
            .map(|attempt| attempt["probe"].as_str().expect("probe id"))
            .collect();
        assert_eq!(
            actual_probes.as_slice(),
            case.expected_probes,
            "{}: probe boundary",
            case.name
        );
        if let Some(expected) = case.probe_evidence.as_deref() {
            let investigation_evidence = json["investigation"]["evidence"]
                .as_array()
                .expect("investigation evidence");
            assert!(
                investigation_evidence.iter().any(|item| {
                    item["observation"]
                        .as_str()
                        .is_some_and(|observation| observation.contains(expected))
                }),
                "{}: expected probe evidence {:?}; got {investigation_evidence:?}",
                case.name,
                expected
            );
        }

        correct_categories += usize::from(category_matches);
        correct_statuses += usize::from(status_matches);
        correct_root_identities += usize::from(root_matches);
        correct_outcomes += usize::from(category_matches && status_matches && root_matches);
        false_confirmations += usize::from(
            status == "Confirmed"
                && (case.status != "Confirmed" || !category_matches || !root_matches),
        );
        unknown += usize::from(status == "Unknown");
        probes += attempts.len();
        latencies.push(elapsed);
        eprintln!(
            "{}: category={}; {status}; cause={root:?}; probes={}; elapsed={elapsed:?}",
            case.name,
            json["category"],
            attempts.len()
        );
        assert_eq!(json["category"], case.category, "{}: {json}", case.name);
        assert_eq!(status, case.status, "{}: {json}", case.name);
        assert!(root_matches, "{}: {json}", case.name);
    }

    latencies.sort_unstable();
    let middle = latencies.len() / 2;
    let median_latency = if latencies.len() % 2 == 1 {
        latencies[middle]
    } else {
        let nanos = (latencies[middle - 1].as_nanos() + latencies[middle].as_nanos()) / 2;
        Duration::from_nanos(nanos as u64)
    };
    eprintln!(
        "Calibration: {correct_outcomes}/{} expected outcomes; categories {correct_categories}/{}; statuses {correct_statuses}/{}; root identities (including expected absence) {correct_root_identities}/{}; {false_confirmations} false confirmations; unknown {unknown}/{expected_unknown} expected; {probes} probes ({:.2}/diagnosis); median CLI wall time {median_latency:?}",
        cases.len(),
        cases.len(),
        cases.len(),
        cases.len(),
        probes as f64 / cases.len() as f64,
    );
    assert_eq!(correct_outcomes, cases.len());
    assert_eq!(false_confirmations, 0);
    assert_eq!(unknown, expected_unknown);
}
