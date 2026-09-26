use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use wtf_core::capture::{CommandExecution, ProcessExit};
use wtf_core::diagnosis::DiagnosisEngine;
use wtf_core::investigation::{HypothesisStatus, InvestigationEngine};
use wtf_core::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSpec};

struct FixtureRunner {
    output: HashMap<ProbeId, ProbeOutput>,
    programs: Vec<&'static str>,
}

impl FixtureRunner {
    fn new(programs: &[&'static str], output: &[(ProbeId, &str)]) -> Self {
        Self {
            output: output
                .iter()
                .map(|(id, stdout)| (*id, good(stdout)))
                .collect(),
            programs: programs.to_vec(),
        }
    }

    fn with_failure(mut self, id: ProbeId, stderr: &str) -> Self {
        self.output.insert(
            id,
            ProbeOutput {
                stdout: String::new(),
                stderr: stderr.into(),
                exit_code: Some(1),
                truncated: false,
            },
        );
        self
    }
}

impl ProbeRunner for FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        Ok(self.output.get(&spec.id).expect("unexpected probe").clone())
    }

    fn available(&self, program: &str) -> bool {
        self.programs.contains(&program)
    }
}

fn good(stdout: &str) -> ProbeOutput {
    ProbeOutput {
        stdout: stdout.into(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    }
}

fn failed(command: &str, args: &[&str], stderr: &str) -> CommandExecution {
    CommandExecution {
        command: command.into(),
        args: args.iter().map(|a| (*a).into()).collect(),
        cwd: std::env::temp_dir(),
        exit_status: ProcessExit {
            code: Some(1),
            signal: None,
        },
        stdout: String::new(),
        stderr: stderr.into(),
        duration: Duration::from_millis(8),
        timestamp: SystemTime::UNIX_EPOCH,
        spawn_error: None,
    }
}

#[test]
fn port_conflict_confirms_live_pid_but_not_from_message_alone() {
    let execution = failed(
        "node",
        &["server.js"],
        "listen EADDRINUSE: address already in use 0.0.0.0:8080",
    );
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    assert_eq!(diagnosis.category.as_deref(), Some("network/port-conflict"));
    #[cfg(target_os = "linux")]
    let listener = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"node\",pid=4321,fd=4))\n";
    #[cfg(target_os = "macos")]
    let listener = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nnode 4321 me 4u IPv4 0t0 TCP *:8080 (LISTEN)\n";
    let fixture = FixtureRunner::new(
        &[
            if cfg!(target_os = "linux") {
                "ss"
            } else {
                "lsof"
            },
            "ps",
        ],
        &[
            (ProbeId::Listeners, listener),
            (ProbeId::Process, " 4321 node\n"),
        ],
    );
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert!(report
        .root_cause
        .as_deref()
        .is_some_and(|s| s.contains("node (PID 4321)")));
    assert_eq!(
        report.attempts.iter().map(|a| a.probe).collect::<Vec<_>>(),
        [ProbeId::Listeners, ProbeId::Process]
    );
    assert!(report
        .hypotheses
        .iter()
        .any(|h| h.id == "port_owner" && h.status == HypothesisStatus::Confirmed));
}

#[test]
fn refused_connection_follows_stopped_container_to_missing_variable() {
    let execution = failed(
        "curl",
        &["http://localhost:8000"],
        "curl: (7) Failed to connect to localhost port 8000: Connection refused",
    );
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    assert_eq!(
        diagnosis.category.as_deref(),
        Some("network/connection-refused")
    );
    let fixture = FixtureRunner::new(&[if cfg!(target_os = "linux") { "ss" } else { "lsof" }, "docker"], &[
        (ProbeId::Listeners, ""),
        (ProbeId::DockerRunning, ""),
        (ProbeId::DockerAll, "{\"Names\":\"db\",\"Ports\":\"0.0.0.0:8000->80/tcp\",\"Status\":\"Exited (1) 2 minutes ago\"}\n"),
        (ProbeId::DockerInspect, "{\"Status\":\"exited\",\"ExitCode\":1}|{\"80/tcp\":[{\"HostIp\":\"0.0.0.0\",\"HostPort\":\"8000\"}]}|/db\n"),
        (ProbeId::DockerLogs, "Error: DATABASE_URL is required\n"),
    ]);
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert_eq!(report.attempts.len(), 5);
    assert!(report
        .root_cause
        .as_deref()
        .is_some_and(|s| s.contains("Container \"db\" is not running")));
    assert_eq!(report.cause.as_deref(), Some("DATABASE_URL is missing."));
    assert!(report
        .evidence
        .iter()
        .any(|e| e.probe == ProbeId::DockerLogs && e.observation.contains("DATABASE_URL")));
}

#[test]
fn metadata_only_curl_failure_uses_listener_evidence_without_claiming_refusal() {
    let mut execution = failed("curl", &["localhost:8000"], "");
    execution.exit_status.code = Some(7);
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    assert_eq!(
        diagnosis.category.as_deref(),
        Some("network/connect-failed")
    );
    assert_eq!(diagnosis.entities.primary_port(), Some(8000));
    assert!(diagnosis.summary.contains("failed"));
    assert!(!diagnosis.summary.contains("refused"));

    let listener_probe = if cfg!(target_os = "linux") {
        "ss"
    } else {
        "lsof"
    };
    let fixture = FixtureRunner::new(
        &[listener_probe],
        &[(
            ProbeId::Listeners,
            "LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* users:((\"server\",pid=42,fd=1))",
        )],
    );
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert!(report.root_cause.is_none());
    assert!(report.evidence.iter().any(|e| {
        e.probe == ProbeId::Listeners && e.observation.contains("listening on 127.0.0.1:8000")
    }));
}

#[test]
fn no_listener_is_evidence_not_a_claimed_root_cause() {
    let execution = failed("curl", &["http://localhost:8000"], "Connection refused");
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let fixture = FixtureRunner::new(
        &[if cfg!(target_os = "linux") {
            "ss"
        } else {
            "lsof"
        }],
        &[(ProbeId::Listeners, "")],
    );
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert!(report.root_cause.is_none());
    assert!(report
        .evidence
        .iter()
        .any(|e| e.observation.contains("no local TCP listener")));
    assert!(report
        .render(&diagnosis, &Default::default(), false)
        .contains("Root cause not confirmed"));
}

#[test]
fn truncated_probe_cannot_confirm_listener() {
    let execution = failed(
        "node",
        &["server.js"],
        "bind: address already in use 0.0.0.0:8080",
    );
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let program = if cfg!(target_os = "linux") {
        "ss"
    } else {
        "lsof"
    };
    let mut fixture = FixtureRunner::new(
        &[program],
        &[(
            ProbeId::Listeners,
            "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"node\",pid=1,fd=1))",
        )],
    );
    fixture
        .output
        .get_mut(&ProbeId::Listeners)
        .unwrap()
        .truncated = true;
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert!(report.root_cause.is_none());
    assert_eq!(report.attempts[0].result, "truncated");
    assert!(report.evidence.is_empty());
}

#[test]
fn probe_budget_stops_before_inspect_and_logs() {
    let execution = failed("curl", &["http://localhost:8000"], "Connection refused");
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let fixture = FixtureRunner::new(
        &[
            if cfg!(target_os = "linux") {
                "ss"
            } else {
                "lsof"
            },
            "docker",
        ],
        &[
            (ProbeId::Listeners, ""),
            (ProbeId::DockerRunning, ""),
            (
                ProbeId::DockerAll,
                "{\"Names\":\"db\",\"Ports\":\"0.0.0.0:8000->80/tcp\",\"Status\":\"Exited (1)\"}",
            ),
        ],
    );
    let report = InvestigationEngine::with_budget(fixture, 2, Duration::from_secs(2))
        .investigate(&execution, &diagnosis);
    assert!(report.root_cause.is_none());
    assert_eq!(report.attempts.len(), 2);
}

#[test]
fn filesystem_full_requires_df_evidence() {
    let execution = failed(
        "cp",
        &["/tmp/source", "/tmp/destination"],
        "cp: No space left on device",
    );
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let fixture = FixtureRunner::new(&["df"], &[(ProbeId::Filesystem, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk1 1000 1000 0 100% /tmp\n")]);
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert!(report
        .root_cause
        .as_deref()
        .is_some_and(|s| s.contains("100% full")));
    let fixture = FixtureRunner::new(&["df"], &[
        (ProbeId::Filesystem, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk1 1000 900 100 90% /tmp\n"),
        (ProbeId::FilesystemInodes, "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/disk1 100 70 30 70% /tmp\n"),
    ]);
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert!(report.root_cause.is_none());
    assert_eq!(
        report
            .hypotheses
            .iter()
            .find(|h| h.id == "filesystem_full")
            .map(|h| h.status),
        Some(HypothesisStatus::Rejected)
    );
}

#[test]
fn disk_error_with_free_blocks_but_no_inodes_has_confirmed_cause() {
    let execution = failed(
        "cp",
        &["/tmp/source", "/tmp/destination"],
        "cp: No space left on device",
    );
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let fixture = FixtureRunner::new(&["df"], &[
        (ProbeId::Filesystem, "Filesystem Blocks Used Available Capacity Mounted on\n/dev/disk1 1000 900 100 90% /tmp\n"),
        (ProbeId::FilesystemInodes, "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/disk1 100 100 0 100% /tmp\n"),
    ]);
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert!(report
        .root_cause
        .as_deref()
        .is_some_and(|s| s.contains("exhausted its inodes")));
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|attempt| attempt.probe)
            .collect::<Vec<_>>(),
        [ProbeId::Filesystem, ProbeId::FilesystemInodes]
    );
}

#[test]
fn disk_full_is_rejected_only_by_two_valid_matching_df_reports() {
    let execution = failed("cp", &[], "cp: No space left on device");
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let blocks = "Filesystem Blocks Used Available Capacity Mounted on\n/dev/disk 1000 900 100 90% /private/mount\n";
    let inodes = "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/disk 1000 900 100 90% /private/mount\n";
    for bad_blocks in [
        "Filesystem Blocks Used Available Capacity Mounted on\n/dev/disk 100% 900 100 N/A /private/mount\n",
        "Filesystem Blocks Used Available IUse% Mounted on\n/dev/disk 1000 900 100 90% /private/mount\n",
        "Filesystem Blocks Used Available Capacity Mounted on\n/dev/disk 1000 900 100 90% /private/mount\n/dev/other 1000 900 100 90% /other\n",
        "Filesystem Blocks Used Available Capacity Mounted on\n/dev/disk 1000 bad 100 90% /private/mount\n",
        "Bad Blocks Used Available Capacity Mounted on\n/dev/disk 1000 900 100 90% /private/mount\n",
    ] {
        let fixture = FixtureRunner::new(
            &["df"],
            &[(ProbeId::Filesystem, bad_blocks), (ProbeId::FilesystemInodes, inodes)],
        );
        let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
        assert!(report.root_cause.is_none());
        assert_eq!(
            report.hypotheses.iter().find(|h| h.id == "filesystem_full").map(|h| h.status),
            Some(HypothesisStatus::Candidate)
        );
    }
    let mismatched_inodes = inodes.replace("/private/mount", "/different/mount");
    let fixture = FixtureRunner::new(
        &["df"],
        &[
            (ProbeId::Filesystem, blocks),
            (ProbeId::FilesystemInodes, &mismatched_inodes),
        ],
    );
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert_eq!(
        report
            .hypotheses
            .iter()
            .find(|h| h.id == "filesystem_full")
            .map(|h| h.status),
        Some(HypothesisStatus::Candidate)
    );
    let mut fixture = FixtureRunner::new(
        &["df"],
        &[
            (ProbeId::Filesystem, blocks),
            (ProbeId::FilesystemInodes, inodes),
        ],
    );
    fixture
        .output
        .get_mut(&ProbeId::Filesystem)
        .unwrap()
        .truncated = true;
    fixture = fixture.with_failure(ProbeId::FilesystemInodes, "unavailable");
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert_eq!(
        report
            .hypotheses
            .iter()
            .find(|h| h.id == "filesystem_full")
            .map(|h| h.status),
        Some(HypothesisStatus::Candidate)
    );
}

#[test]
fn file_absence_requires_corresponding_stat_error() {
    let execution = failed(
        "cat",
        &["/tmp/wtf-nonexistent-fixture"],
        "cat: /tmp/wtf-nonexistent-fixture: No such file or directory",
    );
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let fixture = FixtureRunner::new(&["stat"], &[]).with_failure(
        ProbeId::Stat,
        "stat: /tmp/wtf-nonexistent-fixture: No such file or directory",
    );
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    assert!(report
        .root_cause
        .as_deref()
        .is_some_and(|s| s.contains("wtf-nonexistent-fixture does not exist")));
}

#[test]
fn git_changes_are_not_claimed_to_cause_an_unrelated_failure() {
    let mut execution = failed("git", &["fetch"], "fatal: invalid refspec");
    let cwd = std::env::temp_dir().join(format!(
        "wtf-fixture-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(cwd.join(".git")).unwrap();
    execution.cwd = PathBuf::from(&cwd);
    let diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let fixture = FixtureRunner::new(
        &["git"],
        &[
            (ProbeId::GitStatus, " M config.toml"),
            (ProbeId::GitDiff, " config.toml | 1 +"),
        ],
    );
    let report = InvestigationEngine::new(fixture).investigate(&execution, &diagnosis);
    std::fs::remove_dir_all(&cwd).unwrap();
    assert!(report.root_cause.is_none());
    assert_eq!(
        report.attempts.iter().map(|a| a.probe).collect::<Vec<_>>(),
        [ProbeId::GitStatus, ProbeId::GitDiff]
    );
}

#[test]
fn shell_cargo_compiler_diagnostic_reaches_existing_diagnosis_and_evidence() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname=\"probe-fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    let mut execution = failed("/usr/bin/cargo", &["build"], "");
    execution.cwd = project.path().into();
    let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let compiler = serde_json::json!({
        "reason": "compiler-message",
        "message": {
            "level": "error",
            "message": "mismatched types",
            "code": {"code": "E0308"},
            "spans": [{"file_name": "src/api.rs", "line_start": 84, "column_start": 9, "is_primary": true}]
        }
    });
    let output = format!("{compiler}\n");
    let mut fixture = FixtureRunner::new(&["cargo"], &[]);
    fixture.output.insert(
        ProbeId::CargoCheck,
        ProbeOutput {
            stdout: output,
            stderr: String::new(),
            exit_code: Some(101),
            truncated: false,
        },
    );
    let report =
        InvestigationEngine::new(fixture).investigate_reconstructed(&execution, &mut diagnosis);
    assert_eq!(diagnosis.summary, "Rust compilation failed.");
    assert!(report
        .root_cause
        .as_deref()
        .is_some_and(|s| s.contains("src/api.rs:84")));
    assert!(report
        .evidence
        .iter()
        .any(|e| e.observation.contains("E0308")));
    assert_eq!(report.adapter, Some("cargo"));
}
