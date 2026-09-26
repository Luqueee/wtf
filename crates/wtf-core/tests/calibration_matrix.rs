#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::cell::Cell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use wtf_core::capture::{CommandExecution, ProcessExit};
use wtf_core::diagnosis::{DiagnosisEngine, DiagnosisStatus};
use wtf_core::investigation::{HypothesisStatus, Investigation, InvestigationEngine};
use wtf_core::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSpec};

enum Reply {
    Output(ProbeOutput),
    Timeout,
}

struct ExpectedCall {
    id: ProbeId,
    program: &'static str,
    args: Vec<String>,
    reply: Reply,
}

struct FixtureRunner {
    expected: Vec<ExpectedCall>,
    cwd: PathBuf,
    unavailable: HashSet<&'static str>,
    next: Cell<usize>,
}

impl FixtureRunner {
    fn new(expected: Vec<ExpectedCall>, cwd: &Path, unavailable: &[&'static str]) -> Self {
        Self {
            expected,
            cwd: cwd.to_path_buf(),
            unavailable: unavailable.iter().copied().collect(),
            next: Cell::new(0),
        }
    }

    fn assert_consumed(&self, scenario: &str) {
        assert_eq!(
            self.next.get(),
            self.expected.len(),
            "{scenario}: not all scripted probe calls were consumed"
        );
    }
}

impl ProbeRunner for FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        let index = self.next.get();
        let expected = self
            .expected
            .get(index)
            .unwrap_or_else(|| panic!("unexpected extra probe: {:?}", spec.id));
        assert_eq!(spec.id, expected.id, "probe sequence at call {index}");
        assert_eq!(
            spec.program, expected.program,
            "probe program at call {index}"
        );
        assert_eq!(spec.args, expected.args, "probe argv at call {index}");
        assert_eq!(
            spec.cwd, self.cwd,
            "probe working directory at call {index}"
        );
        self.next.set(index + 1);
        match &expected.reply {
            Reply::Output(output) => Ok(output.clone()),
            Reply::Timeout => Err(ProbeError::Timeout),
        }
    }

    fn available(&self, program: &str) -> bool {
        !self
            .unavailable
            .iter()
            .any(|unavailable| *unavailable == program)
    }
}

impl ProbeRunner for &FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        FixtureRunner::run(*self, spec)
    }

    fn available(&self, program: &str) -> bool {
        FixtureRunner::available(*self, program)
    }
}

#[derive(Clone, Copy)]
enum InvestigationMode {
    Direct,
    Reconstructed,
}

struct Scenario {
    name: &'static str,
    execution: CommandExecution,
    mode: InvestigationMode,
    unavailable_programs: Vec<&'static str>,
    calls: Vec<ExpectedCall>,
    expected_attempts: Vec<(ProbeId, &'static str)>,
    max_probes: usize,
    initial_category: &'static str,
    initial_status: DiagnosisStatus,
    final_category: &'static str,
    final_status: DiagnosisStatus,
    root_cause: Option<String>,
    cause: Option<&'static str>,
    evidence: Vec<(ProbeId, &'static str)>,
    hypotheses: Vec<(&'static str, HypothesisStatus)>,
}

fn output(stdout: &str) -> ProbeOutput {
    ProbeOutput {
        stdout: stdout.into(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    }
}

fn truncated_output(stdout: &str) -> ProbeOutput {
    ProbeOutput {
        truncated: true,
        ..output(stdout)
    }
}

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn output_call(
    id: ProbeId,
    program: &'static str,
    args: Vec<String>,
    stdout: &str,
) -> ExpectedCall {
    ExpectedCall {
        id,
        program,
        args,
        reply: Reply::Output(output(stdout)),
    }
}

fn truncated_call(
    id: ProbeId,
    program: &'static str,
    args: Vec<String>,
    stdout: &str,
) -> ExpectedCall {
    ExpectedCall {
        id,
        program,
        args,
        reply: Reply::Output(truncated_output(stdout)),
    }
}

fn timeout_call(id: ProbeId, program: &'static str, args: Vec<String>) -> ExpectedCall {
    ExpectedCall {
        id,
        program,
        args,
        reply: Reply::Timeout,
    }
}

fn listeners_call(stdout: &str) -> ExpectedCall {
    #[cfg(target_os = "linux")]
    let (program, args) = ("ss", words(&["-ltnp"]));
    #[cfg(target_os = "macos")]
    let (program, args) = ("lsof", words(&["-nP", "-iTCP", "-sTCP:LISTEN"]));
    output_call(ProbeId::Listeners, program, args, stdout)
}

fn docker_running_call(stdout: &str) -> ExpectedCall {
    output_call(
        ProbeId::DockerRunning,
        "docker",
        words(&["ps", "--format", "{{json .}}"]),
        stdout,
    )
}

fn docker_all_call(stdout: &str) -> ExpectedCall {
    output_call(
        ProbeId::DockerAll,
        "docker",
        words(&["ps", "-a", "--format", "{{json .}}"]),
        stdout,
    )
}

fn docker_inspect_call(name: &str, stdout: &str) -> ExpectedCall {
    output_call(
        ProbeId::DockerInspect,
        "docker",
        vec![
            "inspect".into(),
            "--format".into(),
            "{{json .State}}|{{json .HostConfig.PortBindings}}|{{.Name}}".into(),
            name.into(),
        ],
        stdout,
    )
}

fn docker_logs_call(name: &str, stdout: &str) -> ExpectedCall {
    output_call(
        ProbeId::DockerLogs,
        "docker",
        vec!["logs".into(), "--tail".into(), "40".into(), name.into()],
        stdout,
    )
}

fn filesystem_call(id: ProbeId, target: &Path, stdout: &str) -> ExpectedCall {
    let flag = if id == ProbeId::FilesystemInodes {
        "-Pi"
    } else {
        "-P"
    };
    output_call(
        id,
        "df",
        vec![
            flag.into(),
            "--".into(),
            target.to_string_lossy().into_owned(),
        ],
        stdout,
    )
}

fn stat_call(target: &Path, stdout: &str) -> ExpectedCall {
    #[cfg(target_os = "linux")]
    let args = vec![
        "-c".into(),
        "%F|%a|%U|%G|%n".into(),
        "--".into(),
        target.to_string_lossy().into_owned(),
    ];
    #[cfg(target_os = "macos")]
    let args = vec![
        "-f".into(),
        "%HT|%Lp|%Su|%Sg|%N".into(),
        "--".into(),
        target.to_string_lossy().into_owned(),
    ];
    output_call(ProbeId::Stat, "stat", args, stdout)
}

fn execution(
    command: &str,
    args: &[String],
    cwd: &Path,
    exit_code: i32,
    stderr: &str,
) -> CommandExecution {
    CommandExecution {
        command: command.into(),
        args: args.to_vec(),
        cwd: cwd.to_path_buf(),
        exit_status: ProcessExit {
            code: Some(exit_code),
            signal: None,
        },
        stdout: String::new(),
        stderr: stderr.into(),
        duration: Duration::from_millis(8),
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_704_067_200),
        spawn_error: None,
    }
}

fn disk_execution(cwd: &Path, scenario_name: &str) -> (CommandExecution, PathBuf) {
    let directory = cwd.join(scenario_name);
    std::fs::create_dir_all(&directory).expect("private fixture directory");
    let path = directory.join("source.dat");
    let execution = execution(
        "cp",
        &[
            path.to_string_lossy().into_owned(),
            directory.join("output.dat").to_string_lossy().into_owned(),
        ],
        cwd,
        1,
        "cp: No space left on device",
    );
    (execution, path)
}

fn df_blocks(percent: u16) -> String {
    format!(
        "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/calibration 1000 990 10 {percent}% /fixture\n"
    )
}

fn df_inodes(percent: u16) -> String {
    format!(
        "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/calibration 1000 990 10 {percent}% /fixture\n"
    )
}

fn docker_run_execution(cwd: &Path, name: &str) -> CommandExecution {
    execution(
        "docker",
        &[
            "run".into(),
            "--name".into(),
            name.into(),
            "image:fixture".into(),
        ],
        cwd,
        125,
        "",
    )
}

fn docker_recent_list(name: &str) -> String {
    format!(
        "{{\"Names\":\"{name}\",\"CreatedAt\":\"2024-01-01 00:00:01 +0000 UTC\",\"ID\":\"fixture-id\"}}\n"
    )
}

fn assert_case(scenario: Scenario, cwd: &Path) -> (usize, usize, usize, usize) {
    let runner = FixtureRunner::new(scenario.calls, cwd, &scenario.unavailable_programs);
    let mut diagnosis = DiagnosisEngine::new().diagnose(&scenario.execution);
    assert_eq!(
        diagnosis.category.as_deref(),
        Some(scenario.initial_category),
        "{}: initial category",
        scenario.name
    );
    assert_eq!(
        diagnosis.status, scenario.initial_status,
        "{}: initial certainty",
        scenario.name
    );

    let report: Investigation = match scenario.mode {
        InvestigationMode::Direct => {
            InvestigationEngine::with_budget(&runner, scenario.max_probes, Duration::from_secs(2))
                .investigate(&scenario.execution, &diagnosis)
        }
        InvestigationMode::Reconstructed => {
            InvestigationEngine::with_budget(&runner, scenario.max_probes, Duration::from_secs(2))
                .investigate_reconstructed(&scenario.execution, &mut diagnosis)
        }
    };

    assert_eq!(
        diagnosis.category.as_deref(),
        Some(scenario.final_category),
        "{}: final category",
        scenario.name
    );
    assert_eq!(
        diagnosis.status, scenario.final_status,
        "{}: final certainty",
        scenario.name
    );
    assert_eq!(
        report.root_cause, scenario.root_cause,
        "{}: root-cause identity",
        scenario.name
    );
    assert_eq!(
        report.cause.as_deref(),
        scenario.cause,
        "{}: secondary cause",
        scenario.name
    );

    let actual_attempts: Vec<_> = report
        .attempts
        .iter()
        .map(|attempt| (attempt.probe, attempt.result.as_str()))
        .collect();
    let expected_attempts: Vec<_> = scenario
        .expected_attempts
        .iter()
        .map(|(probe, result)| (*probe, *result))
        .collect();
    assert_eq!(
        actual_attempts, expected_attempts,
        "{}: exact attempted-probe path and outcomes",
        scenario.name
    );
    assert!(
        report.attempts.len() <= scenario.max_probes,
        "{}: probe budget exceeded",
        scenario.name
    );
    runner.assert_consumed(scenario.name);

    for (probe, text) in &scenario.evidence {
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.probe == *probe && item.observation.contains(text)),
            "{}: missing {:?} evidence containing {text:?}; got {:?}",
            scenario.name,
            probe,
            report
                .evidence
                .iter()
                .map(|item| (item.probe, item.observation.as_str()))
                .collect::<Vec<_>>()
        );
    }
    for (id, expected_status) in &scenario.hypotheses {
        assert_eq!(
            report
                .hypotheses
                .iter()
                .find(|hypothesis| hypothesis.id == *id)
                .map(|hypothesis| hypothesis.status),
            Some(*expected_status),
            "{}: hypothesis {id}",
            scenario.name
        );
    }

    let timeouts = actual_attempts
        .iter()
        .filter(|(_, result)| *result == "probe exceeded its deadline")
        .count();
    let unavailable = actual_attempts
        .iter()
        .filter(|(_, result)| *result == "unavailable")
        .count();
    let truncated = actual_attempts
        .iter()
        .filter(|(_, result)| *result == "truncated")
        .count();
    println!(
        "calibration scenario={}: category={} root={} probes={}/{}",
        scenario.name,
        scenario.final_category,
        if scenario.root_cause.is_some() {
            "confirmed"
        } else {
            "unconfirmed"
        },
        report.attempts.len(),
        scenario.max_probes
    );
    (report.attempts.len(), timeouts, unavailable, truncated)
}

#[test]
fn calibration_matrix_exercises_distinct_diagnostic_boundaries() {
    let sandbox = tempfile::tempdir().expect("private calibration sandbox");
    let cwd = sandbox.path().join("work");
    std::fs::create_dir_all(&cwd).expect("private working directory");

    let curl_active = execution(
        "curl",
        &["http://localhost:8080".into()],
        &cwd,
        7,
        "curl: (7) Failed to connect to localhost port 8080: Connection refused",
    );
    let curl_wrong_port = execution(
        "curl",
        &["http://localhost:8081".into()],
        &cwd,
        7,
        "curl: (7) Failed to connect to localhost port 8081: Connection refused",
    );

    let (blocks_99_exec, blocks_99_path) = disk_execution(&cwd, "blocks-99-inodes-99");
    let (inode_boundary_exec, inode_boundary_path) = disk_execution(&cwd, "blocks-99-inodes-100");
    let (timeout_exec, timeout_path) = disk_execution(&cwd, "df-timeout-inodes-100");
    let (truncated_exec, truncated_path) = disk_execution(&cwd, "df-truncated-inodes-99");
    let source_parent = blocks_99_path.parent().expect("fixture parent");
    let inode_parent = inode_boundary_path.parent().expect("fixture parent");
    let timeout_parent = timeout_path.parent().expect("fixture parent");
    let truncated_parent = truncated_path.parent().expect("fixture parent");

    let missing_path = cwd.join("stat-unavailable.txt");
    let missing_execution = execution(
        "cat",
        &[missing_path.to_string_lossy().into_owned()],
        &cwd,
        1,
        &format!("cat: {}: No such file or directory", missing_path.display()),
    );

    let contradictory_path = cwd.join("appears-missing-but-exists.txt");
    std::fs::write(&contradictory_path, "private fixture").expect("private stat fixture");
    let contradictory_execution = execution(
        "cat",
        &[contradictory_path.to_string_lossy().into_owned()],
        &cwd,
        1,
        &format!(
            "cat: {}: No such file or directory",
            contradictory_path.display()
        ),
    );

    let scenarios = vec![
        Scenario {
            name: "refusal-with-matching-live-container",
            execution: curl_active,
            mode: InvestigationMode::Direct,
            unavailable_programs: vec![],
            calls: vec![
                listeners_call(""),
                docker_running_call(
                    "{\"Names\":\"web\",\"Ports\":\"0.0.0.0:8080->80/tcp\",\"Status\":\"Up 2 minutes\"}\n",
                ),
            ],
            expected_attempts: vec![(ProbeId::Listeners, "ok"), (ProbeId::DockerRunning, "ok")],
            max_probes: 5,
            initial_category: "network/connection-refused",
            initial_status: DiagnosisStatus::Likely,
            final_category: "network/connection-refused",
            final_status: DiagnosisStatus::Likely,
            root_cause: None,
            cause: None,
            evidence: vec![
                (ProbeId::Listeners, "no local TCP listener on :8080"),
                (ProbeId::DockerRunning, "web is running"),
            ],
            hypotheses: vec![
                ("no_local_listener", HypothesisStatus::Confirmed),
                ("container_exited", HypothesisStatus::Rejected),
            ],
        },
        Scenario {
            name: "refusal-does-not-match-unrelated-exited-port",
            execution: curl_wrong_port,
            mode: InvestigationMode::Direct,
            unavailable_programs: vec![],
            calls: vec![
                listeners_call(""),
                docker_running_call(""),
                docker_all_call(
                    "{\"Names\":\"old-web\",\"Ports\":\"0.0.0.0:9001->80/tcp\",\"Status\":\"Exited (1) 2 minutes ago\"}\n",
                ),
            ],
            expected_attempts: vec![
                (ProbeId::Listeners, "ok"),
                (ProbeId::DockerRunning, "ok"),
                (ProbeId::DockerAll, "ok"),
            ],
            max_probes: 5,
            initial_category: "network/connection-refused",
            initial_status: DiagnosisStatus::Likely,
            final_category: "network/connection-refused",
            final_status: DiagnosisStatus::Likely,
            root_cause: None,
            cause: None,
            evidence: vec![(ProbeId::Listeners, "no local TCP listener on :8081")],
            hypotheses: vec![("container_exited", HypothesisStatus::Candidate)],
        },
        Scenario {
            name: "99-percent-blocks-and-inodes-are-not-full",
            execution: blocks_99_exec,
            mode: InvestigationMode::Direct,
            unavailable_programs: vec![],
            calls: vec![
                filesystem_call(ProbeId::Filesystem, source_parent, &df_blocks(99)),
                filesystem_call(ProbeId::FilesystemInodes, source_parent, &df_inodes(99)),
            ],
            expected_attempts: vec![
                (ProbeId::Filesystem, "ok"),
                (ProbeId::FilesystemInodes, "ok"),
            ],
            max_probes: 5,
            initial_category: "filesystem/disk-full",
            initial_status: DiagnosisStatus::Likely,
            final_category: "filesystem/disk-full",
            final_status: DiagnosisStatus::Likely,
            root_cause: None,
            cause: None,
            evidence: vec![
                (ProbeId::Filesystem, "99% used"),
                (ProbeId::FilesystemInodes, "99% of inodes used"),
            ],
            hypotheses: vec![("filesystem_full", HypothesisStatus::Rejected)],
        },
        Scenario {
            name: "inode-saturation-at-100-beats-99-percent-blocks",
            execution: inode_boundary_exec,
            mode: InvestigationMode::Direct,
            unavailable_programs: vec![],
            calls: vec![
                filesystem_call(ProbeId::Filesystem, inode_parent, &df_blocks(99)),
                filesystem_call(ProbeId::FilesystemInodes, inode_parent, &df_inodes(100)),
            ],
            expected_attempts: vec![
                (ProbeId::Filesystem, "ok"),
                (ProbeId::FilesystemInodes, "ok"),
            ],
            max_probes: 5,
            initial_category: "filesystem/disk-full",
            initial_status: DiagnosisStatus::Likely,
            final_category: "filesystem/disk-full",
            final_status: DiagnosisStatus::Likely,
            root_cause: Some(format!(
                "Filesystem containing {} has exhausted its inodes (mounted at /fixture).",
                inode_boundary_path.display()
            )),
            cause: None,
            evidence: vec![(ProbeId::FilesystemInodes, "100% of inodes used")],
            hypotheses: vec![("filesystem_full", HypothesisStatus::Confirmed)],
        },
        Scenario {
            name: "filesystem-timeout-falls-through-to-inode-proof",
            execution: timeout_exec,
            mode: InvestigationMode::Direct,
            unavailable_programs: vec![],
            calls: vec![
                timeout_call(
                    ProbeId::Filesystem,
                    "df",
                    vec!["-P".into(), "--".into(), timeout_parent.to_string_lossy().into_owned()],
                ),
                filesystem_call(ProbeId::FilesystemInodes, timeout_parent, &df_inodes(100)),
            ],
            expected_attempts: vec![
                (ProbeId::Filesystem, "probe exceeded its deadline"),
                (ProbeId::FilesystemInodes, "ok"),
            ],
            max_probes: 5,
            initial_category: "filesystem/disk-full",
            initial_status: DiagnosisStatus::Likely,
            final_category: "filesystem/disk-full",
            final_status: DiagnosisStatus::Likely,
            root_cause: Some(format!(
                "Filesystem containing {} has exhausted its inodes (mounted at /fixture).",
                timeout_path.display()
            )),
            cause: None,
            evidence: vec![(ProbeId::FilesystemInodes, "100% of inodes used")],
            hypotheses: vec![("filesystem_full", HypothesisStatus::Confirmed)],
        },
        Scenario {
            name: "truncated-full-block-report-cannot-confirm",
            execution: truncated_exec,
            mode: InvestigationMode::Direct,
            unavailable_programs: vec![],
            calls: vec![
                truncated_call(
                    ProbeId::Filesystem,
                    "df",
                    vec!["-P".into(), "--".into(), truncated_parent.to_string_lossy().into_owned()],
                    &df_blocks(100),
                ),
                filesystem_call(ProbeId::FilesystemInodes, truncated_parent, &df_inodes(99)),
            ],
            expected_attempts: vec![
                (ProbeId::Filesystem, "truncated"),
                (ProbeId::FilesystemInodes, "ok"),
            ],
            max_probes: 5,
            initial_category: "filesystem/disk-full",
            initial_status: DiagnosisStatus::Likely,
            final_category: "filesystem/disk-full",
            final_status: DiagnosisStatus::Likely,
            root_cause: None,
            cause: None,
            evidence: vec![(ProbeId::FilesystemInodes, "99% of inodes used")],
            hypotheses: vec![("filesystem_full", HypothesisStatus::Candidate)],
        },
        Scenario {
            name: "missing-stat-executable-is-not-file-absence-proof",
            execution: missing_execution,
            mode: InvestigationMode::Direct,
            unavailable_programs: vec!["stat"],
            calls: vec![],
            expected_attempts: vec![(ProbeId::Stat, "unavailable")],
            max_probes: 5,
            initial_category: "filesystem/not-found",
            initial_status: DiagnosisStatus::Likely,
            final_category: "filesystem/not-found",
            final_status: DiagnosisStatus::Likely,
            root_cause: None,
            cause: None,
            evidence: vec![],
            hypotheses: vec![("file_absent", HypothesisStatus::Candidate)],
        },
        Scenario {
            name: "successful-stat-contradicts-captured-no-such-file",
            execution: contradictory_execution,
            mode: InvestigationMode::Direct,
            unavailable_programs: vec![],
            calls: vec![stat_call(
                &contradictory_path,
                &format!(
                    "regular file|644|fixture|fixture|{}\n",
                    contradictory_path.display()
                ),
            )],
            expected_attempts: vec![(ProbeId::Stat, "ok")],
            max_probes: 5,
            initial_category: "filesystem/not-found",
            initial_status: DiagnosisStatus::Likely,
            final_category: "filesystem/not-found",
            final_status: DiagnosisStatus::Likely,
            root_cause: None,
            cause: None,
            evidence: vec![(ProbeId::Stat, "regular file, mode 644")],
            hypotheses: vec![("file_absent", HypothesisStatus::Rejected)],
        },
        Scenario {
            name: "connection-refused-container-exit-is-correlated-with-log-cause",
            execution: execution(
                "curl",
                &["http://localhost:8082".into()],
                &cwd,
                7,
                "curl: (7) Failed to connect to localhost port 8082: Connection refused",
            ),
            mode: InvestigationMode::Direct,
            unavailable_programs: vec![],
            calls: vec![
                listeners_call(""),
                docker_running_call(""),
                docker_all_call(
                    r#"{"Names":"cache-db","Ports":"0.0.0.0:8082->5432/tcp","Status":"Exited (2) 2 minutes ago"}"#,
                ),
                docker_inspect_call(
                    "cache-db",
                    r#"{"Status":"exited","ExitCode":2,"OOMKilled":false}|{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"8082"}]}|/cache-db"#,
                ),
                docker_logs_call("cache-db", "No space left on device\n"),
            ],
            expected_attempts: vec![
                (ProbeId::Listeners, "ok"),
                (ProbeId::DockerRunning, "ok"),
                (ProbeId::DockerAll, "ok"),
                (ProbeId::DockerInspect, "ok"),
                (ProbeId::DockerLogs, "ok"),
            ],
            max_probes: 5,
            initial_category: "network/connection-refused",
            initial_status: DiagnosisStatus::Likely,
            final_category: "network/connection-refused",
            final_status: DiagnosisStatus::Likely,
            root_cause: Some("Container \"cache-db\" is not running (exited 2).".into()),
            cause: Some("Container logs report no space left on device."),
            evidence: vec![
                (ProbeId::DockerAll, "cache-db exited (2)"),
                (ProbeId::DockerInspect, "published port verified"),
                (ProbeId::DockerLogs, "No space left on device"),
            ],
            hypotheses: vec![("container_exited", HypothesisStatus::Confirmed)],
        },
        Scenario {
            name: "container-root-survives-budget-cut-before-logs",
            execution: docker_run_execution(&cwd, "worker"),
            mode: InvestigationMode::Reconstructed,
            unavailable_programs: vec![],
            calls: vec![
                docker_all_call(&docker_recent_list("worker")),
                docker_inspect_call("worker", "{\"Status\":\"exited\",\"ExitCode\":137,\"OOMKilled\":true}|{}|/worker\n"),
            ],
            expected_attempts: vec![(ProbeId::DockerAll, "ok"), (ProbeId::DockerInspect, "ok")],
            max_probes: 2,
            initial_category: "unknown",
            initial_status: DiagnosisStatus::Unknown,
            final_category: "container/exited",
            final_status: DiagnosisStatus::Confirmed,
            root_cause: Some("Container \"worker\" was killed by the OOM killer.".into()),
            cause: None,
            evidence: vec![(ProbeId::DockerInspect, "OOM killed: true")],
            hypotheses: vec![("container_exited", HypothesisStatus::Confirmed)],
        },
    ];

    let case_count = scenarios.len();
    let mut attempts = 0;
    let mut timeouts = 0;
    let mut unavailable = 0;
    let mut truncated = 0;
    let mut confirmed_roots = 0;
    for scenario in scenarios {
        confirmed_roots += usize::from(scenario.root_cause.is_some());
        let (case_attempts, case_timeouts, case_unavailable, case_truncated) =
            assert_case(scenario, &cwd);
        attempts += case_attempts;
        timeouts += case_timeouts;
        unavailable += case_unavailable;
        truncated += case_truncated;
    }
    println!(
        "calibration summary: scenarios={case_count}, confirmed_roots={confirmed_roots}, probe_attempts={attempts}, timeout/unavailable/truncated={timeouts}/{unavailable}/{truncated}; fixture outcomes only, not an accuracy estimate"
    );
}
