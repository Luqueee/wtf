#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::cell::Cell;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use wtf_core::capture::{CommandExecution, ProcessExit};
use wtf_core::diagnosis::{Diagnosis, DiagnosisEngine, DiagnosisStatus};
use wtf_core::investigation::{HypothesisStatus, Investigation, InvestigationEngine};
use wtf_core::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSpec};

const SOURCE: &str = "/private/wtf-bind-source-missing";
const OTHER_SOURCE: &str = "/private/wtf-bind-source-other";
const TARGET: &str = "/app/data";
const CWD: &str = "/fixture/cwd";
const IMAGE: &str = "image:fixture";
const CONTAINER: &str = "cache-fixture";

struct ExpectedCall {
    id: ProbeId,
    program: &'static str,
    args: Vec<String>,
    output: ProbeOutput,
}

struct FixtureRunner {
    expected: Vec<ExpectedCall>,
    unavailable: HashSet<&'static str>,
    next: Cell<usize>,
}

impl FixtureRunner {
    fn new(expected: Vec<ExpectedCall>) -> Self {
        Self {
            expected,
            unavailable: HashSet::new(),
            next: Cell::new(0),
        }
    }

    fn unavailable(expected: Vec<ExpectedCall>, program: &'static str) -> Self {
        Self {
            expected,
            unavailable: HashSet::from([program]),
            next: Cell::new(0),
        }
    }

    fn assert_consumed(&self) {
        assert_eq!(
            self.next.get(),
            self.expected.len(),
            "not all scripted probe calls were consumed"
        );
    }

    fn run_one(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        let index = self.next.get();
        let expected = self
            .expected
            .get(index)
            .unwrap_or_else(|| panic!("unexpected extra probe: {:?}", spec.id));
        assert_eq!(spec.id, expected.id, "probe at call {index}");
        assert_eq!(spec.program, expected.program, "program at call {index}");
        assert_eq!(spec.args, expected.args, "argv at call {index}");
        assert_eq!(spec.cwd, PathBuf::from(CWD), "cwd at call {index}");
        self.next.set(index + 1);
        Ok(expected.output.clone())
    }
}

impl ProbeRunner for FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        self.run_one(spec)
    }

    fn available(&self, program: &str) -> bool {
        !self.unavailable.contains(program)
    }
}

impl ProbeRunner for &FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        FixtureRunner::run_one(self, spec)
    }

    fn available(&self, program: &str) -> bool {
        FixtureRunner::available(self, program)
    }
}

fn response(exit_code: Option<i32>, stdout: &str, stderr: &str, truncated: bool) -> ProbeOutput {
    ProbeOutput {
        stdout: stdout.into(),
        stderr: stderr.into(),
        exit_code,
        truncated,
    }
}

fn expected_call(
    id: ProbeId,
    program: &'static str,
    args: Vec<String>,
    output: ProbeOutput,
) -> ExpectedCall {
    ExpectedCall {
        id,
        program,
        args,
        output,
    }
}

fn stat_call(source: &str, output: ProbeOutput) -> ExpectedCall {
    #[cfg(target_os = "linux")]
    let args = vec![
        "-c".into(),
        "%F|%a|%U|%G|%n".into(),
        "--".into(),
        source.into(),
    ];
    #[cfg(target_os = "macos")]
    let args = vec![
        "-f".into(),
        "%HT|%Lp|%Su|%Sg|%N".into(),
        "--".into(),
        source.into(),
    ];
    expected_call(ProbeId::Stat, "stat", args, output)
}

fn docker_all_call(stdout: &str) -> ExpectedCall {
    expected_call(
        ProbeId::DockerAll,
        "docker",
        ["ps", "-a", "--format", "{{json .}}"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        response(Some(0), stdout, "", false),
    )
}

fn docker_execution(args: Vec<String>, stdout: &str, stderr: &str) -> CommandExecution {
    CommandExecution {
        command: "docker".into(),
        args,
        cwd: PathBuf::from(CWD),
        exit_status: ProcessExit {
            code: Some(125),
            signal: None,
        },
        stdout: stdout.into(),
        stderr: stderr.into(),
        duration: Duration::from_millis(12),
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_704_067_200),
        spawn_error: None,
    }
}

fn investigate(execution: &CommandExecution, runner: &FixtureRunner) -> (Diagnosis, Investigation) {
    let mut diagnosis = DiagnosisEngine::new().diagnose(execution);
    let report =
        InvestigationEngine::new(runner).investigate_reconstructed(execution, &mut diagnosis);
    (diagnosis, report)
}

fn requested_bind_args(name: &str) -> Vec<String> {
    [
        "run".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        "--mount".to_owned(),
        format!("type=bind,source={SOURCE},target={TARGET}"),
        IMAGE.to_owned(),
    ]
    .into()
}

fn equals_bind_args(name: &str) -> Vec<String> {
    [
        "run".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        format!("--mount=type=bind,source={SOURCE},target={TARGET}"),
        IMAGE.to_owned(),
    ]
    .into()
}

fn alias_bind_args(name: &str) -> Vec<String> {
    [
        "run".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        format!("--mount=type=bind,src={SOURCE},dst={TARGET}"),
        IMAGE.to_owned(),
    ]
    .into()
}

fn missing_source_error(source: &str) -> String {
    format!("bind source path does not exist: {source}")
}

fn assert_no_confirmed_mount(diagnosis: &Diagnosis, report: &Investigation) {
    assert!(
        report.root_cause.is_none(),
        "unexpected confirmed root cause"
    );
    assert_ne!(diagnosis.status, DiagnosisStatus::Confirmed);
    assert!(!report.hypotheses.iter().any(|hypothesis| {
        hypothesis.id == "docker_missing_bind" && hypothesis.status == HypothesisStatus::Confirmed
    }));
}

fn assert_private_paths_not_exposed(
    diagnosis: &Diagnosis,
    report: &Investigation,
    private_paths: &[&str],
) {
    for path in private_paths {
        if let Some(root) = report.root_cause.as_deref() {
            assert!(
                !root.contains(path),
                "raw source path exposed in root cause"
            );
        }
        for value in [
            report.cause.as_deref(),
            report.remedy.as_deref(),
            report.reconstruction_note.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!value.contains(path), "raw source path exposed in report");
        }
        for evidence in &report.evidence {
            assert!(
                !evidence.source.contains(path),
                "raw source path exposed in evidence"
            );
            assert!(
                !evidence.observation.contains(path),
                "raw source path exposed in evidence"
            );
        }
        for hypothesis in &report.hypotheses {
            for value in hypothesis
                .evidence_for
                .iter()
                .chain(hypothesis.evidence_against.iter())
            {
                assert!(
                    !value.contains(path),
                    "raw source path exposed in hypothesis evidence"
                );
            }
        }
        for value in &diagnosis.evidence {
            assert!(
                !value.contains(path),
                "raw source path exposed in diagnosis evidence"
            );
        }
        if let Some(detection) = &diagnosis.detection {
            for value in &detection.evidence {
                assert!(
                    !value.contains(path),
                    "raw source path exposed in detection evidence"
                );
            }
        }
    }
}

#[test]
fn missing_bind_mount_is_confirmed_by_exact_daemon_error_and_absent_stat() {
    for (name, args) in [
        (CONTAINER, requested_bind_args(CONTAINER)),
        ("equals-fixture", equals_bind_args("equals-fixture")),
        ("worker-fixture", alias_bind_args("worker-fixture")),
    ] {
        let execution = docker_execution(args, "", &missing_source_error(SOURCE));
        let runner = FixtureRunner::new(vec![stat_call(
            SOURCE,
            response(
                Some(1),
                "",
                &format!("stat: {SOURCE}: No such file or directory"),
                false,
            ),
        )]);
        let (diagnosis, report) = investigate(&execution, &runner);

        assert_eq!(diagnosis.status, DiagnosisStatus::Confirmed);
        assert_eq!(diagnosis.category.as_deref(), Some("container/mount"));
        let root = report.root_cause.as_deref().expect("confirmed mount root");
        assert!(root.contains(name), "root cause should name the container");
        assert!(
            !root.contains(SOURCE),
            "root cause must not expose the bind path"
        );
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.evidence[0].probe, ProbeId::Stat);
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.attempts[0].probe, ProbeId::Stat);
        assert_eq!(
            report
                .hypotheses
                .iter()
                .find(|hypothesis| hypothesis.id == "docker_missing_bind")
                .map(|hypothesis| hypothesis.status),
            Some(HypothesisStatus::Confirmed)
        );
        assert_private_paths_not_exposed(&diagnosis, &report, &[SOURCE]);
        runner.assert_consumed();
    }
}

#[test]
fn successful_stat_never_confirms_missing_bind_source() {
    let execution = docker_execution(
        requested_bind_args(CONTAINER),
        "",
        &missing_source_error(SOURCE),
    );
    let runner = FixtureRunner::new(vec![stat_call(
        SOURCE,
        response(
            Some(0),
            &format!("directory|755|root|root|{SOURCE}"),
            "",
            false,
        ),
    )]);
    let (diagnosis, report) = investigate(&execution, &runner);

    assert_no_confirmed_mount(&diagnosis, &report);
    assert_private_paths_not_exposed(&diagnosis, &report, &[SOURCE]);
    runner.assert_consumed();
}

#[test]
fn unavailable_truncated_or_unrelated_stat_failure_never_confirms_missing_bind() {
    let scenarios = [
        (
            "unavailable",
            FixtureRunner::unavailable(Vec::new(), "stat"),
            Some("unavailable"),
        ),
        (
            "truncated",
            FixtureRunner::new(vec![stat_call(
                SOURCE,
                response(
                    Some(1),
                    "",
                    &format!("stat: {SOURCE}: No such file or directory"),
                    true,
                ),
            )]),
            Some("truncated"),
        ),
        (
            "unrelated error",
            FixtureRunner::new(vec![stat_call(
                SOURCE,
                response(
                    Some(1),
                    "",
                    &format!("stat: {SOURCE}: Permission denied"),
                    false,
                ),
            )]),
            Some("exit 1"),
        ),
        (
            "contradictory output",
            FixtureRunner::new(vec![stat_call(
                SOURCE,
                response(
                    Some(1),
                    &format!("directory|755|root|root|{SOURCE}"),
                    &format!("stat: {SOURCE}: No such file or directory"),
                    false,
                ),
            )]),
            Some("exit 1"),
        ),
    ];

    for (label, runner, expected_result) in scenarios {
        let execution = docker_execution(
            requested_bind_args(CONTAINER),
            "",
            &missing_source_error(SOURCE),
        );
        let (diagnosis, report) = investigate(&execution, &runner);

        assert_no_confirmed_mount(&diagnosis, &report);
        assert_private_paths_not_exposed(&diagnosis, &report, &[SOURCE]);
        if let Some(expected_result) = expected_result {
            assert_eq!(
                report
                    .attempts
                    .first()
                    .map(|attempt| attempt.result.as_str()),
                Some(expected_result),
                "{label} probe result"
            );
        }
        runner.assert_consumed();
    }
}

#[test]
fn mismatched_error_and_unsupported_or_ambiguous_mounts_do_not_probe() {
    let mismatched = docker_execution(
        requested_bind_args(CONTAINER),
        "",
        &missing_source_error(OTHER_SOURCE),
    );
    let runner = FixtureRunner::new(Vec::new());
    let (diagnosis, report) = investigate(&mismatched, &runner);
    assert_no_confirmed_mount(&diagnosis, &report);
    assert_private_paths_not_exposed(&diagnosis, &report, &[SOURCE, OTHER_SOURCE]);
    assert!(report.attempts.is_empty());
    runner.assert_consumed();

    let unsupported_volume = docker_execution(
        [
            "run".to_owned(),
            "--name".to_owned(),
            CONTAINER.to_owned(),
            "--volume".to_owned(),
            format!("{SOURCE}:{TARGET}"),
            IMAGE.to_owned(),
        ]
        .into(),
        "",
        &missing_source_error(SOURCE),
    );
    let runner = FixtureRunner::new(Vec::new());
    let (diagnosis, report) = investigate(&unsupported_volume, &runner);
    assert_no_confirmed_mount(&diagnosis, &report);
    assert_private_paths_not_exposed(&diagnosis, &report, &[SOURCE]);
    assert!(report.attempts.is_empty());
    runner.assert_consumed();

    let unsupported_mount_type = docker_execution(
        [
            "run".to_owned(),
            "--name".to_owned(),
            CONTAINER.to_owned(),
            "--mount".to_owned(),
            format!("type=volume,source={SOURCE},target={TARGET}"),
            IMAGE.to_owned(),
        ]
        .into(),
        "",
        &missing_source_error(SOURCE),
    );
    let runner = FixtureRunner::new(Vec::new());
    let (diagnosis, report) = investigate(&unsupported_mount_type, &runner);
    assert_no_confirmed_mount(&diagnosis, &report);
    assert_private_paths_not_exposed(&diagnosis, &report, &[SOURCE]);
    assert!(report.attempts.is_empty());
    runner.assert_consumed();

    let ambiguous_mounts = docker_execution(
        [
            "run".to_owned(),
            "--name".to_owned(),
            CONTAINER.to_owned(),
            "--mount".to_owned(),
            format!("type=bind,source={SOURCE},target={TARGET}"),
            "--mount".to_owned(),
            format!("type=bind,source={OTHER_SOURCE},target=/app/other"),
            IMAGE.to_owned(),
        ]
        .into(),
        "",
        &missing_source_error(SOURCE),
    );
    let runner = FixtureRunner::new(Vec::new());
    let (diagnosis, report) = investigate(&ambiguous_mounts, &runner);
    assert_no_confirmed_mount(&diagnosis, &report);
    assert_private_paths_not_exposed(&diagnosis, &report, &[SOURCE, OTHER_SOURCE]);
    assert!(report.attempts.is_empty());
    runner.assert_consumed();
}

#[test]
fn metadata_only_shell_failure_cannot_confirm_precreation_mount_failure() {
    let execution = docker_execution(requested_bind_args(CONTAINER), "", "");
    let runner = FixtureRunner::new(vec![docker_all_call("")]);
    let (diagnosis, report) = investigate(&execution, &runner);

    assert_no_confirmed_mount(&diagnosis, &report);
    assert_private_paths_not_exposed(&diagnosis, &report, &[SOURCE]);
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|attempt| attempt.probe)
            .collect::<Vec<_>>(),
        [ProbeId::DockerAll]
    );
    runner.assert_consumed();
}
