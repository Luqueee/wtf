#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::cell::Cell;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use wtf_core::capture::{CommandExecution, ProcessExit};
use wtf_core::diagnosis::{Diagnosis, DiagnosisEngine, DiagnosisStatus};
use wtf_core::investigation::{Investigation, InvestigationEngine};
use wtf_core::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSafety, ProbeSpec};

const CWD: &str = "/fixture/cwd";
const IMAGE: &str = "image:fixture";
const PORT: u16 = 8080;

struct ExpectedCall {
    id: ProbeId,
    program: &'static str,
    args: Vec<String>,
    outcome: ProbeOutcome,
}

enum ProbeOutcome {
    Output(ProbeOutput),
    Unavailable,
}

struct FixtureRunner {
    expected: Vec<ExpectedCall>,
    next: Cell<usize>,
}

impl FixtureRunner {
    fn new(expected: Vec<ExpectedCall>) -> Self {
        Self {
            expected,
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
        assert_eq!(spec.safety, ProbeSafety::Safe, "safety at call {index}");
        self.next.set(index + 1);
        match &expected.outcome {
            ProbeOutcome::Output(output) => Ok(output.clone()),
            ProbeOutcome::Unavailable => Err(ProbeError::Unavailable(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "fixture probe unavailable",
            ))),
        }
    }
}

impl ProbeRunner for FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        self.run_one(spec)
    }

    fn available(&self, _program: &str) -> bool {
        true
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
    outcome: ProbeOutcome,
) -> ExpectedCall {
    ExpectedCall {
        id,
        program,
        args,
        outcome,
    }
}

fn words(args: &[&str]) -> Vec<String> {
    args.iter().map(|word| (*word).to_owned()).collect()
}

fn docker_running_call(outcome: ProbeOutcome) -> ExpectedCall {
    expected_call(
        ProbeId::DockerRunning,
        "docker",
        words(&["ps", "--format", "{{json .}}"]),
        outcome,
    )
}

fn docker_all_call(stdout: &str) -> ExpectedCall {
    expected_call(
        ProbeId::DockerAll,
        "docker",
        words(&["ps", "-a", "--format", "{{json .}}"]),
        ProbeOutcome::Output(response(Some(0), stdout, "", false)),
    )
}

fn running_row(name: &str, ports: &str, status: &str) -> String {
    running_row_at(
        name,
        ports,
        status,
        "2026-09-25 05:57:00 +0000 UTC",
        "3 minutes",
    )
}

fn running_row_at(
    name: &str,
    ports: &str,
    status: &str,
    created_at: &str,
    running_for: &str,
) -> String {
    format!(
        r#"{{"ID":"fixture-id","Image":"fixture","Command":"entrypoint","CreatedAt":"{created_at}","RunningFor":"{running_for}","Ports":"{ports}","Names":"{name}","Status":"{status}"}}"#
    )
}

fn docker_execution(args: Vec<String>, stderr: &str) -> CommandExecution {
    CommandExecution {
        command: "docker".into(),
        args,
        cwd: PathBuf::from(CWD),
        exit_status: ProcessExit {
            code: Some(125),
            signal: None,
        },
        stdout: String::new(),
        stderr: stderr.into(),
        duration: Duration::from_millis(12),
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_316_000),
        spawn_error: None,
    }
}
fn docker_execution_with_exit(args: Vec<String>, stderr: &str, exit_code: i32) -> CommandExecution {
    let mut execution = docker_execution(args, stderr);
    execution.exit_status.code = Some(exit_code);
    execution
}

fn investigate(execution: &CommandExecution, runner: &FixtureRunner) -> (Diagnosis, Investigation) {
    let mut diagnosis = DiagnosisEngine::new().diagnose(execution);
    let report =
        InvestigationEngine::new(runner).investigate_reconstructed(execution, &mut diagnosis);
    (diagnosis, report)
}

fn bind_error(address_port: &str) -> String {
    format!(
        "Error response from daemon: driver failed programming external connectivity on endpoint fixture-attempt (id): Bind for {address_port} failed: port is already allocated"
    )
}

fn assert_unconfirmed(label: &str, diagnosis: &Diagnosis, report: &Investigation) {
    assert_eq!(diagnosis.status, DiagnosisStatus::Unknown, "{label}");
    assert_ne!(
        diagnosis.category.as_deref(),
        Some("container/port-conflict"),
        "{label}"
    );
    assert!(
        report.root_cause.is_none(),
        "{label}: unexpected root cause: {:?}",
        report.root_cause
    );
}

fn assert_attempts(report: &Investigation, expected: &[ProbeId]) {
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|attempt| attempt.probe)
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn one_explicit_tcp_publish_and_exact_daemon_bind_error_confirm_running_owner() {
    let cases = [
        (
            words(&["run", "-p", "8080:80", IMAGE]),
            bind_error("0.0.0.0:8080"),
            "0.0.0.0:8080->80/tcp",
            "wildcard-owner",
        ),
        (
            words(&["run", "--publish=8080:80", IMAGE]),
            "Error response from daemon: failed to bind host port for 0.0.0.0:8080: listen tcp 0.0.0.0:8080: bind: address already in use".into(),
            "0.0.0.0:8080->80/tcp",
            "equals-owner",
        ),
        (
            words(&["run", "--publish", "127.0.0.1:8080:80", IMAGE]),
            bind_error("127.0.0.1:8080"),
            "127.0.0.1:8080->80/tcp",
            "loopback-owner",
        ),
    ];

    for (args, stderr, ports, owner) in cases {
        let execution = docker_execution(args, &stderr);
        let runner = FixtureRunner::new(vec![docker_running_call(ProbeOutcome::Output(response(
            Some(0),
            &format!("{}\n", running_row(owner, ports, "Up 3 minutes")),
            "",
            false,
        )))]);
        let (diagnosis, report) = investigate(&execution, &runner);

        assert_eq!(diagnosis.status, DiagnosisStatus::Confirmed);
        assert_eq!(
            diagnosis.category.as_deref(),
            Some("container/port-conflict")
        );
        let root = report.root_cause.as_deref().expect("confirmed port owner");
        assert!(
            root.contains(&PORT.to_string()),
            "root must name host port: {root}"
        );
        assert!(
            root.contains(owner),
            "root must name exact container owner: {root}"
        );
        assert!(report
            .evidence
            .iter()
            .any(|evidence| evidence.probe == ProbeId::DockerRunning));
        assert_attempts(&report, &[ProbeId::DockerRunning]);
        let synthesized_evidence = report
            .evidence
            .iter()
            .map(|evidence| evidence.observation.as_str())
            .chain(diagnosis.evidence.iter().map(String::as_str))
            .collect::<Vec<_>>();
        assert!(
            synthesized_evidence
                .iter()
                .all(|evidence| !evidence.contains(stderr.as_str())
                    && !evidence.contains("Error response from daemon:")
                    && !evidence.contains("failed to bind host port")),
            "daemon stderr must not be copied into evidence"
        );
        runner.assert_consumed();
    }
}

#[test]
fn daemon_error_host_or_port_must_match_the_single_published_mapping() {
    let cases = [
        (
            words(&["run", "-p", "8080:80", IMAGE]),
            bind_error("0.0.0.0:8081"),
        ),
        (
            words(&["run", "-p", "8080:80", IMAGE]),
            bind_error("127.0.0.1:8080"),
        ),
        (
            words(&["run", "-p", "127.0.0.1:8080:80", IMAGE]),
            bind_error("0.0.0.0:8080"),
        ),
    ];

    for (args, stderr) in cases {
        let execution = docker_execution(args, &stderr);
        let runner = FixtureRunner::new(Vec::new());
        let (diagnosis, report) = investigate(&execution, &runner);

        assert_unconfirmed("mismatched daemon address or port", &diagnosis, &report);
        assert!(
            report.attempts.is_empty(),
            "mismatched stderr must not trigger probes"
        );
        runner.assert_consumed();
    }
}

#[test]
fn daemon_bind_error_from_non_docker_failure_exit_code_does_not_probe_or_confirm() {
    let execution = docker_execution_with_exit(
        words(&["run", "-p", "8080:80", IMAGE]),
        &bind_error("0.0.0.0:8080"),
        1,
    );
    let runner = FixtureRunner::new(Vec::new());
    let (diagnosis, report) = investigate(&execution, &runner);

    assert_unconfirmed("non-125 exit status", &diagnosis, &report);
    assert!(report.attempts.is_empty());
    runner.assert_consumed();
}

#[test]
fn unmatched_ambiguous_invalid_and_contradictory_running_rows_are_not_confirmed() {
    let mut truncated_json = running_row("malformed-owner", "0.0.0.0:8080->80/tcp", "Up 3 minutes");
    truncated_json.pop();
    let cases = [
        (
            "unmatched host port",
            words(&["run", "-p", "8080:80", IMAGE]),
            "0.0.0.0:8080",
            format!(
                "{}\n",
                running_row("other-port", "0.0.0.0:8081->80/tcp", "Up 3 minutes")
            ),
        ),
        (
            "unmatched host address",
            words(&["run", "-p", "127.0.0.1:8080:80", IMAGE]),
            "127.0.0.1:8080",
            format!(
                "{}\n",
                running_row("other-address", "127.0.0.2:8080->80/tcp", "Up 3 minutes")
            ),
        ),
        (
            "ambiguous owners",
            words(&["run", "-p", "8080:80", IMAGE]),
            "0.0.0.0:8080",
            format!(
                "{}\n{}\n",
                running_row("first-owner", "0.0.0.0:8080->80/tcp", "Up 3 minutes"),
                running_row("second-owner", "0.0.0.0:8080->81/tcp", "Up 4 minutes")
            ),
        ),
        (
            "malformed JSON",
            words(&["run", "-p", "8080:80", IMAGE]),
            "0.0.0.0:8080",
            "not-json\n".into(),
        ),
        (
            "truncated JSON row",
            words(&["run", "-p", "8080:80", IMAGE]),
            "0.0.0.0:8080",
            format!("{truncated_json}\n"),
        ),
        (
            "invalid row fields",
            words(&["run", "-p", "8080:80", IMAGE]),
            "0.0.0.0:8080",
            r#"{"Names":42,"Ports":["0.0.0.0:8080->80/tcp"],"Status":"Up 3 minutes"}"#.into(),
        ),
        (
            "invalid port binding",
            words(&["run", "-p", "8080:80", IMAGE]),
            "0.0.0.0:8080",
            format!(
                "{}\n",
                running_row("invalid-binding", "0.0.0.0:8080->80", "Up 3 minutes")
            ),
        ),
        (
            "contradictory stopped status",
            words(&["run", "-p", "8080:80", IMAGE]),
            "0.0.0.0:8080",
            format!(
                "{}\n",
                running_row(
                    "stopped-owner",
                    "0.0.0.0:8080->80/tcp",
                    "Exited (1) 2 minutes ago"
                )
            ),
        ),
        (
            "container created after captured failure",
            words(&["run", "-p", "8080:80", IMAGE]),
            "0.0.0.0:8080",
            format!(
                "{}\n",
                running_row_at(
                    "new-owner",
                    "0.0.0.0:8080->80/tcp",
                    "Up 1 minute",
                    "2026-09-25 06:01:00 +0000 UTC",
                    "1 minute"
                )
            ),
        ),
    ];

    for (label, args, address_port, stdout) in cases {
        let execution = docker_execution(args, &bind_error(address_port));
        let runner = FixtureRunner::new(vec![docker_running_call(ProbeOutcome::Output(response(
            Some(0),
            &stdout,
            "",
            false,
        )))]);
        let (diagnosis, report) = investigate(&execution, &runner);

        assert_unconfirmed(label, &diagnosis, &report);
        assert_attempts(&report, &[ProbeId::DockerRunning]);
        runner.assert_consumed();
    }
}

#[test]
fn unavailable_truncated_and_failed_running_probe_outputs_are_not_confirmed() {
    let owner = running_row("probe-owner", "0.0.0.0:8080->80/tcp", "Up 3 minutes");
    let cases = [
        ("unavailable", ProbeOutcome::Unavailable),
        (
            "truncated",
            ProbeOutcome::Output(response(Some(0), &format!("{owner}\n"), "", true)),
        ),
        (
            "failed command with matching-looking stdout",
            ProbeOutcome::Output(response(
                Some(1),
                &format!("{owner}\n"),
                "permission denied",
                false,
            )),
        ),
    ];

    for (label, outcome) in cases {
        let execution = docker_execution(
            words(&["run", "-p", "8080:80", IMAGE]),
            &bind_error("0.0.0.0:8080"),
        );
        let runner = FixtureRunner::new(vec![docker_running_call(outcome)]);
        let (diagnosis, report) = investigate(&execution, &runner);

        assert_unconfirmed(label, &diagnosis, &report);
        assert_attempts(&report, &[ProbeId::DockerRunning]);
        runner.assert_consumed();
    }
}

#[test]
fn unsupported_or_ambiguous_publish_forms_do_not_probe_or_confirm() {
    let cases = [
        ("UDP publish", words(&["run", "-p", "8080:80/udp", IMAGE])),
        ("port range", words(&["run", "-p", "8080-8081:80", IMAGE])),
        (
            "multiple mappings",
            words(&["run", "-p", "8080:80", "-p", "8081:81", IMAGE]),
        ),
        ("publish all", words(&["run", "-P", IMAGE])),
        (
            "host network with publish",
            words(&["run", "--network", "host", "-p", "8080:80", IMAGE]),
        ),
        (
            "IPv6 publish",
            words(&["run", "-p", "[::1]:8080:80", IMAGE]),
        ),
    ];

    for (label, args) in cases {
        let execution = docker_execution(args, &bind_error("0.0.0.0:8080"));
        let runner = FixtureRunner::new(Vec::new());
        let (diagnosis, report) = investigate(&execution, &runner);

        assert_unconfirmed(label, &diagnosis, &report);
        assert!(
            report.attempts.is_empty(),
            "unsupported mapping must not trigger probes"
        );
        runner.assert_consumed();
    }
}

#[test]
fn metadata_only_shell_failure_cannot_confirm_a_port_owner() {
    let execution = docker_execution(
        words(&[
            "run",
            "--name",
            "attempted-container",
            "--publish=8080:80",
            IMAGE,
        ]),
        "",
    );
    let running_owner = format!(
        "{}\n",
        running_row(
            "unverified-port-owner",
            "0.0.0.0:8080->80/tcp",
            "Up 3 minutes"
        )
    );
    let runner = FixtureRunner::new(vec![docker_all_call(&running_owner)]);
    let (diagnosis, report) = investigate(&execution, &runner);

    assert_unconfirmed("metadata-only shell failure", &diagnosis, &report);
    assert_attempts(&report, &[ProbeId::DockerAll]);
    runner.assert_consumed();
}
