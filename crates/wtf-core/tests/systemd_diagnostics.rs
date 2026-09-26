#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

use wtf_core::capture::{CommandExecution, ProcessExit};
use wtf_core::diagnosis::{Diagnosis, DiagnosisEngine, DiagnosisStatus};
use wtf_core::investigation::{Investigation, InvestigationEngine};
use wtf_core::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSafety, ProbeSpec};

const UNIT: &str = "api.service";
const INVOCATION: &str = "0123456789abcdef0123456789abcdef";
const COMMAND_START: u64 = 1_700_000_000;
const COMMAND_DURATION: u64 = 10;

#[derive(Clone)]
enum Reply {
    Output(ProbeOutput),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeCall {
    id: ProbeId,
    program: String,
    args: Vec<String>,
    safety: ProbeSafety,
}

#[derive(Clone)]
struct FixtureRunner {
    replies: HashMap<ProbeId, Reply>,
    available_programs: HashSet<&'static str>,
    calls: Rc<RefCell<Vec<ProbeCall>>>,
    availability_queries: Rc<RefCell<Vec<String>>>,
}

impl FixtureRunner {
    fn new(show: Reply, logs: Option<Reply>) -> Self {
        let mut replies = HashMap::from([(ProbeId::SystemdShow, show)]);
        if let Some(logs) = logs {
            replies.insert(ProbeId::SystemdLogs, logs);
        }
        Self {
            replies,
            available_programs: HashSet::from(["systemctl", "journalctl"]),
            calls: Rc::new(RefCell::new(Vec::new())),
            availability_queries: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn without_program(mut self, program: &'static str) -> Self {
        self.available_programs.remove(program);
        self
    }

    fn calls(&self) -> Vec<ProbeCall> {
        self.calls.borrow().clone()
    }

    fn availability_queries(&self) -> Vec<String> {
        self.availability_queries.borrow().clone()
    }
}

impl ProbeRunner for FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        self.calls.borrow_mut().push(ProbeCall {
            id: spec.id,
            program: spec.program.to_owned(),
            args: spec.args.clone(),
            safety: spec.safety,
        });
        match self
            .replies
            .get(&spec.id)
            .unwrap_or_else(|| panic!("unexpected unconfigured probe: {:?}", spec.id))
        {
            Reply::Output(output) => Ok(output.clone()),
            Reply::Unavailable => Err(ProbeError::Unavailable(io::Error::other(
                "fixture executable unavailable",
            ))),
        }
    }

    fn available(&self, program: &str) -> bool {
        assert!(
            matches!(program, "systemctl" | "journalctl"),
            "systemd fixture was asked about unexpected executable {program:?}"
        );
        self.availability_queries
            .borrow_mut()
            .push(program.to_owned());
        self.available_programs.contains(program)
    }
}

struct Outcome {
    diagnosis: Diagnosis,
    investigation: Investigation,
    runner: FixtureRunner,
}

fn investigate(execution: CommandExecution, runner: FixtureRunner, max_probes: usize) -> Outcome {
    let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let engine =
        InvestigationEngine::with_budget(runner.clone(), max_probes, Duration::from_secs(2));
    let investigation = engine.investigate_reconstructed(&execution, &mut diagnosis);
    Outcome {
        diagnosis,
        investigation,
        runner,
    }
}

fn execution(args: &[&str], stdout: &str, stderr: &str, duration: Duration) -> CommandExecution {
    CommandExecution {
        command: "/usr/bin/systemctl".into(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        cwd: PathBuf::from("/tmp/wtf-systemd-fixture"),
        exit_status: ProcessExit {
            code: Some(1),
            signal: None,
        },
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        duration,
        timestamp: UNIX_EPOCH + Duration::from_secs(COMMAND_START),
        spawn_error: None,
    }
}

fn output(stdout: &str) -> ProbeOutput {
    ProbeOutput {
        stdout: stdout.to_owned(),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    }
}

fn show_state(
    unit: &str,
    load: &str,
    active: &str,
    result: &str,
    invocation: Option<&str>,
) -> ProbeOutput {
    let mut stdout =
        format!("Id={unit}\nLoadState={load}\nActiveState={active}\nResult={result}\n");
    if let Some(invocation) = invocation {
        stdout.push_str(&format!("InvocationID={invocation}\n"));
    }
    output(&stdout)
}

fn failed_state(invocation: Option<&str>) -> ProbeOutput {
    show_state(UNIT, "loaded", "failed", "exit-code", invocation)
}

fn string_args(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

fn assert_show_call(call: &ProbeCall, unit: &str) {
    assert_eq!(call.id, ProbeId::SystemdShow);
    assert_eq!(call.program, "systemctl");
    assert_eq!(
        call.args,
        string_args(&[
            "show",
            "--no-pager",
            "--property=Id,LoadState,ActiveState,Result,InvocationID",
            "--",
            unit,
        ])
    );
    assert_eq!(call.safety, ProbeSafety::Safe);
}

fn expected_log_args(unit: &str, invocation: &str, duration: u64) -> Vec<String> {
    let margin = duration + 1;
    let start = COMMAND_START - margin;
    let end = COMMAND_START + margin;
    vec![
        format!("--unit={unit}"),
        format!("--since=@{start}"),
        format!("--until=@{end}"),
        "--lines=40".into(),
        "--no-pager".into(),
        "--output=cat".into(),
        "--quiet".into(),
        format!("_SYSTEMD_INVOCATION_ID={invocation}"),
    ]
}

fn assert_log_call(call: &ProbeCall, unit: &str, invocation: &str, duration: u64) {
    assert_eq!(call.id, ProbeId::SystemdLogs);
    assert_eq!(call.program, "journalctl");
    assert_eq!(call.args, expected_log_args(unit, invocation, duration));
    assert_eq!(call.safety, ProbeSafety::Safe);

    let since = call.args[1]
        .strip_prefix("--since=@")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let until = call.args[2]
        .strip_prefix("--until=@")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(since < COMMAND_START);
    assert!(until > COMMAND_START + duration);
    assert!(until - since <= 3600, "journal request exceeds one hour");
    assert!(call.args.contains(&format!("--unit={unit}")));
    assert!(call
        .args
        .contains(&format!("_SYSTEMD_INVOCATION_ID={invocation}")));
}

fn assert_read_only(outcome: &Outcome) {
    let calls = outcome.runner.calls();
    assert!(calls
        .iter()
        .all(|call| matches!(call.id, ProbeId::SystemdShow | ProbeId::SystemdLogs)));
    let mutating_verbs = [
        "start",
        "stop",
        "restart",
        "reload",
        "enable",
        "disable",
        "mask",
        "unmask",
        "kill",
        "daemon-reload",
        "reset-failed",
    ];
    for call in calls {
        assert_eq!(call.safety, ProbeSafety::Safe);
        assert!(!call
            .args
            .iter()
            .any(|arg| mutating_verbs.contains(&arg.as_str())));
    }
    assert!(outcome
        .runner
        .availability_queries()
        .iter()
        .all(|program| matches!(program.as_str(), "systemctl" | "journalctl")));
}

fn assert_attempts(outcome: &Outcome, expected: &[ProbeId]) {
    assert_eq!(
        outcome
            .investigation
            .attempts
            .iter()
            .map(|attempt| attempt.probe)
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn bare_unit_not_found_is_confirmed_from_exact_show_state_without_journal() {
    let runner = FixtureRunner::new(
        Reply::Output(show_state(
            "api.service",
            "not-found",
            "inactive",
            "success",
            None,
        )),
        Some(Reply::Output(output("No space left on device"))),
    );
    let outcome = investigate(
        execution(
            &["start", "api"],
            "",
            "",
            Duration::from_secs(COMMAND_DURATION),
        ),
        runner,
        5,
    );

    assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Confirmed);
    assert_eq!(
        outcome.diagnosis.category.as_deref(),
        Some("service/not-found")
    );
    assert!(outcome
        .investigation
        .root_cause
        .as_deref()
        .is_some_and(|root| root.contains("api.service")));
    assert_eq!(outcome.investigation.evidence.len(), 1);
    assert_eq!(
        outcome.investigation.evidence[0].probe,
        ProbeId::SystemdShow
    );
    let calls = outcome.runner.calls();
    assert_eq!(calls.len(), 1);
    assert_show_call(&calls[0], "api.service");
    assert_attempts(&outcome, &[ProbeId::SystemdShow]);
    assert_read_only(&outcome);
}

#[test]
fn failed_start_confirms_only_with_correlated_known_journal_causes() {
    for (journal_line, expected_root) in [
        ("No space left on device", "no space left on device"),
        ("bind: address already in use", "address already in use"),
    ] {
        let journal = format!("unrelated token=fixture-secret\u{1b}[31m\n{journal_line}\n");
        let runner = FixtureRunner::new(
            Reply::Output(failed_state(Some(INVOCATION))),
            Some(Reply::Output(output(&journal))),
        );
        let outcome = investigate(
            execution(
                &["start", UNIT],
                "",
                "Job for api.service failed.",
                Duration::from_secs(COMMAND_DURATION),
            ),
            runner,
            5,
        );

        assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Confirmed);
        assert_eq!(
            outcome.diagnosis.category.as_deref(),
            Some("service/failed")
        );
        let root = outcome.investigation.root_cause.as_deref().unwrap();
        assert!(root.contains(UNIT));
        assert!(root.contains(expected_root));
        let evidence = outcome
            .investigation
            .evidence
            .iter()
            .map(|item| item.observation.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(evidence.contains(UNIT));
        assert!(evidence.contains(expected_root));
        assert!(!evidence.contains("fixture-secret"));
        assert!(!evidence.contains('\u{1b}'));
        assert_eq!(
            outcome
                .investigation
                .evidence
                .iter()
                .map(|item| item.probe)
                .collect::<Vec<_>>(),
            [ProbeId::SystemdShow, ProbeId::SystemdLogs]
        );

        let calls = outcome.runner.calls();
        assert_eq!(calls.len(), 2);
        assert_show_call(&calls[0], UNIT);
        assert_log_call(&calls[1], UNIT, INVOCATION, COMMAND_DURATION);
        assert_attempts(&outcome, &[ProbeId::SystemdShow, ProbeId::SystemdLogs]);
        assert_read_only(&outcome);
    }
}

#[test]
fn captured_output_and_metadata_only_failures_use_the_same_adapter_but_output_is_not_proof() {
    let failed = failed_state(Some(INVOCATION));
    let output_case = investigate(
        execution(
            &["start", UNIT],
            "No space left on device",
            "systemctl start failed",
            Duration::from_secs(COMMAND_DURATION),
        ),
        FixtureRunner::new(
            Reply::Output(failed.clone()),
            Some(Reply::Output(output("helper exited with status 1"))),
        ),
        5,
    );
    assert_eq!(output_case.investigation.adapter, Some("systemctl"));
    assert_eq!(output_case.diagnosis.status, DiagnosisStatus::Likely);
    assert_eq!(
        output_case.diagnosis.category.as_deref(),
        Some("service/failed")
    );
    assert!(output_case.investigation.root_cause.is_none());
    assert_eq!(
        output_case
            .runner
            .calls()
            .iter()
            .map(|call| call.id)
            .collect::<Vec<_>>(),
        [ProbeId::SystemdShow, ProbeId::SystemdLogs]
    );
    assert_read_only(&output_case);

    let metadata_only = investigate(
        execution(
            &["start", UNIT],
            "",
            "",
            Duration::from_secs(COMMAND_DURATION),
        ),
        FixtureRunner::new(
            Reply::Output(show_state(UNIT, "not-found", "inactive", "success", None)),
            None,
        ),
        5,
    );
    assert_eq!(metadata_only.investigation.adapter, Some("systemctl"));
    assert_eq!(metadata_only.diagnosis.status, DiagnosisStatus::Confirmed);
    assert_eq!(
        metadata_only.diagnosis.category.as_deref(),
        Some("service/not-found")
    );
    assert!(metadata_only
        .investigation
        .root_cause
        .as_deref()
        .is_some_and(|root| root.contains(UNIT)));
    assert_read_only(&metadata_only);
}

#[test]
fn empty_and_unrecognized_journals_leave_failed_service_only_likely() {
    for journal in ["", "helper failed with EADDRINUSE"] {
        let outcome = investigate(
            execution(
                &["start", UNIT],
                "",
                "",
                Duration::from_secs(COMMAND_DURATION),
            ),
            FixtureRunner::new(
                Reply::Output(failed_state(Some(INVOCATION))),
                Some(Reply::Output(output(journal))),
            ),
            5,
        );
        assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Likely);
        assert_eq!(
            outcome.diagnosis.category.as_deref(),
            Some("service/failed")
        );
        assert!(outcome.investigation.root_cause.is_none());
        assert_eq!(outcome.runner.calls().len(), 2);
        assert_attempts(&outcome, &[ProbeId::SystemdShow, ProbeId::SystemdLogs]);
        assert_read_only(&outcome);
    }
}

#[test]
fn truncated_or_unavailable_journal_cannot_confirm_a_failed_service() {
    let mut truncated = output("No space left on device");
    truncated.truncated = true;
    for runner in [
        FixtureRunner::new(
            Reply::Output(failed_state(Some(INVOCATION))),
            Some(Reply::Output(truncated)),
        ),
        FixtureRunner::new(
            Reply::Output(failed_state(Some(INVOCATION))),
            Some(Reply::Unavailable),
        ),
        FixtureRunner::new(
            Reply::Output(failed_state(Some(INVOCATION))),
            Some(Reply::Output(output("No space left on device"))),
        )
        .without_program("journalctl"),
    ] {
        let outcome = investigate(
            execution(
                &["start", UNIT],
                "",
                "",
                Duration::from_secs(COMMAND_DURATION),
            ),
            runner,
            5,
        );
        assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Likely);
        assert_eq!(
            outcome.diagnosis.category.as_deref(),
            Some("service/failed")
        );
        assert!(outcome.investigation.root_cause.is_none());
        assert!(outcome
            .investigation
            .evidence
            .iter()
            .all(|item| item.probe == ProbeId::SystemdShow));
        assert_read_only(&outcome);
    }
}

#[test]
fn unavailable_or_truncated_show_output_cannot_trigger_journal_lookup() {
    let mut truncated = output(&format!(
        "Id={UNIT}\nLoadState=loaded\nActiveState=failed\nResult=exit-code\nInvocationID={INVOCATION}\n"
    ));
    truncated.truncated = true;
    for runner in [
        FixtureRunner::new(Reply::Unavailable, None),
        FixtureRunner::new(Reply::Output(truncated), None),
    ] {
        let outcome = investigate(
            execution(
                &["start", UNIT],
                "",
                "",
                Duration::from_secs(COMMAND_DURATION),
            ),
            runner,
            5,
        );
        assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Unknown);
        assert_eq!(outcome.investigation.root_cause, None);
        assert!(outcome
            .runner
            .calls()
            .iter()
            .all(|call| call.id == ProbeId::SystemdShow));
        assert_attempts(&outcome, &[ProbeId::SystemdShow]);
        assert_read_only(&outcome);
    }
}

#[test]
fn unavailable_systemctl_executable_is_unknown_without_any_probe_execution() {
    let outcome = investigate(
        execution(
            &["start", UNIT],
            "",
            "",
            Duration::from_secs(COMMAND_DURATION),
        ),
        FixtureRunner::new(Reply::Output(failed_state(Some(INVOCATION))), None)
            .without_program("systemctl"),
        5,
    );
    assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Unknown);
    assert!(outcome.investigation.root_cause.is_none());
    assert!(outcome.runner.calls().is_empty());
    assert_eq!(
        outcome.runner.availability_queries(),
        vec!["systemctl".to_owned()]
    );
    assert_attempts(&outcome, &[ProbeId::SystemdShow]);
    assert_read_only(&outcome);
}

#[test]
fn malformed_and_mismatched_show_fields_do_not_establish_unit_state() {
    let malformed = output(&format!(
        "Id={UNIT}\nLoadState=loaded\nActiveState=failed\nInvocationID={INVOCATION}\n"
    ));
    let duplicate_identity = output(&format!(
        "Id={UNIT}\nId=other.service\nLoadState=loaded\nActiveState=failed\nResult=exit-code\nInvocationID={INVOCATION}\n"
    ));
    let mismatched_identity = show_state(
        "other.service",
        "loaded",
        "failed",
        "exit-code",
        Some(INVOCATION),
    );
    for show in [malformed, duplicate_identity, mismatched_identity] {
        let outcome = investigate(
            execution(
                &["start", UNIT],
                "",
                "",
                Duration::from_secs(COMMAND_DURATION),
            ),
            FixtureRunner::new(Reply::Output(show), None),
            5,
        );
        assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Unknown);
        assert_eq!(outcome.diagnosis.category.as_deref(), Some("unknown"));
        assert!(outcome.investigation.root_cause.is_none());
        let calls = outcome.runner.calls();
        assert_eq!(calls.len(), 1);
        assert_show_call(&calls[0], UNIT);
        assert_attempts(&outcome, &[ProbeId::SystemdShow]);
        assert_read_only(&outcome);
    }
}

#[test]
fn exact_unit_identity_is_required_and_nonfailed_units_are_not_journalled() {
    let outcome = investigate(
        execution(
            &["start", UNIT],
            "",
            "",
            Duration::from_secs(COMMAND_DURATION),
        ),
        FixtureRunner::new(
            Reply::Output(show_state(
                UNIT,
                "loaded",
                "active",
                "success",
                Some(INVOCATION),
            )),
            Some(Reply::Output(output("address already in use"))),
        ),
        5,
    );
    assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Unknown);
    assert!(outcome.investigation.root_cause.is_none());
    let calls = outcome.runner.calls();
    assert_eq!(calls.len(), 1);
    assert_show_call(&calls[0], UNIT);
    assert_attempts(&outcome, &[ProbeId::SystemdShow]);
    assert_read_only(&outcome);
}

#[test]
fn invalid_units_and_unsupported_systemctl_arguments_never_probe() {
    let unsupported = [
        vec!["start", "api/child"],
        vec!["start", "--help"],
        vec!["start", "-api"],
        vec!["start", "café"],
        vec!["restart", UNIT],
        vec!["--user", "start", UNIT],
        vec!["--machine=remote", "start", UNIT],
        vec!["start", UNIT, "database.service"],
        vec!["start", "--", UNIT],
    ];
    for args in unsupported {
        let outcome = investigate(
            execution(&args, "", "", Duration::from_secs(COMMAND_DURATION)),
            FixtureRunner::new(
                Reply::Output(show_state(UNIT, "not-found", "inactive", "success", None)),
                None,
            ),
            5,
        );
        assert_eq!(
            outcome.diagnosis.status,
            DiagnosisStatus::Unknown,
            "args={args:?}"
        );
        assert!(outcome.investigation.root_cause.is_none(), "args={args:?}");
        assert!(outcome.runner.calls().is_empty(), "args={args:?}");
        assert!(outcome.investigation.attempts.is_empty(), "args={args:?}");
        assert_read_only(&outcome);
    }
}

#[test]
fn missing_or_malformed_invocation_ids_prevent_journal_lookup() {
    for invocation in [None, Some("not-a-32-digit-hex-id")] {
        let outcome = investigate(
            execution(
                &["start", UNIT],
                "",
                "",
                Duration::from_secs(COMMAND_DURATION),
            ),
            FixtureRunner::new(Reply::Output(failed_state(invocation)), None),
            5,
        );
        assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Likely);
        assert_eq!(
            outcome.diagnosis.category.as_deref(),
            Some("service/failed")
        );
        assert!(outcome.investigation.root_cause.is_none());
        let calls = outcome.runner.calls();
        assert_eq!(calls.len(), 1);
        assert_show_call(&calls[0], UNIT);
        assert_attempts(&outcome, &[ProbeId::SystemdShow]);
        assert_read_only(&outcome);
    }
}

#[test]
fn stale_or_overlong_command_window_cannot_be_used_for_journal_correlation() {
    let outcome = investigate(
        execution(&["start", UNIT], "", "", Duration::from_secs(30 * 60)),
        FixtureRunner::new(
            Reply::Output(failed_state(Some(INVOCATION))),
            Some(Reply::Output(output("No space left on device"))),
        ),
        5,
    );
    assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Likely);
    assert_eq!(
        outcome.diagnosis.category.as_deref(),
        Some("service/failed")
    );
    assert!(outcome.investigation.root_cause.is_none());
    let calls = outcome.runner.calls();
    assert_eq!(calls.len(), 1);
    assert_show_call(&calls[0], UNIT);
    assert_attempts(&outcome, &[ProbeId::SystemdShow]);
    assert_read_only(&outcome);
}

#[test]
fn probe_budget_stops_before_the_optional_journal_lookup() {
    let outcome = investigate(
        execution(
            &["start", UNIT],
            "",
            "",
            Duration::from_secs(COMMAND_DURATION),
        ),
        FixtureRunner::new(
            Reply::Output(failed_state(Some(INVOCATION))),
            Some(Reply::Output(output("No space left on device"))),
        ),
        1,
    );
    assert_eq!(outcome.diagnosis.status, DiagnosisStatus::Likely);
    assert_eq!(
        outcome.diagnosis.category.as_deref(),
        Some("service/failed")
    );
    assert!(outcome.investigation.root_cause.is_none());
    let calls = outcome.runner.calls();
    assert_eq!(calls.len(), 1);
    assert_show_call(&calls[0], UNIT);
    assert_attempts(&outcome, &[ProbeId::SystemdShow]);
    assert_read_only(&outcome);
}
