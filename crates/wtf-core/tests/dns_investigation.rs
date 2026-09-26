#![cfg(target_os = "linux")]

use std::cell::Cell;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use wtf_core::capture::{CommandExecution, ProcessExit};
use wtf_core::diagnosis::{DiagnosisEngine, DiagnosisStatus};
use wtf_core::investigation::{HypothesisStatus, InvestigationEngine};
use wtf_core::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSpec};

struct Resolver {
    answer: Option<ProbeOutput>,
    calls: Cell<usize>,
}

impl ProbeRunner for Resolver {
    fn available(&self, program: &str) -> bool {
        program == "getent" && self.answer.is_some()
    }

    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        assert_eq!(spec.id, ProbeId::Hosts);
        assert_eq!(spec.program, "getent");
        assert_eq!(spec.args, ["hosts", "fixture.invalid"]);
        self.calls.set(self.calls.get() + 1);
        Ok(self
            .answer
            .clone()
            .expect("available resolver has an answer"))
    }
}

impl ProbeRunner for &Resolver {
    fn available(&self, program: &str) -> bool {
        Resolver::available(self, program)
    }

    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        Resolver::run(self, spec)
    }
}

fn failure(stderr: &str) -> CommandExecution {
    CommandExecution {
        command: "curl".into(),
        args: vec!["https://fixture.invalid/resource".into()],
        cwd: PathBuf::from("/tmp"),
        exit_status: ProcessExit {
            code: Some(6),
            signal: None,
        },
        stdout: String::new(),
        stderr: stderr.into(),
        duration: Duration::from_millis(5),
        timestamp: SystemTime::UNIX_EPOCH,
        spawn_error: None,
    }
}

fn answer(stdout: &str, code: i32) -> ProbeOutput {
    ProbeOutput {
        stdout: stdout.into(),
        stderr: String::new(),
        exit_code: Some(code),
        truncated: false,
    }
}

#[test]
fn explicit_dns_failure_distinguishes_current_lookup_from_root_cause() {
    for (probe, hypothesis, observation) in [
        (answer("", 2), HypothesisStatus::Likely, "no address"),
        (
            answer("192.0.2.8 fixture.invalid\n", 0),
            HypothesisStatus::Rejected,
            "resolves locally",
        ),
    ] {
        let execution = failure("curl: (6) Could not resolve host: fixture.invalid");
        let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
        assert_eq!(diagnosis.category.as_deref(), Some("network/dns"));
        assert_eq!(diagnosis.status, DiagnosisStatus::Likely);
        let resolver = Resolver {
            answer: Some(probe),
            calls: Cell::new(0),
        };
        let report = InvestigationEngine::new(&resolver)
            .investigate_reconstructed(&execution, &mut diagnosis);
        assert_eq!(resolver.calls.get(), 1);
        assert!(report.root_cause.is_none());
        assert!(report.cause.is_none());
        assert!(report
            .evidence
            .iter()
            .any(|e| { e.probe == ProbeId::Hosts && e.observation.contains(observation) }));
        assert!(report
            .hypotheses
            .iter()
            .any(|h| { h.id == "current_resolution_failure" && h.status == hypothesis }));
        assert_eq!(diagnosis.status, DiagnosisStatus::Likely);
    }
}

#[test]
fn mismatch_and_unavailable_lookup_never_invent_dns_evidence() {
    for (stderr, available, attempted) in [
        (
            "curl: (6) Could not resolve host: other.invalid",
            true,
            false,
        ),
        (
            "curl: (6) Could not resolve host: fixture.invalid",
            false,
            true,
        ),
    ] {
        let execution = failure(stderr);
        let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
        let resolver = Resolver {
            answer: available.then(|| answer("", 2)),
            calls: Cell::new(0),
        };
        let report = InvestigationEngine::new(&resolver)
            .investigate_reconstructed(&execution, &mut diagnosis);
        assert_eq!(diagnosis.category.as_deref(), Some("network/dns"));
        assert_eq!(diagnosis.status, DiagnosisStatus::Likely);
        assert_eq!(
            report.attempts.iter().any(|a| a.probe == ProbeId::Hosts),
            attempted
        );
        assert_eq!(resolver.calls.get(), 0);
        assert!(report.evidence.is_empty());
        assert!(report.root_cause.is_none());
    }
}

#[test]
fn shell_dns_failure_uses_only_bounded_lookup_and_remains_uncertain() {
    let execution = failure("");
    let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
    assert_eq!(diagnosis.status, DiagnosisStatus::Unknown);
    let resolver = Resolver {
        answer: Some(answer("", 2)),
        calls: Cell::new(0),
    };
    let report =
        InvestigationEngine::new(&resolver).investigate_reconstructed(&execution, &mut diagnosis);
    assert_eq!(diagnosis.category.as_deref(), Some("network/dns"));
    assert_eq!(diagnosis.status, DiagnosisStatus::Likely);
    assert!(report.root_cause.is_none());
    assert!(report.evidence.iter().any(|e| e.probe == ProbeId::Hosts));
    assert_eq!(resolver.calls.get(), 1);
}
