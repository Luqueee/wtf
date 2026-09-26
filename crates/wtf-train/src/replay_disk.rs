use std::cell::RefCell;
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use wtf_core::capture::{CommandExecution, ProcessExit};
use wtf_core::diagnosis::{Diagnosis, DiagnosisEngine};
use wtf_core::investigation::{
    DiskReplayPoint, HypothesisStatus, Investigation, InvestigationEngine,
};
use wtf_core::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSafety, ProbeSpec};

const REPLAY_TIME_LIMIT: Duration = Duration::from_secs(2);
const OFFERED: [ProbeId; 2] = [ProbeId::Filesystem, ProbeId::FilesystemInodes];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FixtureCase {
    BlockFull,
    InodeFull,
    BelowFull,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OracleRoot {
    BlockCapacity,
    InodeCapacity,
    NoConfirmedRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RootClassification {
    BlockCapacity,
    InodeCapacity,
    NoConfirmedRoot,
    Unconfirmed,
    Unclassifiable,
}

#[derive(Debug, Serialize)]
struct CapturedHypothesis {
    id: &'static str,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct CapturedState {
    category: &'static str,
    hypotheses: [CapturedHypothesis; 1],
    probe_results: [(); 0],
}

#[derive(Debug, Serialize)]
struct ReplaySummary {
    case: FixtureCase,
    budget: usize,
    first: ProbeId,
    state: CapturedState,
    offered: [ProbeId; 2],
    root_classification: RootClassification,
    oracle_root: OracleRoot,
    correct: bool,
    oracle_check_passed: bool,
    attempt_count: usize,
    attempts: Vec<ProbeId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeRecord {
    id: ProbeId,
    program: &'static str,
    args: Vec<String>,
    cwd: std::path::PathBuf,
    safety: ProbeSafety,
}

struct FixtureRunner {
    case: FixtureCase,
    records: Rc<RefCell<Vec<ProbeRecord>>>,
}

impl FixtureRunner {
    fn new(case: FixtureCase, records: Rc<RefCell<Vec<ProbeRecord>>>) -> Self {
        Self { case, records }
    }
}

impl ProbeRunner for FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        self.records.borrow_mut().push(ProbeRecord {
            id: spec.id,
            program: spec.program,
            args: spec.args.clone(),
            cwd: spec.cwd.clone(),
            safety: spec.safety,
        });

        if self.case == FixtureCase::Timeout && spec.id == ProbeId::Filesystem {
            return Err(ProbeError::Timeout);
        }

        let percent = match (self.case, spec.id) {
            (FixtureCase::BlockFull, ProbeId::Filesystem) => 100,
            (FixtureCase::InodeFull, ProbeId::FilesystemInodes)
            | (FixtureCase::Timeout, ProbeId::FilesystemInodes) => 100,
            (_, ProbeId::Filesystem | ProbeId::FilesystemInodes) => 40,
            _ => return Err(ProbeError::Unsafe),
        };
        Ok(df_output(spec.id, percent))
    }

    fn available(&self, program: &str) -> bool {
        program == "df"
    }
}

fn df_output(probe: ProbeId, percent: u16) -> ProbeOutput {
    let used = u64::from(percent) * 10;
    let (header, values) = match probe {
        ProbeId::Filesystem => (
            "Filesystem 1024-blocks Used Available Capacity Mounted on",
            format!("fixture 1000 {used} {} {percent}% /fixture", 1000 - used),
        ),
        ProbeId::FilesystemInodes => (
            "Filesystem Inodes IUsed IFree IUse% Mounted on",
            format!("fixture 1000 {used} {} {percent}% /fixture", 1000 - used),
        ),
        _ => unreachable!("only the offered disk probes have fixture output"),
    };
    ProbeOutput {
        stdout: format!("{header}\n{values}\n"),
        stderr: String::new(),
        exit_code: Some(0),
        truncated: false,
    }
}

pub fn run() -> Result<ExitCode, String> {
    let summaries = replay_matrix()?;
    let output = serde_json::to_string_pretty(&summaries)
        .map_err(|_| "could not serialize the disk replay summary".to_owned())?;
    println!("{output}");
    Ok(ExitCode::SUCCESS)
}

fn replay_matrix() -> Result<Vec<ReplaySummary>, String> {
    let mut summaries = Vec::with_capacity(16);
    for case in [
        FixtureCase::BlockFull,
        FixtureCase::InodeFull,
        FixtureCase::BelowFull,
        FixtureCase::Timeout,
    ] {
        let sandbox =
            tempfile::tempdir().map_err(|_| "could not create a replay sandbox".to_owned())?;
        let target = sandbox.path().join("output.bin");
        std::fs::File::create(&target)
            .map_err(|_| "could not create a synthetic disk target".to_owned())?;
        let execution = synthetic_failure(sandbox.path(), &target);
        let diagnosis = DiagnosisEngine::new().diagnose(&execution);
        if diagnosis.category.as_deref() != Some("filesystem/disk-full")
            || diagnosis.entities.primary_path() != Some(&target)
        {
            return Err(format!(
                "{case:?}: synthetic failure did not diagnose as disk-full at its target"
            ));
        }

        for budget in [1, 5] {
            for first in OFFERED {
                summaries.push(replay_one(
                    case,
                    budget,
                    first,
                    sandbox.path(),
                    &target,
                    &execution,
                    &diagnosis,
                )?);
            }
        }
    }
    Ok(summaries)
}

fn synthetic_failure(cwd: &Path, target: &Path) -> CommandExecution {
    let target = target.to_string_lossy().into_owned();
    CommandExecution {
        command: "cp".to_owned(),
        args: vec!["fixture-source".to_owned(), target.clone()],
        cwd: cwd.to_path_buf(),
        exit_status: ProcessExit {
            code: Some(1),
            signal: None,
        },
        stdout: String::new(),
        stderr: format!("cp: error writing '{target}': No space left on device"),
        duration: Duration::from_millis(1),
        timestamp: SystemTime::UNIX_EPOCH,
        spawn_error: None,
    }
}

fn replay_one(
    case: FixtureCase,
    budget: usize,
    first: ProbeId,
    cwd: &Path,
    target: &Path,
    execution: &CommandExecution,
    diagnosis: &Diagnosis,
) -> Result<ReplaySummary, String> {
    let records = Rc::new(RefCell::new(Vec::new()));
    let runner = FixtureRunner::new(case, Rc::clone(&records));
    let engine = InvestigationEngine::with_budget(runner, budget, REPLAY_TIME_LIMIT);
    let point = engine
        .disk_replay_point(execution, diagnosis)
        .ok_or_else(|| format!("{case:?}: core did not offer a disk replay point"))?;
    check_point(case, &point, first)?;
    if !records.borrow().is_empty() {
        return Err(format!("{case:?}: capturing the replay point ran a probe"));
    }

    let investigation = engine
        .replay_disk_first(execution, diagnosis, first)
        .ok_or_else(|| format!("{case:?}: core rejected an offered first probe"))?;
    let calls = records.borrow().clone();
    check_probe_calls(case, budget, first, cwd, target, &calls, &investigation)?;

    let root_classification = classify_root(&investigation);
    let oracle_root = oracle_for(case);
    let correct = matches_oracle(root_classification, oracle_root);
    // A one-probe budget may legitimately leave the root unresolved.
    let oracle_check_passed =
        correct || (budget == 1 && root_classification == RootClassification::Unconfirmed);
    if !oracle_check_passed {
        return Err(format!(
            "{case:?} with budget {budget} and first {first:?} reported {root_classification:?}, expected {oracle_root:?}"
        ));
    }

    Ok(ReplaySummary {
        case,
        budget,
        first,
        state: CapturedState {
            category: point.category,
            hypotheses: [CapturedHypothesis {
                id: point.hypothesis_id,
                status: "candidate",
            }],
            probe_results: [],
        },
        offered: point.offered,
        root_classification,
        oracle_root,
        correct,
        oracle_check_passed,
        attempt_count: investigation.attempts.len(),
        attempts: investigation
            .attempts
            .iter()
            .map(|attempt| attempt.probe)
            .collect(),
    })
}

fn check_point(case: FixtureCase, point: &DiskReplayPoint, first: ProbeId) -> Result<(), String> {
    if point.category != "filesystem/disk-full"
        || point.hypothesis_id != "filesystem_full"
        || point.offered != OFFERED
        || !point.offered.contains(&first)
    {
        return Err(format!(
            "{case:?}: core offered an unexpected disk replay point"
        ));
    }
    Ok(())
}

fn check_probe_calls(
    case: FixtureCase,
    budget: usize,
    first: ProbeId,
    cwd: &Path,
    target: &Path,
    calls: &[ProbeRecord],
    investigation: &Investigation,
) -> Result<(), String> {
    let attempts: Vec<_> = investigation
        .attempts
        .iter()
        .map(|attempt| attempt.probe)
        .collect();
    if attempts.first() != Some(&first)
        || attempts.len() != expected_attempt_count(case, budget, first)
        || attempts.len() != calls.len()
        || attempts != calls.iter().map(|call| call.id).collect::<Vec<_>>()
        || attempts.iter().any(|probe| !OFFERED.contains(probe))
        || attempts.get(1).is_some_and(|probe| *probe == first)
    {
        return Err(format!(
            "{case:?}: core attempted an unexpected probe count or order"
        ));
    }

    let target = target.to_string_lossy();
    for call in calls {
        let expected_flag = match call.id {
            ProbeId::Filesystem => "-P",
            ProbeId::FilesystemInodes => "-Pi",
            _ => return Err(format!("{case:?}: core attempted a non-disk probe")),
        };
        if call.program != "df"
            || call.args.len() != 3
            || call.args[0] != expected_flag
            || call.args[1] != "--"
            || call.args[2] != target.as_ref()
            || call.cwd != cwd
            || call.safety != ProbeSafety::Safe
        {
            return Err(format!(
                "{case:?}: core constructed an unexpected filesystem probe"
            ));
        }
    }
    Ok(())
}

fn expected_attempt_count(case: FixtureCase, budget: usize, first: ProbeId) -> usize {
    if budget == 1 {
        return 1;
    }
    match (case, first) {
        (FixtureCase::BlockFull, ProbeId::Filesystem)
        | (FixtureCase::InodeFull, ProbeId::FilesystemInodes)
        | (FixtureCase::Timeout, ProbeId::FilesystemInodes) => 1,
        _ => 2,
    }
}

fn classify_root(investigation: &Investigation) -> RootClassification {
    let Some(hypothesis) = investigation
        .hypotheses
        .iter()
        .find(|hypothesis| hypothesis.id == "filesystem_full")
    else {
        return RootClassification::Unclassifiable;
    };
    match hypothesis.status {
        HypothesisStatus::Confirmed => {
            let full = |probe| {
                investigation.evidence.iter().any(|evidence| {
                    evidence.probe == probe
                        && percentage(&evidence.observation).is_some_and(|value| value >= 100)
                })
            };
            match (full(ProbeId::Filesystem), full(ProbeId::FilesystemInodes)) {
                (true, false) => RootClassification::BlockCapacity,
                (false, true) => RootClassification::InodeCapacity,
                _ => RootClassification::Unclassifiable,
            }
        }
        HypothesisStatus::Rejected => RootClassification::NoConfirmedRoot,
        HypothesisStatus::Candidate | HypothesisStatus::Likely => RootClassification::Unconfirmed,
    }
}

fn percentage(observation: &str) -> Option<u16> {
    observation
        .split_whitespace()
        .find_map(|field| field.strip_suffix('%')?.parse().ok())
}

fn oracle_for(case: FixtureCase) -> OracleRoot {
    match case {
        FixtureCase::BlockFull => OracleRoot::BlockCapacity,
        FixtureCase::InodeFull | FixtureCase::Timeout => OracleRoot::InodeCapacity,
        FixtureCase::BelowFull => OracleRoot::NoConfirmedRoot,
    }
}

fn matches_oracle(root: RootClassification, oracle: OracleRoot) -> bool {
    matches!(
        (root, oracle),
        (RootClassification::BlockCapacity, OracleRoot::BlockCapacity)
            | (RootClassification::InodeCapacity, OracleRoot::InodeCapacity)
            | (
                RootClassification::NoConfirmedRoot,
                OracleRoot::NoConfirmedRoot
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_replay_matrix_matches_independent_oracles_in_both_orders() {
        let summaries = replay_matrix().unwrap();
        assert_eq!(summaries.len(), 16);

        for case in [
            FixtureCase::BlockFull,
            FixtureCase::InodeFull,
            FixtureCase::Timeout,
        ] {
            let full_budget: Vec<_> = summaries
                .iter()
                .filter(|summary| summary.case == case && summary.budget == 5)
                .collect();
            assert_eq!(full_budget.len(), 2);
            assert!(full_budget
                .iter()
                .any(|summary| summary.first == ProbeId::Filesystem));
            assert!(full_budget
                .iter()
                .any(|summary| summary.first == ProbeId::FilesystemInodes));
            assert!(full_budget.iter().all(|summary| summary.correct));
            assert!(full_budget
                .iter()
                .all(|summary| summary.oracle_check_passed));
            assert_eq!(
                full_budget[0].root_classification,
                full_budget[1].root_classification
            );
        }
        let below_full: Vec<_> = summaries
            .iter()
            .filter(|summary| summary.case == FixtureCase::BelowFull && summary.budget == 5)
            .collect();
        assert_eq!(below_full.len(), 2);
        assert!(below_full.iter().all(|summary| {
            summary.root_classification == RootClassification::NoConfirmedRoot && summary.correct
        }));

        let timeout_one: Vec<_> = summaries
            .iter()
            .filter(|summary| summary.case == FixtureCase::Timeout && summary.budget == 1)
            .collect();
        assert_eq!(timeout_one.len(), 2);
        assert!(timeout_one.iter().any(|summary| {
            summary.first == ProbeId::Filesystem
                && summary.root_classification == RootClassification::Unconfirmed
                && !summary.correct
                && summary.oracle_check_passed
        }));
        assert!(timeout_one.iter().any(|summary| {
            summary.first == ProbeId::FilesystemInodes
                && summary.root_classification == RootClassification::InodeCapacity
                && summary.correct
        }));
        for summary in summaries.iter().filter(|summary| summary.budget == 1) {
            assert!(summary.oracle_check_passed);
            assert_eq!(summary.attempt_count, 1);
            assert_eq!(summary.attempts.first(), Some(&summary.first));
        }
        assert!(summaries.iter().any(|summary| {
            summary.case == FixtureCase::BlockFull
                && summary.budget == 1
                && summary.root_classification == RootClassification::Unconfirmed
                && !summary.correct
                && summary.oracle_check_passed
        }));
    }

    #[test]
    fn summary_contains_only_payload_free_state_offers_and_outcomes() {
        let summaries = replay_matrix().unwrap();
        let output = serde_json::to_value(&summaries).unwrap();
        let rows = output.as_array().unwrap();
        assert_eq!(rows.len(), 16);

        let expected_fields = [
            "case",
            "budget",
            "first",
            "state",
            "offered",
            "root_classification",
            "oracle_root",
            "correct",
            "oracle_check_passed",
            "attempt_count",
            "attempts",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        let expected_state_fields = ["category", "hypotheses", "probe_results"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        for row in rows {
            let fields = row
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(fields, expected_fields);

            let state = row["state"].as_object().unwrap();
            let state_fields = state
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(state_fields, expected_state_fields);
            assert_eq!(
                state.get("category").and_then(|value| value.as_str()),
                Some("filesystem/disk-full")
            );
            assert_eq!(
                state.get("hypotheses"),
                Some(&serde_json::json!([{"id":"filesystem_full","status":"candidate"}]))
            );
            assert_eq!(state.get("probe_results"), Some(&serde_json::json!([])));
            assert_eq!(row["offered"], serde_json::json!(OFFERED));
        }
        assert!(!output.to_string().contains("cwd"));
        assert!(!output.to_string().contains("stdout"));
        assert!(!output.to_string().contains("stderr"));
        assert!(!output.to_string().contains("root_cause"));
    }
}
