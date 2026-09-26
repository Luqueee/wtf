use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use wtf_core::capture::{CommandExecution, ProcessExit};
use wtf_core::diagnosis::{Diagnosis, DiagnosisEngine, DiagnosisStatus};
use wtf_core::investigation::{
    GitReplayPoint, HypothesisStatus, Investigation, InvestigationEngine,
};
use wtf_core::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSafety, ProbeSpec};

const REPLAY_TIME_LIMIT: Duration = Duration::from_secs(2);
const OFFERED: [ProbeId; 2] = [ProbeId::GitRemote, ProbeId::GitPorcelain];
const CACHED_PROBES: [ProbeId; 5] = [
    ProbeId::GitTopLevel,
    ProbeId::GitBranch,
    ProbeId::GitUpstream,
    ProbeId::GitRemote,
    ProbeId::GitPorcelain,
];
const INITIAL_PROBES: [ProbeId; 3] = [
    ProbeId::GitTopLevel,
    ProbeId::GitBranch,
    ProbeId::GitUpstream,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FixtureCase {
    NoUpstream,
    NoRemote,
    NoCommit,
    UpstreamConfigured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OracleRoot {
    GitNoUpstream,
    NoConfirmedRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RootClassification {
    GitNoUpstream,
    OtherConfirmedRoot,
    NoConfirmedRoot,
}

#[derive(Debug, Serialize)]
struct CapturedState {
    category: &'static str,
    hypotheses: Vec<CapturedHypothesis>,
    probe_results: Vec<CapturedProbeResult>,
}

#[derive(Debug, Serialize)]
struct CapturedHypothesis {
    id: &'static str,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct CapturedProbeResult {
    id: ProbeId,
    outcome: &'static str,
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
    attempts: Vec<ProbeId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeCall {
    id: ProbeId,
    program: &'static str,
    args: Vec<String>,
    cwd: PathBuf,
    safety: ProbeSafety,
}

struct FixtureRunner {
    outputs: HashMap<ProbeId, ProbeOutput>,
    calls: Rc<RefCell<Vec<ProbeCall>>>,
}

impl FixtureRunner {
    fn new(outputs: HashMap<ProbeId, ProbeOutput>, calls: Rc<RefCell<Vec<ProbeCall>>>) -> Self {
        Self { outputs, calls }
    }
}

impl ProbeRunner for FixtureRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        self.calls.borrow_mut().push(ProbeCall {
            id: spec.id,
            program: spec.program,
            args: spec.args.clone(),
            cwd: spec.cwd.clone(),
            safety: spec.safety,
        });
        if !is_fixed_probe(spec) {
            return Err(ProbeError::Unsafe);
        }
        self.outputs
            .get(&spec.id)
            .cloned()
            .ok_or(ProbeError::Unsafe)
    }

    fn available(&self, program: &str) -> bool {
        program == "git"
    }
}

struct LocalFixture {
    _sandbox: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    path: OsString,
    outputs: HashMap<ProbeId, ProbeOutput>,
    oracle: OracleFacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OracleFacts {
    has_remote_config: bool,
    has_commit: bool,
    has_upstream_config: bool,
}

impl OracleFacts {
    fn root(self) -> OracleRoot {
        if self.has_remote_config && self.has_commit && !self.has_upstream_config {
            OracleRoot::GitNoUpstream
        } else {
            OracleRoot::NoConfirmedRoot
        }
    }
}

pub fn run() -> Result<ExitCode, String> {
    let summaries = replay_matrix()?;
    let output = serde_json::to_string_pretty(&summaries)
        .map_err(|_| "could not serialize the Git replay summary".to_owned())?;
    println!("{output}");
    Ok(ExitCode::SUCCESS)
}

fn replay_matrix() -> Result<Vec<ReplaySummary>, String> {
    let mut summaries = Vec::with_capacity(12);
    for case in [
        FixtureCase::NoUpstream,
        FixtureCase::NoRemote,
        FixtureCase::NoCommit,
    ] {
        let fixture = prepare_fixture(case)?;
        let oracle = fixture.oracle.root();
        for budget in [4, 5] {
            for first in OFFERED {
                let summary = replay_one(case, budget, first, &fixture, oracle)?;
                let should_confirm = case == FixtureCase::NoUpstream && budget == 5;
                let should_be_correct = case != FixtureCase::NoUpstream || budget == 5;
                if (summary.root_classification == RootClassification::GitNoUpstream)
                    != should_confirm
                    || summary.correct != should_be_correct
                {
                    return Err(format!(
                        "{case:?} with budget {budget} and first {first:?} had an unexpected root classification"
                    ));
                }
                summaries.push(summary);
            }
        }
    }

    let configured = prepare_fixture(FixtureCase::UpstreamConfigured)?;
    if !configured.oracle.has_upstream_config {
        return Err("UpstreamConfigured fixture lacks its local upstream config key".into());
    }
    let calls = Rc::new(RefCell::new(Vec::new()));
    let runner = FixtureRunner::new(configured.outputs.clone(), Rc::clone(&calls));
    let engine = InvestigationEngine::with_budget(runner, 5, REPLAY_TIME_LIMIT);
    let execution = synthetic_push_failure(&configured.repo);
    let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
    if engine
        .replay_git_first(&execution, &mut diagnosis, ProbeId::GitRemote)
        .is_some()
    {
        return Err("UpstreamConfigured fixture unexpectedly reached the replay point".into());
    }
    let initial_calls = calls
        .borrow()
        .iter()
        .map(|call| call.id)
        .collect::<Vec<_>>();
    if initial_calls.as_slice() != INITIAL_PROBES.as_slice() {
        return Err("UpstreamConfigured fixture ran probes after its configured upstream".into());
    }

    Ok(summaries)
}

fn prepare_fixture(case: FixtureCase) -> Result<LocalFixture, String> {
    let sandbox =
        tempfile::tempdir().map_err(|_| "could not create a local Git fixture".to_owned())?;
    let repo = sandbox.path().join("repo");
    let remote = sandbox.path().join("remote.git");
    let home = sandbox.path().join("home");
    std::fs::create_dir(&repo).map_err(|_| "could not create a local Git repository".to_owned())?;
    std::fs::create_dir(&home).map_err(|_| "could not create a local Git home".to_owned())?;
    let path = std::env::var_os("PATH").ok_or_else(|| "Git is not available".to_owned())?;
    let fixture = LocalFixture {
        _sandbox: sandbox,
        repo,
        home,
        path,
        outputs: HashMap::new(),
        oracle: OracleFacts {
            has_remote_config: false,
            has_commit: false,
            has_upstream_config: false,
        },
    };
    initialize_repository(&fixture, &remote, case)?;
    let oracle = check_oracle_facts(&fixture)?;
    let expected = expected_facts(case);
    if oracle != expected {
        return Err(format!(
            "{case:?}: local Git fixture did not match its independent oracle"
        ));
    }
    let outputs = capture_probe_outputs(&fixture)?;
    Ok(LocalFixture {
        outputs,
        oracle,
        ..fixture
    })
}

fn initialize_repository(
    fixture: &LocalFixture,
    remote: &Path,
    case: FixtureCase,
) -> Result<(), String> {
    run_git_success(
        fixture,
        &fixture.repo,
        &["init", "--quiet"],
        "could not initialize the fixture repository",
    )?;
    run_git_success(
        fixture,
        &fixture.repo,
        &["symbolic-ref", "HEAD", "refs/heads/fixture-branch"],
        "could not select the fixture branch",
    )?;
    run_git_success(
        fixture,
        &fixture.repo,
        &["config", "--local", "user.name", "Fixture"],
        "could not configure the fixture identity",
    )?;
    run_git_success(
        fixture,
        &fixture.repo,
        &["config", "--local", "user.email", "fixture@example.invalid"],
        "could not configure the fixture identity",
    )?;

    if matches!(
        case,
        FixtureCase::NoUpstream | FixtureCase::NoCommit | FixtureCase::UpstreamConfigured
    ) {
        let remote_path = remote.to_string_lossy().into_owned();
        run_git_args_success(
            fixture,
            sandbox_root(&fixture.repo),
            &[
                "init".into(),
                "--bare".into(),
                "--quiet".into(),
                remote_path,
            ],
            "could not create the local fixture remote",
        )?;
        run_git_args_success(
            fixture,
            &fixture.repo,
            &[
                "remote".into(),
                "add".into(),
                "fixture-remote".into(),
                remote.to_string_lossy().into_owned(),
            ],
            "could not configure the local fixture remote",
        )?;
    }

    if matches!(
        case,
        FixtureCase::NoUpstream | FixtureCase::NoRemote | FixtureCase::UpstreamConfigured
    ) {
        std::fs::write(fixture.repo.join("fixture.txt"), "local fixture\n")
            .map_err(|_| "could not create the local fixture commit".to_owned())?;
        run_git_success(
            fixture,
            &fixture.repo,
            &["add", "--", "fixture.txt"],
            "could not stage the local fixture commit",
        )?;
        run_git_success(
            fixture,
            &fixture.repo,
            &["commit", "--quiet", "--message", "fixture commit"],
            "could not create the local fixture commit",
        )?;
    }

    if case == FixtureCase::UpstreamConfigured {
        run_git_success(
            fixture,
            &fixture.repo,
            &[
                "config",
                "--local",
                "branch.fixture-branch.remote",
                "fixture-remote",
            ],
            "could not configure the local fixture upstream",
        )?;
        run_git_success(
            fixture,
            &fixture.repo,
            &[
                "config",
                "--local",
                "branch.fixture-branch.merge",
                "refs/heads/fixture-branch",
            ],
            "could not configure the local fixture upstream",
        )?;
        run_git_success(
            fixture,
            &fixture.repo,
            &[
                "update-ref",
                "refs/remotes/fixture-remote/fixture-branch",
                "HEAD",
            ],
            "could not prepare the local upstream reference",
        )?;
    }
    Ok(())
}

fn sandbox_root(repo: &Path) -> &Path {
    repo.parent()
        .expect("the fixture repository has a sandbox parent")
}

fn expected_facts(case: FixtureCase) -> OracleFacts {
    match case {
        FixtureCase::NoUpstream => OracleFacts {
            has_remote_config: true,
            has_commit: true,
            has_upstream_config: false,
        },
        FixtureCase::NoRemote => OracleFacts {
            has_remote_config: false,
            has_commit: true,
            has_upstream_config: false,
        },
        FixtureCase::NoCommit => OracleFacts {
            has_remote_config: true,
            has_commit: false,
            has_upstream_config: false,
        },
        FixtureCase::UpstreamConfigured => OracleFacts {
            has_remote_config: true,
            has_commit: true,
            has_upstream_config: true,
        },
    }
}

fn check_oracle_facts(fixture: &LocalFixture) -> Result<OracleFacts, String> {
    let has_remote_config = config_key_present(
        fixture,
        &fixture.repo,
        "^remote\\..*\\.url$",
        "remote.fixture-remote.url",
    )?;
    let has_upstream_remote = config_key_present(
        fixture,
        &fixture.repo,
        "^branch\\.fixture-branch\\.remote$",
        "branch.fixture-branch.remote",
    )?;
    let has_upstream_merge = config_key_present(
        fixture,
        &fixture.repo,
        "^branch\\.fixture-branch\\.merge$",
        "branch.fixture-branch.merge",
    )?;
    let has_upstream_config = has_upstream_remote && has_upstream_merge;
    let commit = run_git(
        fixture,
        &fixture.repo,
        &["rev-parse", "--verify", "HEAD^{commit}"],
    )?;
    Ok(OracleFacts {
        has_remote_config,
        has_commit: commit.status.success(),
        has_upstream_config,
    })
}

fn config_key_present(
    fixture: &LocalFixture,
    cwd: &Path,
    pattern: &str,
    expected_key: &str,
) -> Result<bool, String> {
    let output = run_git(
        fixture,
        cwd,
        &["config", "--local", "--name-only", "--get-regexp", pattern],
    )?;
    match output.status.code() {
        Some(0) => {
            let keys: Vec<_> = output
                .stdout
                .split(|byte| *byte == b'\n')
                .filter(|key| !key.is_empty())
                .collect();
            if keys.iter().any(|key| *key != expected_key.as_bytes()) {
                return Err("local Git config oracle returned an unexpected key".into());
            }
            Ok(keys.contains(&expected_key.as_bytes()))
        }
        Some(1) => Ok(false),
        _ => Err("could not inspect local Git config keys".into()),
    }
}

fn capture_probe_outputs(fixture: &LocalFixture) -> Result<HashMap<ProbeId, ProbeOutput>, String> {
    let mut outputs = HashMap::with_capacity(CACHED_PROBES.len());
    for id in CACHED_PROBES {
        let spec = fixed_probe_spec(id, &fixture.repo)?;
        let output = run_probe(fixture, &spec)?;
        if id == ProbeId::GitRemote {
            let names_only = output.stdout.lines().all(|name| {
                !name.is_empty()
                    && !name.contains('/')
                    && !name.contains('\\')
                    && !name.contains(':')
                    && !name.chars().any(char::is_whitespace)
            });
            if !output.ok() || !names_only {
                return Err("Git remote fixture probe did not return names only".into());
            }
        }
        outputs.insert(id, output);
    }
    Ok(outputs)
}

fn fixed_probe_spec(id: ProbeId, cwd: &Path) -> Result<ProbeSpec, String> {
    let spec = ProbeSpec::new(id, cwd, None)
        .ok_or_else(|| "core did not construct a fixed Git probe".to_owned())?;
    if spec.cwd != cwd || !is_fixed_probe(&spec) {
        return Err("core constructed an unexpected Git fixture probe".into());
    }
    Ok(spec)
}

fn is_fixed_probe(spec: &ProbeSpec) -> bool {
    if spec.program != "git" || spec.safety != ProbeSafety::Safe {
        return false;
    }
    let expected: &[&str] = match spec.id {
        ProbeId::GitTopLevel => &["rev-parse", "--show-toplevel"],
        ProbeId::GitBranch => &["branch", "--show-current"],
        ProbeId::GitUpstream => &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        ProbeId::GitRemote => &["remote"],
        ProbeId::GitPorcelain => &["status", "--porcelain=v2", "--branch"],
        _ => return false,
    };
    spec.args
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

fn run_probe(fixture: &LocalFixture, spec: &ProbeSpec) -> Result<ProbeOutput, String> {
    let output = Command::new(spec.program)
        .args(&spec.args)
        .current_dir(&spec.cwd)
        .env_clear()
        .env("PATH", &fixture.path)
        .env("HOME", &fixture.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|_| "could not capture a fixed local Git probe".to_owned())?;
    Ok(probe_output(output))
}

fn run_git_success(
    fixture: &LocalFixture,
    cwd: &Path,
    args: &[&str],
    error: &'static str,
) -> Result<(), String> {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    run_git_args_success(fixture, cwd, &args, error)
}

fn run_git_args_success(
    fixture: &LocalFixture,
    cwd: &Path,
    args: &[String],
    error: &'static str,
) -> Result<(), String> {
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let output = run_git(fixture, cwd, &args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(error.to_owned())
    }
}

fn run_git(fixture: &LocalFixture, cwd: &Path, args: &[&str]) -> Result<Output, String> {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", &fixture.path)
        .env("HOME", &fixture.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|_| "could not run a local Git fixture command".to_owned())
}

fn probe_output(output: Output) -> ProbeOutput {
    ProbeOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code(),
        truncated: false,
    }
}

fn replay_one(
    case: FixtureCase,
    budget: usize,
    first: ProbeId,
    fixture: &LocalFixture,
    oracle_root: OracleRoot,
) -> Result<ReplaySummary, String> {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let runner = FixtureRunner::new(fixture.outputs.clone(), Rc::clone(&calls));
    let engine = InvestigationEngine::with_budget(runner, budget, REPLAY_TIME_LIMIT);
    let execution = synthetic_push_failure(&fixture.repo);
    let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
    let replay = engine
        .replay_git_first(&execution, &mut diagnosis, first)
        .ok_or_else(|| format!("{case:?}: core did not expose the Git replay point"))?;
    check_point(case, &replay.point, first)?;
    let calls = calls.borrow().clone();
    check_probe_calls(case, budget, first, &fixture.repo, &calls)?;

    let root_classification = classify_root(&diagnosis, &replay.investigation);
    let correct = root_classification == oracle_root.into();
    let attempts = calls.iter().map(|call| call.id).collect();
    Ok(ReplaySummary {
        case,
        budget,
        first,
        state: CapturedState {
            category: "unknown",
            hypotheses: Vec::new(),
            probe_results: replay
                .point
                .prior
                .iter()
                .map(|prior| CapturedProbeResult {
                    id: prior.probe,
                    outcome: prior.outcome,
                })
                .collect(),
        },
        offered: replay.point.offered,
        root_classification,
        oracle_root,
        correct,
        attempts,
    })
}

impl From<OracleRoot> for RootClassification {
    fn from(value: OracleRoot) -> Self {
        match value {
            OracleRoot::GitNoUpstream => RootClassification::GitNoUpstream,
            OracleRoot::NoConfirmedRoot => RootClassification::NoConfirmedRoot,
        }
    }
}

fn check_point(case: FixtureCase, point: &GitReplayPoint, first: ProbeId) -> Result<(), String> {
    if point.offered != OFFERED || !point.offered.contains(&first) {
        return Err(format!(
            "{case:?}: core offered an unexpected Git replay point"
        ));
    }
    let expected_prior = [
        (ProbeId::GitTopLevel, "available"),
        (ProbeId::GitBranch, "available"),
        (ProbeId::GitUpstream, "failed"),
    ];
    if point.prior.len() != expected_prior.len()
        || point
            .prior
            .iter()
            .zip(expected_prior)
            .any(|(actual, expected)| actual.probe != expected.0 || actual.outcome != expected.1)
    {
        return Err(format!(
            "{case:?}: core reported unexpected Git prior outcomes"
        ));
    }
    Ok(())
}

fn check_probe_calls(
    case: FixtureCase,
    budget: usize,
    first: ProbeId,
    cwd: &Path,
    calls: &[ProbeCall],
) -> Result<(), String> {
    let second = OFFERED.into_iter().find(|probe| *probe != first).unwrap();
    let mut expected = INITIAL_PROBES.to_vec();
    expected.push(first);
    if budget == 5 {
        expected.push(second);
    }
    if calls.len() != expected.len()
        || calls
            .iter()
            .map(|call| call.id)
            .ne(expected.iter().copied())
    {
        return Err(format!(
            "{case:?}: replay used an unexpected probe count or order"
        ));
    }
    for call in calls {
        let spec = ProbeSpec {
            id: call.id,
            description: "fixture probe",
            program: call.program,
            args: call.args.clone(),
            cwd: call.cwd.clone(),
            timeout: Duration::from_secs(1),
            safety: call.safety,
            evidence_kind: "fixture",
            useful_for: &[],
        };
        if call.cwd != cwd || !is_fixed_probe(&spec) {
            return Err(format!(
                "{case:?}: replay constructed an unexpected Git probe"
            ));
        }
    }
    Ok(())
}

fn classify_root(diagnosis: &Diagnosis, investigation: &Investigation) -> RootClassification {
    if diagnosis.status != DiagnosisStatus::Confirmed {
        return RootClassification::NoConfirmedRoot;
    }
    if diagnosis.category.as_deref() == Some("git/upstream")
        && investigation.root_cause.is_some()
        && investigation.hypotheses.iter().any(|hypothesis| {
            hypothesis.id == "git_no_upstream" && hypothesis.status == HypothesisStatus::Confirmed
        })
    {
        RootClassification::GitNoUpstream
    } else {
        RootClassification::OtherConfirmedRoot
    }
}

fn synthetic_push_failure(cwd: &Path) -> CommandExecution {
    CommandExecution {
        command: "git".into(),
        args: vec!["push".into()],
        cwd: cwd.to_path_buf(),
        exit_status: ProcessExit {
            code: Some(1),
            signal: None,
        },
        stdout: String::new(),
        stderr: String::new(),
        duration: Duration::from_millis(1),
        timestamp: SystemTime::UNIX_EPOCH,
        spawn_error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_replay_matrix_checks_budget_order_and_independent_local_oracles() {
        let summaries = replay_matrix().unwrap();
        assert_eq!(summaries.len(), 12);
        for case in [
            FixtureCase::NoUpstream,
            FixtureCase::NoRemote,
            FixtureCase::NoCommit,
        ] {
            for budget in [4, 5] {
                let rows: Vec<_> = summaries
                    .iter()
                    .filter(|summary| summary.case == case && summary.budget == budget)
                    .collect();
                assert_eq!(rows.len(), 2);
                assert!(rows
                    .iter()
                    .any(|summary| summary.first == ProbeId::GitRemote));
                assert!(rows
                    .iter()
                    .any(|summary| summary.first == ProbeId::GitPorcelain));
                assert_eq!(rows[0].root_classification, rows[1].root_classification);
                let should_be_correct = case != FixtureCase::NoUpstream || budget == 5;
                assert!(rows
                    .iter()
                    .all(|summary| summary.correct == should_be_correct));
                assert_eq!(
                    rows.iter()
                        .all(|summary| summary.root_classification
                            == RootClassification::GitNoUpstream),
                    case == FixtureCase::NoUpstream && budget == 5
                );
            }
        }
        for summary in summaries.iter().filter(|summary| summary.budget == 4) {
            assert_ne!(
                summary.root_classification,
                RootClassification::GitNoUpstream
            );
        }
    }

    #[test]
    fn summary_is_model_state_and_payload_free_replay_metadata_only() {
        let summaries = replay_matrix().unwrap();
        let output = serde_json::to_value(&summaries).unwrap();
        let rows = output.as_array().unwrap();
        assert_eq!(rows.len(), 12);
        let expected_fields = [
            "case",
            "budget",
            "first",
            "state",
            "offered",
            "root_classification",
            "oracle_root",
            "correct",
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
            assert_eq!(row["offered"], serde_json::json!(OFFERED));
            assert_eq!(
                row["attempts"].as_array().unwrap().len(),
                row["budget"].as_u64().unwrap() as usize
            );

            let state = row["state"].as_object().unwrap();
            let state_fields = state
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(state_fields, expected_state_fields);
            assert_eq!(state["category"], "unknown");
            assert_eq!(state["hypotheses"], serde_json::json!([]));
            assert_eq!(
                state["probe_results"],
                serde_json::json!([
                    {"id":"GitTopLevel","outcome":"available"},
                    {"id":"GitBranch","outcome":"available"},
                    {"id":"GitUpstream","outcome":"failed"}
                ])
            );
        }
        let rendered = output.to_string();
        assert!(!rendered.contains("stdout"));
        assert!(!rendered.contains("stderr"));
        assert!(!rendered.contains("root_cause"));
        assert!(!rendered.contains("fixture-branch"));
        assert!(!rendered.contains("fixture-remote"));
        assert!(!rendered.contains("remote.git"));
        assert!(!rendered.contains("example.invalid"));
        let fixture = prepare_fixture(FixtureCase::NoUpstream).unwrap();
        let repo_path = fixture.repo.to_string_lossy().into_owned();
        let remote_path = fixture
            ._sandbox
            .path()
            .join("remote.git")
            .to_string_lossy()
            .into_owned();
        let row = replay_one(
            FixtureCase::NoUpstream,
            5,
            ProbeId::GitRemote,
            &fixture,
            fixture.oracle.root(),
        )
        .unwrap();
        let rendered = serde_json::to_string(&row).unwrap();
        assert!(!rendered.contains(repo_path.as_str()));
        assert!(!rendered.contains(remote_path.as_str()));
        assert!(!rendered.contains("fixture-branch"));
        assert!(!rendered.contains("fixture-remote"));
    }

    #[test]
    fn configured_upstream_does_not_expose_a_replay_point() {
        let fixture = prepare_fixture(FixtureCase::UpstreamConfigured).unwrap();
        assert_eq!(
            fixture.oracle,
            expected_facts(FixtureCase::UpstreamConfigured)
        );
        let calls = Rc::new(RefCell::new(Vec::new()));
        let runner = FixtureRunner::new(fixture.outputs.clone(), Rc::clone(&calls));
        let engine = InvestigationEngine::with_budget(runner, 5, REPLAY_TIME_LIMIT);
        let execution = synthetic_push_failure(&fixture.repo);
        let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
        assert!(engine
            .replay_git_first(&execution, &mut diagnosis, ProbeId::GitRemote)
            .is_none());
        let called = calls
            .borrow()
            .iter()
            .map(|call| call.id)
            .collect::<Vec<_>>();
        assert_eq!(called.as_slice(), INITIAL_PROBES.as_slice());
    }
}
