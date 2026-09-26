use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod linux {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::time::Duration;

    use serde::Serialize;
    use wtf_core::investigation::{
        HypothesisStatus, InvestigationEngine, UnixSocketObservation as CoreObservation,
    };
    use wtf_core::probes::{
        LocalProbeRunner, ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSafety, ProbeSpec,
    };

    const REPLAY_TIME_LIMIT: Duration = Duration::from_secs(2);
    const OFFERED: [ProbeId; 2] = [ProbeId::Stat, ProbeId::UnixListeners];

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum FixtureCase {
        Active,
        Residual,
        Absent,
        ChangedDuringCapture,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum Observation {
        ListenerAndSocket,
        SocketWithoutListener,
        Neither,
        Inconsistent,
        Unknown,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum ProbeStatus {
        Succeeded,
        Failed,
        Truncated,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum RootClassification {
        NoConfirmedRoot,
    }

    #[derive(Debug, Serialize)]
    struct CapturedAttempt {
        probe: ProbeId,
        status: ProbeStatus,
    }

    #[derive(Debug, Serialize)]
    struct ReplaySummary {
        case: FixtureCase,
        budget: usize,
        first: ProbeId,
        experimental: bool,
        eligible_for_training: bool,
        runtime_offer_under_spec_7: bool,
        interpretation_scope: &'static str,
        experimental_probe_pair: [ProbeId; 2],
        observation: Observation,
        oracle_state: Observation,
        root_classification: RootClassification,
        attempt_count: usize,
        attempts: Vec<CapturedAttempt>,
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
        target: PathBuf,
        target_arg: String,
        cwd: PathBuf,
        calls: Rc<RefCell<Vec<ProbeCall>>>,
    }

    impl FixtureRunner {
        fn new(
            outputs: HashMap<ProbeId, ProbeOutput>,
            target: &Path,
            cwd: &Path,
            calls: Rc<RefCell<Vec<ProbeCall>>>,
        ) -> Result<Self, String> {
            let target_arg = target
                .to_str()
                .ok_or_else(|| "fixture socket path is not valid UTF-8".to_owned())?
                .to_owned();
            Ok(Self {
                outputs,
                target: target.to_path_buf(),
                target_arg,
                cwd: cwd.to_path_buf(),
                calls,
            })
        }

        fn matches_fixed_spec(&self, spec: &ProbeSpec) -> bool {
            if !OFFERED.contains(&spec.id) {
                return false;
            }
            let Some(expected) = ProbeSpec::new(spec.id, &self.cwd, Some(self.target_arg.as_str()))
            else {
                return false;
            };
            expected.id == spec.id
                && expected.program == spec.program
                && expected.args == spec.args
                && expected.cwd == spec.cwd
                && expected.safety == spec.safety
                && spec.cwd == self.cwd
                && spec.safety == ProbeSafety::Safe
                && spec.args.iter().any(|arg| arg == &self.target_arg)
                && self.target.is_absolute()
        }
    }

    impl ProbeRunner for FixtureRunner {
        fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
            if !self.matches_fixed_spec(spec) {
                return Err(ProbeError::Unsafe);
            }
            self.calls.borrow_mut().push(ProbeCall {
                id: spec.id,
                program: spec.program,
                args: spec.args.clone(),
                cwd: spec.cwd.clone(),
                safety: spec.safety,
            });
            self.outputs
                .get(&spec.id)
                .cloned()
                .ok_or(ProbeError::Unsafe)
        }

        fn available(&self, program: &str) -> bool {
            OFFERED.iter().any(|id| {
                self.outputs.contains_key(id)
                    && ProbeSpec::new(*id, &self.cwd, Some(self.target_arg.as_str()))
                        .is_some_and(|spec| spec.program == program)
            })
        }
    }

    struct LocalFixture {
        _sandbox: tempfile::TempDir,
        cwd: PathBuf,
        target: PathBuf,
        outputs: HashMap<ProbeId, ProbeOutput>,
        _listener: Option<UnixListener>,
        oracle_state: Observation,
    }

    pub(super) fn run() -> Result<std::process::ExitCode, String> {
        let summaries = replay_matrix()?;
        let output = serde_json::to_string_pretty(&summaries)
            .map_err(|_| "could not serialize the Unix socket replay summary".to_owned())?;
        println!("{output}");
        Ok(std::process::ExitCode::SUCCESS)
    }

    fn replay_matrix() -> Result<Vec<ReplaySummary>, String> {
        let mut summaries = Vec::with_capacity(16);
        for case in [
            FixtureCase::Active,
            FixtureCase::Residual,
            FixtureCase::Absent,
            FixtureCase::ChangedDuringCapture,
        ] {
            let fixture = prepare_fixture(case)?;
            for budget in [1, 2] {
                for first in OFFERED {
                    let summary = replay_one(case, budget, first, &fixture)?;
                    let expected = expected_observation(case, budget);
                    if summary.observation != expected
                        || summary.oracle_state != oracle_for_case(case)
                        || summary.root_classification != RootClassification::NoConfirmedRoot
                        || summary.attempt_count != budget
                    {
                        return Err(format!(
                            "{case:?} replay did not match the current-state fixture contract"
                        ));
                    }
                    summaries.push(summary);
                }
            }
        }
        if summaries.len() != 16
            || summaries.iter().any(|summary| {
                !summary.experimental
                    || summary.eligible_for_training
                    || summary.runtime_offer_under_spec_7
                    || summary.interpretation_scope != "current_observations_not_historical_cause"
            })
        {
            return Err("Unix socket replay matrix failed its experimental-scope checks".into());
        }
        Ok(summaries)
    }

    fn prepare_fixture(case: FixtureCase) -> Result<LocalFixture, String> {
        let sandbox = tempfile::Builder::new()
            .prefix("PRIVATE_SOCKET_PATH_")
            .tempdir()
            .map_err(|_| "could not create a local Unix socket replay sandbox".to_owned())?;
        let cwd = std::fs::canonicalize(sandbox.path())
            .map_err(|_| "could not resolve the local Unix socket replay sandbox".to_owned())?;
        let target = cwd.join("s");
        let target_bytes = target.as_os_str().as_bytes();
        if !target.is_absolute()
            || target_bytes.len() > 107
            || target_bytes.contains(&0)
            || target_bytes.contains(&b'\n')
            || target_bytes.contains(&b'\r')
        {
            return Err(
                "local Unix socket fixture path does not meet the safe pathname bounds".into(),
            );
        }

        let mut listener = match case {
            FixtureCase::Active => Some(bind_listener(&target)?),
            FixtureCase::Residual => {
                drop(bind_listener(&target)?);
                None
            }
            FixtureCase::Absent | FixtureCase::ChangedDuringCapture => None,
        };

        let local_runner = LocalProbeRunner;
        let mut outputs = HashMap::with_capacity(2);
        let stat = capture_fixed_probe(&local_runner, ProbeId::Stat, &cwd, &target)?;
        outputs.insert(ProbeId::Stat, stat);

        if case == FixtureCase::ChangedDuringCapture {
            listener = Some(bind_listener(&target)?);
        }

        let unix_listeners =
            capture_fixed_probe(&local_runner, ProbeId::UnixListeners, &cwd, &target)?;
        outputs.insert(ProbeId::UnixListeners, unix_listeners);

        let oracle_state = oracle_state(listener.as_ref(), &target)?;
        let expected_oracle = oracle_for_case(case);
        if oracle_state != expected_oracle {
            return Err(format!(
                "{case:?} local fixture did not match its independent current-state oracle"
            ));
        }

        Ok(LocalFixture {
            _sandbox: sandbox,
            cwd,
            target,
            outputs,
            _listener: listener,
            oracle_state,
        })
    }

    fn bind_listener(target: &Path) -> Result<UnixListener, String> {
        UnixListener::bind(target)
            .map_err(|_| "could not prepare a local Unix socket fixture".to_owned())
    }

    fn capture_fixed_probe(
        runner: &LocalProbeRunner,
        id: ProbeId,
        cwd: &Path,
        target: &Path,
    ) -> Result<ProbeOutput, String> {
        let target_arg = target
            .to_str()
            .ok_or_else(|| "fixture socket path is not valid UTF-8".to_owned())?;
        let spec = ProbeSpec::new(id, cwd, Some(target_arg))
            .ok_or_else(|| "fixed Unix socket probe is unavailable on this platform".to_owned())?;
        if spec.safety != ProbeSafety::Safe {
            return Err("fixed Unix socket probe is not marked safe".into());
        }
        if !runner.available(spec.program) {
            return Err("a required local Unix socket probe command is unavailable".into());
        }
        runner
            .run(&spec)
            .map_err(|_| "could not capture a bounded local Unix socket probe result".to_owned())
    }

    fn oracle_state(listener: Option<&UnixListener>, target: &Path) -> Result<Observation, String> {
        let has_listener = listener.is_some();
        let has_socket = match std::fs::symlink_metadata(target) {
            Ok(metadata) => metadata.file_type().is_socket(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err("could not inspect the local socket fixture state".into()),
        };
        Ok(match (has_listener, has_socket) {
            (true, true) => Observation::ListenerAndSocket,
            (false, true) => Observation::SocketWithoutListener,
            (false, false) => Observation::Neither,
            (true, false) => Observation::Inconsistent,
        })
    }

    fn oracle_for_case(case: FixtureCase) -> Observation {
        match case {
            FixtureCase::Active | FixtureCase::ChangedDuringCapture => {
                Observation::ListenerAndSocket
            }
            FixtureCase::Residual => Observation::SocketWithoutListener,
            FixtureCase::Absent => Observation::Neither,
        }
    }

    fn expected_observation(case: FixtureCase, budget: usize) -> Observation {
        if budget < 2 {
            return Observation::Unknown;
        }
        match case {
            FixtureCase::Active => Observation::ListenerAndSocket,
            FixtureCase::Residual => Observation::SocketWithoutListener,
            FixtureCase::Absent => Observation::Neither,
            FixtureCase::ChangedDuringCapture => Observation::Inconsistent,
        }
    }

    fn replay_one(
        case: FixtureCase,
        budget: usize,
        first: ProbeId,
        fixture: &LocalFixture,
    ) -> Result<ReplaySummary, String> {
        let calls = Rc::new(RefCell::new(Vec::with_capacity(budget)));
        let runner = FixtureRunner::new(
            fixture.outputs.clone(),
            &fixture.target,
            &fixture.cwd,
            Rc::clone(&calls),
        )?;
        let engine = InvestigationEngine::with_budget(runner, budget, REPLAY_TIME_LIMIT);
        let result = engine
            .replay_unix_socket_first(&fixture.cwd, &fixture.target, first)
            .ok_or_else(|| format!("{case:?} fixture was not eligible for Unix socket replay"))?;

        if result.offered != OFFERED
            || result.investigation.root_cause.is_some()
            || result.investigation.remedy.is_some()
            || result
                .investigation
                .hypotheses
                .iter()
                .any(|hypothesis| hypothesis.status == HypothesisStatus::Confirmed)
        {
            return Err(format!(
                "{case:?} replay produced a root, remedy, confirmed hypothesis, or altered offer"
            ));
        }

        let observation = from_core_observation(result.observation);
        let probe_calls = calls.borrow();
        let attempts = result
            .investigation
            .attempts
            .iter()
            .map(|attempt| {
                let output = fixture.outputs.get(&attempt.probe).ok_or_else(|| {
                    "Unix socket replay attempted a probe without a captured safe output".to_owned()
                })?;
                Ok(CapturedAttempt {
                    probe: attempt.probe,
                    status: probe_status(output),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        if attempts.len() != budget
            || probe_calls.len() != attempts.len()
            || probe_calls
                .iter()
                .zip(&attempts)
                .any(|(call, attempt)| call.id != attempt.probe)
        {
            return Err(format!(
                "{case:?} replay did not use the expected bounded cached probe attempts"
            ));
        }

        Ok(ReplaySummary {
            case,
            budget,
            first,
            experimental: true,
            eligible_for_training: false,
            runtime_offer_under_spec_7: false,
            interpretation_scope: "current_observations_not_historical_cause",
            experimental_probe_pair: result.offered,
            observation,
            oracle_state: fixture.oracle_state,
            root_classification: RootClassification::NoConfirmedRoot,
            attempt_count: attempts.len(),
            attempts,
        })
    }

    fn from_core_observation(observation: CoreObservation) -> Observation {
        match observation {
            CoreObservation::ListenerAndSocket => Observation::ListenerAndSocket,
            CoreObservation::SocketWithoutListener => Observation::SocketWithoutListener,
            CoreObservation::Neither => Observation::Neither,
            CoreObservation::Inconsistent => Observation::Inconsistent,
            CoreObservation::Unknown => Observation::Unknown,
        }
    }

    fn probe_status(output: &ProbeOutput) -> ProbeStatus {
        if output.truncated {
            ProbeStatus::Truncated
        } else if output.exit_code == Some(0) {
            ProbeStatus::Succeeded
        } else {
            ProbeStatus::Failed
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn replays_all_sixteen_current_state_trajectories_without_training_labels() {
            let summaries = replay_matrix().expect("Unix socket fixture matrix should replay");
            assert_eq!(summaries.len(), 16);

            for case in [
                FixtureCase::Active,
                FixtureCase::Residual,
                FixtureCase::Absent,
                FixtureCase::ChangedDuringCapture,
            ] {
                for budget in [1, 2] {
                    let pair: Vec<_> = summaries
                        .iter()
                        .filter(|summary| summary.case == case && summary.budget == budget)
                        .collect();
                    assert_eq!(pair.len(), 2);
                    assert_ne!(pair[0].first, pair[1].first);
                    assert!(pair.iter().all(|summary| {
                        summary.observation == expected_observation(case, budget)
                            && summary.root_classification == RootClassification::NoConfirmedRoot
                            && !summary.eligible_for_training
                            && summary.experimental
                            && !summary.runtime_offer_under_spec_7
                    }));
                    assert_eq!(pair[0].observation, pair[1].observation);
                    assert_eq!(pair[0].attempt_count, budget);
                    assert_eq!(pair[1].attempt_count, budget);
                }
            }
        }

        #[test]
        fn serialized_replay_never_contains_fixture_paths_or_probe_output() {
            let summaries = replay_matrix().expect("Unix socket fixture matrix should replay");
            let serialized = serde_json::to_string(&summaries).unwrap();
            assert!(!serialized.contains("PRIVATE_SOCKET_PATH_"));
            assert!(!serialized.contains("No such file or directory"));
            assert!(!serialized.contains("/tmp/"));
            assert!(serialized.contains("\"eligible_for_training\":false"));
            assert!(serialized.contains("\"experimental\":true"));
            assert!(serialized.contains("current_observations_not_historical_cause"));
        }

        #[test]
        fn cached_replay_calls_only_exact_safe_catalog_commands() {
            let fixture = prepare_fixture(FixtureCase::ChangedDuringCapture).unwrap();
            for first in OFFERED {
                let calls = Rc::new(RefCell::new(Vec::new()));
                let runner = FixtureRunner::new(
                    fixture.outputs.clone(),
                    &fixture.target,
                    &fixture.cwd,
                    Rc::clone(&calls),
                )
                .unwrap();
                let engine = InvestigationEngine::with_budget(runner, 2, REPLAY_TIME_LIMIT);
                let result = engine
                    .replay_unix_socket_first(&fixture.cwd, &fixture.target, first)
                    .unwrap();
                let calls = calls.borrow();
                assert_eq!(calls.len(), result.investigation.attempts.len());
                assert_eq!(calls.len(), 2);
                for call in calls.iter() {
                    assert!(OFFERED.contains(&call.id));
                    assert_eq!(call.cwd, fixture.cwd);
                    assert_eq!(call.safety, ProbeSafety::Safe);
                    let target_arg = fixture.target.to_str().unwrap();
                    assert!(call.args.iter().any(|arg| arg.as_str() == target_arg));
                    assert!(!call.args.iter().any(|arg| arg == "-p" || arg == "-K"));
                    let expected = ProbeSpec::new(
                        call.id,
                        &fixture.cwd,
                        Some(fixture.target.to_str().unwrap()),
                    )
                    .unwrap();
                    assert_eq!(call.program, expected.program);
                    assert_eq!(call.args, expected.args);
                }
            }
        }
    }
}

pub fn run() -> Result<ExitCode, String> {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("replay-unix-socket is supported only on Linux".to_owned())
    }
}
