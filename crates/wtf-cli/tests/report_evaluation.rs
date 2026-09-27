//! Family-separated acceptance corpus for the generic evidence report.
//!
//! Every invocation gets a private cwd and a PATH containing only fixture commands and
//! explicitly instrumented read-only probes. Expectations come from fixture process state,
//! filesystem setup, and controlled command output—not from detector status or category.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use serde_json::Value;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    const WTF: &str = env!("CARGO_BIN_EXE_wtf");

    fn listener_program() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            "ss"
        }
        #[cfg(target_os = "macos")]
        {
            "lsof"
        }
    }

    struct Fixture {
        _temp: TempDir,
        work: PathBuf,
        bin: PathBuf,
        probe_log: PathBuf,
        replay_marker: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("private fixture directory");
            let work = temp.path().to_path_buf();
            let bin = work.join("bin");
            fs::create_dir(&bin).expect("fixture PATH directory");
            Self {
                probe_log: work.join("probe-calls.log"),
                replay_marker: work.join("replayed.marker"),
                _temp: temp,
                work,
                bin,
            }
        }

        fn install(&self, name: &str, body: &str) -> PathBuf {
            let path = self.bin.join(name);
            fs::write(&path, body).expect("write fixture executable");
            let mut permissions = fs::metadata(&path).expect("fixture metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("make fixture executable");
            path
        }

        fn install_stat_probe(&self) {
            self.install(
                "stat",
                "#!/bin/sh\nprintf 'stat\\n' >> \"$WTF_PROBE_LOG\"\nexec /usr/bin/stat \"$@\"\n",
            );
        }

        fn install_listener_probe(&self) {
            #[cfg(target_os = "linux")]
            self.install(
                "ss",
                "#!/bin/sh\nprintf 'ss\\n' >> \"$WTF_PROBE_LOG\"\n[ \"$1\" = '-ltnp' ] || exit 97\nexit 0\n",
            );
            #[cfg(target_os = "macos")]
            self.install(
                "lsof",
                "#!/bin/sh\nprintf 'lsof\\n' >> \"$WTF_PROBE_LOG\"\n[ \"$1\" = '-nP' ] && [ \"$2\" = '-iTCP' ] && [ \"$3\" = '-sTCP:LISTEN' ] || exit 97\nexit 0\n",
            );
        }

        fn run(&self, args: &[String]) -> (Output, Duration) {
            let start = Instant::now();
            let output = Command::new(WTF)
                .args(args)
                .current_dir(&self.work)
                .env_clear()
                .env("PATH", &self.bin)
                .env("HOME", &self.work)
                .env("XDG_CONFIG_HOME", self.work.join("config"))
                .env("XDG_RUNTIME_DIR", &self.work)
                .env("TMPDIR", &self.work)
                .env("LC_ALL", "C")
                .env("WTF_NO_MODEL", "1")
                .env("WTF_PROBE_LOG", &self.probe_log)
                .env("WTF_REPLAY_MARKER", &self.replay_marker)
                .output()
                .expect("run actual wtf CLI");
            (output, start.elapsed())
        }

        fn run_json(&self, command: Option<&[String]>) -> Measured {
            let mut args = vec!["--json".to_owned()];
            if let Some(command) = command {
                args.push("--".to_owned());
                args.extend_from_slice(command);
            }
            let (output, elapsed) = self.run(&args);
            let stdout = String::from_utf8(output.stdout.clone()).expect("JSON stdout is UTF-8");
            let json = serde_json::from_str(&stdout).unwrap_or_else(|error| {
                panic!(
                    "invalid JSON from actual CLI: {error}; stdout={stdout:?}; stderr={:?}",
                    output.stderr
                )
            });
            Measured {
                json,
                stdout,
                process_code: output.status.code(),
                elapsed,
                probe_log: fs::read_to_string(&self.probe_log).unwrap_or_default(),
            }
        }
    }

    struct Measured {
        json: Value,
        stdout: String,
        process_code: Option<i32>,
        elapsed: Duration,
        probe_log: String,
    }

    #[derive(Clone)]
    enum EvidenceOrigin {
        SpawnError,
        Stderr(&'static str),
        Probe {
            id: &'static str,
            marker: String,
            log_name: &'static str,
        },
    }

    struct GroundTruth {
        name: &'static str,
        family: &'static str,
        code: Option<i64>,
        signal: Option<i64>,
        capture: &'static str,
        source_mode: &'static str,
        evidence: Option<EvidenceOrigin>,
        next_discriminator: Option<String>,
        supported_root_marker: Option<String>,
        generic: bool,
        distinct_report_time: bool,
        privacy_canary: Option<&'static str>,
    }

    struct CorpusResult {
        ground: GroundTruth,
        measured: Measured,
    }

    fn command(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    fn now_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
    }

    fn add(
        results: &mut Vec<CorpusResult>,
        fixture: &Fixture,
        ground: GroundTruth,
        command: Option<&[String]>,
    ) {
        results.push(CorpusResult {
            ground,
            measured: fixture.run_json(command),
        });
    }

    fn claims(result: &CorpusResult) -> &[Value] {
        result.measured.json["report"]["claims"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: report claims must be an array", result.ground.name))
    }

    fn assert_exit_and_capture(result: &CorpusResult) {
        let ground = &result.ground;
        let status = &result.measured.json["exit_status"];
        assert_eq!(
            status["code"].as_i64(),
            ground.code,
            "{}: independently expected command exit code",
            ground.name
        );
        assert_eq!(
            status["signal"].as_i64(),
            ground.signal,
            "{}: independently expected process signal",
            ground.name
        );
        let report = &result.measured.json["report"];
        assert_eq!(
            report["source_mode"].as_str(),
            Some(ground.source_mode),
            "{}",
            ground.name
        );
        assert_eq!(
            report["capture"].as_str(),
            Some(ground.capture),
            "{}",
            ground.name
        );
        let outcome = if let Some(signal) = ground.signal {
            format!("signal {signal}")
        } else {
            ground.code.expect("code or signal").to_string()
        };
        assert_eq!(
            report["outcome"].as_str(),
            Some(outcome.as_str()),
            "{}",
            ground.name
        );
        let expected_process_code = ground
            .code
            .map(|code| code as i32)
            .or_else(|| ground.signal.map(|signal| 128 + signal as i32));
        assert_eq!(
            result.measured.process_code, expected_process_code,
            "{}",
            ground.name
        );
    }

    fn assert_no_unsupported_cause(result: &CorpusResult) {
        let ground = &result.ground;
        let diagnosis_status = result.measured.json["status"].as_str().unwrap_or_default();
        if diagnosis_status == "Confirmed" {
            let has_independent_root_fact = ground.supported_root_marker.is_some()
                || ground
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| matches!(evidence, EvidenceOrigin::SpawnError));
            assert!(
                has_independent_root_fact,
                "{}: a report with no independently established root fact promoted a confirmed diagnosis: {}",
                ground.name,
                result.measured.json
            );
        }
        let investigation = &result.measured.json["investigation"];
        for field in ["root_cause", "cause"] {
            if let Some(cause) = investigation[field].as_str() {
                let marker = ground.supported_root_marker.as_deref().or_else(|| {
                    ground
                        .evidence
                        .as_ref()
                        .is_some_and(|evidence| matches!(evidence, EvidenceOrigin::SpawnError))
                        .then_some("wtf_acceptance_missing_executable")
                });
                assert!(
                    marker.is_some_and(|marker| cause.contains(marker)),
                    "{}: unsupported confirmed cause {field}={cause:?}",
                    ground.name
                );
            }
        }
    }

    fn assert_claim_facts(result: &CorpusResult) -> (usize, usize, bool, usize) {
        let ground = &result.ground;
        let mut observed = 0;
        let mut matched = 0;
        let mut missing_metadata_fallback = false;
        let mut supported_next = 0;
        let mut expected_observation_seen = false;
        for claim in claims(result) {
            let kind = claim["kind"].as_str().unwrap_or_default();
            let source = &claim["source"];
            let source_type = source["type"].as_str().unwrap_or_default();
            let text = claim["text"].as_str().unwrap_or_default();
            assert!(
                !text.trim().is_empty(),
                "{}: empty consumer-facing claim",
                ground.name
            );
            match kind {
                "observed" => {
                    observed += 1;
                    let expected = ground.evidence.as_ref().unwrap_or_else(|| {
                        panic!(
                            "{}: observation claim without independent source evidence: {claim}",
                            ground.name
                        )
                    });
                    match (expected, source_type) {
                        (EvidenceOrigin::SpawnError, "execution") => {
                            assert_eq!(
                                source["field"].as_str(),
                                Some("spawn_error"),
                                "{}",
                                ground.name
                            );
                            matched += 1;
                            expected_observation_seen = true;
                        }
                        (EvidenceOrigin::Stderr(marker), "execution") => {
                            assert_eq!(source["field"].as_str(), Some("stderr"), "{}", ground.name);
                            assert!(
                                text.contains(marker),
                                "{}: observation lacks fixture stderr fact {marker:?}: {text:?}",
                                ground.name
                            );
                            matched += 1;
                            expected_observation_seen = true;
                        }
                        (EvidenceOrigin::Probe { marker, .. }, "execution") => {
                            assert_eq!(source["field"].as_str(), Some("stderr"), "{}", ground.name);
                            assert!(
                                text.contains(marker) && !text.starts_with("Now:"),
                                "{}: historical stderr must be attributed to the execution, not current state: {claim}",
                                ground.name
                            );
                            matched += 1;
                        }
                        (
                            EvidenceOrigin::Probe {
                                id,
                                marker,
                                log_name,
                            },
                            "probe",
                        ) => {
                            assert_eq!(source["id"].as_str(), Some(*id), "{}", ground.name);
                            assert!(text.contains(marker), "{}: observation lacks independently known probe fact {marker:?}: {text:?}", ground.name);
                            assert!(
                                result.measured.probe_log.lines().any(|line| line == *log_name),
                                "{}: claim cites a probe that did not run in its isolated fixture PATH",
                                ground.name
                            );
                            let observed_at = source["observed_at"]
                                .as_u64()
                                .expect("probe observation timestamp");
                            let captured_at = result.measured.json["report"]["captured_at"]
                                .as_u64()
                                .unwrap();
                            let reported_at = result.measured.json["report"]["reported_at"]
                                .as_u64()
                                .unwrap();
                            assert!(
                                captured_at <= observed_at && observed_at <= reported_at,
                                "{}: probe observation cannot predate capture or postdate report",
                                ground.name
                            );
                            assert!(
                                result.measured.json["investigation"]["attempts"]
                                    .as_array()
                                    .is_some_and(|attempts| attempts
                                        .iter()
                                        .any(|attempt| attempt["probe"] == *id
                                            && attempt["result"] == source["outcome"])),
                                "{}: claim must cite the actual probe outcome",
                                ground.name
                            );
                            matched += 1;
                            expected_observation_seen = true;
                        }
                        _ => panic!(
                            "{}: claim source does not match independent ground truth: {claim}",
                            ground.name
                        ),
                    }
                }
                "missing" => {
                    assert_eq!(
                        source_type, "metadata",
                        "{}: missing-fact claim needs metadata provenance",
                        ground.name
                    );
                    missing_metadata_fallback = true;
                }
                "next" => {
                    assert_eq!(
                        source_type, "suggestion",
                        "{}: next step is not presented as an executed fact",
                        ground.name
                    );
                    let discriminator = ground.next_discriminator.as_deref().unwrap_or_else(|| {
                        panic!(
                            "{}: NEXT has no independently known fact to discriminate: {text:?}",
                            ground.name
                        )
                    });
                    assert!(
                        text.contains(discriminator),
                        "{}: NEXT does not distinguish the known missing fact {discriminator:?}: {text:?}",
                        ground.name
                    );
                    supported_next += 1;
                }
                other => panic!("{}: unsupported claim kind {other:?}", ground.name),
            }
        }
        if ground.evidence.is_some() {
            assert!(
                expected_observation_seen,
                "{}: expected independent observation was not surfaced",
                ground.name
            );
        }
        (observed, matched, missing_metadata_fallback, supported_next)
    }

    fn assert_probe_budget_and_fixture_calls(result: &CorpusResult) -> usize {
        let attempts = result.measured.json["investigation"]["attempts"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let attempt_count = attempts.len();
        assert!(
            attempt_count <= 4,
            "{}: bounded acceptance case exceeded four safe probe attempts",
            result.ground.name
        );
        let mut expected_calls = Vec::new();
        for attempt in attempts {
            let id = attempt["probe"].as_str().unwrap_or_default();
            let result_text = attempt["result"].as_str().unwrap_or_default();
            let program = match id {
                "Stat" => "stat",
                "Listeners" => listener_program(),
                other => panic!(
                    "{}: unexpected probe in this isolated corpus: {other}",
                    result.ground.name
                ),
            };
            if result_text != "unavailable" {
                expected_calls.push(program);
            }
        }
        let actual_calls: Vec<_> = result
            .measured
            .probe_log
            .lines()
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(
            actual_calls, expected_calls,
            "{}: actual isolated read-only probe invocations",
            result.ground.name
        );
        attempt_count
    }

    fn assert_json_privacy(result: &CorpusResult) {
        assert!(
            !result.measured.stdout.contains('\u{1b}'),
            "{}: raw ANSI escape in JSON stream",
            result.ground.name
        );
        assert!(
            !contains_ansi_string(&result.measured.json),
            "{}: captured ANSI escape survived in JSON string data",
            result.ground.name
        );
        if let Some(canary) = result.ground.privacy_canary {
            assert!(
                !result.measured.stdout.contains(canary),
                "{}: private canary leaked into JSON",
                result.ground.name
            );
        }
    }

    fn contains_ansi_string(value: &Value) -> bool {
        match value {
            Value::String(text) => text.contains('\u{1b}'),
            Value::Array(items) => items.iter().any(contains_ansi_string),
            Value::Object(fields) => fields.values().any(contains_ansi_string),
            _ => false,
        }
    }

    fn median_and_p95_ms(times: &mut [Duration]) -> (f64, f64) {
        times.sort_unstable();
        let median = if times.len().is_multiple_of(2) {
            (times[times.len() / 2 - 1].as_secs_f64() + times[times.len() / 2].as_secs_f64())
                * 500.0
        } else {
            times[times.len() / 2].as_secs_f64() * 1000.0
        };
        let p95_index = (times.len() * 95)
            .div_ceil(100)
            .saturating_sub(1)
            .min(times.len() - 1);
        (median, times[p95_index].as_secs_f64() * 1000.0)
    }

    fn root_text<'a>(result: &'a CorpusResult, field: &str) -> Option<&'a str> {
        result.measured.json["investigation"][field].as_str()
    }

    #[test]
    fn generic_report_acceptance_corpus_is_family_separated_and_measured() {
        let mut results = Vec::new();

        // Process truth family: actual exit/signal status is known independently of diagnosis.
        let fixture = Fixture::new();
        fixture.install(
            "fixture_success",
            "#!/bin/sh\nprintf 'PRIVATE_SUCCESS_PAYLOAD\\n'\nexit 0\n",
        );
        let success_command = command(&["fixture_success"]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "success",
                family: "process truth",
                code: Some(0),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: None,
                next_discriminator: None,
                supported_root_marker: None,
                generic: false,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&success_command),
        );

        let fixture = Fixture::new();
        let absent_executable = "wtf_acceptance_missing_executable";
        let absent_command = command(&[absent_executable]);
        assert!(
            !fixture.bin.join(absent_executable).exists(),
            "spawn-failure command is absent from the entire fixture PATH"
        );
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "spawn failure",
                family: "process truth",
                code: Some(127),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: Some(EvidenceOrigin::SpawnError),
                next_discriminator: Some(absent_executable.to_owned()),
                supported_root_marker: None,
                generic: false,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&absent_command),
        );

        let fixture = Fixture::new();
        fixture.install(
            "fixture_unknown_evidence",
            "#!/bin/sh\nprintf 'GENERIC_FAILURE_EVIDENCE: alpha-17\\n' >&2\nexit 23\n",
        );
        let unknown_with_evidence = command(&["fixture_unknown_evidence"]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "unfamiliar failure with stderr",
                family: "generic fallback",
                code: Some(23),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: Some(EvidenceOrigin::Stderr("GENERIC_FAILURE_EVIDENCE: alpha-17")),
                next_discriminator: None,
                supported_root_marker: None,
                generic: true,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&unknown_with_evidence),
        );

        let fixture = Fixture::new();
        fixture.install("fixture_unknown_silent", "#!/bin/sh\nexit 37\n");
        let unknown_without_evidence = command(&["fixture_unknown_silent"]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "unfamiliar failure without output",
                family: "generic fallback",
                code: Some(37),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: None,
                next_discriminator: None,
                supported_root_marker: None,
                generic: true,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&unknown_without_evidence),
        );

        let fixture = Fixture::new();
        let signal_command = command(&["/bin/sh", "-c", "kill -TERM $$"]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "signal termination",
                family: "process truth",
                code: None,
                signal: Some(15),
                capture: "captured",
                source_mode: "explicit",
                evidence: None,
                next_discriminator: None,
                supported_root_marker: None,
                generic: false,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&signal_command),
        );

        // Shell metadata family: stale-enough timestamps distinguish command time from report time;
        // an installed marker command would visibly mutate the fixture if the failed action replayed.
        let fixture = Fixture::new();
        let replay_marker = fixture.replay_marker.to_string_lossy().into_owned();
        fixture.install(
            "would_replay",
            &format!("#!/bin/sh\nprintf replayed > '{}'\n", replay_marker),
        );
        let now = now_seconds();
        let started = now.saturating_sub(120);
        let finished = now.saturating_sub(110);
        let record_args = vec![
            "__record".to_owned(),
            "bash".to_owned(),
            "23".to_owned(),
            started.to_string(),
            finished.to_string(),
            fixture.work.to_string_lossy().into_owned(),
            "would_replay".to_owned(),
        ];
        let (recorded, _) = fixture.run(&record_args);
        assert!(
            recorded.status.success(),
            "store shell metadata without executing its command"
        );
        let shell_result_index = results.len();
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "shell metadata without replay",
                family: "shell metadata",
                code: Some(23),
                signal: None,
                capture: "unavailable",
                source_mode: "shell_record",
                evidence: None,
                next_discriminator: None,
                supported_root_marker: None,
                generic: false,
                distinct_report_time: true,
                privacy_canary: None,
            },
            None,
        );
        assert!(
            !fixture.replay_marker.exists(),
            "the recorded failed action must not be replayed"
        );
        assert!(
            claims(&results[shell_result_index]).iter().any(|claim| {
                claim["kind"] == "missing"
                    && claim["source"]["type"] == "metadata"
                    && claim["source"]["field"] == "capture"
            }),
            "shell metadata must disclose that original output is absent"
        );

        // Contradictory current-state family: the command reports a missing path that is present;
        // the real stat utility in the fixture PATH establishes the independent current state.
        let fixture = Fixture::new();
        fixture.install_stat_probe();
        let present = fixture.work.join("contradictory-state.txt");
        fs::write(&present, "known-present").expect("create contradictory current-state target");
        let present_arg = present.to_string_lossy().into_owned();
        fixture.install(
            "cat",
            "#!/bin/sh\nprintf 'cat: %s: No such file or directory\\n' \"$1\" >&2\nexit 1\n",
        );
        let contradiction_command = command(&["cat", &present_arg]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "reported absence contradicted by current file",
                family: "current-state contradiction",
                code: Some(1),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: Some(EvidenceOrigin::Probe {
                    id: "Stat",
                    marker: "contradictory-state.txt".to_owned(),
                    log_name: "stat",
                }),
                next_discriminator: None,
                supported_root_marker: None,
                generic: false,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&contradiction_command),
        );

        // Positive current-state family: stat verifies a real missing target, separate from
        // the fake cat stderr used to trigger a bounded read-only inspection.
        let fixture = Fixture::new();
        fixture.install_stat_probe();
        let missing = fixture.work.join("known-missing-target.txt");
        assert!(
            !missing.exists(),
            "the positive missing-file ground truth is established before execution"
        );
        fixture.install(
            "cat",
            "#!/bin/sh\nprintf 'cat: %s: No such file or directory\\n' \"$1\" >&2\nexit 1\n",
        );
        let missing_arg = missing.to_string_lossy().into_owned();
        let missing_command = command(&["cat", &missing_arg]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "missing path independently verified",
                family: "current-state evidence",
                code: Some(1),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: Some(EvidenceOrigin::Probe {
                    id: "Stat",
                    marker: "known-missing-target.txt".to_owned(),
                    log_name: "stat",
                }),
                next_discriminator: Some("known-missing-target.txt".to_owned()),
                supported_root_marker: Some("known-missing-target.txt".to_owned()),
                generic: false,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&missing_command),
        );

        // Unavailable-probe family: PATH intentionally lacks ss, so a connection-refused
        // symptom cannot be promoted into a claim about current listeners.
        let fixture = Fixture::new();
        let unavailable_port = "43871";
        assert!(
            !fixture.bin.join(listener_program()).exists(),
            "unavailable-probe PATH must not contain its platform listener executable"
        );
        fixture.install(
            "curl",
            &format!("#!/bin/sh\nprintf 'curl: (7) Failed to connect to 127.0.0.1 port {unavailable_port}: Connection refused\\n' >&2\nexit 7\n"),
        );
        let unavailable_url = format!("http://127.0.0.1:{unavailable_port}/fixture");
        let curl_unavailable_command = command(&["curl", &unavailable_url]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "listener probe unavailable",
                family: "probe availability",
                code: Some(7),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: Some(EvidenceOrigin::Stderr("Connection refused")),
                next_discriminator: Some(unavailable_port.to_owned()),
                supported_root_marker: None,
                generic: false,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&curl_unavailable_command),
        );

        // A local refusal with no identified service has a useful current observation,
        // but no justified automatic follow-up for an arbitrary port.
        let fixture = Fixture::new();
        fixture.install_listener_probe();
        let listener_port = "43872";
        fixture.install(
            "curl",
            &format!("#!/bin/sh\nprintf 'curl: (7) Failed to connect to 127.0.0.1 port {listener_port}: Connection refused\\n' >&2\nexit 7\n"),
        );
        let listener_url = format!("http://127.0.0.1:{listener_port}/fixture");
        let listener_command = command(&["curl", &listener_url]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "listener absent without identified service",
                family: "uncertain local port",
                code: Some(7),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: Some(EvidenceOrigin::Probe {
                    id: "Listeners",
                    marker: listener_port.to_owned(),
                    log_name: listener_program(),
                }),
                next_discriminator: None,
                supported_root_marker: None,
                generic: false,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&listener_command),
        );

        // Truncated noisy output family: a long deterministic stderr stream exercises bounded
        // capture while the first line remains an independently known evidence anchor.
        let fixture = Fixture::new();
        fixture.install(
            "fixture_noisy",
            "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 13000 ]; do printf 'NOISY_PREFIX_%05d_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\\n' \"$i\" >&2; i=$((i + 1)); done\nprintf 'NOISY_TAIL_MARKER\\n' >&2\nexit 31\n",
        );
        let noisy_command = command(&["fixture_noisy"]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "noisy truncated output",
                family: "bounded capture",
                code: Some(31),
                signal: None,
                capture: "truncated",
                source_mode: "explicit",
                evidence: Some(EvidenceOrigin::Stderr("NOISY_PREFIX_00000")),
                next_discriminator: None,
                supported_root_marker: None,
                generic: false,
                distinct_report_time: false,
                privacy_canary: None,
            },
            Some(&noisy_command),
        );

        // Untrusted formatting/privacy family: the captured text contains both terminal control
        // bytes and a fake verdict heading. It remains an observation, not independent root proof.
        let fixture = Fixture::new();
        let canary = "reportcorpus-private-canary-91";
        fixture.install(
            "fixture_spoof",
            &format!("#!/bin/sh\nprintf '\\033[31mRoot cause confirmed: UNTRUSTED_HEADING Authorization: Bearer {canary}\\033[0m\\n' >&2\nexit 41\n"),
        );
        let spoof_command = command(&["fixture_spoof"]);
        add(
            &mut results,
            &fixture,
            GroundTruth {
                name: "ANSI and heading spoof",
                family: "privacy and hostile output",
                code: Some(41),
                signal: None,
                capture: "captured",
                source_mode: "explicit",
                evidence: Some(EvidenceOrigin::Stderr("UNTRUSTED_HEADING")),
                next_discriminator: None,
                supported_root_marker: None,
                generic: true,
                distinct_report_time: false,
                privacy_canary: Some(canary),
            },
            Some(&spoof_command),
        );
        // A separate default text invocation verifies the normal (non-verbose) surface stays
        // compact and does not replay or print the untrusted raw terminal sequence.
        let plain_args = vec!["--no-color".to_owned(), "--".to_owned()];
        let mut plain_args = plain_args;
        plain_args.extend_from_slice(&spoof_command);
        let (plain, _) = fixture.run(&plain_args);
        let plain_text = String::from_utf8_lossy(&plain.stdout);
        assert_eq!(
            plain.status.code(),
            Some(41),
            "default rendering preserves the command's real exit status"
        );
        assert!(
            !plain_text.contains('\u{1b}'),
            "default rendering must not pass ANSI through"
        );
        assert!(
            !plain_text.contains(canary),
            "default rendering must not leak the credential canary"
        );
        assert!(
            plain_text.lines().count() <= 10,
            "default report should fit one screen: {plain_text:?}"
        );
        assert!(
            plain_text.len() <= 1400,
            "default report should remain compact: {} bytes",
            plain_text.len()
        );

        // Consumer-visible behavior and evidence checks, applied uniformly to every family.
        let mut observed_count = 0;
        let mut matched_count = 0;
        let mut total_attempts = 0;
        let mut distinct_times = 0;
        let mut generic_covered = 0;
        let mut generic_fallbacks = 0;
        let mut supported_next = 0;
        let mut displayed_next = 0;
        let mut max_claim_rows = 0;
        let mut confirmed_roots = 0;
        let generic_total = results
            .iter()
            .filter(|result| result.ground.generic)
            .count();
        let mut times = Vec::with_capacity(results.len());

        for result in &results {
            assert_exit_and_capture(result);
            assert!(
                claims(result).len() <= 3,
                "{}: report exceeded three claims",
                result.ground.name
            );
            assert_json_privacy(result);
            assert_no_unsupported_cause(result);
            let (observed, matched, missing_fallback, next) = assert_claim_facts(result);
            observed_count += observed;
            matched_count += matched;
            supported_next += next;
            displayed_next += claims(result)
                .iter()
                .filter(|claim| claim["kind"] == "next")
                .count();
            max_claim_rows = max_claim_rows.max(claims(result).len());
            confirmed_roots += usize::from(result.measured.json["status"] == "Confirmed");
            let attempts = assert_probe_budget_and_fixture_calls(result);
            total_attempts += attempts;

            let report = &result.measured.json["report"];
            let captured_at = report["captured_at"].as_u64().expect("captured timestamp");
            let reported_at = report["reported_at"].as_u64().expect("report timestamp");
            assert!(
                reported_at >= captured_at,
                "{}: report predates command capture",
                result.ground.name
            );
            if reported_at > captured_at {
                distinct_times += 1;
            }
            if result.ground.distinct_report_time {
                assert!(
                    reported_at > captured_at,
                    "{}: deliberately stale shell record must distinguish capture and report time",
                    result.ground.name
                );
            }
            times.push(result.measured.elapsed);

            if result.ground.generic {
                let has_claim = !claims(result).is_empty();
                if has_claim {
                    generic_covered += 1;
                }
                assert!(
                    has_claim,
                    "{}: generic failure fell through without a usable claim",
                    result.ground.name
                );
                if result.ground.evidence.is_none() || (observed == 0 && missing_fallback) {
                    generic_fallbacks += 1;
                }
            }
        }

        assert_eq!(
            observed_count, matched_count,
            "every observed claim must match an independently known execution/probe fact"
        );
        let generic_silent = results
            .iter()
            .find(|result| result.ground.name == "unfamiliar failure without output")
            .expect("silent generic case");
        assert!(
            claims(generic_silent)
                .iter()
                .any(|claim| claim["kind"] == "missing" && claim["source"]["type"] == "metadata"),
            "an evidence-free generic failure needs a metadata-backed uncertainty fallback"
        );
        let unavailable = results
            .iter()
            .find(|result| result.ground.name == "listener probe unavailable")
            .expect("unavailable probe case");
        assert!(
            unavailable.measured.json["investigation"]["attempts"]
                .as_array()
                .is_some_and(|attempts| {
                    attempts.iter().any(|attempt| {
                        attempt["probe"] == "Listeners" && attempt["result"] == "unavailable"
                    })
                }),
            "fixture PATH must make the requested read-only listener probe explicitly unavailable"
        );
        let contradiction = results
            .iter()
            .find(|result| result.ground.name == "reported absence contradicted by current file")
            .expect("contradictory state case");
        assert_ne!(
            contradiction.measured.json["status"], "Confirmed",
            "a missing-file message cannot overrule the existing file observed by stat"
        );
        assert!(
            root_text(contradiction, "root_cause").is_none(),
            "contradictory current state cannot support a confirmed root cause"
        );
        let noisy = results
            .iter()
            .find(|result| result.ground.name == "noisy truncated output")
            .expect("truncated output case");
        assert_eq!(noisy.measured.json["report"]["capture"], "truncated");
        assert!(
            claims(noisy)
                .iter()
                .all(|claim| claim["text"].as_str().unwrap_or_default().len() <= 220),
            "noisy output must not turn a claim into a dump"
        );
        assert_eq!(
            generic_covered, generic_total,
            "generic fallback coverage denominator"
        );

        let families: std::collections::BTreeSet<_> =
            results.iter().map(|result| result.ground.family).collect();
        let (median_ms, p95_ms) = median_and_p95_ms(&mut times);
        println!(
            "report acceptance corpus: cases={}; families={}; claim-source evidence matched={}/{} observed claims; supported NEXT={}/{} displayed next steps; max default claim rows={}; independently supported confirmations={}; generic coverage={}/{}; generic evidence-free fallback={}/{}; safe read-only probe attempts={}; report-time-after-capture={}/{}; CLI wall time median={median_ms:.3}ms p95={p95_ms:.3}ms",
            results.len(), families.len(), matched_count, observed_count, supported_next,
            displayed_next, max_claim_rows, confirmed_roots, generic_covered, generic_total,
            generic_fallbacks, generic_total, total_attempts, distinct_times, results.len()
        );
        println!("families: {families:?}; no external-accuracy claim");
    }
}
