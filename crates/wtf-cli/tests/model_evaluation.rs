#![cfg(unix)]

//! Opt-in, offline evaluation of advisory model behavior against identical CLI evidence.
//! Apart from the real missing-file case, reported failures and probe responses
//! are scripted. The only confirmed scripted root uses a matching fixture oracle;
//! current observations alone do not establish the other original roots.
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

enum Fixture {
    MissingFile,
    FullFilesystem,
    QuotaExceeded,
    DnsLookupFailed,
    DnsLookupSucceeded,
    RefusalNoListener,
    RefusalProbeFailed,
}

impl Fixture {
    fn name(&self) -> &'static str {
        match self {
            Self::MissingFile => "real missing file (known root)",
            Self::FullFilesystem => "scripted full filesystem (known fixture root)",
            Self::QuotaExceeded => "scripted quota failure, filesystem below full",
            Self::DnsLookupFailed => "reported DNS failure, lookup currently fails",
            Self::DnsLookupSucceeded => "reported DNS failure, lookup currently succeeds",
            Self::RefusalNoListener => "reported refusal, no current listener",
            Self::RefusalProbeFailed => "reported refusal, listener probe fails",
        }
    }

    fn configure(&self, root: &Path, bin: &Path) -> (String, Vec<String>, Option<String>) {
        match self {
            Self::MissingFile => {
                symlink("/usr/bin/stat", bin.join("stat")).expect("isolate stat executable");
                let missing = root.join("missing.txt");
                (
                    "/usr/bin/cat".into(),
                    vec![missing.display().to_string()],
                    Some(format!("{} does not exist.", missing.display())),
                )
            }
            Self::FullFilesystem => {
                script(
                    bin.join("write"),
                    "#!/bin/sh\nprintf '%s\\n' 'No space left on device' >&2\nexit 1\n",
                );
                script(
                    bin.join("df"),
                    "#!/bin/sh\nprintf '%s\\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' '/dev/calibration 1000 1000 0 100% /fixture'\n",
                );
                (
                    "write".into(),
                    Vec::new(),
                    Some(format!(
                        "Filesystem containing {} is 100% full (mounted at /fixture).",
                        root.display()
                    )),
                )
            }
            Self::QuotaExceeded => {
                fs::write(root.join("quota-exhausted"), "").expect("establish quota fixture cause");
                script(
                    bin.join("write"),
                    "#!/bin/sh\nif [ -f quota-exhausted ]; then printf '%s\\n' 'No space left on device' >&2; exit 1; fi\nexit 0\n",
                );
                script(
                    bin.join("df"),
                    "#!/bin/sh\nif [ \"$1\" = '-Pi' ]; then printf '%s\\n' 'Filesystem Inodes IUsed IFree IUse% Mounted on' '/dev/calibration 1000 200 800 20% /fixture'; else printf '%s\\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' '/dev/calibration 1000 950 50 95% /fixture'; fi\n",
                );
                ("write".into(), Vec::new(), None)
            }
            Self::DnsLookupFailed | Self::DnsLookupSucceeded => {
                script(
                    bin.join("curl"),
                    "#!/bin/sh\nprintf '%s\\n' 'curl: (6) Could not resolve host: eval.invalid' >&2\nexit 6\n",
                );
                let getent = if matches!(self, Self::DnsLookupFailed) {
                    "#!/bin/sh\nexit 2\n"
                } else {
                    "#!/bin/sh\nprintf '%s\\n' '127.0.0.1 eval.invalid'\n"
                };
                script(bin.join("getent"), getent);
                ("curl".into(), vec!["http://eval.invalid/".into()], None)
            }
            Self::RefusalNoListener | Self::RefusalProbeFailed => {
                script(
                    bin.join("curl"),
                    "#!/bin/sh\nprintf '%s\\n' 'curl: (7) Failed to connect to 127.0.0.1 port 49152: Connection refused' >&2\nexit 7\n",
                );
                let ss = if matches!(self, Self::RefusalNoListener) {
                    "#!/bin/sh\nprintf '%s\\n' 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'\n"
                } else {
                    "#!/bin/sh\nexit 1\n"
                };
                script(bin.join("ss"), ss);
                ("curl".into(), vec!["http://127.0.0.1:49152/".into()], None)
            }
        }
    }

    fn eligible(&self) -> bool {
        !matches!(
            self,
            Self::MissingFile
                | Self::FullFilesystem
                | Self::QuotaExceeded
                | Self::DnsLookupSucceeded
        )
    }
}

fn script(path: PathBuf, text: &str) {
    fs::write(&path, text).expect("write isolated fixture program");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("make fixture executable");
}

fn run(
    root: &Path,
    bin: &Path,
    program: &str,
    args: &[String],
    model: Option<&Path>,
) -> (Value, Duration, i32) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wtf"));
    command.arg("--json");
    if let Some(dir) = model {
        command.arg("--model-dir").arg(dir);
    } else {
        command.arg("--no-model");
    }
    let start = Instant::now();
    let output = command
        .arg("--")
        .arg(program)
        .args(args)
        .env_clear()
        .env("PATH", bin)
        .env("HOME", root)
        .env("LC_ALL", "C")
        .current_dir(root)
        .output()
        .expect("run isolated diagnosis");
    let elapsed = start.elapsed();
    let code = output.status.code().expect("child exited normally");
    let json = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid CLI JSON: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (json, elapsed, code)
}

#[test]
#[ignore = "requires WTF_MODEL_EVAL_DIR pointing to an already installed local Laya bundle"]
fn compare_advisory_model_with_identical_deterministic_diagnoses() {
    let model_dir = PathBuf::from(
        std::env::var_os("WTF_MODEL_EVAL_DIR")
            .expect("set WTF_MODEL_EVAL_DIR to an existing Laya bundle; no download is allowed"),
    );
    assert!(
        model_dir.join("laya.onnx").is_file(),
        "model graph must be preinstalled"
    );

    // Distinct fixture families are needed before any claim of generalization. The
    // holdout here is a frozen smoke sample, not a statistical accuracy estimate.
    let cases = [
        ("development", Fixture::MissingFile),
        ("development", Fixture::FullFilesystem),
        ("development", Fixture::DnsLookupFailed),
        ("holdout", Fixture::DnsLookupSucceeded),
        ("holdout", Fixture::QuotaExceeded),
        ("holdout", Fixture::RefusalNoListener),
        ("holdout", Fixture::RefusalProbeFailed),
    ];
    let mut known_roots = 0;
    let mut confirmed_correct = 0;
    let mut false_roots = 0;
    let mut eligible = 0;
    let mut confident_without_root = 0;
    let mut probes = 0;
    let mut model_overhead = Vec::new();
    for (index, (split, fixture)) in cases.iter().enumerate() {
        let root = tempfile::tempdir().expect("create isolated case");
        let bin = root.path().join("bin");
        fs::create_dir(&bin).expect("create private PATH");
        let (program, args, gold_root) = fixture.configure(root.path(), &bin);
        let baseline_first = index % 2 == 0;
        let first = run(
            root.path(),
            &bin,
            &program,
            &args,
            if baseline_first {
                None
            } else {
                Some(&model_dir)
            },
        );
        let second = run(
            root.path(),
            &bin,
            &program,
            &args,
            if baseline_first {
                Some(&model_dir)
            } else {
                None
            },
        );
        let ((baseline, base_time, base_exit), (guided, model_time, model_exit)) = if baseline_first
        {
            (first, second)
        } else {
            (second, first)
        };
        assert_eq!(base_exit, model_exit, "{}: exit status", fixture.name());
        for key in [
            "category",
            "status",
            "summary",
            "investigation",
            "evidence",
            "remedy",
        ] {
            assert_eq!(
                baseline[key],
                guided[key],
                "{}: changed {key}",
                fixture.name()
            );
        }
        let root_cause = baseline["investigation"]["root_cause"].as_str();
        match gold_root.as_deref() {
            Some(expected) => {
                known_roots += 1;
                confirmed_correct += usize::from(root_cause == Some(expected));
            }
            None => false_roots += usize::from(root_cause.is_some()),
        }
        probes += baseline["investigation"]["attempts"]
            .as_array()
            .expect("probe attempts")
            .len();
        assert!(baseline.get("model_decision").is_none());
        if matches!(fixture, Fixture::QuotaExceeded) {
            assert!(
                root_cause.is_none(),
                "quota must not be labeled as a full filesystem"
            );
            assert!(baseline["investigation"]["hypotheses"]
                .as_array()
                .is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| item["id"] == "filesystem_full" && item["status"] == "Rejected")
                }));
        }
        assert!(baseline.get("model_error").is_none());
        let decision = guided.get("model_decision");
        assert!(
            guided.get("model_error").is_none(),
            "{}: model unavailable: {guided}",
            fixture.name()
        );
        if fixture.eligible() {
            eligible += 1;
            let decision =
                decision.unwrap_or_else(|| panic!("{}: missing model decision", fixture.name()));
            let options = decision["probabilities"]
                .as_array()
                .expect("ranked options");
            let top = options
                .iter()
                .max_by(|a, b| {
                    a["probability"]
                        .as_f64()
                        .unwrap()
                        .total_cmp(&b["probability"].as_f64().unwrap())
                })
                .expect("at least one option");
            let preferred = decision["preferred"].as_str();
            confident_without_root += usize::from(preferred.is_some());
            eprintln!("{split}: {}: top={} ({:.3}), preferred={preferred:?}, root={root_cause:?}, baseline={base_time:?}, model={model_time:?}",
                fixture.name(), top["hypothesis"], top["probability"].as_f64().unwrap());
            model_overhead.push(model_time.as_secs_f64() - base_time.as_secs_f64());
        } else {
            assert!(
                decision.is_none(),
                "{}: should not invoke Laya",
                fixture.name()
            );
            eprintln!(
                "{split}: {}: skipped model, baseline={base_time:?}, model={model_time:?}",
                fixture.name()
            );
        }
    }
    model_overhead.sort_by(f64::total_cmp);
    eprintln!("Exploratory paired evaluation: cases={}, known roots correct={confirmed_correct}/{known_roots}, false roots={false_roots}, eligible={eligible}, probes={probes}, confident advisory without confirmed root={confident_without_root}, median eligible model overhead={:.3}s. Advisory scores do not count as root-cause accuracy.", cases.len(), model_overhead[model_overhead.len() / 2]);
}
