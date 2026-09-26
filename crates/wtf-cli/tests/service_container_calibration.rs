#![cfg(target_os = "linux")]

//! Cross-family calibration of real CLI outcomes, not an accuracy estimate.
//! systemctl, journalctl, and docker are faked; stat inspects only private local files.
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const SYSTEMCTL: &str = r#"#!/bin/sh
case "$1" in
    start) printf '%s\n' 'fixture start failed' >&2; exit 1 ;;
    show)
        case "$CAL_EVIDENCE" in
            matching) printf '%s\n' 'Id=api.service' 'LoadState=loaded' 'ActiveState=failed' 'Result=exit-code' 'InvocationID=0123456789abcdef0123456789abcdef'; exit 0 ;;
            contradictory) printf '%s\n' 'Id=other.service' 'LoadState=loaded' 'ActiveState=failed' 'Result=exit-code' 'InvocationID=0123456789abcdef0123456789abcdef'; exit 0 ;;
            missing) exit 1 ;;
        esac ;;
esac
exit 64
"#;
const JOURNALCTL: &str = r#"#!/bin/sh
printf '%s\n' 'api.service: No space left on device'
"#;
const DOCKER: &str = r#"#!/bin/sh
if [ "$CAL_FAMILY" = daemon ]; then
    printf '%s\n' "$1" >> "$CAL_DOCKER_CALLS"
    if [ "$1" = ps ]; then
        printf 'Cannot connect to the Docker daemon at unix://%s. Is the docker daemon running?\n' "$CAL_SOURCE" >&2
        exit 1
    fi
    exit 64
fi
case "$1" in
    run)
        if [ "$CAL_FAMILY" = bind ]; then
            printf 'Error response from daemon: invalid mount config for type "bind": bind source path does not exist: %s\n' "$CAL_SOURCE" >&2
            exit 1
        fi
        printf '%s\n' 'Error response from daemon: Bind for 0.0.0.0:8080 failed: port is already allocated' >&2
        exit 125 ;;
    ps)
        case "$CAL_EVIDENCE" in
            matching) printf '%s\n' '{"ID":"owner","Names":"port-owner","Ports":"0.0.0.0:8080->80/tcp","Status":"Up 2 minutes","CreatedAt":"2020-01-01 00:00:00 +0000 UTC"}'; exit 0 ;;
            contradictory) printf '%s\n' '{"ID":"other","Names":"other-service","Ports":"0.0.0.0:9090->80/tcp","Status":"Up 2 minutes","CreatedAt":"2020-01-01 00:00:00 +0000 UTC"}'; exit 0 ;;
            missing) exit 1 ;;
        esac ;;
esac
exit 64
"#;

#[derive(Clone, Copy)]
enum Family {
    Systemd,
    Bind,
    Daemon,
    Port,
}

impl Family {
    fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Bind => "bind",
            Self::Port => "port",
            Self::Daemon => "daemon",
        }
    }
}

#[derive(Clone, Copy)]
enum Evidence {
    Matching,
    Contradictory,
    Missing,
}

impl Evidence {
    fn as_str(self) -> &'static str {
        match self {
            Self::Matching => "matching",
            Self::Contradictory => "contradictory",
            Self::Missing => "missing",
        }
    }
}

struct Case {
    family: Family,
    evidence: Evidence,
    category: &'static str,
    status: &'static str,
    root: &'static [&'static str],
    probes: &'static [(&'static str, &'static str)],
}

fn executable(path: &Path, script: &str) {
    fs::write(path, script).expect("write private command fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make private fixture executable");
}

fn run_case(case: &Case) -> (Value, Duration) {
    let temp = tempfile::tempdir().expect("create calibration sandbox");
    let bin = temp.path().join("bin");
    let home = temp.path().join("home");
    let runtime = temp.path().join("runtime");
    for path in [&bin, &home, &runtime] {
        fs::create_dir(path).expect("create private calibration directory");
    }
    executable(&bin.join("systemctl"), SYSTEMCTL);
    executable(&bin.join("journalctl"), JOURNALCTL);
    executable(&bin.join("docker"), DOCKER);
    let source = temp.path().join(if matches!(case.family, Family::Daemon) {
        "daemon.sock"
    } else {
        "bind-source"
    });
    if matches!(case.family, Family::Bind | Family::Daemon) {
        match case.evidence {
            Evidence::Matching => symlink("/usr/bin/stat", bin.join("stat"))
                .expect("make stat available for absent source"),
            Evidence::Contradictory => {
                fs::write(&source, "present").expect("create contradictory bind source");
                symlink("/usr/bin/stat", bin.join("stat"))
                    .expect("make stat available for existing source");
            }
            Evidence::Missing => {} // No stat in the private PATH; no ambient executable fallback.
        }
    }
    let source = source.to_str().expect("UTF-8 private bind source");
    let mount = format!("type=bind,source={source},target=/config");
    let args: &[&str] = match case.family {
        Family::Systemd => &["systemctl", "start", "api"],
        Family::Bind => &["docker", "run", "--name", "app", "--mount", &mount, "image"],
        Family::Port => &["docker", "run", "-p", "8080:80", "image"],
        Family::Daemon => &["docker", "ps"],
    };
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_wtf"))
        .args(["--json", "--"])
        .args(args)
        .env_clear()
        .env("WTF_NO_MODEL", "1")
        .env("PATH", &bin)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("LC_ALL", "C")
        .env("CAL_FAMILY", case.family.as_str())
        .env("CAL_EVIDENCE", case.evidence.as_str())
        .env("CAL_SOURCE", source)
        .env("CAL_DOCKER_CALLS", temp.path().join("docker-calls.log"))
        .current_dir(temp.path())
        .output()
        .expect("run isolated WTF calibration case");
    let elapsed = started.elapsed();
    let expected_exit = if matches!(case.family, Family::Port) {
        125
    } else {
        1
    };
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "{args:?}: {output:?}"
    );
    let json: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{args:?}: invalid JSON ({error}), output: {output:?}"));
    if matches!(case.family, Family::Daemon) {
        assert_eq!(
            fs::read_to_string(temp.path().join("docker-calls.log"))
                .expect("read Docker invocation log"),
            "ps\n",
            "diagnosis must not reissue the failed Docker command"
        );
        let investigation = &json["investigation"];
        assert_eq!(investigation["adapter"], "docker");
        assert!(
            !investigation.to_string().contains(source),
            "private socket path must not appear in investigation: {json}"
        );
    }
    (json, elapsed)
}

#[test]
fn service_and_container_calibration_respects_evidence_boundaries() {
    use Evidence::{Contradictory, Matching, Missing};
    use Family::{Bind, Daemon, Port, Systemd};
    let cases = [
        Case {
            family: Systemd,
            evidence: Matching,
            category: "service/failed",
            status: "Confirmed",
            root: &["api.service", "no space left on device"],
            probes: &[("SystemdShow", "ok"), ("SystemdLogs", "ok")],
        },
        Case {
            family: Systemd,
            evidence: Contradictory,
            category: "unknown",
            status: "Unknown",
            root: &[],
            probes: &[("SystemdShow", "ok")],
        },
        Case {
            family: Systemd,
            evidence: Missing,
            category: "unknown",
            status: "Unknown",
            root: &[],
            probes: &[("SystemdShow", "exit 1")],
        },
        Case {
            family: Bind,
            evidence: Matching,
            category: "container/mount",
            status: "Confirmed",
            root: &["app"],
            probes: &[("Stat", "exit 1")],
        },
        Case {
            family: Bind,
            evidence: Contradictory,
            category: "unknown",
            status: "Unknown",
            root: &[],
            probes: &[("Stat", "ok")],
        },
        Case {
            family: Bind,
            evidence: Missing,
            category: "unknown",
            status: "Unknown",
            root: &[],
            probes: &[("Stat", "unavailable")],
        },
        Case {
            family: Port,
            evidence: Matching,
            category: "container/port-conflict",
            status: "Confirmed",
            root: &["port-owner", "8080"],
            probes: &[("DockerRunning", "ok")],
        },
        Case {
            family: Port,
            evidence: Contradictory,
            category: "unknown",
            status: "Unknown",
            root: &[],
            probes: &[("DockerRunning", "ok")],
        },
        Case {
            family: Port,
            evidence: Missing,
            category: "unknown",
            status: "Unknown",
            root: &[],
            probes: &[("DockerRunning", "exit 1")],
        },
        Case {
            family: Daemon,
            evidence: Matching,
            category: "container/daemon",
            status: "Confirmed",
            root: &["local Docker Unix socket", "does not exist"],
            probes: &[("Stat", "exit 1")],
        },
        Case {
            family: Daemon,
            evidence: Contradictory,
            category: "unknown",
            status: "Unknown",
            root: &[],
            probes: &[("Stat", "ok")],
        },
        Case {
            family: Daemon,
            evidence: Missing,
            category: "unknown",
            status: "Unknown",
            root: &[],
            probes: &[("Stat", "unavailable")],
        },
    ];
    let mut false_confirmations = 0;
    let mut unknown = 0;
    let mut correct = 0;
    let mut probes = 0;
    let mut elapsed = Vec::with_capacity(cases.len());
    for case in &cases {
        let (json, time) = run_case(case);
        let name = format!("{} / {}", case.family.as_str(), case.evidence.as_str());
        let category_matches = json["category"] == case.category;
        let status = json["status"].as_str().expect("diagnosis status");
        let root = json["investigation"]["root_cause"].as_str();
        let root_matches = match root {
            Some(actual) => {
                !case.root.is_empty() && case.root.iter().all(|part| actual.contains(part))
            }
            None => case.root.is_empty(),
        };
        let attempts = json["investigation"]["attempts"]
            .as_array()
            .expect("bounded investigation attempts");
        let actual_probes: Vec<_> = attempts
            .iter()
            .map(|attempt| {
                (
                    attempt["probe"].as_str().expect("probe ID"),
                    attempt["result"].as_str().expect("probe result"),
                )
            })
            .collect();
        assert_eq!(
            actual_probes, case.probes,
            "{name}: unexpected probe budget; {json}"
        );
        false_confirmations += usize::from(
            status == "Confirmed"
                && (case.status != "Confirmed" || !category_matches || !root_matches),
        );
        unknown += usize::from(status == "Unknown");
        correct += usize::from(category_matches && status == case.status && root_matches);
        probes += attempts.len();
        elapsed.push(time);
        eprintln!(
            "{name}: category={}; status={status}; root={root:?}; probes={}; elapsed={time:?}",
            json["category"],
            attempts.len()
        );
        assert!(
            category_matches && status == case.status && root_matches,
            "{name}: {json}"
        );
    }
    elapsed.sort_unstable();
    eprintln!(
        "Service/container calibration: {correct}/{} expected outcomes; {false_confirmations} false confirmations; {unknown}/8 expected unknown; {probes} probes ({:.2}/diagnosis); median CLI wall time {:?}; fixture outcomes only",
        cases.len(), probes as f64 / cases.len() as f64, elapsed[elapsed.len() / 2],
    );
    assert_eq!(correct, cases.len());
    assert_eq!(false_confirmations, 0);
    assert_eq!(unknown, 8);
}
