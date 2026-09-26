use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::capture::drain_stream_bounded;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeSafety {
    Safe,
    RequiresConfirmation,
    Forbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeId {
    Listeners,
    Hosts,
    Route,
    Filesystem,
    FilesystemInodes,
    Stat,
    #[cfg(feature = "counterfactual-replay")]
    UnixListeners,
    Process,
    DockerRunning,
    DockerAll,
    DockerInspect,
    DockerLogs,
    SystemdShow,
    SystemdLogs,
    GitStatus,
    GitDiff,
    // Retained for training validation; this probe is not executable.
    CargoCheck,
    GitPorcelain,
    GitBranch,
    GitUpstream,
    GitTopLevel,
    GitRemote,
}

/// Only this closed catalogue constructs commands for automatic execution.
#[derive(Debug, Clone)]
pub struct ProbeSpec {
    pub id: ProbeId,
    pub description: &'static str,
    pub program: &'static str,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub timeout: Duration,
    pub safety: ProbeSafety,
    pub evidence_kind: &'static str,
    pub useful_for: &'static [&'static str],
}

impl ProbeSpec {
    pub fn new(id: ProbeId, cwd: &Path, target: Option<&str>) -> Option<Self> {
        let (description, program, args, evidence_kind) = match id {
            ProbeId::Listeners => {
                #[cfg(target_os = "linux")]
                let command = ("ss", vec!["-ltnp".into()]);
                #[cfg(target_os = "macos")]
                let command = (
                    "lsof",
                    vec!["-nP".into(), "-iTCP".into(), "-sTCP:LISTEN".into()],
                );
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                return None;
                ("TCP listeners", command.0, command.1, "listener")
            }
            ProbeId::Hosts => {
                let host = target.filter(|s| valid_name(s))?;
                #[cfg(target_os = "linux")]
                let command = ("getent", vec!["hosts".into(), host.into()]);
                #[cfg(target_os = "macos")]
                let command = (
                    "dscacheutil",
                    vec![
                        "-q".into(),
                        "host".into(),
                        "-a".into(),
                        "name".into(),
                        host.into(),
                    ],
                );
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                return None;
                ("host resolution", command.0, command.1, "host")
            }
            ProbeId::Route => {
                #[cfg(target_os = "linux")]
                let command = ("ip", vec!["route".into()]);
                #[cfg(target_os = "macos")]
                let command = ("route", vec!["-n".into(), "get".into(), "default".into()]);
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                return None;
                ("routing table", command.0, command.1, "route")
            }
            ProbeId::Filesystem => {
                let path = target?;
                (
                    "filesystem usage",
                    "df",
                    vec!["-P".into(), "--".into(), path.into()],
                    "usage",
                )
            }
            ProbeId::FilesystemInodes => {
                let path = target?;
                (
                    "filesystem inode usage",
                    "df",
                    vec!["-Pi".into(), "--".into(), path.into()],
                    "inode-usage",
                )
            }
            ProbeId::Stat => {
                let path = target?;
                #[cfg(target_os = "linux")]
                let args = vec![
                    "-c".into(),
                    "%F|%a|%U|%G|%n".into(),
                    "--".into(),
                    path.into(),
                ];
                #[cfg(target_os = "macos")]
                let args = vec![
                    "-f".into(),
                    "%HT|%Lp|%Su|%Sg|%N".into(),
                    "--".into(),
                    path.into(),
                ];
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                return None;
                ("file metadata", "stat", args, "metadata")
            }
            #[cfg(feature = "counterfactual-replay")]
            ProbeId::UnixListeners => {
                #[cfg(target_os = "linux")]
                {
                    let path = target.filter(|path| valid_unix_socket_path(path))?;
                    (
                        "Unix domain socket listeners",
                        "ss",
                        vec!["-xlnH".into(), "src".into(), path.into()],
                        "unix-listener",
                    )
                }
                #[cfg(not(target_os = "linux"))]
                return None;
            }
            ProbeId::Process => {
                let pid = target?.parse::<u32>().ok()?.to_string();
                (
                    "process",
                    "ps",
                    vec!["-p".into(), pid, "-o".into(), "pid=,comm=".into()],
                    "process",
                )
            }
            ProbeId::DockerRunning => (
                "running containers",
                "docker",
                vec!["ps".into(), "--format".into(), "{{json .}}".into()],
                "container",
            ),
            ProbeId::DockerAll => (
                "all containers",
                "docker",
                vec![
                    "ps".into(),
                    "-a".into(),
                    "--format".into(),
                    "{{json .}}".into(),
                ],
                "container",
            ),
            ProbeId::DockerInspect => {
                let name = target.filter(|s| valid_name(s))?;
                (
                    "container state and bindings",
                    "docker",
                    vec![
                        "inspect".into(),
                        "--format".into(),
                        "{{json .State}}|{{json .HostConfig.PortBindings}}|{{.Name}}".into(),
                        name.into(),
                    ],
                    "container-state",
                )
            }
            ProbeId::DockerLogs => {
                let name = target.filter(|s| valid_name(s))?;
                (
                    "recent container logs",
                    "docker",
                    vec!["logs".into(), "--tail".into(), "40".into(), name.into()],
                    "container-log",
                )
            }
            ProbeId::SystemdShow => {
                #[cfg(not(target_os = "linux"))]
                return None;
                let unit = target.filter(|unit| valid_systemd_service(unit))?;
                (
                    "systemd unit state",
                    "systemctl",
                    vec![
                        "show".into(),
                        "--no-pager".into(),
                        "--property=Id,LoadState,ActiveState,Result,InvocationID".into(),
                        "--".into(),
                        unit.into(),
                    ],
                    "unit-state",
                )
            }
            ProbeId::SystemdLogs => {
                #[cfg(not(target_os = "linux"))]
                return None;
                let mut parts = target?.split('|');
                let (Some(unit), Some(invocation), Some(start), Some(end), None) = (
                    parts.next(),
                    parts.next(),
                    parts.next(),
                    parts.next(),
                    parts.next(),
                ) else {
                    return None;
                };
                let (start_time, end_time) = (start.parse::<u64>().ok()?, end.parse::<u64>().ok()?);
                if !valid_systemd_service(unit)
                    || invocation.len() != 32
                    || !invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || end_time < start_time
                    || end_time - start_time > 3600
                {
                    return None;
                }
                (
                    "bounded unit journal for the failed invocation",
                    "journalctl",
                    vec![
                        format!("--unit={unit}"),
                        format!("--since=@{start_time}"),
                        format!("--until=@{end_time}"),
                        "--lines=40".into(),
                        "--no-pager".into(),
                        "--output=cat".into(),
                        "--quiet".into(),
                        format!("_SYSTEMD_INVOCATION_ID={invocation}"),
                    ],
                    "unit-log",
                )
            }
            ProbeId::GitStatus => (
                "repository status",
                "git",
                vec!["status".into(), "--short".into()],
                "changes",
            ),
            ProbeId::GitDiff => (
                "change summary",
                "git",
                vec!["diff".into(), "--no-ext-diff".into(), "--stat".into()],
                "changes",
            ),
            ProbeId::CargoCheck => return None,
            ProbeId::GitPorcelain => (
                "repository conflicts and branch status",
                "git",
                vec!["status".into(), "--porcelain=v2".into(), "--branch".into()],
                "git-status",
            ),
            ProbeId::GitBranch => (
                "current branch",
                "git",
                vec!["branch".into(), "--show-current".into()],
                "git-branch",
            ),
            ProbeId::GitUpstream => (
                "configured upstream",
                "git",
                vec![
                    "rev-parse".into(),
                    "--abbrev-ref".into(),
                    "--symbolic-full-name".into(),
                    "@{u}".into(),
                ],
                "git-upstream",
            ),
            ProbeId::GitTopLevel => (
                "repository root",
                "git",
                vec!["rev-parse".into(), "--show-toplevel".into()],
                "git-root",
            ),
            ProbeId::GitRemote => (
                "configured remote names",
                "git",
                vec!["remote".into()],
                "git-remote",
            ),
        };
        let useful_for: &'static [&'static str] = match id {
            ProbeId::Listeners => &["port_owner", "no_local_listener"],
            ProbeId::Hosts | ProbeId::Route => &["remote_connectivity"],
            ProbeId::Filesystem | ProbeId::FilesystemInodes => &["filesystem_full"],
            ProbeId::Stat => &["file_absent", "permission_mismatch", "docker_daemon"],
            #[cfg(feature = "counterfactual-replay")]
            ProbeId::UnixListeners => &[],
            ProbeId::Process => &["port_owner"],
            ProbeId::DockerRunning => &["container_exited", "docker_port_conflict"],
            ProbeId::DockerAll | ProbeId::DockerInspect => &["container_exited"],
            ProbeId::DockerLogs => &["missing_env", "container_exited"],
            ProbeId::SystemdShow | ProbeId::SystemdLogs => &["service_failed"],
            ProbeId::GitStatus | ProbeId::GitDiff => &["recent_changes"],
            ProbeId::CargoCheck => return None,
            ProbeId::GitPorcelain
            | ProbeId::GitBranch
            | ProbeId::GitUpstream
            | ProbeId::GitTopLevel
            | ProbeId::GitRemote => &["git_context"],
        };
        Some(Self {
            id,
            description,
            program,
            args,
            cwd: cwd.to_path_buf(),
            timeout: Duration::from_millis(500),
            safety: ProbeSafety::Safe,
            evidence_kind,
            useful_for,
        })
    }
}

#[cfg(all(feature = "counterfactual-replay", target_os = "linux"))]
fn valid_unix_socket_path(path: &str) -> bool {
    Path::new(path).is_absolute()
        && path.len() <= 107
        && !path.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) fn systemd_unit(name: &str) -> Option<String> {
    let unit = if name.ends_with(".service") {
        name.to_owned()
    } else {
        format!("{name}.service")
    };
    valid_systemd_service(&unit).then_some(unit)
}

fn valid_systemd_service(unit: &str) -> bool {
    unit.len() <= 128
        && unit.strip_suffix(".service").is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'-')
                })
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub truncated: bool,
}

impl ProbeOutput {
    pub fn ok(&self) -> bool {
        self.exit_code == Some(0) && !self.truncated
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("probe is not authorized for automatic execution")]
    Unsafe,
    #[error("probe exceeded its deadline")]
    Timeout,
    #[error("probe unavailable: {0}")]
    Unavailable(#[from] io::Error),
}

/// A single seam for fixture-driven tests and real local execution.
pub trait ProbeRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError>;

    fn available(&self, program: &str) -> bool {
        executable_on_path(program)
    }
}

/// Returns whether `program` names an executable file found through `PATH`.
pub fn executable_on_path(program: &str) -> bool {
    if program.is_empty() || program.contains(std::path::MAIN_SEPARATOR) {
        return false;
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| {
        let candidate = directory.join(program);
        if !candidate.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            candidate
                .metadata()
                .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            true
        }
    })
}

pub struct LocalProbeRunner;

impl ProbeRunner for LocalProbeRunner {
    fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        let log_target = if spec.id == ProbeId::SystemdLogs {
            (|| {
                let unit = spec.args.first()?.strip_prefix("--unit=")?;
                let start = spec.args.get(1)?.strip_prefix("--since=@")?;
                let end = spec.args.get(2)?.strip_prefix("--until=@")?;
                let invocation = spec.args.last()?.strip_prefix("_SYSTEMD_INVOCATION_ID=")?;
                Some(format!("{unit}|{invocation}|{start}|{end}"))
            })()
        } else {
            None
        };
        let target = match spec.id {
            ProbeId::Process => spec.args.get(1).map(String::as_str),
            ProbeId::Hosts
            | ProbeId::Filesystem
            | ProbeId::FilesystemInodes
            | ProbeId::Stat
            | ProbeId::DockerInspect
            | ProbeId::DockerLogs
            | ProbeId::SystemdShow => spec.args.last().map(String::as_str),
            ProbeId::SystemdLogs => log_target.as_deref(),
            #[cfg(feature = "counterfactual-replay")]
            ProbeId::UnixListeners => spec.args.last().map(String::as_str),
            _ => None,
        };
        let expected = ProbeSpec::new(spec.id, &spec.cwd, target);
        if spec.safety != ProbeSafety::Safe
            || !expected.as_ref().is_some_and(|expected| {
                expected.description == spec.description
                    && expected.program == spec.program
                    && expected.args == spec.args
                    && expected.evidence_kind == spec.evidence_kind
                    && expected.useful_for == spec.useful_for
            })
        {
            return Err(ProbeError::Unsafe);
        }

        run_bounded(
            spec.program,
            &spec.args,
            &spec.cwd,
            spec.timeout.min(Duration::from_millis(500)),
        )
    }
}

fn run_bounded(
    program: &str,
    args: &[String],
    cwd: &Path,
    timeout: Duration,
) -> Result<ProbeOutput, ProbeError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let (out_tx, out_rx) = mpsc::sync_channel(1);
    let (err_tx, err_rx) = mpsc::sync_channel(1);
    let stdout_limit = 16 * 1024;
    thread::spawn(move || {
        let _ = out_tx.send(drain_stream_bounded(stdout, stdout_limit));
    });
    thread::spawn(move || {
        let _ = err_tx.send(drain_stream_bounded(stderr, 4 * 1024));
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                #[cfg(unix)]
                terminate_process_group(child.id());
                break Ok(status);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                terminate_process_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                break Err(ProbeError::Timeout);
            }
            Err(error) => {
                terminate_process_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                break Err(ProbeError::Unavailable(error));
            }
        }
    };
    let status = status?;
    // Never block on a pipe inherited by a child that escaped the process group.
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let stdout = out_rx
        .recv_timeout(remaining())
        .map_err(|_| ProbeError::Timeout)??;
    let stderr = err_rx
        .recv_timeout(remaining())
        .map_err(|_| ProbeError::Timeout)??;
    let truncated =
        stdout.contains(" bytes omitted ...]") || stderr.contains(" bytes omitted ...]");
    Ok(ProbeOutput {
        stdout,
        stderr,
        exit_code: status.code(),
        truncated,
    })
}

#[cfg(unix)]
fn terminate_process_group(pid: u32) {
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;
    let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: ProbeId, target: Option<&str>) -> ProbeSpec {
        ProbeSpec::new(id, Path::new("."), target).expect("probe supported on this platform")
    }

    #[test]
    fn cargo_check_cannot_run_as_an_automatic_probe() {
        assert!(ProbeSpec::new(ProbeId::CargoCheck, Path::new("."), None).is_none());

        let forged = ProbeSpec {
            id: ProbeId::CargoCheck,
            description: "Rust compile diagnostics",
            program: "cargo",
            args: vec![
                "check".into(),
                "--offline".into(),
                "--message-format=json".into(),
            ],
            cwd: Path::new(".").to_path_buf(),
            timeout: Duration::from_secs(12),
            safety: ProbeSafety::Safe,
            evidence_kind: "compiler-diagnostic",
            useful_for: &["rust_compile_error"],
        };
        assert!(matches!(
            LocalProbeRunner.run(&forged),
            Err(ProbeError::Unsafe)
        ));
    }

    #[test]
    fn rejects_flag_injection_and_forged_probe_args() {
        assert!(ProbeSpec::new(
            ProbeId::DockerInspect,
            Path::new("."),
            Some("--format=evil")
        )
        .is_none());
        assert!(ProbeSpec::new(ProbeId::Hosts, Path::new("."), Some("foo;echo evil")).is_none());
        let mut forged = spec(ProbeId::GitDiff, None);
        forged.args.push("--output=/tmp/surprise".into());
        assert!(matches!(
            LocalProbeRunner.run(&forged),
            Err(ProbeError::Unsafe)
        ));
    }

    #[test]
    fn rejects_forged_program_and_non_safe_policy() {
        let runner = LocalProbeRunner;
        let mut forged = spec(ProbeId::GitStatus, None);
        forged.program = "definitely-not-a-catalog-program";
        assert!(matches!(runner.run(&forged), Err(ProbeError::Unsafe)));
        for safety in [ProbeSafety::RequiresConfirmation, ProbeSafety::Forbidden] {
            let mut blocked = spec(ProbeId::GitStatus, None);
            blocked.safety = safety;
            assert!(matches!(runner.run(&blocked), Err(ProbeError::Unsafe)));
        }
    }

    #[test]
    fn probe_timeout_is_bounded() {
        // `sleep` is present on supported Unix development systems. Skip only if PATH
        // intentionally excludes it; this exercises the same bounded lifecycle used by
        // catalog commands without adding a production test-only probe.
        if !executable_on_path("sleep") {
            return;
        }
        let started = Instant::now();
        let result = run_bounded(
            "sleep",
            &["2".into()],
            Path::new("."),
            Duration::from_millis(30),
        );
        assert!(matches!(result, Err(ProbeError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[cfg(all(feature = "counterfactual-replay", target_os = "linux"))]
    #[test]
    fn unix_listener_probe_is_fixed_and_validates_pathname_bounds() {
        let valid = ProbeSpec::new(
            ProbeId::UnixListeners,
            Path::new("/fixture"),
            Some("/tmp/example.sock"),
        )
        .expect("valid pathname");
        assert_eq!(valid.program, "ss");
        assert_eq!(
            valid.args,
            vec![
                "-xlnH".to_owned(),
                "src".to_owned(),
                "/tmp/example.sock".to_owned()
            ]
        );
        assert_eq!(valid.timeout, Duration::from_millis(500));
        assert_eq!(valid.safety, ProbeSafety::Safe);
        assert!(!valid.args.iter().any(|arg| arg == "-p" || arg == "-K"));

        let max_length_path = format!("/{}", "x".repeat(106));
        assert_eq!(max_length_path.len(), 107);
        assert!(ProbeSpec::new(
            ProbeId::UnixListeners,
            Path::new("/fixture"),
            Some(&max_length_path)
        )
        .is_some());

        for invalid in [
            "relative.sock".to_owned(),
            "/tmp/new\nline.sock".to_owned(),
            "/tmp/new\rline.sock".to_owned(),
            "/tmp/nul\0sock".to_owned(),
            format!("/{}", "x".repeat(107)),
        ] {
            assert!(
                ProbeSpec::new(
                    ProbeId::UnixListeners,
                    Path::new("/fixture"),
                    Some(&invalid)
                )
                .is_none(),
                "accepted an invalid pathname"
            );
        }
        assert!(ProbeSpec::new(ProbeId::UnixListeners, Path::new("/fixture"), None).is_none());
    }
}
