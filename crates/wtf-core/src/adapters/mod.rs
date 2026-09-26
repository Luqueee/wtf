//! Read-only reconstruction of failures recorded without terminal output.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::capture::CommandExecution;
use crate::investigation::ProbeAttempt;
use crate::probes::{ProbeId, ProbeOutput, ProbeRunner, ProbeSpec};

mod cargo;
mod curl;
mod docker;
mod docker_port;
mod git;
mod systemd;

#[derive(Debug, Clone)]
pub struct AdapterEvidence {
    pub probe: ProbeId,
    pub observation: String,
}

#[derive(Debug, Clone)]
pub enum Finding {
    CargoError {
        code: Option<String>,
        message: String,
        file: String,
        line: u64,
        column: u64,
    },
    GitNoUpstream {
        branch: String,
    },
    GitDetached,
    GitConflicts,
    CurlNoListener {
        port: u16,
    },
    CurlDnsFailure {
        host: String,
    },
    DockerExited {
        name: String,
        code: i64,
        oom: bool,
    },
    DockerMissingEnv {
        name: String,
        variable: String,
    },
    DockerMissingBind {
        name: String,
    },
    DockerPortOccupied {
        owner: String,
        port: u16,
    },
    DockerDaemonUnavailable,
    SystemdUnitNotFound {
        unit: String,
    },
    SystemdFailed {
        unit: String,
        cause: Option<&'static str>,
    },
}

#[derive(Debug, Default, Clone)]
pub struct AdapterResult {
    pub evidence: Vec<AdapterEvidence>,
    pub finding: Option<Finding>,
    pub note: Option<String>,
}

pub struct AdapterContext<'a, R> {
    runner: &'a R,
    cwd: &'a Path,
    max_probes: usize,
    deadline: Instant,
    pub attempts: Vec<ProbeAttempt>,
}

impl<'a, R: ProbeRunner> AdapterContext<'a, R> {
    pub fn new(runner: &'a R, cwd: &'a Path, max_probes: usize, duration: Duration) -> Self {
        Self {
            runner,
            cwd,
            max_probes,
            deadline: Instant::now() + duration,
            attempts: Vec::new(),
        }
    }

    /// A closed probe catalogue enforces program/argv, timeout, and output bounds.
    pub fn run(&mut self, id: ProbeId, target: Option<&str>) -> Option<ProbeOutput> {
        if self.attempts.len() >= self.max_probes || Instant::now() >= self.deadline {
            return None;
        }
        let mut spec = ProbeSpec::new(id, self.cwd, target)?;
        if !self.runner.available(spec.program) {
            self.attempts.push(ProbeAttempt {
                probe: id,
                result: "unavailable".into(),
            });
            return None;
        }
        spec.timeout = spec
            .timeout
            .min(self.deadline.saturating_duration_since(Instant::now()));
        if spec.timeout.is_zero() {
            return None;
        }
        let output = self.runner.run(&spec);
        self.attempts.push(ProbeAttempt {
            probe: id,
            result: match &output {
                Ok(out) if out.ok() => "ok".into(),
                Ok(out) if out.truncated => "truncated".into(),
                Ok(out) => format!(
                    "exit {}",
                    out.exit_code
                        .map_or_else(|| "signal".into(), |c| c.to_string())
                ),
                Err(err) => err.to_string(),
            },
        });
        output.ok()
    }
}

pub(crate) fn curl_host(args: &[String]) -> Option<String> {
    curl::request_target(args).map(|(host, _, _)| host)
}
pub(crate) fn docker_targeted_error(stderr: &str) -> bool {
    docker::bind_mount_error(stderr).is_some()
        || docker_port::is_port_error(stderr)
        || docker::is_daemon_error(stderr)
}

pub fn select(failure: &CommandExecution) -> Option<&'static str> {
    if failure.is_success() {
        return None;
    }
    let basename = Path::new(&failure.command).file_name()?.to_str()?;
    if basename == "systemctl" {
        return Some("systemctl");
    }
    if basename == "docker" && docker_targeted_error(&failure.stderr) {
        return Some("docker");
    }
    if !failure.stdout.is_empty() || !failure.stderr.is_empty() {
        return None;
    }
    match basename {
        "cargo" => Some("cargo"),
        "git" => Some("git"),
        "curl" => Some("curl"),
        "docker" => Some("docker"),
        _ => None,
    }
}

pub fn collect<R: ProbeRunner>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'_, R>,
) -> Option<(&'static str, AdapterResult)> {
    let id = select(failure)?;
    let result = match id {
        "cargo" => cargo::collect(failure, context),
        "git" => git::collect(failure, context),
        "curl" => curl::collect(failure, context),
        "docker" => docker::collect(failure, context),
        "systemctl" => systemd::collect(failure, context),
        _ => unreachable!(),
    };
    Some((id, result))
}
