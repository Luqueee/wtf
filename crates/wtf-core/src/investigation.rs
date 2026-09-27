use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::adapters::{self, AdapterContext, AdapterResult, Finding};
use crate::capture::CommandExecution;
use crate::diagnosis::Diagnosis;
use crate::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSpec};

#[cfg(feature = "counterfactual-replay")]
use crate::probes::ProbeSafety;

static MISSING_VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([A-Z][A-Z0-9_]*_[A-Z0-9_]+)\s+(?:is\s+)?(?:required|missing|not\s+set)\b|\b(?:missing|required)(?:\s+required)?\s+(?:environment\s+variable\s*:\s*)?([A-Z][A-Z0-9_]*_[A-Z0-9_]+)\b").expect("valid environment variable pattern")
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HypothesisStatus {
    Candidate,
    Likely,
    Confirmed,
    Rejected,
}
#[derive(Debug, Clone, Serialize)]
pub struct Hypothesis {
    pub id: &'static str,
    pub confidence: f32,
    pub evidence_for: Vec<String>,
    pub evidence_against: Vec<String>,
    pub status: HypothesisStatus,
}
#[derive(Debug, Clone, Serialize)]
pub struct ProbeEvidence {
    pub probe: ProbeId,
    pub source: String,
    pub observation: String,
    pub observed_at: std::time::SystemTime,
}
#[derive(Debug, Clone, Serialize)]
pub struct ProbeAttempt {
    pub probe: ProbeId,
    pub result: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Investigation {
    pub root_cause: Option<String>,
    pub cause: Option<String>,
    pub evidence: Vec<ProbeEvidence>,
    pub hypotheses: Vec<Hypothesis>,
    pub attempts: Vec<ProbeAttempt>,
    pub remedy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconstruction_note: Option<String>,
}

/// The ready probes and stable label for a disk-scoped counterfactual replay.
#[cfg(feature = "counterfactual-replay")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskReplayPoint {
    pub category: &'static str,
    pub hypothesis_id: &'static str,
    pub offered: [ProbeId; 2],
}

/// The safe evidence alternatives reached after a failed Git upstream lookup.
#[cfg(feature = "counterfactual-replay")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitReplayPoint {
    pub offered: [ProbeId; 2],
    pub prior: Vec<GitReplayPrior>,
}

/// Coarse status of a probe actually attempted before the Git replay point.
#[cfg(feature = "counterfactual-replay")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitReplayPrior {
    pub probe: ProbeId,
    pub outcome: &'static str,
}

/// The choice point and interpretation from one counterfactual Git replay.
#[cfg(feature = "counterfactual-replay")]
#[derive(Debug, Clone)]
pub struct GitReplayResult {
    pub point: GitReplayPoint,
    pub investigation: Investigation,
}

/// Current observations from the experimental Unix-socket replay.
#[cfg(feature = "counterfactual-replay")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UnixSocketObservation {
    ListenerAndSocket,
    /// A current socket inode has no matching listener; this is not a historical cause.
    SocketWithoutListener,
    Neither,
    Inconsistent,
    Unknown,
}

/// Path-free result of interpreting the two fixed Unix-socket probes.
#[cfg(feature = "counterfactual-replay")]
#[derive(Debug, Clone)]
pub struct UnixSocketReplayResult {
    pub offered: [ProbeId; 2],
    pub investigation: Investigation,
    pub observation: UnixSocketObservation,
}

impl Investigation {
    fn candidate(&mut self, id: &'static str) {
        if !self.hypotheses.iter().any(|h| h.id == id) {
            self.hypotheses.push(Hypothesis {
                id,
                confidence: 0.2,
                evidence_for: Vec::new(),
                evidence_against: Vec::new(),
                status: HypothesisStatus::Candidate,
            });
        }
    }

    fn support(&mut self, id: &'static str, fact: &str, confirmed: bool) {
        if let Some(h) = self.hypotheses.iter_mut().find(|h| h.id == id) {
            h.evidence_for.push(fact.to_owned());
            h.confidence = if confirmed { 1.0 } else { 0.7 };
            h.status = if confirmed {
                HypothesisStatus::Confirmed
            } else {
                HypothesisStatus::Likely
            };
        }
    }

    fn reject(&mut self, id: &'static str, fact: &str) {
        if let Some(h) = self.hypotheses.iter_mut().find(|h| h.id == id) {
            h.evidence_against.push(fact.to_owned());
            h.confidence = 0.0;
            h.status = HypothesisStatus::Rejected;
        }
    }

    fn record(&mut self, id: ProbeId, observation: String) {
        self.evidence.push(ProbeEvidence {
            probe: id,
            source: probe_label(id).into(),
            observation,
            observed_at: std::time::SystemTime::now(),
        });
    }

    fn apply_finding(&mut self, finding: Finding, diagnosis: &mut Diagnosis) {
        let (hypothesis, category, summary, root) = match finding {
            Finding::GitNoUpstream { branch } => (
                "git_no_upstream",
                "git/upstream",
                "Git push failed.".into(),
                Some(format!(
                    "Branch {} has no upstream configured.",
                    safe_observation(&branch)
                )),
            ),
            Finding::GitDetached => (
                "git_detached",
                "git/detached",
                "Git operation failed.".into(),
                Some("HEAD is detached; no branch is checked out.".into()),
            ),
            Finding::GitConflicts => (
                "git_conflicts",
                "git/conflicts",
                "Git operation failed.".into(),
                Some("Unresolved merge conflicts are present.".into()),
            ),
            Finding::CurlNoListener { port } => {
                if !diagnosis.entities.ports.contains(&port) {
                    diagnosis.entities.ports.insert(0, port);
                }
                self.candidate("no_local_listener");
                self.support(
                    "no_local_listener",
                    &format!("no listener on :{port}"),
                    false,
                );
                diagnosis.category = Some("network/no-local-listener".into());
                diagnosis.summary = format!("Nothing is listening on port {port}.");
                diagnosis.remedy = None;
                diagnosis.status = crate::diagnosis::DiagnosisStatus::Likely;
                return;
            }
            Finding::CurlDnsFailure { host } => {
                diagnosis.category = Some("network/dns".into());
                diagnosis.summary = format!("curl could not resolve {}.", safe_observation(&host));
                diagnosis.status = crate::diagnosis::DiagnosisStatus::Likely;
                return;
            }
            Finding::DockerExited { name, code, oom } => {
                let name = safe_observation(&name);
                let root = if oom {
                    format!("Container \"{name}\" was killed by the OOM killer.")
                } else {
                    format!("Container \"{name}\" exited with status {code}.")
                };
                (
                    "container_exited",
                    "container/exited",
                    "Docker container is not running.".into(),
                    Some(root),
                )
            }
            Finding::DockerMissingEnv { name, variable } => {
                let name = safe_observation(&name);
                let variable = safe_observation(&variable);
                (
                    "missing_env",
                    "container/configuration",
                    "Docker container failed to start.".into(),
                    Some(format!("Container \"{name}\" requires {variable}.")),
                )
            }
            Finding::DockerMissingBind { name } => {
                let name = safe_observation(&name);
                (
                    "docker_missing_bind",
                    "container/mount",
                    format!("Docker could not create container \"{name}\"."),
                    Some(format!(
                        "The bind source requested for container \"{name}\" does not exist."
                    )),
                )
            }
            Finding::DockerPortOccupied { owner, port } => {
                let owner = safe_observation(&owner);
                if !diagnosis.entities.ports.contains(&port) {
                    diagnosis.entities.ports.insert(0, port);
                }
                (
                    "docker_port_conflict",
                    "container/port-conflict",
                    format!("Docker could not publish host TCP port {port}."),
                    Some(format!(
                        "Running container \"{owner}\" already publishes host TCP port {port}."
                    )),
                )
            }
            Finding::DockerDaemonUnavailable => (
                "docker_daemon",
                "container/daemon",
                "Docker cannot reach its local daemon.".into(),
                Some("The reported local Docker Unix socket does not exist.".into()),
            ),
            Finding::SystemdUnitNotFound { unit } => {
                let unit = safe_observation(&unit);
                (
                    "service_not_found",
                    "service/not-found",
                    format!("Service {unit} could not be started."),
                    Some(format!("Service unit {unit} was not found.")),
                )
            }
            Finding::SystemdFailed { unit, cause } => {
                let unit = safe_observation(&unit);
                diagnosis.category = Some("service/failed".into());
                diagnosis.summary = format!("Service {unit} failed to start.");
                if let Some(cause) = cause {
                    let root =
                        format!("Service unit {unit} reported {cause} during the failed start.");
                    self.candidate("service_failed");
                    self.support("service_failed", &root, true);
                    self.root_cause = Some(root);
                    diagnosis.status = crate::diagnosis::DiagnosisStatus::Confirmed;
                } else {
                    self.candidate("service_failed");
                    self.support(
                        "service_failed",
                        "the requested unit is in a failed state",
                        false,
                    );
                    diagnosis.status = crate::diagnosis::DiagnosisStatus::Likely;
                }
                return;
            }
        };
        diagnosis.category = Some(category.into());
        diagnosis.summary = summary;
        if let Some(root) = root {
            self.candidate(hypothesis);
            self.support(hypothesis, &root, true);
            self.root_cause = Some(root);
            diagnosis.status = crate::diagnosis::DiagnosisStatus::Confirmed;
        }
    }
}

fn safe_observation(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(300)
        .collect()
}

fn probe_label(id: ProbeId) -> &'static str {
    match id {
        ProbeId::Listeners => {
            if cfg!(target_os = "macos") {
                "lsof"
            } else {
                "ss"
            }
        }
        ProbeId::Hosts => "getent hosts",
        ProbeId::Route => {
            if cfg!(target_os = "macos") {
                "route"
            } else {
                "ip route"
            }
        }
        ProbeId::Filesystem => "df",
        ProbeId::FilesystemInodes => "df -i",
        ProbeId::Stat => "stat",
        #[cfg(feature = "counterfactual-replay")]
        ProbeId::UnixListeners => "ss -xlnH src",
        ProbeId::Process => "ps",
        ProbeId::DockerRunning => "docker ps",
        ProbeId::DockerAll => "docker ps -a",
        ProbeId::DockerInspect => "docker inspect",
        ProbeId::DockerLogs => "docker logs",
        ProbeId::SystemdShow => "systemctl show",
        ProbeId::SystemdLogs => "journalctl",
        ProbeId::GitStatus => "git status",
        ProbeId::GitDiff => "git diff",
        ProbeId::CargoCheck => "cargo check",
        ProbeId::GitPorcelain => "git status --porcelain=v2 --branch",
        ProbeId::GitBranch => "git branch --show-current",
        ProbeId::GitUpstream => "git rev-parse @{u}",
        ProbeId::GitTopLevel => "git rev-parse --show-toplevel",
        ProbeId::GitRemote => "git remote",
    }
}

/// Only fixed recipes can produce a displayed remedy. No remedy is executed.
fn recipe(id: &'static str) -> Option<&'static str> {
    match id {
        "port_owner" => Some("Stop the listener deliberately or choose another port."),
        "filesystem_full" => Some("Inspect filesystem usage and free space deliberately."),
        "container_exited" => {
            Some("Review the container logs and restart only after addressing the failure.")
        }
        "missing_env" => {
            Some("Set the required variable in the container configuration before restarting.")
        }
        _ => None,
    }
}

pub struct InvestigationEngine<R> {
    runner: R,
    max_probes: usize,
    max_duration: Duration,
}

impl<R: ProbeRunner> InvestigationEngine<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            max_probes: 5,
            max_duration: Duration::from_secs(2),
        }
    }

    pub fn with_budget(runner: R, max_probes: usize, max_duration: Duration) -> Self {
        Self {
            runner,
            max_probes,
            max_duration,
        }
    }

    /// Runs the fixed Unix-socket evidence probes in either order for an isolated replay.
    ///
    /// This is experimental, not an engine-offered runtime choice under SPEC section 7.
    /// It records only probe attempts and a coarse current observation, never raw output or path.
    #[cfg(feature = "counterfactual-replay")]
    pub fn replay_unix_socket_first(
        &self,
        cwd: &Path,
        target: &Path,
        first: ProbeId,
    ) -> Option<UnixSocketReplayResult> {
        if self.max_probes == 0 || self.max_duration.is_zero() {
            return None;
        }
        let target = target.to_str()?;
        let offered = [ProbeId::Stat, ProbeId::UnixListeners];
        if !offered.contains(&first) {
            return None;
        }
        for id in offered {
            let spec = ProbeSpec::new(id, cwd, Some(target))?;
            if spec.safety != ProbeSafety::Safe || !self.runner.available(spec.program) {
                return None;
            }
        }

        let deadline = Instant::now() + self.max_duration.min(Duration::from_secs(2));
        let second = offered.into_iter().find(|probe| *probe != first)?;
        let mut investigation = Investigation::default();
        let mut stat_observation = None;
        let mut listener_observation = None;
        for id in [first, second] {
            let Some(output) =
                self.probe_output(&mut investigation, cwd, id, Some(target), deadline, true)
            else {
                continue;
            };
            match id {
                ProbeId::Stat => {
                    stat_observation = parse_unix_socket_stat(&output, target);
                }
                ProbeId::UnixListeners => {
                    listener_observation = parse_unix_listener_output(&output, target);
                }
                _ => unreachable!("the offered Unix-socket probes are fixed"),
            }
        }
        let observation = match (stat_observation, listener_observation) {
            (Some(UnixSocketStat::Socket), Some(true)) => UnixSocketObservation::ListenerAndSocket,
            (Some(UnixSocketStat::Socket), Some(false)) => {
                UnixSocketObservation::SocketWithoutListener
            }
            (Some(UnixSocketStat::Missing), Some(true))
            | (Some(UnixSocketStat::Other), Some(true)) => UnixSocketObservation::Inconsistent,
            (Some(UnixSocketStat::Missing | UnixSocketStat::Other), Some(false)) => {
                UnixSocketObservation::Neither
            }
            _ => UnixSocketObservation::Unknown,
        };
        Some(UnixSocketReplayResult {
            offered,
            investigation,
            observation,
        })
    }

    /// Describes the disk probes that are ready for an offline replay.
    ///
    /// This only checks probe readiness; it never runs either probe.
    #[cfg(feature = "counterfactual-replay")]
    pub fn disk_replay_point(
        &self,
        execution: &CommandExecution,
        diagnosis: &Diagnosis,
    ) -> Option<DiskReplayPoint> {
        if execution.is_success()
            || diagnosis.category.as_deref() != Some("filesystem/disk-full")
            || self.max_probes == 0
            || self.max_duration.is_zero()
        {
            return None;
        }

        let cwd = execution.cwd.as_path();
        let path = disk_probe_path(diagnosis, cwd);
        let target = path.to_string_lossy();
        let offered = [ProbeId::Filesystem, ProbeId::FilesystemInodes];
        if offered[0] == offered[1] {
            return None;
        }

        for id in offered {
            let spec = ProbeSpec::new(id, cwd, Some(target.as_ref()))?;
            if spec.safety != ProbeSafety::Safe || !self.runner.available(spec.program) {
                return None;
            }
        }

        Some(DiskReplayPoint {
            category: "filesystem/disk-full",
            hypothesis_id: "filesystem_full",
            offered,
        })
    }

    /// Replays the disk evidence interpretation with the selected first probe.
    #[cfg(feature = "counterfactual-replay")]
    pub fn replay_disk_first(
        &self,
        execution: &CommandExecution,
        diagnosis: &Diagnosis,
        first: ProbeId,
    ) -> Option<Investigation> {
        let point = self.disk_replay_point(execution, diagnosis)?;
        if !point.offered.contains(&first) {
            return None;
        }

        let second = point.offered.into_iter().find(|probe| *probe != first)?;
        let mut result = Investigation::default();
        let path = disk_diagnostic_path(diagnosis, &execution.cwd);
        self.disk_ordered(
            &mut result,
            &execution.cwd,
            Instant::now() + self.max_duration,
            path,
            [first, second],
        );
        Some(result)
    }

    /// Replays the Git no-upstream interpretation with a selected first evidence probe.
    ///
    /// This is available only for failed, output-free `git push` executions with no
    /// explicit remote arguments. It reaches the choice point through the real Git
    /// adapter, then changes only the order of the two safe follow-up probes.
    #[cfg(feature = "counterfactual-replay")]
    pub fn replay_git_first(
        &self,
        execution: &CommandExecution,
        diagnosis: &mut Diagnosis,
        first: ProbeId,
    ) -> Option<GitReplayResult> {
        if execution.is_success()
            || execution.spawn_error.is_some()
            || !execution.stdout.is_empty()
            || !execution.stderr.is_empty()
            || Path::new(&execution.command)
                .file_name()
                .and_then(|name| name.to_str())
                != Some("git")
            || execution.args.len() != 1
            || execution.args[0] != "push"
            || !matches!(first, ProbeId::GitRemote | ProbeId::GitPorcelain)
        {
            return None;
        }

        let mut context = AdapterContext::new(
            &self.runner,
            &execution.cwd,
            self.max_probes,
            self.max_duration,
        );
        let (adapter_result, point) = adapters::collect_git_replay(execution, &mut context, first);
        let point = point?;

        let mut investigation = Investigation {
            adapter: Some("git"),
            attempts: context.attempts,
            ..Investigation::default()
        };
        let AdapterResult {
            evidence,
            finding,
            note,
        } = adapter_result;
        for item in evidence {
            investigation.record(item.probe, safe_observation(&item.observation));
        }
        investigation.reconstruction_note = note.map(|text| safe_observation(&text));
        if let Some(finding) = finding {
            investigation.apply_finding(finding, diagnosis);
        }
        Some(GitReplayResult {
            point,
            investigation,
        })
    }

    fn probe(
        &self,
        result: &mut Investigation,
        cwd: &Path,
        id: ProbeId,
        target: Option<&str>,
        deadline: Instant,
    ) -> Option<ProbeOutput> {
        self.probe_output(result, cwd, id, target, deadline, false)
    }

    fn probe_output(
        &self,
        result: &mut Investigation,
        cwd: &Path,
        id: ProbeId,
        target: Option<&str>,
        deadline: Instant,
        coarse_errors: bool,
    ) -> Option<ProbeOutput> {
        if result.attempts.len() >= self.max_probes
            || result.attempts.iter().any(|attempt| attempt.probe == id)
            || Instant::now() >= deadline
        {
            return None;
        }
        let mut spec = ProbeSpec::new(id, cwd, target)?;
        if !self.runner.available(spec.program) {
            result.attempts.push(ProbeAttempt {
                probe: id,
                result: "unavailable".into(),
            });
            return None;
        }
        spec.timeout = spec
            .timeout
            .min(deadline.saturating_duration_since(Instant::now()));
        if spec.timeout.is_zero() {
            return None;
        }
        let output = self.runner.run(&spec);
        result.attempts.push(ProbeAttempt {
            probe: id,
            result: match &output {
                Ok(out) if out.ok() => "ok".into(),
                Ok(out) if out.truncated => "truncated".into(),
                Ok(out) => format!(
                    "exit {}",
                    out.exit_code
                        .map_or_else(|| "signal".into(), |code| code.to_string())
                ),
                Err(ProbeError::Timeout) if coarse_errors => "timeout".into(),
                Err(ProbeError::Unsafe) if coarse_errors => "unsafe".into(),
                Err(ProbeError::Unavailable(_)) if coarse_errors => "unavailable".into(),
                Err(error) => error.to_string(),
            },
        });
        output.ok()
    }

    /// Reconstruct output-free shell failures without replaying the failed action.
    /// The existing investigation remains the owner of hypotheses and evidence.
    pub fn investigate_reconstructed(
        &self,
        execution: &CommandExecution,
        diagnosis: &mut Diagnosis,
    ) -> Investigation {
        let original_diagnosis = diagnosis.clone();
        let deadline = Instant::now() + self.max_duration;
        let (adapter_result, attempts) = {
            let mut context = AdapterContext::with_deadline(
                &self.runner,
                &execution.cwd,
                self.max_probes,
                deadline,
            );
            let adapter_result = adapters::collect(execution, &mut context);
            (adapter_result, context.attempts)
        };
        let mut result = Investigation {
            attempts,
            ..Investigation::default()
        };
        let adapter = if let Some((adapter, finding)) = adapter_result {
            result.adapter = Some(adapter);
            let AdapterResult {
                evidence,
                finding,
                note,
            } = finding;
            for item in evidence {
                result.record(item.probe, safe_observation(&item.observation));
            }
            result.reconstruction_note = note.map(|text| safe_observation(&text));
            if adapter == "docker" && adapters::docker_targeted_error(&execution.stderr) {
                // Only synthesized evidence belongs to this finding; captured output remains
                // accessible through the explicit capture fields, not reclassified as proof.
                diagnosis.evidence.clear();
                diagnosis.detection = None;
                diagnosis.remedy = None;
            }
            if let Some(finding) = finding {
                result.apply_finding(finding, diagnosis);
            } else if adapter == "systemctl" {
                // Captured stderr is a symptom, not evidence for a service root cause.
                diagnosis.category = Some("unknown".into());
                diagnosis.summary = "The service failure could not be verified.".into();
                diagnosis.status = crate::diagnosis::DiagnosisStatus::Unknown;
            } else if adapter == "docker" && adapters::docker_targeted_error(&execution.stderr) {
                // A daemon message alone, or contradictory current state, is not proof.
                diagnosis.category = Some("unknown".into());
                diagnosis.summary = "The Docker failure could not be verified.".into();
                diagnosis.status = crate::diagnosis::DiagnosisStatus::Unknown;
            }
            Some(adapter)
        } else {
            None
        };

        // A Docker daemon error is about the adapter's exact run target. Its
        // textual paths/ports may disagree with argv; generic detectors cannot
        // safely infer a second target from that message and confirm it.
        if !(adapter == Some("docker") && adapters::docker_targeted_error(&execution.stderr)) {
            self.investigate_with_deadline(
                execution,
                &original_diagnosis,
                &mut result,
                deadline,
                adapter,
            );
        }
        if adapter.is_none()
            && execution.stdout.is_empty()
            && execution.stderr.is_empty()
            && result.attempts.is_empty()
        {
            if let Some(path) = literal_cat_path(execution) {
                self.cat_path(execution, &mut result, path, deadline);
            }
        }
        if adapter.is_some()
            && diagnosis.status == crate::diagnosis::DiagnosisStatus::Unknown
            && result.root_cause.is_none()
            && result.reconstruction_note.is_none()
        {
            result.reconstruction_note =
                Some("The original failure could not be reconstructed safely.".into());
        }
        result
    }

    pub fn investigate(
        &self,
        execution: &CommandExecution,
        diagnosis: &Diagnosis,
    ) -> Investigation {
        let mut result = Investigation::default();
        let deadline = Instant::now() + self.max_duration;
        self.investigate_with_deadline(execution, diagnosis, &mut result, deadline, None);
        result
    }

    fn investigate_with_deadline(
        &self,
        execution: &CommandExecution,
        diagnosis: &Diagnosis,
        result: &mut Investigation,
        deadline: Instant,
        adapter: Option<&'static str>,
    ) {
        if execution.is_success() {
            return;
        }
        let cwd = execution.cwd.as_path();
        let docker_targeted_error =
            adapter == Some("docker") && adapters::docker_targeted_error(&execution.stderr);
        match diagnosis.category.as_deref() {
            Some("network/port-conflict")
            | Some("network/connection-refused")
            | Some("network/connect-failed") => {
                if !docker_targeted_error {
                    self.network(
                        execution,
                        diagnosis,
                        result,
                        cwd,
                        deadline,
                        adapter != Some("docker"),
                    );
                }
            }
            Some("network/dns") => self.dns(execution, result, cwd, deadline),
            Some("filesystem/disk-full") => self.disk(diagnosis, result, cwd, deadline),
            Some("filesystem/not-found") | Some("filesystem/permission-denied") => {
                self.file(diagnosis, result, cwd, deadline);
            }
            _ => {
                // Docker's adapter verifies exact targets; do not widen that reconstruction
                // into a second, uncorrelated current-state scan.
                if command_basename(&execution.command) == "docker" && adapter != Some("docker") {
                    self.docker(execution, diagnosis, result, cwd, deadline, false);
                }
            }
        }
    }

    fn dns(
        &self,
        execution: &CommandExecution,
        result: &mut Investigation,
        cwd: &Path,
        deadline: Instant,
    ) {
        if command_basename(&execution.command) != "curl" {
            return;
        }
        let Some(host) = adapters::curl_host(&execution.args) else {
            return;
        };
        if host.parse::<std::net::IpAddr>().is_ok() {
            return;
        }
        // Only inspect the URL's host if curl reported that same host.
        let reported = execution
            .stderr
            .lines()
            .chain(execution.stdout.lines())
            .find_map(crate::detectors::dns_failure::reported_host);
        if !reported.is_some_and(|reported| reported.eq_ignore_ascii_case(&host)) {
            return;
        }
        result.candidate("current_resolution_failure");
        if let Some(out) = self.probe(result, cwd, ProbeId::Hosts, Some(&host), deadline) {
            if out.truncated {
                return;
            }
            if out.ok() && !out.stdout.trim().is_empty() {
                let fact = "the hostname currently resolves locally";
                result.record(ProbeId::Hosts, fact.into());
                result.reject("current_resolution_failure", fact);
            } else if out.exit_code == Some(2) || (out.ok() && out.stdout.trim().is_empty()) {
                let fact = "the local lookup returned no address";
                result.record(ProbeId::Hosts, fact.into());
                result.support("current_resolution_failure", fact, false);
            }
        }
    }

    fn network(
        &self,
        execution: &CommandExecution,
        diagnosis: &Diagnosis,
        result: &mut Investigation,
        cwd: &Path,
        deadline: Instant,
        allow_docker_investigation: bool,
    ) {
        let port = match diagnosis.entities.primary_port() {
            Some(p) => p,
            None => return,
        };
        let conflict = diagnosis.category.as_deref() == Some("network/port-conflict");
        let docker_command = command_basename(&execution.command) == "docker";
        result.candidate("port_owner");
        result.candidate("no_local_listener");
        if docker_command {
            result.candidate("container_exited");
        }
        let host = target_host(execution);
        // A remote target's local listener state says nothing about its availability.
        if !conflict
            && host
                .as_deref()
                .is_some_and(|h| !matches!(h, "localhost" | "127.0.0.1" | "::1" | "[::1]"))
        {
            result.candidate("remote_connectivity");
            if let Some(host) = host.as_deref() {
                if let Some(out) = self.probe(result, cwd, ProbeId::Hosts, Some(host), deadline) {
                    if out.ok() && !out.stdout.trim().is_empty() {
                        result.record(ProbeId::Hosts, "hostname resolves locally".into());
                        result.support("remote_connectivity", "hostname resolves locally", false);
                    }
                }
            }
            if let Some(out) = self.probe(result, cwd, ProbeId::Route, None, deadline) {
                if out.ok() {
                    result.record(
                        ProbeId::Route,
                        "routing information available; connectivity not established".into(),
                    );
                }
            }
            return;
        }
        if let Some(out) = self.probe(result, cwd, ProbeId::Listeners, None, deadline) {
            if out.ok() {
                match parse_listener(&out.stdout, port) {
                    Some(listener) => {
                        let fact = format!(
                            "{} is listening on {}",
                            listener.name.as_deref().unwrap_or("a process"),
                            listener.address
                        );
                        result.record(ProbeId::Listeners, fact.clone());
                        result.reject("no_local_listener", &fact);
                        if conflict {
                            if let Some(pid) = listener.pid {
                                // Verify the PID still exists before naming an owner.
                                if let Some(ps) = self.probe(
                                    result,
                                    cwd,
                                    ProbeId::Process,
                                    Some(&pid.to_string()),
                                    deadline,
                                ) {
                                    if ps.ok()
                                        && ps
                                            .stdout
                                            .split_whitespace()
                                            .next()
                                            .and_then(|word| word.parse::<u32>().ok())
                                            == Some(pid)
                                    {
                                        let name = listener.name.as_deref().unwrap_or("A process");
                                        result.root_cause = Some(format!(
                                            "{name} (PID {pid}) is listening on {}.",
                                            listener.address
                                        ));
                                        result.support("port_owner", &fact, true);
                                        result.remedy = recipe("port_owner").map(str::to_owned);
                                    }
                                }
                            }
                        } else if docker_command {
                            result.reject("container_exited", "a local listener now exists");
                        }
                        return;
                    }
                    None => {
                        let fact = format!("no local TCP listener on :{port}");
                        result.record(ProbeId::Listeners, fact.clone());
                        result.support("no_local_listener", &fact, true);
                        result.reject("port_owner", &fact);
                    }
                }
            }
        }
        if !conflict && docker_command && allow_docker_investigation {
            self.docker(execution, diagnosis, result, cwd, deadline, true);
        }
    }

    fn disk(
        &self,
        diagnosis: &Diagnosis,
        result: &mut Investigation,
        cwd: &Path,
        deadline: Instant,
    ) {
        self.disk_ordered(
            result,
            cwd,
            deadline,
            disk_diagnostic_path(diagnosis, cwd),
            [ProbeId::Filesystem, ProbeId::FilesystemInodes],
        );
    }

    fn disk_ordered(
        &self,
        result: &mut Investigation,
        cwd: &Path,
        deadline: Instant,
        path: PathBuf,
        order: [ProbeId; 2],
    ) {
        result.candidate("filesystem_full");
        let existing = existing_ancestor(&path);
        let target = existing.to_string_lossy();
        let mut below_full_blocks: Option<String> = None;
        let mut below_full_inodes: Option<String> = None;

        for probe in order {
            let Some(out) = self.probe(result, cwd, probe, Some(&target), deadline) else {
                continue;
            };
            if !out.ok() {
                continue;
            }
            let Some((pct, mount)) = parse_df(&out.stdout, probe) else {
                continue;
            };

            let fact = match probe {
                ProbeId::Filesystem => format!("filesystem {mount} is {pct}% used"),
                ProbeId::FilesystemInodes => {
                    format!("filesystem {mount} has {pct}% of inodes used")
                }
                _ => continue,
            };
            result.record(probe, fact.clone());
            if pct >= 100 {
                result.root_cause = Some(match probe {
                    ProbeId::Filesystem => format!(
                        "Filesystem containing {} is {pct}% full (mounted at {mount}).",
                        path.display()
                    ),
                    ProbeId::FilesystemInodes => format!(
                        "Filesystem containing {} has exhausted its inodes (mounted at {mount}).",
                        path.display()
                    ),
                    _ => unreachable!(),
                });
                result.support("filesystem_full", &fact, true);
                result.remedy = recipe("filesystem_full").map(str::to_owned);
                return;
            }

            match probe {
                ProbeId::Filesystem => below_full_blocks = Some(mount.to_owned()),
                ProbeId::FilesystemInodes => below_full_inodes = Some(mount.to_owned()),
                _ => continue,
            }
            if let (Some(block_mount), Some(inode_mount)) = (&below_full_blocks, &below_full_inodes)
            {
                if block_mount == inode_mount {
                    result.reject(
                        "filesystem_full",
                        "both block and inode capacity are below full on the same filesystem",
                    );
                }
            }
        }
    }

    fn cat_path(
        &self,
        execution: &CommandExecution,
        result: &mut Investigation,
        path: &str,
        deadline: Instant,
    ) {
        if let Some(out) = self.probe(result, &execution.cwd, ProbeId::Stat, Some(path), deadline) {
            if out.ok() {
                if parse_stat(&out.stdout).is_some() {
                    result.record(ProbeId::Stat, format!("{path} exists"));
                }
            } else if !out.truncated && out.stderr.to_lowercase().contains("no such file") {
                result.record(ProbeId::Stat, format!("{path} does not exist"));
            }
        }
    }

    fn file(
        &self,
        diagnosis: &Diagnosis,
        result: &mut Investigation,
        cwd: &Path,
        deadline: Instant,
    ) {
        let path = match diagnosis.entities.primary_path() {
            Some(path) => path,
            None => return,
        };
        let target = if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        };
        let id = if diagnosis.category.as_deref() == Some("filesystem/not-found") {
            "file_absent"
        } else {
            "permission_mismatch"
        };
        result.candidate(id);
        if let Some(out) = self.probe(
            result,
            cwd,
            ProbeId::Stat,
            Some(&target.to_string_lossy()),
            deadline,
        ) {
            if out.ok() {
                if let Some((kind, mode, owner, group)) = parse_stat(&out.stdout) {
                    let fact = format!(
                        "{}: {kind}, mode {mode}, owner {owner}:{group}",
                        target.display()
                    );
                    result.record(ProbeId::Stat, fact.clone());
                    result.reject("file_absent", &fact);
                    // Metadata alone does not prove a permission mismatch for this user.
                    if id == "permission_mismatch" {
                        result.support(id, &fact, false);
                    }
                }
            } else if out.stderr.to_lowercase().contains("no such file") {
                let fact = format!("{} does not exist", target.display());
                result.record(ProbeId::Stat, fact.clone());
                if id == "file_absent" {
                    result.root_cause = Some(format!("{} does not exist.", target.display()));
                    result.support(id, &fact, true);
                }
            }
        }
    }

    fn docker(
        &self,
        execution: &CommandExecution,
        diagnosis: &Diagnosis,
        result: &mut Investigation,
        cwd: &Path,
        deadline: Instant,
        network: bool,
    ) {
        if !self.runner.available("docker") {
            return;
        }
        result.candidate("container_exited");
        result.candidate("missing_env");
        let name = explicit_docker_name(execution);
        let port = if network {
            diagnosis.entities.primary_port()
        } else {
            None
        };
        // First establish whether the container is running. An unrelated container is not evidence.
        let Some(running) = self
            .probe(result, cwd, ProbeId::DockerRunning, None, deadline)
            .filter(|out| out.ok())
        else {
            return;
        };
        let running_match = matching_container(&running.stdout, name.as_deref(), port);
        if let Some(container) = running_match {
            result.record(
                ProbeId::DockerRunning,
                format!("{} is running", container.name),
            );
            result.reject("container_exited", "matched container is running");
            return;
        }
        let all = self.probe(result, cwd, ProbeId::DockerAll, None, deadline);
        let candidate = all
            .as_ref()
            .filter(|out| out.ok())
            .and_then(|out| matching_container(&out.stdout, name.as_deref(), port));
        let Some(container) = candidate else { return };
        if !container.status.to_lowercase().contains("exited") {
            return;
        }
        let Some(inspect) = self.probe(
            result,
            cwd,
            ProbeId::DockerInspect,
            Some(&container.name),
            deadline,
        ) else {
            return;
        };
        if !inspect.ok() {
            return;
        }
        let Some(state) = parse_inspect(&inspect.stdout, port) else {
            return;
        };
        if !state.exited {
            return;
        }
        let fact = format!("{} exited ({})", container.name, state.exit_code);
        result.record(ProbeId::DockerAll, fact.clone());
        result.record(
            ProbeId::DockerInspect,
            if port.is_some() {
                "container state and published port verified".into()
            } else {
                "container state verified".into()
            },
        );
        result.support("container_exited", &fact, true);
        result.root_cause = Some(format!(
            "Container \"{}\" is not running (exited {}).",
            container.name, state.exit_code
        ));
        result.remedy = recipe("container_exited").map(str::to_owned);
        if let Some(logs) = self.probe(
            result,
            cwd,
            ProbeId::DockerLogs,
            Some(&container.name),
            deadline,
        ) {
            if logs.ok() {
                if let Some(cause) = known_log_cause(&format!("{}\n{}", logs.stdout, logs.stderr)) {
                    result.record(ProbeId::DockerLogs, cause.evidence);
                    result.cause = Some(cause.summary);
                    result.remedy = recipe(cause.recipe).map(str::to_owned);
                    result.support(cause.recipe, "known error in recent container logs", true);
                }
            }
        }
    }
}

fn command_basename(command: &str) -> &str {
    Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command)
}

fn disk_diagnostic_path(diagnosis: &Diagnosis, cwd: &Path) -> PathBuf {
    diagnosis
        .entities
        .primary_path()
        .map(|path| {
            if path.is_absolute() {
                path.clone()
            } else {
                cwd.join(path)
            }
        })
        .unwrap_or_else(|| cwd.to_path_buf())
}

#[cfg(feature = "counterfactual-replay")]
fn disk_probe_path(diagnosis: &Diagnosis, cwd: &Path) -> PathBuf {
    existing_ancestor(&disk_diagnostic_path(diagnosis, cwd))
}

fn existing_ancestor(path: &Path) -> PathBuf {
    path.ancestors()
        .find(|p| p.exists())
        .unwrap_or(Path::new("/"))
        .to_path_buf()
}

fn target_host(execution: &CommandExecution) -> Option<String> {
    // A URL's authority is a target; arbitrary flags (such as Docker -p) are not.
    execution
        .args
        .iter()
        .filter_map(|arg| {
            let (_, rest) = arg.split_once("://")?;
            let authority = rest.split('/').next()?.rsplit('@').next()?;
            let host = if authority.starts_with('[') {
                authority.split_once(']')?.0
            } else {
                authority.split(':').next()?
            };
            (!host.is_empty()).then(|| host.to_owned())
        })
        .next()
}

struct Listener {
    name: Option<String>,
    pid: Option<u32>,
    address: String,
}
fn parse_listener(output: &str, port: u16) -> Option<Listener> {
    let needle = format!(":{port}");
    for line in output.lines() {
        if line.starts_with("LISTEN ") || line.starts_with("LISTEN\t") {
            let address = line.split_whitespace().nth(3)?;
            if !address.ends_with(&needle) {
                continue;
            }
            let pid = line
                .split("pid=")
                .nth(1)
                .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|s| s.parse().ok());
            let name = line
                .split("users:((\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .map(str::to_owned);
            return Some(Listener {
                name,
                pid,
                address: address.to_owned(),
            });
        }
        // macOS lsof: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        if !line.contains("(LISTEN)") {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        let pid = fields.next().and_then(|s| s.parse().ok());
        let address = line.split_whitespace().find(|s| s.ends_with(&needle));
        if let Some(address) = address {
            return Some(Listener {
                name: Some(name.to_owned()),
                pid,
                address: address.to_owned(),
            });
        }
    }
    None
}

fn parse_df(output: &str, probe: ProbeId) -> Option<(u16, &str)> {
    let mut lines = output.lines();
    let expected_column = match probe {
        ProbeId::Filesystem => "Capacity",
        ProbeId::FilesystemInodes => "IUse%",
        _ => return None,
    };
    let mut header = lines.next()?.split_whitespace();
    if header.next()? != "Filesystem"
        || header.nth(3)? != expected_column
        || header.next()? != "Mounted"
        || header.next()? != "on"
        || header.next().is_some()
    {
        return None;
    }
    let mut fields = lines.next()?.split_whitespace();
    fields.next()?;
    for _ in 0..3 {
        fields.next()?.parse::<u64>().ok()?;
    }
    let pct = fields.next()?.strip_suffix('%')?.parse::<u16>().ok()?;
    let mount = fields.next()?;
    if fields.next().is_some() || lines.any(|line| !line.trim().is_empty()) {
        return None;
    }
    Some((pct, mount))
}

fn literal_cat_path(execution: &CommandExecution) -> Option<&str> {
    if execution.is_success()
        || execution.spawn_error.is_some()
        || command_basename(&execution.command) != "cat"
        || execution.args.len() != 1
    {
        return None;
    }
    let path = execution.args[0].as_str();
    (path.len() <= 4096
        && path.starts_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')))
    .then_some(path)
}

fn parse_stat(output: &str) -> Option<(&str, &str, &str, &str)> {
    let mut fields = output.trim().split('|');
    Some((
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
    ))
}

#[cfg(feature = "counterfactual-replay")]
#[derive(Debug, Clone, Copy)]
enum UnixSocketStat {
    Socket,
    Other,
    Missing,
}

#[cfg(feature = "counterfactual-replay")]
fn parse_unix_socket_stat(output: &ProbeOutput, target: &str) -> Option<UnixSocketStat> {
    if output.truncated {
        return None;
    }
    if output.exit_code == Some(0) && output.stderr.is_empty() {
        let line = single_probe_line(&output.stdout)?;
        let mut fields = line.splitn(5, '|');
        let kind = fields.next()?;
        let mode = fields.next()?;
        let owner = fields.next()?;
        let group = fields.next()?;
        let path = fields.next()?;
        if kind.is_empty()
            || mode.is_empty()
            || !mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
            || owner.is_empty()
            || group.is_empty()
            || path != target
        {
            return None;
        }
        return Some(if kind == "socket" {
            UnixSocketStat::Socket
        } else {
            UnixSocketStat::Other
        });
    }
    if output.exit_code == Some(1) && output.stdout.is_empty() {
        let line = single_probe_line(&output.stderr)?;
        let path = line
            .strip_prefix("stat: cannot statx '")
            .or_else(|| line.strip_prefix("stat: cannot stat '"))?
            .strip_suffix("': No such file or directory")?;
        return (path == target).then_some(UnixSocketStat::Missing);
    }
    None
}

#[cfg(feature = "counterfactual-replay")]
fn parse_unix_listener_output(output: &ProbeOutput, target: &str) -> Option<bool> {
    if output.exit_code != Some(0) || output.truncated || !output.stderr.is_empty() {
        return None;
    }
    if output.stdout.is_empty() {
        return Some(false);
    }

    let mut found = false;
    for line in output.stdout.lines() {
        let mut fields = line.split_whitespace();
        let netid = fields.next()?;
        let state = fields.next()?;
        let recv_queue = fields.next()?;
        let send_queue = fields.next()?;
        let local_address = fields.next()?;
        let _peer_address = fields.next()?;
        if !matches!(netid, "u_str" | "u_dgr" | "u_seq")
            || !matches!(state, "LISTEN" | "UNCONN")
            || recv_queue.parse::<u64>().is_err()
            || send_queue.parse::<u64>().is_err()
            || local_address.is_empty()
        {
            return None;
        }
        found |= local_address == target;
    }
    Some(found)
}

#[cfg(feature = "counterfactual-replay")]
fn single_probe_line(output: &str) -> Option<&str> {
    let line = output.strip_suffix('\n').unwrap_or(output);
    (!line.is_empty() && !line.bytes().any(|byte| matches!(byte, b'\n' | b'\r'))).then_some(line)
}

#[derive(Debug)]
struct Container {
    name: String,
    status: String,
}
fn matching_container(
    output: &str,
    explicit: Option<&str>,
    port: Option<u16>,
) -> Option<Container> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|row| {
            let name = row.get("Names")?.as_str()?.trim_start_matches('/');
            let ports = row.get("Ports").and_then(Value::as_str).unwrap_or("");
            let matches = if let Some(expected) = explicit {
                expected == name
            } else {
                port.is_some_and(|p| {
                    ports.split(',').any(|binding| {
                        binding
                            .trim()
                            .split("->")
                            .next()
                            .is_some_and(|s| s.ends_with(&format!(":{p}")))
                    })
                })
            };
            if matches {
                Some(Container {
                    name: name.to_owned(),
                    status: row.get("Status")?.as_str()?.to_owned(),
                })
            } else {
                None
            }
        })
}

fn explicit_docker_name(execution: &CommandExecution) -> Option<String> {
    if command_basename(&execution.command) != "docker" {
        return None;
    }
    for pair in execution.args.windows(2) {
        if pair[0] == "--name" {
            return Some(pair[1].clone());
        }
    }
    match execution.args.first().map(String::as_str) {
        Some("start" | "stop" | "restart" | "logs" | "inspect") => execution
            .args
            .iter()
            .skip(1)
            .find(|s| !s.starts_with('-'))
            .cloned(),
        _ => None,
    }
}

struct ContainerState {
    exited: bool,
    exit_code: i64,
}
fn parse_inspect(output: &str, port: Option<u16>) -> Option<ContainerState> {
    let mut parts = output.trim().splitn(3, '|');
    let state: Value = serde_json::from_str(parts.next()?).ok()?;
    let bindings: Value = serde_json::from_str(parts.next()?).ok()?;
    let _name = parts.next()?;
    if port.is_some_and(|p| {
        !bindings.as_object().is_some_and(|map| {
            map.values().any(|entries| {
                entries.as_array().is_some_and(|list| {
                    list.iter().any(|entry| {
                        entry
                            .get("HostPort")
                            .and_then(Value::as_str)
                            .is_some_and(|s| s == p.to_string())
                    })
                })
            })
        })
    }) {
        return None;
    }
    Some(ContainerState {
        exited: state.get("Status")?.as_str()? == "exited",
        exit_code: state.get("ExitCode")?.as_i64()?,
    })
}

struct LogCause {
    summary: String,
    evidence: String,
    recipe: &'static str,
}
fn known_log_cause(log: &str) -> Option<LogCause> {
    for line in log.lines().rev() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("no space left on device") {
            return Some(LogCause {
                summary: "Container logs report no space left on device.".into(),
                evidence: "No space left on device".into(),
                recipe: "filesystem_full",
            });
        }
        if lower.contains("address already in use") {
            return Some(LogCause {
                summary: "Container logs report a port conflict.".into(),
                evidence: "address already in use".into(),
                recipe: "port_owner",
            });
        }
        if lower.contains("permission denied") {
            return Some(LogCause {
                summary: "Container logs report permission denied.".into(),
                evidence: "permission denied".into(),
                recipe: "container_exited",
            });
        }
        if let Some(captures) = MISSING_VARIABLE.captures(line) {
            let var = captures
                .get(1)
                .or_else(|| captures.get(2))
                .map(|m| m.as_str());
            if let Some(var) = var.filter(|s| {
                s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            }) {
                return Some(LogCause {
                    summary: format!("{var} is missing."),
                    evidence: format!("{var} is required"),
                    recipe: "missing_env",
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::known_log_cause;

    #[test]
    fn missing_variable_must_be_tied_to_error_phrase() {
        assert_eq!(
            known_log_cause("DATABASE_URL is present, PASSWORD_RESET_URL is missing")
                .unwrap()
                .summary,
            "PASSWORD_RESET_URL is missing."
        );
        assert_eq!(
            known_log_cause("Missing required environment variable: DATABASE_URL")
                .unwrap()
                .summary,
            "DATABASE_URL is missing."
        );
        assert!(known_log_cause("DATABASE_URL set; startup complete").is_none());
    }
}

#[cfg(all(test, feature = "counterfactual-replay"))]
mod disk_replay_tests {
    use super::*;
    use crate::capture::ProcessExit;
    use crate::diagnosis::DiagnosisEngine;
    use crate::probes::ProbeError;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::time::SystemTime;

    struct FixtureRunner {
        responses: HashMap<ProbeId, ProbeOutput>,
        calls: RefCell<Vec<ProbeId>>,
        unavailable: Option<&'static str>,
    }

    impl ProbeRunner for FixtureRunner {
        fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
            self.calls.borrow_mut().push(spec.id);
            self.responses
                .get(&spec.id)
                .cloned()
                .ok_or_else(|| ProbeError::Unavailable(std::io::Error::other("no fixture")))
        }

        fn available(&self, program: &str) -> bool {
            self.unavailable != Some(program)
        }
    }

    fn fixture_runner(block_pct: u16, inode_pct: u16) -> FixtureRunner {
        FixtureRunner {
            responses: HashMap::from([
                (
                    ProbeId::Filesystem,
                    df_output(ProbeId::Filesystem, block_pct, "/fixture"),
                ),
                (
                    ProbeId::FilesystemInodes,
                    df_output(ProbeId::FilesystemInodes, inode_pct, "/fixture"),
                ),
            ]),
            calls: RefCell::new(Vec::new()),
            unavailable: None,
        }
    }

    fn df_output(probe: ProbeId, pct: u16, mount: &str) -> ProbeOutput {
        let (header, blocks, used, available) = match probe {
            ProbeId::Filesystem => (
                "Filesystem 1024-blocks Used Available Capacity Mounted on",
                100,
                pct,
                100 - pct,
            ),
            ProbeId::FilesystemInodes => (
                "Filesystem Inodes IUsed IFree IUse% Mounted on",
                100,
                pct,
                100 - pct,
            ),
            _ => unreachable!(),
        };
        ProbeOutput {
            stdout: format!("{header}\n/dev/fixture {blocks} {used} {available} {pct}% {mount}\n"),
            stderr: String::new(),
            exit_code: Some(0),
            truncated: false,
        }
    }

    fn failed_disk_execution() -> (tempfile::TempDir, CommandExecution, Diagnosis) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("not-created");
        let execution = CommandExecution {
            command: "cp".into(),
            args: vec!["source".into(), target.to_string_lossy().into_owned()],
            cwd: directory.path().to_path_buf(),
            exit_status: ProcessExit {
                code: Some(1),
                signal: None,
            },
            stdout: String::new(),
            stderr: format!(
                "cp: error writing '{}': No space left on device",
                target.display()
            ),
            duration: Duration::from_millis(1),
            timestamp: SystemTime::now(),
            spawn_error: None,
        };
        let diagnosis = DiagnosisEngine::new().diagnose(&execution);
        (directory, execution, diagnosis)
    }

    fn hypothesis_status(investigation: &Investigation) -> Option<HypothesisStatus> {
        investigation
            .hypotheses
            .iter()
            .find(|hypothesis| hypothesis.id == "filesystem_full")
            .map(|hypothesis| hypothesis.status)
    }

    #[test]
    fn below_full_rejects_disk_hypothesis_in_both_probe_orders() {
        let (_directory, execution, diagnosis) = failed_disk_execution();
        assert_eq!(diagnosis.category.as_deref(), Some("filesystem/disk-full"));

        for first in [ProbeId::Filesystem, ProbeId::FilesystemInodes] {
            let runner = fixture_runner(50, 50);
            let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));
            let result = engine
                .replay_disk_first(&execution, &diagnosis, first)
                .expect("offered first probe");

            let second = if first == ProbeId::Filesystem {
                ProbeId::FilesystemInodes
            } else {
                ProbeId::Filesystem
            };
            assert_eq!(
                result
                    .attempts
                    .iter()
                    .map(|attempt| attempt.probe)
                    .collect::<Vec<_>>(),
                vec![first, second]
            );
            assert_eq!(hypothesis_status(&result), Some(HypothesisStatus::Rejected));
        }
    }

    #[test]
    fn a_full_first_probe_stops_before_the_other_probe_in_either_order() {
        let (_directory, execution, diagnosis) = failed_disk_execution();

        for (first, block_pct, inode_pct, expected_cause) in [
            (ProbeId::Filesystem, 100, 50, "is 100% full"),
            (
                ProbeId::FilesystemInodes,
                50,
                100,
                "has exhausted its inodes",
            ),
        ] {
            let runner = fixture_runner(block_pct, inode_pct);
            let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));
            let result = engine
                .replay_disk_first(&execution, &diagnosis, first)
                .expect("offered first probe");

            assert_eq!(result.attempts.len(), 1);
            assert_eq!(result.attempts[0].probe, first);
            assert!(result
                .root_cause
                .as_deref()
                .is_some_and(|cause| cause.contains(expected_cause)));
            assert_eq!(
                hypothesis_status(&result),
                Some(HypothesisStatus::Confirmed)
            );
        }
    }

    #[test]
    fn replay_requires_an_offered_first_probe() {
        let (_directory, execution, diagnosis) = failed_disk_execution();
        let runner = fixture_runner(50, 50);
        let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));

        assert!(engine
            .replay_disk_first(&execution, &diagnosis, ProbeId::Hosts)
            .is_none());
        assert!(engine.runner.calls.borrow().is_empty());
    }

    #[test]
    fn replay_point_requires_failure_disk_category_positive_budget_and_ready_probes() {
        let (_directory, execution, diagnosis) = failed_disk_execution();
        let runner = fixture_runner(50, 50);
        let engine = InvestigationEngine::with_budget(runner, 1, Duration::from_secs(2));
        let point = engine
            .disk_replay_point(&execution, &diagnosis)
            .expect("ready failed disk diagnosis");
        assert_eq!(point.category, "filesystem/disk-full");
        assert_eq!(point.hypothesis_id, "filesystem_full");
        assert_eq!(
            point.offered,
            [ProbeId::Filesystem, ProbeId::FilesystemInodes]
        );
        assert!(engine.runner.calls.borrow().is_empty());

        let mut success = execution.clone();
        success.exit_status.code = Some(0);
        assert!(engine.disk_replay_point(&success, &diagnosis).is_none());

        let mut other_category = diagnosis.clone();
        other_category.category = Some("filesystem/not-found".into());
        assert!(engine
            .disk_replay_point(&execution, &other_category)
            .is_none());

        let zero_probes =
            InvestigationEngine::with_budget(fixture_runner(50, 50), 0, Duration::from_secs(2));
        assert!(zero_probes
            .disk_replay_point(&execution, &diagnosis)
            .is_none());

        let zero_time = InvestigationEngine::with_budget(fixture_runner(50, 50), 1, Duration::ZERO);
        assert!(zero_time
            .disk_replay_point(&execution, &diagnosis)
            .is_none());

        let unavailable = FixtureRunner {
            unavailable: Some("df"),
            ..fixture_runner(50, 50)
        };
        let missing_probe =
            InvestigationEngine::with_budget(unavailable, 1, Duration::from_secs(2));
        assert!(missing_probe
            .disk_replay_point(&execution, &diagnosis)
            .is_none());
    }

    #[test]
    fn default_disk_investigation_keeps_block_then_inode_order() {
        let (_directory, execution, diagnosis) = failed_disk_execution();
        let runner = fixture_runner(50, 50);
        let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));

        let result = engine.investigate(&execution, &diagnosis);

        assert_eq!(
            result
                .attempts
                .iter()
                .map(|attempt| attempt.probe)
                .collect::<Vec<_>>(),
            vec![ProbeId::Filesystem, ProbeId::FilesystemInodes]
        );
        assert_eq!(hypothesis_status(&result), Some(HypothesisStatus::Rejected));
    }

    #[test]
    fn one_probe_budget_stops_early_while_five_allows_same_mount_rejection() {
        let (_directory, execution, diagnosis) = failed_disk_execution();

        for first in [ProbeId::Filesystem, ProbeId::FilesystemInodes] {
            let runner = fixture_runner(50, 50);
            let engine = InvestigationEngine::with_budget(runner, 1, Duration::from_secs(2));
            let result = engine
                .replay_disk_first(&execution, &diagnosis, first)
                .expect("offered first probe");
            assert_eq!(result.attempts.len(), 1);
            assert_eq!(result.attempts[0].probe, first);
            assert_eq!(
                hypothesis_status(&result),
                Some(HypothesisStatus::Candidate)
            );
        }

        let runner = fixture_runner(50, 50);
        let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));
        let result = engine
            .replay_disk_first(&execution, &diagnosis, ProbeId::FilesystemInodes)
            .expect("offered first probe");
        assert_eq!(result.attempts.len(), 2);
        assert_eq!(hypothesis_status(&result), Some(HypothesisStatus::Rejected));
    }
}

#[cfg(all(test, feature = "counterfactual-replay"))]
mod git_replay_tests {
    use super::*;
    use crate::capture::ProcessExit;
    use crate::diagnosis::{DiagnosisEngine, DiagnosisStatus};
    use crate::probes::{ProbeError, ProbeSafety};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::path::Path;
    use std::time::SystemTime;

    struct FixtureRunner {
        responses: HashMap<ProbeId, ProbeOutput>,
        calls: RefCell<Vec<ProbeId>>,
        availability_checks: Cell<usize>,
        unavailable_from: Option<usize>,
    }

    impl ProbeRunner for FixtureRunner {
        fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
            self.calls.borrow_mut().push(spec.id);
            self.responses
                .get(&spec.id)
                .cloned()
                .ok_or_else(|| ProbeError::Unavailable(std::io::Error::other("no fixture")))
        }

        fn available(&self, program: &str) -> bool {
            let check = self.availability_checks.get() + 1;
            self.availability_checks.set(check);
            program == "git" && self.unavailable_from.is_none_or(|from| check < from)
        }
    }

    fn output(stdout: &str, code: i32) -> ProbeOutput {
        ProbeOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: Some(code),
            truncated: false,
        }
    }

    fn fixture_runner(
        remote: &str,
        status: &str,
        upstream_code: i32,
        unavailable_from: Option<usize>,
    ) -> FixtureRunner {
        FixtureRunner {
            responses: HashMap::from([
                (ProbeId::GitTopLevel, output("/repo\n", 0)),
                (ProbeId::GitBranch, output("branch\n", 0)),
                (
                    ProbeId::GitUpstream,
                    output(
                        if upstream_code == 0 {
                            "configured\n"
                        } else {
                            ""
                        },
                        upstream_code,
                    ),
                ),
                (ProbeId::GitRemote, output(remote, 0)),
                (ProbeId::GitPorcelain, output(status, 0)),
            ]),
            calls: RefCell::new(Vec::new()),
            availability_checks: Cell::new(0),
            unavailable_from,
        }
    }

    fn failed_push(cwd: &Path, args: &[&str]) -> CommandExecution {
        CommandExecution {
            command: "git".into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            cwd: cwd.to_path_buf(),
            exit_status: ProcessExit {
                code: Some(128),
                signal: None,
            },
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::from_millis(1),
            timestamp: SystemTime::now(),
            spawn_error: None,
        }
    }

    fn positive_runner(unavailable_from: Option<usize>) -> FixtureRunner {
        fixture_runner(
            "remote\n",
            "# branch.oid commit\n# branch.head branch\n",
            128,
            unavailable_from,
        )
    }

    fn prior_ids() -> [ProbeId; 3] {
        [
            ProbeId::GitTopLevel,
            ProbeId::GitBranch,
            ProbeId::GitUpstream,
        ]
    }

    #[test]
    fn replay_uses_both_probe_orders_with_the_same_four_and_five_probe_budgets() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let execution = failed_push(directory.path(), &["push"]);

        for (budget, confirms) in [(4, false), (5, true)] {
            for first in [ProbeId::GitRemote, ProbeId::GitPorcelain] {
                let runner = positive_runner(None);
                let engine =
                    InvestigationEngine::with_budget(runner, budget, Duration::from_secs(2));
                let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
                let replay = engine
                    .replay_git_first(&execution, &mut diagnosis, first)
                    .expect("failed upstream reaches the replay point");

                assert_eq!(
                    replay.point.offered,
                    [ProbeId::GitRemote, ProbeId::GitPorcelain]
                );
                assert_eq!(
                    replay.point.prior,
                    vec![
                        GitReplayPrior {
                            probe: ProbeId::GitTopLevel,
                            outcome: "available",
                        },
                        GitReplayPrior {
                            probe: ProbeId::GitBranch,
                            outcome: "available",
                        },
                        GitReplayPrior {
                            probe: ProbeId::GitUpstream,
                            outcome: "failed",
                        },
                    ]
                );

                let other = if first == ProbeId::GitRemote {
                    ProbeId::GitPorcelain
                } else {
                    ProbeId::GitRemote
                };
                let mut expected_attempts = prior_ids().to_vec();
                expected_attempts.push(first);
                if budget == 5 {
                    expected_attempts.push(other);
                }
                assert_eq!(
                    replay
                        .investigation
                        .attempts
                        .iter()
                        .map(|attempt| attempt.probe)
                        .collect::<Vec<_>>(),
                    expected_attempts
                );
                assert_eq!(replay.investigation.root_cause.is_some(), confirms);
                assert_eq!(diagnosis.status == DiagnosisStatus::Confirmed, confirms);
            }
        }
    }

    #[test]
    fn prior_records_the_actual_truncated_upstream_attempt() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let execution = failed_push(directory.path(), &["push"]);
        let mut runner = positive_runner(None);
        runner
            .responses
            .get_mut(&ProbeId::GitUpstream)
            .expect("upstream fixture")
            .truncated = true;
        let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));
        let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);

        let replay = engine
            .replay_git_first(&execution, &mut diagnosis, ProbeId::GitRemote)
            .expect("truncated upstream output still reaches the failed-upstream gate");

        assert_eq!(
            replay.point.prior[2],
            GitReplayPrior {
                probe: ProbeId::GitUpstream,
                outcome: "truncated",
            }
        );
    }

    #[test]
    fn remote_or_commit_absence_prevents_a_false_git_no_upstream_root() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let execution = failed_push(directory.path(), &["push"]);
        let cases = [
            ("", "# branch.oid commit\n# branch.head branch\n"),
            ("remote\n", "# branch.oid (initial)\n# branch.head branch\n"),
        ];

        for (remote, status) in cases {
            for first in [ProbeId::GitRemote, ProbeId::GitPorcelain] {
                let runner = fixture_runner(remote, status, 128, None);
                let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));
                let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
                let replay = engine
                    .replay_git_first(&execution, &mut diagnosis, first)
                    .expect("failed upstream reaches the replay point");

                assert!(replay.investigation.root_cause.is_none());
                assert_ne!(diagnosis.category.as_deref(), Some("git/upstream"));
                assert_ne!(diagnosis.status, DiagnosisStatus::Confirmed);
            }
        }
    }

    #[test]
    fn configured_upstream_and_non_push_actions_do_not_reach_the_choice_point() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let execution = failed_push(directory.path(), &["push"]);
        let runner = fixture_runner(
            "remote\n",
            "# branch.oid commit\n# branch.head branch\n",
            0,
            None,
        );
        let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));
        let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);

        assert!(engine
            .replay_git_first(&execution, &mut diagnosis, ProbeId::GitRemote)
            .is_none());
        assert_eq!(
            engine.runner.calls.borrow().as_slice(),
            prior_ids().as_slice()
        );

        let runner = positive_runner(None);
        let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));
        let wrong_action = failed_push(directory.path(), &["fetch"]);
        let mut diagnosis = DiagnosisEngine::new().diagnose(&wrong_action);
        assert!(engine
            .replay_git_first(&wrong_action, &mut diagnosis, ProbeId::GitRemote)
            .is_none());
        assert!(engine.runner.calls.borrow().is_empty());

        let explicit_remote = failed_push(directory.path(), &["push", "remote"]);
        let mut diagnosis = DiagnosisEngine::new().diagnose(&explicit_remote);
        assert!(engine
            .replay_git_first(&explicit_remote, &mut diagnosis, ProbeId::GitRemote)
            .is_none());
        assert!(engine.runner.calls.borrow().is_empty());

        let mut outputful = failed_push(directory.path(), &["push"]);
        outputful.stderr = "captured output".into();
        let mut diagnosis = DiagnosisEngine::new().diagnose(&outputful);
        assert!(engine
            .replay_git_first(&outputful, &mut diagnosis, ProbeId::GitRemote)
            .is_none());
        assert!(engine.runner.calls.borrow().is_empty());

        let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
        assert!(engine
            .replay_git_first(&execution, &mut diagnosis, ProbeId::Hosts)
            .is_none());
        assert!(engine.runner.calls.borrow().is_empty());
    }

    #[test]
    fn choice_point_requires_ready_safe_specs_and_remaining_probe_budget() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let execution = failed_push(directory.path(), &["push"]);
        for id in [ProbeId::GitRemote, ProbeId::GitPorcelain] {
            let spec = ProbeSpec::new(id, &execution.cwd, None).expect("fixed Git spec");
            assert_eq!(spec.program, "git");
            assert_eq!(spec.safety, ProbeSafety::Safe);
        }

        let runner = positive_runner(Some(4));
        let engine = InvestigationEngine::with_budget(runner, 5, Duration::from_secs(2));
        let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
        assert!(engine
            .replay_git_first(&execution, &mut diagnosis, ProbeId::GitRemote)
            .is_none());
        assert_eq!(
            engine.runner.calls.borrow().as_slice(),
            prior_ids().as_slice()
        );

        let runner = positive_runner(None);
        let engine = InvestigationEngine::with_budget(runner, 3, Duration::from_secs(2));
        let mut diagnosis = DiagnosisEngine::new().diagnose(&execution);
        assert!(engine
            .replay_git_first(&execution, &mut diagnosis, ProbeId::GitRemote)
            .is_none());
        assert_eq!(
            engine.runner.calls.borrow().as_slice(),
            prior_ids().as_slice()
        );
    }
}

#[cfg(all(test, feature = "counterfactual-replay", target_os = "linux"))]
mod unix_socket_replay_tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const CWD: &str = "/fixture";
    const TARGET: &str = "/tmp/core-replay.sock";

    struct FixtureRunner {
        outputs: HashMap<ProbeId, ProbeOutput>,
        calls: RefCell<Vec<(ProbeId, Vec<String>, Duration)>>,
        ready: bool,
    }

    impl ProbeRunner for FixtureRunner {
        fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
            assert_eq!(spec.safety, ProbeSafety::Safe);
            let target = spec.args.last().map(String::as_str);
            let expected = ProbeSpec::new(spec.id, &spec.cwd, target)
                .expect("fixed probe spec must be reconstructible");
            assert_eq!(spec.program, expected.program);
            assert_eq!(spec.args, expected.args);
            assert!(spec.timeout <= Duration::from_millis(500));
            self.calls
                .borrow_mut()
                .push((spec.id, spec.args.clone(), spec.timeout));
            self.outputs
                .get(&spec.id)
                .cloned()
                .ok_or_else(|| ProbeError::Unavailable(std::io::Error::other("no fixture")))
        }

        fn available(&self, program: &str) -> bool {
            self.ready && matches!(program, "stat" | "ss")
        }
    }

    fn output(stdout: &str, stderr: &str, exit_code: i32, truncated: bool) -> ProbeOutput {
        ProbeOutput {
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit_code: Some(exit_code),
            truncated,
        }
    }

    fn stat_socket() -> ProbeOutput {
        output(&format!("socket|777|user|group|{TARGET}\n"), "", 0, false)
    }

    fn stat_other() -> ProbeOutput {
        output(
            &format!("regular file|644|user|group|{TARGET}\n"),
            "",
            0,
            false,
        )
    }

    fn stat_missing() -> ProbeOutput {
        output(
            "",
            &format!("stat: cannot statx '{TARGET}': No such file or directory\n"),
            1,
            false,
        )
    }

    fn listener(path: &str) -> ProbeOutput {
        output(&format!("u_str LISTEN 0 128 {path} * 0\n"), "", 0, false)
    }

    fn absent_listener() -> ProbeOutput {
        output("", "", 0, false)
    }

    fn fixture_runner(stat: ProbeOutput, listeners: ProbeOutput, ready: bool) -> FixtureRunner {
        FixtureRunner {
            outputs: HashMap::from([(ProbeId::Stat, stat), (ProbeId::UnixListeners, listeners)]),
            calls: RefCell::new(Vec::new()),
            ready,
        }
    }

    #[test]
    fn both_orders_interpret_complete_pairs_without_confirming_a_root_cause() {
        let cases = [
            (
                stat_socket(),
                listener(TARGET),
                UnixSocketObservation::ListenerAndSocket,
            ),
            (
                stat_socket(),
                listener("/tmp/unrelated.sock"),
                UnixSocketObservation::SocketWithoutListener,
            ),
            (
                stat_missing(),
                absent_listener(),
                UnixSocketObservation::Neither,
            ),
            (
                stat_missing(),
                listener(TARGET),
                UnixSocketObservation::Inconsistent,
            ),
            (
                stat_other(),
                listener(TARGET),
                UnixSocketObservation::Inconsistent,
            ),
        ];
        for first in [ProbeId::Stat, ProbeId::UnixListeners] {
            let second = if first == ProbeId::Stat {
                ProbeId::UnixListeners
            } else {
                ProbeId::Stat
            };
            for (stat, listeners, expected) in &cases {
                let runner = fixture_runner((*stat).clone(), (*listeners).clone(), true);
                let engine = InvestigationEngine::with_budget(runner, 2, Duration::from_secs(2));
                let result = engine
                    .replay_unix_socket_first(Path::new(CWD), Path::new(TARGET), first)
                    .expect("both safe probes are available");
                assert_eq!(result.offered, [ProbeId::Stat, ProbeId::UnixListeners]);
                assert_eq!(result.observation, *expected);
                assert_eq!(
                    result
                        .investigation
                        .attempts
                        .iter()
                        .map(|attempt| attempt.probe)
                        .collect::<Vec<_>>(),
                    vec![first, second]
                );
                assert!(result.investigation.root_cause.is_none());
                assert!(result.investigation.cause.is_none());
                assert!(result.investigation.remedy.is_none());
                assert!(result
                    .investigation
                    .hypotheses
                    .iter()
                    .all(|hypothesis| hypothesis.status != HypothesisStatus::Confirmed));
                let json = serde_json::to_string(&result.investigation).unwrap();
                assert!(!json.contains(TARGET));
                assert!(!json.contains("cannot stat"));
                assert!(!json.contains("regular file|"));
            }
        }
    }

    #[test]
    fn one_probe_budget_is_unknown_in_either_order() {
        for first in [ProbeId::Stat, ProbeId::UnixListeners] {
            let runner = fixture_runner(stat_socket(), listener(TARGET), true);
            let engine = InvestigationEngine::with_budget(runner, 1, Duration::from_secs(2));
            let result = engine
                .replay_unix_socket_first(Path::new(CWD), Path::new(TARGET), first)
                .expect("safe probes are offered despite the one-probe budget");
            assert_eq!(result.observation, UnixSocketObservation::Unknown);
            assert_eq!(result.investigation.attempts.len(), 1);
            assert_eq!(result.investigation.attempts[0].probe, first);
            assert_eq!(engine.runner.calls.borrow().len(), 1);
        }
    }

    #[test]
    fn incomplete_outputs_and_unready_targets_do_not_produce_classifications() {
        let runner = fixture_runner(
            ProbeOutput {
                truncated: true,
                ..stat_socket()
            },
            listener(TARGET),
            true,
        );
        let engine = InvestigationEngine::with_budget(runner, 2, Duration::from_secs(2));
        let result = engine
            .replay_unix_socket_first(Path::new(CWD), Path::new(TARGET), ProbeId::Stat)
            .expect("safe probes are available");
        assert_eq!(result.observation, UnixSocketObservation::Unknown);

        let runner = fixture_runner(stat_socket(), listener(TARGET), false);
        let engine = InvestigationEngine::with_budget(runner, 2, Duration::from_secs(2));
        assert!(engine
            .replay_unix_socket_first(Path::new(CWD), Path::new(TARGET), ProbeId::Stat)
            .is_none());
        assert!(engine.runner.calls.borrow().is_empty());
        assert!(engine
            .replay_unix_socket_first(Path::new(CWD), Path::new("relative.sock"), ProbeId::Stat)
            .is_none());
        assert!(engine
            .replay_unix_socket_first(Path::new(CWD), Path::new(TARGET), ProbeId::Hosts)
            .is_none());
    }
}
