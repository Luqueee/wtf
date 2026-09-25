use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::adapters::{self, AdapterContext, AdapterResult, Finding};
use crate::capture::CommandExecution;
use crate::diagnosis::{Diagnosis, RenderOptions};
use crate::probes::{ProbeId, ProbeOutput, ProbeRunner, ProbeSpec};
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
        });
    }

    fn apply_finding(&mut self, finding: Finding, diagnosis: &mut Diagnosis) {
        let (hypothesis, category, summary, root) = match finding {
            Finding::CargoError {
                code,
                message,
                file,
                line,
                column,
            } => {
                let location = format!("{}:{line}:{column}", safe_observation(&file));
                let detail = safe_observation(&message);
                let code = code.map(|code| safe_observation(&code));
                self.record(
                    ProbeId::CargoCheck,
                    format!(
                        "{}: {detail} at {location}",
                        code.as_deref().unwrap_or("error")
                    ),
                );
                (
                    "rust_compile_error",
                    "compilation/rust",
                    "Rust compilation failed.".to_string(),
                    Some(format!("{detail} in {location}.")),
                )
            }
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
                diagnosis.status = crate::diagnosis::DiagnosisStatus::Likely;
                return;
            }
            Finding::CurlDnsFailure { host } => {
                self.record(
                    ProbeId::Hosts,
                    format!("{} does not resolve", safe_observation(&host)),
                );
                (
                    "dns_resolution",
                    "network/dns",
                    "DNS lookup failed.".into(),
                    None,
                )
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
            Finding::DockerDaemonUnavailable => (
                "docker_daemon",
                "container/daemon",
                "Docker daemon is unavailable.".into(),
                None,
            ),
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

    pub fn render(&self, diagnosis: &Diagnosis, options: &RenderOptions, verbose: bool) -> String {
        if let Some(adapter) = self.adapter {
            let icon = if diagnosis.status == crate::diagnosis::DiagnosisStatus::Confirmed {
                "✗"
            } else {
                "?"
            };
            let mut out = format!("{icon} {}\n", diagnosis.summary);
            if let Some(root) = &self.root_cause {
                out.push_str(&format!("\nRoot cause:\n  {root}\n"));
            } else {
                out.push_str("\nRoot cause not confirmed.\n");
            }
            if !self.evidence.is_empty() {
                out.push_str("\nEvidence:\n");
                for evidence in &self.evidence {
                    out.push_str(&format!(
                        "  {} → {}\n",
                        evidence.source, evidence.observation
                    ));
                }
            }
            if let Some(note) = &self.reconstruction_note {
                out.push_str(&format!("\n{note}\n"));
            }
            if options.show_fix {
                if let Some(remedy) = &self.remedy {
                    out.push_str(&format!("\nFix:\n  {remedy}\n"));
                }
            }
            if verbose {
                out.push_str(&format!("\nAdapter: {adapter}\nProbes:\n"));
                for attempt in &self.attempts {
                    out.push_str(&format!(
                        "  {} → {}\n",
                        probe_label(attempt.probe),
                        attempt.result
                    ));
                }
                out.push_str("\nHypotheses:\n");
                for hypothesis in &self.hypotheses {
                    out.push_str(&format!(
                        "  {} {:?} ({:.0}%)\n",
                        hypothesis.id,
                        hypothesis.status,
                        hypothesis.confidence * 100.0
                    ));
                }
                if self.attempts.len() >= 5 {
                    out.push_str("Investigation stopped at probe budget.\n");
                }
            }
            return out;
        }
        let base_options = RenderOptions {
            color: options.color,
            show_fix: options.show_fix && self.remedy.is_none(),
        };
        let mut out = crate::diagnosis::DiagnosisEngine::render(diagnosis, &base_options);
        if let Some(root) = &self.root_cause {
            out.push_str(&format!("\nRoot cause:\n  {root}\n"));
        } else if !self.evidence.is_empty() {
            out.push_str("\nRoot cause not confirmed.\n");
        }
        if !self.evidence.is_empty() {
            out.push_str("\nProbe evidence:\n");
            for evidence in &self.evidence {
                out.push_str(&format!(
                    "  {} → {}\n",
                    evidence.source, evidence.observation
                ));
            }
        }
        if let Some(cause) = &self.cause {
            out.push_str(&format!("\nCause:\n  {cause}\n"));
        }
        if options.show_fix {
            if let Some(remedy) = &self.remedy {
                out.push_str(&format!("\nFix:\n  {remedy}\n"));
            }
        }
        if verbose {
            out.push_str("\nProbes:\n");
            for attempt in &self.attempts {
                out.push_str(&format!(
                    "  {} → {}\n",
                    probe_label(attempt.probe),
                    attempt.result
                ));
            }
            out.push_str("\nHypotheses:\n");
            for hypothesis in &self.hypotheses {
                out.push_str(&format!(
                    "  {} {:?} ({:.0}%)\n",
                    hypothesis.id,
                    hypothesis.status,
                    hypothesis.confidence * 100.0
                ));
            }
        }
        out
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
        ProbeId::Process => "ps",
        ProbeId::DockerRunning => "docker ps",
        ProbeId::DockerAll => "docker ps -a",
        ProbeId::DockerInspect => "docker inspect",
        ProbeId::DockerLogs => "docker logs",
        ProbeId::GitStatus => "git status",
        ProbeId::GitDiff => "git diff",
        ProbeId::CargoCheck => "cargo check",
        ProbeId::GitPorcelain => "git status --porcelain=v2 --branch",
        ProbeId::GitBranch => "git branch --show-current",
        ProbeId::GitUpstream => "git rev-parse @{u}",
        ProbeId::GitTopLevel => "git rev-parse --show-toplevel",
        ProbeId::GitRemote => "git remote -v",
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

    fn probe(
        &self,
        result: &mut Investigation,
        cwd: &Path,
        id: ProbeId,
        target: Option<&str>,
        deadline: Instant,
    ) -> Option<ProbeOutput> {
        if result.attempts.len() >= self.max_probes || Instant::now() >= deadline {
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
                        .map_or_else(|| "signal".into(), |c| c.to_string())
                ),
                Err(err) => err.to_string(),
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
        if adapters::select(execution).is_none() {
            return self.investigate(execution, diagnosis);
        }
        let budget = if adapters::select(execution) == Some("cargo") {
            self.max_duration.max(Duration::from_secs(12))
        } else {
            self.max_duration
        };
        let deadline = Instant::now() + budget;
        let mut context =
            AdapterContext::new(&self.runner, &execution.cwd, self.max_probes, budget);
        let Some((adapter, finding)) = adapters::collect(execution, &mut context) else {
            return self.investigate(execution, diagnosis);
        };
        let mut result = Investigation {
            adapter: Some(adapter),
            attempts: context.attempts,
            ..Investigation::default()
        };
        let AdapterResult {
            evidence,
            finding,
            note,
        } = finding;
        for item in evidence {
            result.record(item.probe, safe_observation(&item.observation));
        }
        result.reconstruction_note = note.map(|text| safe_observation(&text));
        if let Some(finding) = finding {
            result.apply_finding(finding, diagnosis);
        }
        if result.root_cause.is_none()
            && adapter == "curl"
            && diagnosis.category.as_deref() == Some("network/no-local-listener")
        {
            self.docker(
                execution,
                diagnosis,
                &mut result,
                &execution.cwd,
                deadline,
                true,
            );
        }
        if diagnosis.status == crate::diagnosis::DiagnosisStatus::Unknown
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
        if execution.is_success() {
            return result;
        }
        let deadline = Instant::now() + self.max_duration;
        let cwd = execution.cwd.as_path();
        match diagnosis.category.as_deref() {
            Some("network/port-conflict")
            | Some("network/connection-refused")
            | Some("network/connect-failed") => {
                self.network(execution, diagnosis, &mut result, cwd, deadline);
            }
            Some("filesystem/disk-full") => self.disk(diagnosis, &mut result, cwd, deadline),
            Some("filesystem/not-found") | Some("filesystem/permission-denied") => {
                self.file(diagnosis, &mut result, cwd, deadline);
            }
            _ => {
                if command_basename(&execution.command) == "docker" {
                    self.docker(execution, diagnosis, &mut result, cwd, deadline, false);
                } else if command_basename(&execution.command) == "git" {
                    self.git(&mut result, cwd, deadline);
                }
            }
        }
        result
    }

    fn network(
        &self,
        execution: &CommandExecution,
        diagnosis: &Diagnosis,
        result: &mut Investigation,
        cwd: &Path,
        deadline: Instant,
    ) {
        let port = match diagnosis.entities.primary_port() {
            Some(p) => p,
            None => return,
        };
        let conflict = diagnosis.category.as_deref() == Some("network/port-conflict");
        result.candidate("port_owner");
        result.candidate("no_local_listener");
        result.candidate("container_exited");
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
                        } else {
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
        if !conflict {
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
        result.candidate("filesystem_full");
        let path = diagnosis
            .entities
            .primary_path()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    cwd.join(p)
                }
            })
            .unwrap_or_else(|| cwd.to_path_buf());
        let existing = existing_ancestor(&path);
        if let Some(out) = self.probe(
            result,
            cwd,
            ProbeId::Filesystem,
            Some(&existing.to_string_lossy()),
            deadline,
        ) {
            if out.ok() {
                if let Some((pct, mount)) = parse_df(&out.stdout, 0) {
                    let fact = format!("filesystem {mount} is {pct}% used");
                    result.record(ProbeId::Filesystem, fact.clone());
                    if pct >= 100 {
                        result.root_cause = Some(format!(
                            "Filesystem containing {} is {pct}% full (mounted at {mount}).",
                            path.display()
                        ));
                        result.support("filesystem_full", &fact, true);
                        result.remedy = recipe("filesystem_full").map(str::to_owned);
                        return;
                    }
                }
            }
        }
        if let Some(out) = self.probe(
            result,
            cwd,
            ProbeId::FilesystemInodes,
            Some(&existing.to_string_lossy()),
            deadline,
        ) {
            if out.ok() {
                if let Some((pct, mount)) = parse_df(&out.stdout, 1) {
                    let fact = format!("filesystem {mount} has {pct}% of inodes used");
                    result.record(ProbeId::FilesystemInodes, fact.clone());
                    if pct >= 100 {
                        result.root_cause = Some(format!(
                            "Filesystem containing {} has exhausted its inodes (mounted at {mount}).",
                            path.display()
                        ));
                        result.support("filesystem_full", &fact, true);
                        result.remedy = recipe("filesystem_full").map(str::to_owned);
                    }
                }
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

    fn git(&self, result: &mut Investigation, cwd: &Path, deadline: Instant) {
        if !self.runner.available("git") || !inside_git(cwd) {
            return;
        }
        result.candidate("recent_changes");
        if let Some(out) = self.probe(result, cwd, ProbeId::GitStatus, None, deadline) {
            if out.ok() && !out.stdout.trim().is_empty() {
                result.record(
                    ProbeId::GitStatus,
                    "uncommitted changes exist; causality not established".into(),
                );
                result.support("recent_changes", "uncommitted changes exist", false);
            }
        }
        if let Some(out) = self.probe(result, cwd, ProbeId::GitDiff, None, deadline) {
            if out.ok() && !out.stdout.trim().is_empty() {
                result.record(
                    ProbeId::GitDiff,
                    "tracked changes exist; causality not established".into(),
                );
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

fn inside_git(cwd: &Path) -> bool {
    cwd.ancestors().any(|p| p.join(".git").exists())
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

fn parse_df(output: &str, percentage_index: usize) -> Option<(u16, String)> {
    let line = output.lines().skip(1).last()?;
    let pct = line
        .split_whitespace()
        .filter_map(|s| s.strip_suffix('%')?.parse::<u16>().ok())
        .nth(percentage_index)?;
    Some((pct, line.split_whitespace().last()?.to_string()))
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
