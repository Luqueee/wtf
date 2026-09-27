//! The user-facing result is an evidence report, not a root-cause verdict.
//! Detectors/adapters may add observations, but an unknown executable needs no adapter.
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use wtf_core::capture::CommandExecution;
use wtf_core::diagnosis::{Diagnosis, DiagnosisStatus};
use wtf_core::investigation::Investigation;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMode {
    Explicit,
    ShellRecord,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Captured,
    Truncated,
    Unavailable,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    Possible,
    Observed,
    Missing,
    Next,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClaimSource {
    Execution {
        field: &'static str,
    },
    Probe {
        id: wtf_core::probes::ProbeId,
        outcome: String,
        observed_at: u64,
    },
    Metadata {
        field: &'static str,
    },
    Suggestion,
    Model {
        evidence_ids: Vec<String>,
    },
}

#[derive(Serialize)]
pub struct Claim {
    pub kind: ClaimKind,
    pub text: String,
    pub source: ClaimSource,
}

#[derive(Serialize)]
pub struct Report {
    pub source_mode: SourceMode,
    pub capture: CaptureState,
    pub captured_at: u64,
    pub reported_at: u64,
    pub command_label: String,
    pub outcome: String,
    pub summary: String,
    pub claims: Vec<Claim>,
    pub checks: usize,
}

/// Strip terminal controls and mask recognizable credential arguments, headers, and URLs.
/// This is heuristic redaction, not a general detector for arbitrary secrets.
fn visible(text: &str, limit: usize) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    visible_line(line, limit)
}

fn visible_line(line: &str, limit: usize) -> String {
    let (line, _) = scrub_line(line);
    render_visible_line(&line, limit)
}

fn scrub_line(line: &str) -> (String, bool) {
    let stripped = wtf_core::normalizer::strip_ansi(line);
    let (line, header_argument) = redact_header_arguments(&stripped);
    let (line, sensitive_header) = redact_sensitive_header(&line);
    (line, header_argument || sensitive_header)
}

fn render_visible_line(line: &str, limit: usize) -> String {
    let redacted = super::shell_state::redact_and_bound(line, limit);
    redacted
        .chars()
        .filter(|ch| !ch.is_control() && !matches!(*ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .take(limit)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn visible_lines(text: &str, limit: usize) -> String {
    let mut output = String::with_capacity(text.len().min(64 * 1024));
    let mut redact_continuation = false;
    for part in text.split_inclusive('\n') {
        let (line, newline) = part
            .strip_suffix('\n')
            .map_or((part, false), |line| (line, true));
        let (scrubbed, sensitive) = scrub_line(line);
        if redact_continuation {
            output.push_str("[REDACTED]");
            redact_continuation = sensitive || line.starts_with(' ') || line.starts_with('\t');
        } else {
            output.push_str(&render_visible_line(&scrubbed, limit));
            redact_continuation = sensitive;
        }
        if newline {
            output.push('\n');
        }
    }
    output
}

/// Header arguments have arbitrary names, so the credential value cannot be classified
/// reliably. In diagnostic command strings the original argv boundaries are unavailable;
/// redact the remainder of the line after a header flag rather than expose its value.
fn redact_header_arguments(line: &str) -> (String, bool) {
    for (start, token) in line.split_whitespace().scan(0, |offset, token| {
        let relative = line[*offset..].find(token)?;
        let start = *offset + relative;
        *offset = start + token.len();
        Some((start, token))
    }) {
        let unquoted = token.trim_matches(|character| matches!(character, '\'' | '"'));
        if unquoted == "-H" || unquoted == "--header" {
            return (format!("{}{} [REDACTED]", &line[..start], token), true);
        }
        if unquoted.starts_with("--header=") {
            let prefix_len = token.find('=').expect("header option has equals");
            return (
                format!("{}{}=[REDACTED]", &line[..start], &token[..=prefix_len]),
                true,
            );
        }
        if unquoted.starts_with("-H") && unquoted.len() > 2 {
            return (format!("{}-H [REDACTED]", &line[..start]), true);
        }
    }
    (line.to_owned(), false)
}

/// Mask complete values for recognizable credential-bearing header names.
fn redact_sensitive_header(line: &str) -> (String, bool) {
    let bytes = line.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        let ch = line[start..]
            .chars()
            .next()
            .expect("valid character boundary");
        let is_boundary = start == 0
            || !bytes[start - 1].is_ascii_alphanumeric()
                && !matches!(bytes[start - 1], b'_' | b'-');
        if !is_boundary || !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')) {
            start += ch.len_utf8();
            continue;
        }

        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
        {
            end += 1;
        }
        let mut separator = end;
        while separator < bytes.len() && matches!(bytes[separator], b' ' | b'\t') {
            separator += 1;
        }
        if separator < bytes.len() && matches!(bytes[separator], b':' | b'=') {
            let name = line[start..end].to_ascii_lowercase();
            let sensitive = [
                "auth",
                "token",
                "secret",
                "password",
                "passwd",
                "api-key",
                "api_key",
                "apikey",
                "credential",
                "cookie",
                "session",
                "signature",
            ]
            .iter()
            .any(|needle| name.contains(needle));
            if sensitive {
                let prefix = &line[..start];
                let header = &line[start..end];
                let delimiter = &line[end..=separator];
                let value = line[separator + 1..].trim();
                let incomplete = value.is_empty()
                    || ["bearer", "basic"]
                        .iter()
                        .any(|scheme| value.eq_ignore_ascii_case(scheme));
                return (
                    format!("{prefix}{header}{delimiter} [REDACTED]"),
                    incomplete,
                );
            }
        }
        start = end.max(start + ch.len_utf8());
    }
    (line.to_owned(), false)
}

pub fn sanitize_text(text: &str) -> String {
    visible_lines(text, 240)
}

fn captured_line<'a>(
    execution: &'a CommandExecution,
    diagnosis: &'a Diagnosis,
) -> Option<(&'a str, &'static str)> {
    // Prefer a detector's actual excerpt; unknown commands still expose one bounded
    // line from stderr, then stdout. Never claim an excerpt for output-free shell mode.
    if let Some(line) = diagnosis.evidence.iter().find(|line| {
        diagnosis.normalized.clean_stderr.contains(line.as_str())
            || diagnosis.normalized.clean_stdout.contains(line.as_str())
    }) {
        let field = if diagnosis.normalized.clean_stderr.contains(line) {
            "stderr"
        } else {
            "stdout"
        };
        return Some((line, field));
    }
    execution
        .stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| (line, "stderr"))
        .or_else(|| {
            execution
                .stdout
                .lines()
                .find(|line| !line.trim().is_empty())
                .map(|line| (line, "stdout"))
        })
}

impl Report {
    pub fn build(
        execution: &CommandExecution,
        diagnosis: &Diagnosis,
        investigation: Option<&Investigation>,
        source_mode: SourceMode,
        show_fix: bool,
        capture_truncated: bool,
    ) -> Self {
        let shell = matches!(source_mode, SourceMode::ShellRecord);
        let capture = if shell {
            CaptureState::Unavailable
        } else if capture_truncated {
            CaptureState::Truncated
        } else {
            CaptureState::Captured
        };
        let label = std::path::Path::new(&execution.command)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&execution.command);
        let command_label = visible(label, 48);
        let outcome = execution.exit_status.code.map_or_else(
            || {
                execution
                    .exit_status
                    .signal
                    .map_or_else(|| "error".to_owned(), |signal| format!("signal {signal}"))
            },
            |code| code.to_string(),
        );
        let checks = investigation.map_or(0, |inv| inv.attempts.len());
        let summary = if diagnosis.status == DiagnosisStatus::Success {
            "Command completed successfully.".to_owned()
        } else if shell && diagnosis.status == DiagnosisStatus::Unknown {
            "Recent command failed; original output unavailable.".to_owned()
        } else if diagnosis.status == DiagnosisStatus::Unknown {
            format!("Command failed: {}.", execution.exit_status.display())
        } else if diagnosis.status == DiagnosisStatus::Likely {
            let source = if shell {
                if investigation.is_some_and(|inv| !inv.evidence.is_empty()) {
                    "Current inspection"
                } else {
                    "Metadata suggests"
                }
            } else {
                "Reported"
            };
            format!("{source}: {}", visible(&diagnosis.summary, 130))
        } else {
            visible(&diagnosis.summary, 130)
        };
        let mut claims = Vec::with_capacity(3);
        if diagnosis.status != DiagnosisStatus::Success {
            // Original output is the only historical observation. A probe describes
            // current state, so do not let specialized reconstruction hide it.
            if let Some(error) = execution.spawn_error.as_deref() {
                let text = visible(error, 170);
                if !text.is_empty() {
                    claims.push(Claim {
                        kind: ClaimKind::Observed,
                        text,
                        source: ClaimSource::Execution {
                            field: "spawn_error",
                        },
                    });
                }
            } else if !shell {
                if let Some((line, field)) = captured_line(execution, diagnosis) {
                    let text = visible(line, 170);
                    if !text.is_empty() {
                        claims.push(Claim {
                            kind: ClaimKind::Observed,
                            text,
                            source: ClaimSource::Execution { field },
                        });
                    }
                }
            }
            if let Some(inv) = investigation {
                if let Some(evidence) = inv.evidence.first() {
                    if let Some(attempt) = inv
                        .attempts
                        .iter()
                        .find(|attempt| attempt.probe == evidence.probe)
                    {
                        let text = visible(&evidence.observation, 170);
                        if !text.is_empty() {
                            claims.push(Claim {
                                kind: ClaimKind::Observed,
                                text: format!("Now: {text}"),
                                source: ClaimSource::Probe {
                                    id: evidence.probe,
                                    outcome: attempt.result.clone(),
                                    observed_at: evidence
                                        .observed_at
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                },
                            });
                        }
                    }
                }
            }
            if shell {
                claims.push(Claim {
                    kind: ClaimKind::Missing,
                    text: "Original stdout/stderr was not recorded.".to_owned(),
                    source: ClaimSource::Metadata { field: "capture" },
                });
            } else if diagnosis.status == DiagnosisStatus::Unknown {
                if claims.is_empty() {
                    claims.push(Claim {
                        kind: ClaimKind::Missing,
                        text: "No failure detail was captured.".to_owned(),
                        source: ClaimSource::Metadata { field: "capture" },
                    });
                }
            } else if diagnosis.status != DiagnosisStatus::Confirmed {
                claims.push(Claim {
                    kind: ClaimKind::Missing,
                    text: "The original cause is not established by these observations.".to_owned(),
                    source: ClaimSource::Metadata { field: "status" },
                });
            }
            if show_fix {
                if let Some(remedy) = investigation
                    .and_then(|inv| inv.remedy.as_ref())
                    .or(diagnosis.remedy.as_ref())
                {
                    let text = visible(remedy, 170);
                    if !text.is_empty() {
                        claims.push(Claim {
                            kind: ClaimKind::Next,
                            text,
                            source: ClaimSource::Suggestion,
                        });
                    }
                }
            }
        }
        claims.truncate(3);
        let captured_at = execution
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let reported_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            source_mode,
            capture,
            captured_at,
            reported_at,
            command_label,
            outcome,
            summary,
            claims,
            checks,
        }
    }

    pub fn add_interpretation(&mut self, interpretation: &crate::interpreter::Interpretation) {
        if interpretation.possible.is_empty() {
            return;
        }
        let possible = Claim {
            kind: ClaimKind::Possible,
            text: format!("May be: {}", visible(&interpretation.possible, 170)),
            source: ClaimSource::Model {
                evidence_ids: interpretation.evidence_ids.clone(),
            },
        };
        let index = self
            .claims
            .iter()
            .position(|claim| matches!(claim.kind, ClaimKind::Missing | ClaimKind::Next))
            .unwrap_or(self.claims.len());
        self.claims.insert(index, possible);
        if !interpretation.missing.is_empty() {
            self.claims
                .retain(|claim| !matches!(claim.kind, ClaimKind::Missing));
            self.claims.push(Claim {
                kind: ClaimKind::Missing,
                text: visible(&interpretation.missing, 170),
                source: ClaimSource::Model {
                    evidence_ids: interpretation.evidence_ids.clone(),
                },
            });
        }
        if !interpretation.next.is_empty() {
            self.claims
                .retain(|claim| !matches!(claim.kind, ClaimKind::Next));
            self.claims.push(Claim {
                kind: ClaimKind::Next,
                text: visible(&interpretation.next, 170),
                source: ClaimSource::Suggestion,
            });
        }
    }

    pub fn render(
        &self,
        color: bool,
        verbose: bool,
        execution: &CommandExecution,
        investigation: Option<&Investigation>,
    ) -> String {
        use std::fmt::Write as _;

        let icon = if execution.is_success() { "✓" } else { "✗" };
        let accent = if !color {
            ""
        } else if execution.is_success() {
            "\x1b[1;92m"
        } else {
            "\x1b[1;91m"
        };
        let bold = if color { "\x1b[1m" } else { "" };
        let muted = if color { "\x1b[90m" } else { "" };
        let reset = if color { "\x1b[0m" } else { "" };
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{accent}{icon}{reset}  {bold}{}{reset}  {accent}{}{reset}",
            self.command_label, self.outcome
        );
        let _ = writeln!(out, "   {muted}{:<8}{reset}  {}", "RESULT", self.summary);
        for claim in &self.claims {
            let (label, shade) = match claim.kind {
                ClaimKind::Observed => ("OBSERVED", if color { "\x1b[1;96m" } else { "" }),
                ClaimKind::Missing => ("MISSING", if color { "\x1b[1;93m" } else { "" }),
                ClaimKind::Next => ("NEXT", if color { "\x1b[1;95m" } else { "" }),
                ClaimKind::Possible => ("POSSIBLE", if color { "\x1b[1;94m" } else { "" }),
            };
            let _ = writeln!(out, "   {shade}{label:<8}{reset}  {}", claim.text);
        }
        if self.checks > 0 {
            let _ = writeln!(
                out,
                "   {muted}{:<8}{reset}  {} {}",
                "CHECKS",
                self.checks,
                if self.checks == 1 { "check" } else { "checks" }
            );
        }
        if !verbose {
            return out;
        }
        out.push_str("\nDetails:\n");
        out.push_str(&format!("   source: {}\n   captured output: {}\n   captured at: {} (Unix seconds)\n   reported at: {} (Unix seconds)\n", if matches!(self.source_mode, SourceMode::Explicit) { "explicit execution" } else { "shell metadata" }, if matches!(self.capture, CaptureState::Unavailable) { "unavailable" } else if matches!(self.capture, CaptureState::Truncated) { "truncated" } else { "complete" }, self.captured_at, self.reported_at));
        out.push_str(&format!(
            "   working directory: {}\n",
            visible(&execution.cwd.to_string_lossy(), 256)
        ));
        for claim in &self.claims {
            match &claim.source {
                ClaimSource::Execution { field } => {
                    out.push_str(&format!("   evidence: {field}\n"))
                }
                ClaimSource::Probe {
                    id,
                    outcome,
                    observed_at,
                } => out.push_str(&format!(
                    "   evidence: {id:?} ({}) at {observed_at} (Unix seconds)\n",
                    visible(outcome, 70)
                )),
                ClaimSource::Metadata { field } => out.push_str(&format!("   evidence: {field}\n")),
                ClaimSource::Suggestion => out.push_str("   next step: suggestion, not executed\n"),
                ClaimSource::Model { evidence_ids } => out.push_str(&format!("   interpretation: tentative; cited evidence {}; execution at {} (Unix seconds); probes at their listed inspection times\n", evidence_ids.join(", "), self.captured_at)),
            }
        }
        if let Some(inv) = investigation {
            for attempt in &inv.attempts {
                out.push_str(&format!(
                    "   probe: {:?} → {}\n",
                    attempt.probe,
                    visible(&attempt.result, 70)
                ));
            }
            for evidence in &inv.evidence {
                out.push_str(&format!(
                    "   observation: {:?} → {}\n",
                    evidence.probe,
                    visible(&evidence.observation, 240)
                ));
            }
        }
        if matches!(self.source_mode, SourceMode::Explicit) {
            let (stdout, stderr) = Self::sanitized_output(execution);
            if !stdout.is_empty() {
                out.push_str("   stdout:\n");
                for line in stdout.lines() {
                    out.push_str("     ");
                    out.push_str(line);
                    out.push('\n');
                }
            }
            if !stderr.is_empty() {
                out.push_str("   stderr:\n");
                for line in stderr.lines() {
                    out.push_str("     ");
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        out
    }

    pub fn sanitized_output(execution: &CommandExecution) -> (String, String) {
        fn lines(text: &str) -> String {
            let mut output = visible_lines(text, 4096);
            if !text.is_empty() && !text.ends_with('\n') {
                output.push('\n');
            }
            output
        }
        (lines(&execution.stdout), lines(&execution.stderr))
    }
}

/// Scrub free-form legacy diagnostic strings while leaving report structure and provenance intact.
pub fn sanitize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = visible_lines(text, 4096),
        serde_json::Value::Array(items) => {
            for item in items {
                sanitize_json(item);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, item) in fields {
                if key == "command" {
                    if let serde_json::Value::String(text) = item {
                        *text = visible(text, 4096);
                        continue;
                    }
                }
                if matches!(
                    key.as_str(),
                    "paths" | "processes" | "services" | "containers"
                ) {
                    if let serde_json::Value::Array(items) = item {
                        for value in items {
                            if let serde_json::Value::String(text) = value {
                                *text = visible(text, 4096);
                            } else {
                                sanitize_json(value);
                            }
                        }
                        continue;
                    }
                }
                sanitize_json(item);
            }
        }
        _ => {}
    }
}
