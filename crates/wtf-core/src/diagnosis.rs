use std::io::IsTerminal;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::capture::{CommandExecution, ProcessExit};
use crate::detectors::{default_detectors, Detection, Detector, DiagnosisContext};
use crate::entity::{EntityExtractor, ExtractedEntities};
use crate::normalizer::{NormalizedOutput, OutputNormalizer};

/// Status of the diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosisStatus {
    Confirmed,
    Likely,
    Unknown,
    Success,
}

/// The structured result of a diagnostic run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnosis {
    pub status: DiagnosisStatus,
    pub command: String,
    pub exit_status: ProcessExit,
    pub duration: Duration,
    pub summary: String,
    pub category: Option<String>,
    pub evidence: Vec<String>,
    pub detection: Option<Detection>,
    pub entities: ExtractedEntities,
    pub remedy: Option<String>,
    pub normalized: NormalizedOutput,
}

/// Options controlling terminal rendering.
#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    pub color: bool,
    pub show_fix: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        let is_term = std::io::stdout().is_terminal();
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Self {
            color: is_term && !no_color,
            show_fix: false,
        }
    }
}

impl RenderOptions {
    pub fn plain() -> Self {
        Self {
            color: false,
            show_fix: false,
        }
    }
}

/// Diagnostic engine that coordinates normalizers, extractors, and detectors.
pub struct DiagnosisEngine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Default for DiagnosisEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagnosisEngine {
    pub fn new() -> Self {
        Self {
            detectors: default_detectors(),
        }
    }

    pub fn with_detectors(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    /// Diagnoses a captured command execution.
    pub fn diagnose(&self, execution: &CommandExecution) -> Diagnosis {
        let normalized = OutputNormalizer::normalize(&execution.stdout, &execution.stderr);
        let entities = EntityExtractor::extract(execution, &normalized);

        // If execution succeeded without any spawn error or non-zero status
        if execution.is_success() {
            return Diagnosis {
                status: DiagnosisStatus::Success,
                command: execution.full_command(),
                exit_status: execution.exit_status.clone(),
                duration: execution.duration,
                summary: "Command completed successfully.".to_string(),
                category: None,
                evidence: Vec::new(),
                detection: None,
                entities,
                remedy: None,
                normalized,
            };
        }

        let ctx = DiagnosisContext {
            execution,
            normalized: &normalized,
            entities: &entities,
        };

        // Evaluate all detectors and pick the candidate with highest confidence
        let mut candidates: Vec<Detection> = Vec::new();
        for detector in &self.detectors {
            if let Some(detection) = detector.detect(&ctx) {
                candidates.push(detection);
            }
        }

        // Sort descending by confidence
        candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        if let Some(best) = candidates.into_iter().next() {
            // A matching error message identifies a symptom, not necessarily its cause.
            // OS spawn failures directly establish an unavailable executable or EACCES.
            let direct_spawn_failure = execution.spawn_error.is_some()
                && matches!(
                    (execution.exit_code(), best.category.as_str()),
                    (Some(127), "command/not-found") | (Some(126), "filesystem/permission-denied")
                );
            let status = if direct_spawn_failure {
                DiagnosisStatus::Confirmed
            } else {
                DiagnosisStatus::Likely
            };

            let category = Some(best.category.clone());
            let summary = best.summary.clone();
            let evidence = best.evidence.clone();
            let remedy = best.remedy.clone();

            Diagnosis {
                status,
                command: execution.full_command(),
                exit_status: execution.exit_status.clone(),
                duration: execution.duration,
                summary,
                category,
                evidence,
                detection: Some(best),
                entities,
                remedy,
                normalized,
            }
        } else {
            // No detector matched, but command failed
            let evidence = if !normalized.relevant_lines.is_empty() {
                normalized.relevant_lines.clone()
            } else if !execution.stderr.trim().is_empty() {
                execution
                    .stderr
                    .lines()
                    .take(5)
                    .map(|s| s.trim().to_string())
                    .collect()
            } else {
                Vec::new()
            };

            let summary = format!("Command failed with {}.", execution.exit_status.display());

            Diagnosis {
                status: DiagnosisStatus::Unknown,
                command: execution.full_command(),
                exit_status: execution.exit_status.clone(),
                duration: execution.duration,
                summary,
                category: Some("unknown".to_string()),
                evidence,
                detection: None,
                entities,
                remedy: None,
                normalized,
            }
        }
    }

    /// Formats a diagnosis into a concise terminal presentation.
    pub fn render(diagnosis: &Diagnosis, options: &RenderOptions) -> String {
        let mut out = String::new();

        // 1. Status icon and summary
        let (icon, icon_code) = match diagnosis.status {
            DiagnosisStatus::Confirmed => ("✗", "31;1"), // Bold Red
            DiagnosisStatus::Likely => ("?", "33;1"),    // Bold Yellow
            DiagnosisStatus::Unknown => ("?", "33;1"),   // Bold Yellow
            DiagnosisStatus::Success => ("✓", "32;1"),   // Bold Green
        };

        if options.color {
            out.push_str(&format!(
                "\x1B[{icon_code}m{icon}\x1B[0m \x1B[1m{}\x1B[0m\n",
                diagnosis.summary
            ));
        } else {
            out.push_str(&format!("{icon} {}\n", diagnosis.summary));
        }

        // If success, nothing more needed unless requested
        if diagnosis.status == DiagnosisStatus::Success {
            return out;
        }

        // 2. Evidence section
        if !diagnosis.evidence.is_empty() {
            out.push('\n');
            if options.color {
                out.push_str("\x1B[1mEvidence:\x1B[0m\n");
            } else {
                out.push_str("Evidence:\n");
            }
            for line in &diagnosis.evidence {
                out.push_str(&format!("  {line}\n"));
            }
        }

        // 3. Detected section (entities and category)
        let mut detected_items = Vec::new();

        if let Some(port) = diagnosis.entities.primary_port() {
            // Only show port if category involves network/port or detection mentions port
            if let Some(cat) = &diagnosis.category {
                if cat.contains("port") || cat.contains("network") {
                    detected_items.push(("port", port.to_string()));
                }
            }
        }

        if let Some(path) = diagnosis.entities.primary_path() {
            // Only show path if category is filesystem or relevant
            if let Some(cat) = &diagnosis.category {
                if cat.contains("filesystem") || cat.contains("file") || cat.contains("path") {
                    detected_items.push(("path", path.display().to_string()));
                }
            }
        }

        if let Some(cat) = &diagnosis.category {
            detected_items.push(("category", cat.clone()));
        }

        if !detected_items.is_empty() {
            out.push('\n');
            if options.color {
                out.push_str("\x1B[1mDetected:\x1B[0m\n");
            } else {
                out.push_str("Detected:\n");
            }
            for (key, val) in detected_items {
                if options.color {
                    out.push_str(&format!("  \x1B[36m{key}\x1B[0m: {val}\n"));
                } else {
                    out.push_str(&format!("  {key}: {val}\n"));
                }
            }
        }

        // 4. Fix / Remedy section (if enabled)
        if options.show_fix {
            if let Some(remedy) = &diagnosis.remedy {
                out.push('\n');
                if options.color {
                    out.push_str("\x1B[1mFix:\x1B[0m\n");
                } else {
                    out.push_str("Fix:\n");
                }
                out.push_str(&format!("  {remedy}\n"));
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_test_exec(
        cmd: &str,
        args: &[&str],
        stdout: &str,
        stderr: &str,
        code: i32,
    ) -> CommandExecution {
        CommandExecution {
            command: cmd.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: PathBuf::from("/test"),
            exit_status: ProcessExit {
                code: Some(code),
                signal: None,
            },
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            duration: Duration::from_millis(15),
            timestamp: std::time::SystemTime::now(),
            spawn_error: None,
        }
    }

    #[test]
    fn file_not_found_message_does_not_confirm_cause() {
        let exec = make_test_exec(
            "cat",
            &["/foo/bar"],
            "",
            "cat: /foo/bar: No such file or directory\n",
            1,
        );
        let engine = DiagnosisEngine::new();
        let diag = engine.diagnose(&exec);
        assert_eq!(diag.status, DiagnosisStatus::Likely);
        assert_eq!(diag.category.as_deref(), Some("filesystem/not-found"));
        assert_eq!(
            diag.entities.primary_path(),
            Some(&PathBuf::from("/foo/bar"))
        );
    }

    #[test]
    fn port_conflict_message_does_not_confirm_listener() {
        let exec = make_test_exec(
            "docker",
            &["run", "-p", "8080:80", "nginx"],
            "",
            "bind: address already in use\n",
            1,
        );
        let engine = DiagnosisEngine::new();
        let diag = engine.diagnose(&exec);
        assert_eq!(diag.status, DiagnosisStatus::Likely);
        assert_eq!(diag.category.as_deref(), Some("network/port-conflict"));
        assert_eq!(diag.entities.primary_port(), Some(8080));
    }

    #[test]
    fn test_diagnose_success() {
        let exec = make_test_exec("echo", &["ok"], "ok\n", "", 0);
        let engine = DiagnosisEngine::new();
        let diag = engine.diagnose(&exec);
        assert_eq!(diag.status, DiagnosisStatus::Success);
        let rendered = DiagnosisEngine::render(&diag, &RenderOptions::plain());
        assert!(rendered.contains("✓ Command completed successfully."));
    }
}
