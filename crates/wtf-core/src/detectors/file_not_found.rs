use crate::detectors::{Detection, Detector, DiagnosisContext};

pub struct FileNotFoundDetector;

impl Detector for FileNotFoundDetector {
    fn id(&self) -> &'static str {
        "file_not_found"
    }

    fn detect(&self, ctx: &DiagnosisContext) -> Option<Detection> {
        // Exclude command_not_found cases where the missing item is the binary itself
        if ctx.execution.exit_code() == Some(127) && ctx.execution.spawn_error.is_some() {
            return None;
        }

        let mut evidence_lines = Vec::new();
        let full_text = format!(
            "{}\n{}",
            ctx.normalized.clean_stderr, ctx.normalized.clean_stdout
        );

        for line in full_text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("no such file or directory")
                || lower.contains("file not found")
                || lower.contains("cannot open file")
                || lower.contains("cannot find the path")
                || lower.contains("enoent")
                || lower.contains("does not exist")
            {
                // Verify it's not a "command not found" message
                if !lower.contains("command not found") && !lower.ends_with(": not found") {
                    evidence_lines.push(line.trim().to_string());
                    break;
                }
            }
        }

        if evidence_lines.is_empty() {
            return None;
        }

        Some(Detection {
            detector_id: self.id().to_string(),
            category: "filesystem/not-found".to_string(),
            summary: "File does not exist.".to_string(),
            evidence: evidence_lines,
            entities: ctx.entities.clone(),
            confidence: 0.95,
            remedy: ctx.entities.primary_path().map(|p| {
                format!(
                    "Check that the path '{}' exists and is spelled correctly.",
                    p.display()
                )
            }),
        })
    }
}
