use crate::detectors::{Detection, Detector, DiagnosisContext};

pub struct PermissionDeniedDetector;

impl Detector for PermissionDeniedDetector {
    fn id(&self) -> &'static str {
        "permission_denied"
    }

    fn detect(&self, ctx: &DiagnosisContext) -> Option<Detection> {
        let mut evidence_lines = Vec::new();

        // 1. Spawn error permission denied (exit code 126)
        if ctx.execution.exit_code() == Some(126) && ctx.execution.spawn_error.is_some() {
            evidence_lines.push(ctx.execution.stderr.trim().to_string());
        } else {
            let full_text = format!(
                "{}\n{}",
                ctx.normalized.clean_stderr, ctx.normalized.clean_stdout
            );
            for line in full_text.lines() {
                let lower = line.to_lowercase();
                if lower.contains("permission denied")
                    || lower.contains("operation not permitted")
                    || lower.contains("eacces")
                    || lower.contains("eperm")
                {
                    evidence_lines.push(line.trim().to_string());
                    break;
                }
            }
        }

        if evidence_lines.is_empty() {
            return None;
        }

        let summary = "Permission denied.".to_string();
        let remedy = if let Some(path) = ctx.entities.primary_path() {
            format!(
                "Check permissions for '{}' (e.g., chmod/chown) or run with elevated privileges.",
                path.display()
            )
        } else {
            "Check user permissions or consider running with elevated privileges (sudo)."
                .to_string()
        };

        Some(Detection {
            detector_id: self.id().to_string(),
            category: "filesystem/permission-denied".to_string(),
            summary,
            evidence: evidence_lines,
            entities: ctx.entities.clone(),
            confidence: 0.95,
            remedy: Some(remedy),
        })
    }
}
