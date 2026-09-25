use crate::detectors::{Detection, Detector, DiagnosisContext};

pub struct DiskFullDetector;

impl Detector for DiskFullDetector {
    fn id(&self) -> &'static str {
        "disk_full"
    }

    fn detect(&self, ctx: &DiagnosisContext) -> Option<Detection> {
        let mut evidence_lines = Vec::new();
        let full_text = format!(
            "{}\n{}",
            ctx.normalized.clean_stderr, ctx.normalized.clean_stdout
        );

        for line in full_text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("no space left on device")
                || lower.contains("enospc")
                || lower.contains("disk is full")
                || lower.contains("disk full")
                || lower.contains("out of disk space")
            {
                evidence_lines.push(line.trim().to_string());
                break;
            }
        }

        if evidence_lines.is_empty() {
            return None;
        }

        Some(Detection {
            detector_id: self.id().to_string(),
            category: "filesystem/disk-full".to_string(),
            summary: "No space left on device.".to_string(),
            evidence: evidence_lines,
            entities: ctx.entities.clone(),
            confidence: 0.98,
            remedy: Some(
                "Check filesystem disk usage with 'df -h' or 'df -i' (inodes) and free up space."
                    .to_string(),
            ),
        })
    }
}
