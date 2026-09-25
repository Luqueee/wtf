use crate::detectors::{Detection, Detector, DiagnosisContext};

pub struct PortConflictDetector;

impl Detector for PortConflictDetector {
    fn id(&self) -> &'static str {
        "port_conflict"
    }

    fn detect(&self, ctx: &DiagnosisContext) -> Option<Detection> {
        let mut evidence_lines = Vec::new();
        let full_text = format!(
            "{}\n{}",
            ctx.normalized.clean_stderr, ctx.normalized.clean_stdout
        );

        for line in full_text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("address already in use")
                || lower.contains("port is already allocated")
                || lower.contains("eaddrinuse")
                || (lower.contains("bind") && lower.contains("already in use"))
            {
                // If the line contains a concise message like "bind: address already in use", take it
                let trimmed = line.trim();
                evidence_lines.push(trimmed.to_string());
                break;
            }
        }

        if evidence_lines.is_empty() {
            return None;
        }

        let summary = if let Some(port) = ctx.entities.primary_port() {
            format!("Port {port} is already in use.")
        } else {
            "Port is already in use.".to_string()
        };

        let remedy = if let Some(port) = ctx.entities.primary_port() {
            format!("Stop the process listening on port {port} or configure a different port.")
        } else {
            "Identify and stop the conflicting process or choose another port.".to_string()
        };

        Some(Detection {
            detector_id: self.id().to_string(),
            category: "network/port-conflict".to_string(),
            summary,
            evidence: evidence_lines,
            entities: ctx.entities.clone(),
            confidence: 0.98,
            remedy: Some(remedy),
        })
    }
}
