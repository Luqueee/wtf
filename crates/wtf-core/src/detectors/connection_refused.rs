use crate::detectors::{Detection, Detector, DiagnosisContext};

pub struct ConnectionRefusedDetector;

impl Detector for ConnectionRefusedDetector {
    fn id(&self) -> &'static str {
        "connection_refused"
    }

    fn detect(&self, ctx: &DiagnosisContext) -> Option<Detection> {
        let mut evidence_lines = Vec::new();
        let full_text = format!(
            "{}\n{}",
            ctx.normalized.clean_stderr, ctx.normalized.clean_stdout
        );

        for line in full_text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("connection refused")
                || lower.contains("econnrefused")
                || (lower.contains("failed to connect")
                    && (lower.contains("refused") || lower.contains("connect")))
                || lower.contains("could not connect to server")
                || lower.contains("couldn't connect to server")
            {
                evidence_lines.push(line.trim().to_string());
                break;
            }
        }

        if evidence_lines.is_empty() {
            return None;
        }

        let summary = if let Some(port) = ctx.entities.primary_port() {
            format!("Connection to port {port} was refused.")
        } else {
            "Connection refused.".to_string()
        };

        let remedy = if let Some(port) = ctx.entities.primary_port() {
            format!("Check that the service is running and actively listening on port {port}.")
        } else {
            "Ensure the destination service is running and accepting connections on the specified port.".to_string()
        };

        Some(Detection {
            detector_id: self.id().to_string(),
            category: "network/connection-refused".to_string(),
            summary,
            evidence: evidence_lines,
            entities: ctx.entities.clone(),
            confidence: 0.95,
            remedy: Some(remedy),
        })
    }
}
