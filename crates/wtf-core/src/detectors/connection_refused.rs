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

        if !evidence_lines.is_empty() {
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

            return Some(Detection {
                detector_id: self.id().to_string(),
                category: "network/connection-refused".to_string(),
                summary,
                evidence: evidence_lines,
                entities: ctx.entities.clone(),
                confidence: 0.95,
                remedy: Some(remedy),
            });
        }

        let command = std::path::Path::new(&ctx.execution.command)
            .file_name()
            .and_then(|name| name.to_str());
        let local_target = ctx.execution.args.iter().any(|arg| {
            let target = arg
                .split_once("://")
                .map_or(arg.as_str(), |(_, rest)| rest)
                .split('/')
                .next()
                .unwrap_or_default()
                .rsplit('@')
                .next()
                .unwrap_or_default();
            ["localhost:", "127.0.0.1:", "[::1]:", "::1:"]
                .iter()
                .any(|prefix| target.starts_with(prefix))
        });
        let metadata_only_curl_failure = command == Some("curl")
            && ctx.execution.exit_status.code == Some(7)
            && ctx.execution.stdout.is_empty()
            && ctx.execution.stderr.is_empty()
            && ctx.normalized.clean_stdout.is_empty()
            && ctx.normalized.clean_stderr.is_empty()
            && local_target
            && ctx.entities.primary_port().is_some();
        if !metadata_only_curl_failure {
            return None;
        }

        let port = ctx.entities.primary_port().expect("checked above");
        Some(Detection {
            detector_id: self.id().to_string(),
            category: "network/connect-failed".to_string(),
            summary: format!(
                "Connection to localhost port {port} failed; the cause is not yet confirmed."
            ),
            evidence: vec![
                "curl exited with code 7 (connection failure); no output was captured.".to_string(),
            ],
            entities: ctx.entities.clone(),
            confidence: 0.65,
            remedy: Some(format!(
                "Check whether a service is listening on port {port}."
            )),
        })
    }
}
