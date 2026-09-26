use std::path::Path;

use crate::detectors::{Detection, Detector, DiagnosisContext};

pub(crate) fn reported_host(line: &str) -> Option<&str> {
    const MARKER: &[u8] = b"could not resolve host:";
    let offset = line
        .as_bytes()
        .windows(MARKER.len())
        .position(|window| window.eq_ignore_ascii_case(MARKER))?;
    line.get(offset + MARKER.len()..)?.split_whitespace().next()
}

pub struct DnsFailureDetector;

impl Detector for DnsFailureDetector {
    fn id(&self) -> &'static str {
        "dns_failure"
    }

    fn detect(&self, ctx: &DiagnosisContext) -> Option<Detection> {
        if Path::new(&ctx.execution.command).file_name()?.to_str()? != "curl"
            || ctx.execution.exit_code() != Some(6)
        {
            return None;
        }
        let line = ctx
            .normalized
            .clean_stderr
            .lines()
            .chain(ctx.normalized.clean_stdout.lines())
            .find(|line| reported_host(line).is_some())?;
        Some(Detection {
            detector_id: self.id().into(),
            category: "network/dns".into(),
            summary: "curl could not resolve the host.".into(),
            evidence: vec![line.trim().into()],
            entities: ctx.entities.clone(),
            confidence: 0.8,
            remedy: Some("Check the hostname and local DNS configuration.".into()),
        })
    }
}
