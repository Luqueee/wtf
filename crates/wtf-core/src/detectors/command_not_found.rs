use crate::detectors::{Detection, Detector, DiagnosisContext};

pub struct CommandNotFoundDetector;

impl Detector for CommandNotFoundDetector {
    fn id(&self) -> &'static str {
        "command_not_found"
    }

    fn detect(&self, ctx: &DiagnosisContext) -> Option<Detection> {
        let cmd = &ctx.execution.command;

        // 1. Direct spawn error with NotFound (exit code 127)
        if ctx.execution.exit_code() == Some(127) && ctx.execution.spawn_error.is_some() {
            let evidence = if !ctx.execution.stderr.is_empty() {
                vec![ctx.execution.stderr.trim().to_string()]
            } else {
                vec![format!("Command '{cmd}' not found on PATH")]
            };

            let mut entities = ctx.entities.clone();
            if !entities.processes.contains(cmd) {
                entities.processes.push(cmd.clone());
            }

            return Some(Detection {
                detector_id: self.id().to_string(),
                category: "command/not-found".to_string(),
                summary: format!("Command '{cmd}' was not found."),
                evidence,
                entities,
                confidence: 1.0,
                remedy: Some(format!(
                    "Check that '{cmd}' is installed and present in your PATH."
                )),
            });
        }

        // 2. Shell execution where child exited 127 or printed "command not found"
        let full_text = format!(
            "{}\n{}",
            ctx.normalized.clean_stderr, ctx.normalized.clean_stdout
        );
        for line in full_text.lines() {
            let lower = line.to_lowercase();
            if (lower.contains("command not found") || lower.contains(": not found"))
                && (lower.contains(&cmd.to_lowercase()) || ctx.execution.exit_code() == Some(127))
            {
                let mut entities = ctx.entities.clone();
                if !entities.processes.contains(cmd) {
                    entities.processes.push(cmd.clone());
                }

                return Some(Detection {
                    detector_id: self.id().to_string(),
                    category: "command/not-found".to_string(),
                    summary: format!("Command '{cmd}' was not found."),
                    evidence: vec![line.trim().to_string()],
                    entities,
                    confidence: 0.95,
                    remedy: Some(format!(
                        "Install '{cmd}' or verify your PATH environment variable."
                    )),
                });
            }
        }

        None
    }
}
