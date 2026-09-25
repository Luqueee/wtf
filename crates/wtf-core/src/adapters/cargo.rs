use serde_json::Value;

use crate::capture::CommandExecution;
use crate::probes::{ProbeId, ProbeRunner};

use super::{AdapterContext, AdapterEvidence, AdapterResult, Finding};

pub(super) fn collect<R: ProbeRunner>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'_, R>,
) -> AdapterResult {
    let mut result = AdapterResult::default();
    let Some(subcommand) = failure.args.first().map(String::as_str) else {
        result.note =
            Some("Cargo failure could not be diagnosed from the available evidence.".into());
        return result;
    };
    if !matches!(subcommand, "build" | "check" | "test" | "run") {
        result.note = Some("Cargo subcommand is not supported for compile diagnosis.".into());
        return result;
    }

    if failure.args.len() != 1 {
        result.note = Some("Cargo flags or package selection cannot be matched to the fixed check probe; compile cause is unknown.".into());
        return result;
    }

    if local_build_may_execute(&failure.cwd) {
        result.note = Some("Cargo check was skipped because this package may run a build script or procedural macro.".into());
        return result;
    }

    // This fixed offline probe never reuses arbitrary original arguments. The local
    // package guard avoids known build scripts/macros; dependency build scripts and
    // procedural macros are not discoverable through the closed probe interface.
    let Some(output) = context.run(ProbeId::CargoCheck, None) else {
        result.note =
            Some("Cargo check timed out or was unavailable; compile cause is unknown.".into());
        return result;
    };

    if output.truncated {
        result.note =
            Some("Cargo check output exceeded the probe limit; the cause is unknown.".into());
        return result;
    }
    let mut malformed_json = false;
    let mut first_error = None;
    let mut valid_messages = 0usize;
    for line in output.stdout.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            malformed_json = true;
            continue;
        };
        if value.get("reason").and_then(Value::as_str) != Some("compiler-message") {
            continue;
        }
        let Some(message) = value.get("message") else {
            continue;
        };
        let Some(level) = message.get("level").and_then(Value::as_str) else {
            continue;
        };
        valid_messages += 1;
        if level != "error" || first_error.is_some() {
            continue;
        }
        let Some(message_text) = message.get("message").and_then(Value::as_str) else {
            continue;
        };
        let code = message
            .get("code")
            .and_then(|code| code.get("code"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let span = message
            .get("spans")
            .and_then(Value::as_array)
            .and_then(|spans| {
                spans
                    .iter()
                    .find(|span| span.get("is_primary").and_then(Value::as_bool) == Some(true))
                    .or_else(|| spans.first())
            });
        let Some(span) = span else { continue };
        let (Some(file), Some(line), Some(column)) = (
            span.get("file_name").and_then(Value::as_str),
            span.get("line_start").and_then(Value::as_u64),
            span.get("column_start").and_then(Value::as_u64),
        ) else {
            continue;
        };
        first_error = Some(Finding::CargoError {
            code,
            message: message_text.to_owned(),
            file: file.to_owned(),
            line,
            column,
        });
    }
    result.evidence.push(AdapterEvidence {
        probe: ProbeId::CargoCheck,
        observation: format!(
            "cargo check completed with {} compiler message(s)",
            valid_messages
        ),
    });
    result.finding = if matches!(output.exit_code, Some(code) if code != 0) {
        first_error
    } else {
        None
    };
    if result.finding.is_none() {
        result.note = Some(if malformed_json {
            "Cargo check output contained invalid JSON; compile cause is unknown.".into()
        } else if matches!(subcommand, "test" | "run") && output.ok() {
            "Cargo check passed, but that does not explain a runtime test or application failure."
                .into()
        } else if !output.ok() {
            "Cargo check failed without a usable compiler diagnostic; cause is unknown.".into()
        } else {
            "Cargo check passed; the original Cargo failure remains unexplained.".into()
        });
    }
    result
}

fn local_build_may_execute(cwd: &std::path::Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(cwd.join("Cargo.toml")) else {
        return true;
    };
    if cwd.join("build.rs").exists() {
        return true;
    }
    let mut in_package = false;
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            if line == "[workspace]" {
                return true;
            }
            in_package = line == "[package]";
            continue;
        }
        if in_package && line.starts_with("build") && line.contains('=') {
            return true;
        }
        if line.starts_with("proc-macro") && line.contains('=') && line.ends_with("true") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use crate::probes::{ProbeError, ProbeOutput, ProbeSpec};

    use super::*;

    #[derive(Default)]
    struct FixtureRunner {
        output: Option<ProbeOutput>,
        calls: std::cell::RefCell<Vec<ProbeId>>,
    }

    impl ProbeRunner for FixtureRunner {
        fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
            self.calls.borrow_mut().push(spec.id);
            self.output.clone().ok_or_else(|| {
                ProbeError::Unavailable(std::io::Error::other("fixture unavailable"))
            })
        }

        fn available(&self, _: &str) -> bool {
            true
        }
    }

    fn failure(args: &[&str]) -> CommandExecution {
        CommandExecution {
            command: "cargo".into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            cwd: Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf(),
            exit_status: crate::capture::ProcessExit {
                code: Some(1),
                signal: None,
            },
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::ZERO,
            timestamp: std::time::SystemTime::now(),
            spawn_error: None,
        }
    }

    fn context<'a>(runner: &'a FixtureRunner) -> AdapterContext<'a, FixtureRunner> {
        AdapterContext::new(
            runner,
            Path::new(env!("CARGO_MANIFEST_DIR")),
            4,
            Duration::from_secs(20),
        )
    }

    fn output(stdout: &str, code: i32) -> ProbeOutput {
        ProbeOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: Some(code),
            truncated: false,
        }
    }

    #[test]
    fn parses_compiler_error_location_and_code_without_replaying_command() {
        let runner = FixtureRunner {
            output: Some(output(
                r#"{"reason":"compiler-message","message":{"level":"error","code":{"code":"E0425"},"message":"cannot find value `missing`","spans":[{"file_name":"src/main.rs","line_start":8,"column_start":4,"is_primary":true}]}}"#,
                101,
            )),
            ..Default::default()
        };
        let result = collect(&failure(&["build"]), &mut context(&runner));
        assert!(
            matches!(result.finding, Some(Finding::CargoError { code: Some(code), file, line: 8, column: 4, .. }) if code == "E0425" && file == "src/main.rs")
        );
        assert_eq!(*runner.calls.borrow(), [ProbeId::CargoCheck]);
    }

    #[test]
    fn successful_check_does_not_explain_cargo_test_runtime_failure() {
        let runner = FixtureRunner {
            output: Some(output("{}\n", 0)),
            ..Default::default()
        };
        let result = collect(&failure(&["test"]), &mut context(&runner));
        assert!(result.finding.is_none());
        assert!(result.note.as_deref().unwrap().contains("does not explain"));
    }

    #[test]
    fn malformed_json_and_timeout_remain_unknown() {
        let runner = FixtureRunner {
            output: Some(output("not-json\n", 0)),
            ..Default::default()
        };
        let result = collect(&failure(&["check"]), &mut context(&runner));
        assert!(result.finding.is_none());
        assert!(result.note.as_deref().unwrap().contains("invalid JSON"));

        let runner = FixtureRunner {
            output: Some(output("", 0)),
            ..Default::default()
        };
        let result = collect(&failure(&["build", "--release"]), &mut context(&runner));
        assert!(result.finding.is_none());
        assert!(result
            .note
            .as_deref()
            .unwrap()
            .contains("flags or package selection"));
        assert!(runner.calls.borrow().is_empty());

        let runner = FixtureRunner::default();
        let result = collect(&failure(&["build"]), &mut context(&runner));
        assert!(result.finding.is_none());
        assert!(result
            .note
            .as_deref()
            .unwrap()
            .contains("timed out or was unavailable"));
    }
}
