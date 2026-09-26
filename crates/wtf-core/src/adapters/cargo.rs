use crate::capture::CommandExecution;

use super::{AdapterContext, AdapterResult};

pub(super) fn collect<R>(_: &CommandExecution, _: &mut AdapterContext<'_, R>) -> AdapterResult {
    AdapterResult {
        note: Some(
            "No Cargo output was captured; automatic Cargo checks are not run, so the failure cause is unknown."
                .into(),
        ),
        ..AdapterResult::default()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use crate::probes::{ProbeError, ProbeId, ProbeOutput, ProbeRunner, ProbeSpec};

    use super::*;

    #[derive(Default)]
    struct FixtureRunner {
        calls: std::cell::RefCell<Vec<ProbeId>>,
    }

    impl ProbeRunner for FixtureRunner {
        fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
            self.calls.borrow_mut().push(spec.id);
            Err(ProbeError::Unavailable(std::io::Error::other(
                "fixture runner must not be called",
            )))
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

    #[test]
    fn automatic_cargo_adapter_never_runs_cargo_check() {
        for args in [
            &["build"][..],
            &["check"][..],
            &["test"][..],
            &["run"][..],
            &["build", "--release"][..],
        ] {
            let runner = FixtureRunner::default();
            let result = collect(&failure(args), &mut context(&runner));

            assert!(result.finding.is_none());
            assert!(result
                .note
                .as_deref()
                .is_some_and(|note| note.contains("automatic Cargo checks are not run")));
            assert!(runner.calls.borrow().is_empty());
        }
    }
}
