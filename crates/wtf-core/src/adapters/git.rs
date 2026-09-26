use crate::capture::CommandExecution;
#[cfg(feature = "counterfactual-replay")]
use crate::investigation::{GitReplayPoint, GitReplayPrior};
use crate::probes::{ProbeId, ProbeRunner};

use super::{AdapterContext, AdapterEvidence, AdapterResult, Finding};

pub(super) fn collect<R: ProbeRunner>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'_, R>,
) -> AdapterResult {
    collect_ordered(failure, context, None, |_| true)
}

#[cfg(feature = "counterfactual-replay")]
pub(super) fn collect_replay<R: ProbeRunner>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'_, R>,
    first: ProbeId,
) -> (AdapterResult, Option<GitReplayPoint>) {
    let mut point = None;
    let result = collect_ordered(failure, context, Some(first), |context| {
        point = replay_point(context);
        point.is_some()
    });
    (result, point)
}

fn collect_ordered<'a, R, F>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'a, R>,
    replay_first: Option<ProbeId>,
    mut capture_point: F,
) -> AdapterResult
where
    R: ProbeRunner,
    F: FnMut(&AdapterContext<'a, R>) -> bool,
{
    let Some(subcommand) = failure.args.first().map(String::as_str) else {
        return unknown("Git failure has no recognized subcommand.");
    };
    let mut result = AdapterResult::default();
    let conflicts_relevant = matches!(
        subcommand,
        "merge" | "rebase" | "pull" | "checkout" | "switch" | "commit"
    );
    let branch_relevant = matches!(
        subcommand,
        "push" | "commit" | "checkout" | "switch" | "merge" | "rebase" | "pull"
    );

    let mut detached_status = false;
    if conflicts_relevant {
        if let Some(output) = context
            .run(ProbeId::GitPorcelain, None)
            .filter(|output| output.ok() && !output.truncated)
        {
            detached_status = is_detached(&output.stdout);
            let conflicted = output.stdout.lines().any(|line| {
                if line.starts_with("u ") {
                    return true;
                }
                let Some(status) = line.strip_prefix("1 ").and_then(|record| record.get(..2))
                else {
                    return false;
                };
                matches!(status, "DD" | "AU" | "UD" | "UA" | "DU" | "AA" | "UU")
            });
            result.evidence.push(AdapterEvidence {
                probe: ProbeId::GitPorcelain,
                observation: if conflicted {
                    "repository status contains unmerged paths"
                } else {
                    "repository status contains no unmerged paths"
                }
                .into(),
            });
            if conflicted {
                result.finding = Some(Finding::GitConflicts);
                return result;
            }
        }
    }

    if branch_relevant {
        let top_level = context.run(ProbeId::GitTopLevel, None);
        if let Some(output) = top_level
            .as_ref()
            .filter(|output| output.ok() && !output.truncated)
        {
            result.evidence.push(AdapterEvidence {
                probe: ProbeId::GitTopLevel,
                observation: if output.stdout.trim().is_empty() {
                    "repository root found"
                } else {
                    "inside a Git repository"
                }
                .into(),
            });
            if let Some(branch) = context
                .run(ProbeId::GitBranch, None)
                .filter(|output| output.ok() && !output.truncated)
            {
                let branch_name = branch.stdout.trim();
                result.evidence.push(AdapterEvidence {
                    probe: ProbeId::GitBranch,
                    observation: if branch_name.is_empty() {
                        "HEAD is detached"
                    } else {
                        "HEAD names a branch"
                    }
                    .into(),
                });
                if branch_name.is_empty()
                    && (subcommand == "pull" || (subcommand == "push" && failure.args.len() == 1))
                {
                    let detached = if subcommand == "push" {
                        context
                            .run(ProbeId::GitPorcelain, None)
                            .is_some_and(|output| {
                                output.ok() && !output.truncated && is_detached(&output.stdout)
                            })
                    } else {
                        detached_status
                    };
                    if detached {
                        result.finding = Some(Finding::GitDetached);
                        return result;
                    }
                }
                if subcommand == "push"
                    && failure.args.len() == 1
                    && !branch_name.is_empty()
                    && branch.ok()
                {
                    if let Some(upstream) = context.run(ProbeId::GitUpstream, None) {
                        result.evidence.push(AdapterEvidence {
                            probe: ProbeId::GitUpstream,
                            observation: if upstream.ok() {
                                "branch has a configured upstream"
                            } else {
                                "branch has no configured upstream"
                            }
                            .into(),
                        });
                        if !upstream.ok() {
                            let order = if let Some(first) = replay_first {
                                if !capture_point(context) {
                                    return result;
                                }
                                let second = match first {
                                    ProbeId::GitRemote => ProbeId::GitPorcelain,
                                    ProbeId::GitPorcelain => ProbeId::GitRemote,
                                    _ => return result,
                                };
                                [first, second]
                            } else {
                                [ProbeId::GitRemote, ProbeId::GitPorcelain]
                            };
                            let mut remote = None;
                            let mut status = None;
                            for probe in order {
                                match probe {
                                    ProbeId::GitRemote => remote = context.run(probe, None),
                                    ProbeId::GitPorcelain => status = context.run(probe, None),
                                    _ => unreachable!("Git replay choice is fixed"),
                                }
                            }
                            let has_remote = remote.as_ref().is_some_and(|out| {
                                out.ok() && !out.truncated && !out.stdout.trim().is_empty()
                            });
                            let has_commit = status.as_ref().is_some_and(|out| {
                                out.ok()
                                    && !out.truncated
                                    && out.stdout.lines().any(|line| {
                                        line.starts_with("# branch.oid ")
                                            && line != "# branch.oid (initial)"
                                    })
                            });
                            if has_remote && has_commit {
                                result.finding = Some(Finding::GitNoUpstream {
                                    branch: branch_name.to_owned(),
                                });
                                return result;
                            }
                        }
                    }
                }
            }
        }
    }
    if result.evidence.is_empty() {
        result.note = Some("Git cause is unknown from the available safe probes.".into());
    } else {
        result.note = Some("Available Git evidence does not confirm a cause.".into());
    }
    result
}

#[cfg(feature = "counterfactual-replay")]
fn replay_point<R: ProbeRunner>(context: &AdapterContext<'_, R>) -> Option<GitReplayPoint> {
    let offered = [ProbeId::GitRemote, ProbeId::GitPorcelain];
    if !context.replay_probes_ready(offered) {
        return None;
    }

    let expected = [
        ProbeId::GitTopLevel,
        ProbeId::GitBranch,
        ProbeId::GitUpstream,
    ];
    let prior = context
        .attempts
        .iter()
        .filter(|attempt| expected.contains(&attempt.probe))
        .map(|attempt| GitReplayPrior {
            probe: attempt.probe,
            outcome: replay_outcome(&attempt.result),
        })
        .collect::<Vec<_>>();
    if prior.len() != expected.len() || !prior.iter().map(|attempt| attempt.probe).eq(expected) {
        return None;
    }

    Some(GitReplayPoint { offered, prior })
}

#[cfg(feature = "counterfactual-replay")]
fn replay_outcome(attempt: &str) -> &'static str {
    match attempt {
        "ok" => "available",
        "unavailable" => "unavailable",
        "truncated" => "truncated",
        "probe exceeded its deadline" => "timeout",
        value if value.starts_with("probe unavailable:") => "unavailable",
        _ => "failed",
    }
}

fn is_detached(status: &str) -> bool {
    status
        .lines()
        .any(|line| line == "# branch.head (detached)")
}

fn unknown(note: &str) -> AdapterResult {
    AdapterResult {
        note: Some(note.into()),
        ..AdapterResult::default()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::Path;
    use std::time::Duration;

    use crate::capture::ProcessExit;
    use crate::probes::{ProbeError, ProbeOutput, ProbeSpec};

    use super::*;

    #[cfg(feature = "counterfactual-replay")]
    #[test]
    fn replay_prior_statuses_use_the_fixed_training_vocabulary() {
        assert_eq!(super::replay_outcome("ok"), "available");
        assert_eq!(super::replay_outcome("unavailable"), "unavailable");
        assert_eq!(
            super::replay_outcome("probe unavailable: missing"),
            "unavailable"
        );
        assert_eq!(
            super::replay_outcome("probe exceeded its deadline"),
            "timeout"
        );
        assert_eq!(super::replay_outcome("truncated"), "truncated");
        assert_eq!(super::replay_outcome("exit 128"), "failed");
    }

    #[derive(Default)]
    struct FixtureRunner {
        outputs: HashMap<ProbeId, ProbeOutput>,
        calls: RefCell<Vec<ProbeId>>,
    }

    impl ProbeRunner for FixtureRunner {
        fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
            self.calls.borrow_mut().push(spec.id);
            self.outputs.get(&spec.id).cloned().ok_or_else(|| {
                ProbeError::Unavailable(std::io::Error::other("fixture unavailable"))
            })
        }

        fn available(&self, _: &str) -> bool {
            true
        }
    }

    fn output(stdout: &str, code: i32) -> ProbeOutput {
        ProbeOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: Some(code),
            truncated: false,
        }
    }

    fn failure(args: &[&str]) -> CommandExecution {
        CommandExecution {
            command: "git".into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            cwd: ".".into(),
            exit_status: ProcessExit {
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
        AdapterContext::new(runner, Path::new("."), 6, Duration::from_secs(5))
    }

    #[test]
    fn push_without_upstream_is_reported_using_branch_name_only() {
        let runner = FixtureRunner {
            outputs: HashMap::from([
                (ProbeId::GitTopLevel, output("/repo\n", 0)),
                (ProbeId::GitBranch, output("feature\n", 0)),
                (ProbeId::GitUpstream, output("", 128)),
                (ProbeId::GitRemote, output("origin\n", 0)),
                (
                    ProbeId::GitPorcelain,
                    output("# branch.oid 2abcd\n# branch.head feature\n", 0),
                ),
            ]),
            ..Default::default()
        };
        let result = collect(&failure(&["push"]), &mut context(&runner));
        assert!(
            matches!(result.finding, Some(Finding::GitNoUpstream { branch }) if branch == "feature")
        );
        assert_eq!(
            *runner.calls.borrow(),
            [
                ProbeId::GitTopLevel,
                ProbeId::GitBranch,
                ProbeId::GitUpstream,
                ProbeId::GitRemote,
                ProbeId::GitPorcelain
            ]
        );
        assert!(
            result
                .evidence
                .iter()
                .all(|item| !item.observation.contains("http")
                    && !item.observation.contains("origin"))
        );
    }

    #[test]
    fn explicit_push_target_does_not_claim_missing_upstream_or_disclose_remote_credentials() {
        let runner = FixtureRunner {
            outputs: HashMap::from([
                (ProbeId::GitTopLevel, output("/repo\n", 0)),
                (ProbeId::GitBranch, output("feature\n", 0)),
            ]),
            ..Default::default()
        };
        let result = collect(
            &failure(&[
                "push",
                "https://user:password@example.test/repo.git",
                "feature",
            ]),
            &mut context(&runner),
        );
        assert!(result.finding.is_none());
        assert!(!format!("{result:?}").contains("password"));
        assert_eq!(
            *runner.calls.borrow(),
            [ProbeId::GitTopLevel, ProbeId::GitBranch]
        );
    }

    #[test]
    fn detached_head_is_confirmed_by_repository_and_empty_branch() {
        let runner = FixtureRunner {
            outputs: HashMap::from([
                (ProbeId::GitTopLevel, output("/repo\n", 0)),
                (ProbeId::GitBranch, output("", 0)),
                (
                    ProbeId::GitPorcelain,
                    output("# branch.head (detached)\n", 0),
                ),
            ]),
            ..Default::default()
        };
        let result = collect(&failure(&["push"]), &mut context(&runner));
        assert!(matches!(result.finding, Some(Finding::GitDetached)));
        assert_eq!(
            *runner.calls.borrow(),
            [
                ProbeId::GitTopLevel,
                ProbeId::GitBranch,
                ProbeId::GitPorcelain
            ]
        );
    }

    #[test]
    fn unborn_branch_is_not_mistaken_for_detached_head() {
        let runner = FixtureRunner {
            outputs: HashMap::from([
                (ProbeId::GitTopLevel, output("/repo\n", 0)),
                (ProbeId::GitBranch, output("", 0)),
                (
                    ProbeId::GitPorcelain,
                    output("# branch.head main\n# branch.oid (initial)\n", 0),
                ),
            ]),
            ..Default::default()
        };
        let result = collect(&failure(&["push"]), &mut context(&runner));
        assert!(result.finding.is_none());
    }

    #[test]
    fn conflicts_are_reported_for_each_relevant_git_action_without_replay() {
        let runner = FixtureRunner {
            outputs: HashMap::from([(
                ProbeId::GitPorcelain,
                output("u UU N... 100644 100644 100644 100644 a b c file\n", 0),
            )]),
            ..Default::default()
        };
        for subcommand in ["merge", "rebase", "pull", "checkout", "switch", "commit"] {
            let result = collect(&failure(&[subcommand]), &mut context(&runner));
            assert!(
                matches!(result.finding, Some(Finding::GitConflicts)),
                "{subcommand}"
            );
        }
        assert_eq!(*runner.calls.borrow(), [ProbeId::GitPorcelain; 6]);
    }

    #[test]
    fn unrelated_git_command_does_not_run_probes() {
        let runner = FixtureRunner::default();
        let result = collect(&failure(&["log"]), &mut context(&runner));
        assert!(result.finding.is_none());
        assert!(runner.calls.borrow().is_empty());
    }
}
