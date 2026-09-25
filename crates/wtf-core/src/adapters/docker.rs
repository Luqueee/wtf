use super::{AdapterContext, AdapterEvidence, AdapterResult, Finding};
use crate::capture::CommandExecution;
use crate::probes::{ProbeId, ProbeRunner};
use serde_json::Value;

pub(super) fn collect<R: ProbeRunner>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'_, R>,
) -> AdapterResult {
    let mut result = AdapterResult::default();
    if !is_docker(&failure.command) || !matches!(failure.exit_code(), Some(code) if code != 0) {
        return result;
    }
    let Some(name) = explicit_name(&failure.args) else {
        return result;
    };
    let Some(all) = context.run(ProbeId::DockerAll, None) else {
        result.note = Some("Docker inspection was unavailable or timed out.".into());
        return result;
    };

    if all.truncated {
        result.note =
            Some("Docker container list exceeded the probe limit; cause is unknown.".into());
        return result;
    }
    if !all.ok() {
        let message = all.stderr.to_ascii_lowercase();
        if message.contains("cannot connect to the docker daemon")
            || message.contains("is the docker daemon running")
            || (message.contains("failed to connect to the docker api")
                && message.contains("daemon is running"))
        {
            result.evidence.push(AdapterEvidence {
                probe: ProbeId::DockerAll,
                observation: "Docker daemon cannot be reached".into(),
            });
            result.finding = Some(Finding::DockerDaemonUnavailable);
        }
        return result;
    }
    let Some((matched_name, created)) = exact_container(&all.stdout, &name) else {
        result.evidence.push(AdapterEvidence {
            probe: ProbeId::DockerAll,
            observation: "no exact matching container with creation time was found".into(),
        });
        return result;
    };
    // Shell records use the finish time; compare creation with the original execution window.
    let finished = failure
        .timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs());
    let started = finished.map(|end| end.saturating_sub(failure.duration.as_secs()));
    if !started.zip(finished).is_some_and(|(start, end)| {
        created >= start.saturating_sub(2) && created <= end.saturating_add(2)
    }) {
        result.evidence.push(AdapterEvidence {
            probe: ProbeId::DockerAll,
            observation:
                "the matching container predates or cannot be correlated with this command".into(),
        });
        return result;
    }
    result.evidence.push(AdapterEvidence {
        probe: ProbeId::DockerAll,
        observation: "an exact matching container was created during this command".into(),
    });

    let Some(inspect) = context.run(ProbeId::DockerInspect, Some(&matched_name)) else {
        return result;
    };
    if !inspect.ok() || inspect.truncated {
        return result;
    }
    let Some((state, inspected_name)) = parse_inspect(&inspect.stdout) else {
        return result;
    };
    if !container_names_match(&matched_name, &inspected_name) {
        return result;
    }
    let status = state
        .get("Status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if status != "exited" && status != "dead" {
        return result;
    }
    let Some(code) = state.get("ExitCode").and_then(Value::as_i64) else {
        return result;
    };
    let oom = state
        .get("OOMKilled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    result.evidence.push(AdapterEvidence {
        probe: ProbeId::DockerInspect,
        observation: format!(
            "the exact matching container exited with status {code}; OOM killed: {oom}"
        ),
    });
    result.finding = Some(Finding::DockerExited {
        name: name.clone(),
        code,
        oom,
    });

    if let Some(logs) = context
        .run(ProbeId::DockerLogs, Some(&matched_name))
        .filter(|logs| logs.ok() && !logs.truncated)
    {
        if let Some(variable) = missing_environment_variable(&logs.stdout)
            .or_else(|| missing_environment_variable(&logs.stderr))
        {
            result.evidence.push(AdapterEvidence {
                probe: ProbeId::DockerLogs,
                observation: format!(
                    "container logs indicate required environment variable {variable} is missing"
                ),
            });
            result.finding = Some(Finding::DockerMissingEnv { name, variable });
        }
    }
    result
}

fn is_docker(command: &str) -> bool {
    command
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name == "docker")
}

fn explicit_name(args: &[String]) -> Option<String> {
    if args.first().map(String::as_str) != Some("run") {
        return None;
    }
    let mut index = 1;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            break;
        }
        if arg == "--name" {
            let name = args.get(index + 1)?;
            return valid_name(name).then(|| name.clone());
        }
        if let Some(name) = arg.strip_prefix("--name=") {
            return valid_name(name).then(|| name.to_string());
        }
        if arg == "-d" || arg == "--detach" || arg == "-it" || arg == "-i" || arg == "-t" {
            index += 1;
        } else if matches!(
            arg,
            "-e" | "--env"
                | "-p"
                | "--publish"
                | "-v"
                | "--volume"
                | "--network"
                | "--label"
                | "-w"
                | "--workdir"
                | "--entrypoint"
                | "-u"
                | "--user"
                | "--restart"
        ) {
            index += 2;
        } else if arg.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    None
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn exact_container(output: &str, expected: &str) -> Option<(String, u64)> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|value| {
            let matches = value
                .get("Name")
                .and_then(Value::as_str)
                .is_some_and(|s| container_names_match(expected, s))
                || value.get("Names").and_then(Value::as_str).is_some_and(|s| {
                    s.split(',')
                        .any(|name| container_names_match(expected, name))
                });
            let created = value
                .get("CreatedAt")
                .and_then(Value::as_str)
                .and_then(parse_docker_time)?;
            matches.then(|| (expected.to_string(), created))
        })
}

fn parse_docker_time(value: &str) -> Option<u64> {
    let value = value.trim();
    let (date, time) = (value.get(..10)?, value.get(10..)?);
    let time = time.strip_prefix('T').or_else(|| time.strip_prefix(' '))?;
    let mut date = date.split('-');
    let year = date.next()?.parse::<i64>().ok()?;
    let month = date.next()?.parse::<i64>().ok()?;
    let day = date.next()?.parse::<i64>().ok()?;
    if date.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (clock, offset_seconds) = if time.contains(' ') {
        let mut fields = time.split_whitespace();
        let clock = fields.next()?;
        let offset = fields.next()?;
        let polarity = if offset.starts_with('+') {
            1
        } else if offset.starts_with('-') {
            -1
        } else {
            return None;
        };
        let digits = offset.get(1..)?;
        if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let hours = digits.get(..2)?.parse::<i64>().ok()?;
        let minutes = digits.get(2..)?.parse::<i64>().ok()?;
        if hours > 23 || minutes > 59 {
            return None;
        }
        (clock, polarity * (hours * 3600 + minutes * 60))
    } else {
        let (clock, offset) = if let Some((clock, offset)) = time.split_once('+') {
            (clock, Some((offset, 1)))
        } else if let Some((clock, offset)) = time.rsplit_once('-') {
            (clock, Some((offset, -1)))
        } else {
            (time.strip_suffix('Z')?, None)
        };
        let seconds = if let Some((offset, polarity)) = offset {
            let (hours, minutes) = offset.split_once(':')?;
            let hours = hours.parse::<i64>().ok()?;
            let minutes = minutes.parse::<i64>().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            polarity * (hours * 3600 + minutes * 60)
        } else {
            0
        };
        (clock, seconds)
    };
    let mut clock = clock.split(':');
    let hour = clock.next()?.parse::<i64>().ok()?;
    let minute = clock.next()?.parse::<i64>().ok()?;
    let second = clock.next()?.split('.').next()?.parse::<i64>().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    u64::try_from(days * 86400 + hour * 3600 + minute * 60 + second - offset_seconds).ok()
}

fn container_names_match(expected: &str, observed: &str) -> bool {
    observed.strip_prefix('/').unwrap_or(observed) == expected
}

fn parse_inspect(output: &str) -> Option<(Value, String)> {
    let mut parts = output.trim().splitn(3, '|');
    let state = serde_json::from_str(parts.next()?).ok()?;
    let _bindings = parts.next()?;
    let name = parts.next()?.trim().to_string();
    Some((state, name))
}

fn missing_environment_variable(logs: &str) -> Option<String> {
    for line in logs.lines() {
        let lower = line.to_ascii_lowercase();
        let mentions_missing =
            lower.contains("missing") || lower.contains("not set") || lower.contains("required");
        if !mentions_missing {
            continue;
        }
        for marker in [
            "environment variable ",
            "environment variable '",
            "environment variable \"",
        ] {
            let Some(position) = lower.find(marker) else {
                continue;
            };
            let tail = &line[position + marker.len()..];
            let word = tail
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default();
            if !word.is_empty()
                && word.len() <= 128
                && word
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                return Some(word.to_string());
            }
        }
        if let Some(position) = lower
            .find(" is required")
            .or_else(|| lower.find(" is missing"))
        {
            let candidate = line[..position]
                .split_ascii_whitespace()
                .last()
                .unwrap_or_default()
                .trim_matches(['\'', '"', '`', ':']);
            if !candidate.is_empty()
                && candidate.len() <= 128
                && candidate
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{ProbeError, ProbeOutput, ProbeSpec};
    use std::{cell::RefCell, path::Path, time::Duration};

    struct Fixture {
        responses: Vec<(ProbeId, ProbeOutput)>,
        calls: RefCell<Vec<ProbeId>>,
    }
    impl ProbeRunner for Fixture {
        fn run(&self, spec: &ProbeSpec) -> Result<ProbeOutput, ProbeError> {
            self.calls.borrow_mut().push(spec.id);
            self.responses
                .iter()
                .find(|(id, _)| *id == spec.id)
                .map(|(_, output)| output.clone())
                .ok_or_else(|| ProbeError::Unavailable(std::io::ErrorKind::NotFound.into()))
        }
        fn available(&self, _: &str) -> bool {
            true
        }
    }
    fn execution(args: &[&str]) -> CommandExecution {
        CommandExecution {
            command: "docker".into(),
            args: args.iter().map(|s| (*s).into()).collect(),
            cwd: ".".into(),
            exit_status: crate::capture::ProcessExit {
                code: Some(1),
                signal: None,
            },
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::ZERO,
            timestamp: std::time::UNIX_EPOCH + Duration::from_secs(1_704_067_200),
            spawn_error: None,
        }
    }
    fn out(stdout: &str) -> ProbeOutput {
        ProbeOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: Some(0),
            truncated: false,
        }
    }
    fn context<'a>(runner: &'a Fixture) -> AdapterContext<'a, Fixture> {
        AdapterContext::new(runner, Path::new("."), 5, Duration::from_secs(2))
    }
    fn fixtures(logs: &str) -> Fixture {
        Fixture {
            responses: vec![
                (
                    ProbeId::DockerAll,
                    out(r#"{"Names":"web","CreatedAt":"2024-01-01 00:00:01 +0000 UTC","ID":"1"}"#),
                ),
                (
                    ProbeId::DockerInspect,
                    out(r#"{"Status":"exited","ExitCode":137,"OOMKilled":true}|{}|/web"#),
                ),
                (ProbeId::DockerLogs, out(logs)),
            ],
            calls: RefCell::default(),
        }
    }

    #[test]
    fn diagnoses_exited_container_only_after_exact_match() {
        let runner = fixtures("process stopped");
        let mut ctx = context(&runner);
        let result = collect(&execution(&["run", "--name", "web", "image:tag"]), &mut ctx);
        assert!(
            matches!(result.finding, Some(Finding::DockerExited { ref name, code: 137, oom: true }) if name == "web")
        );
        assert_eq!(
            &*runner.calls.borrow(),
            &[
                ProbeId::DockerAll,
                ProbeId::DockerInspect,
                ProbeId::DockerLogs
            ]
        );
        let runner = Fixture {
            responses: vec![(ProbeId::DockerAll, out(r#"{"Names":"web-old"}"#))],
            calls: RefCell::default(),
        };
        let mut ctx = context(&runner);
        assert!(
            collect(&execution(&["run", "--name", "web", "image"]), &mut ctx)
                .finding
                .is_none()
        );
        assert_eq!(&*runner.calls.borrow(), &[ProbeId::DockerAll]);
        let runner = Fixture {
            responses: vec![(
                ProbeId::DockerAll,
                out(r#"{"Names":"web","CreatedAt":"2023-12-31T23:00:00Z"}"#),
            )],
            calls: RefCell::default(),
        };
        let mut ctx = context(&runner);
        let stale = collect(&execution(&["run", "--name", "web", "image"]), &mut ctx);
        assert!(stale.finding.is_none());
        assert_eq!(&*runner.calls.borrow(), &[ProbeId::DockerAll]);
    }

    #[test]
    fn identifies_missing_env_without_exposing_logs_or_command_secrets() {
        let runner = fixtures("environment variable API_KEY is required; value=secret-token");
        let mut ctx = context(&runner);
        let result = collect(
            &execution(&[
                "run",
                "--name",
                "web",
                "-e",
                "API_KEY=secret-token",
                "image",
            ]),
            &mut ctx,
        );
        assert!(
            matches!(result.finding, Some(Finding::DockerMissingEnv { ref variable, .. }) if variable == "API_KEY")
        );
        let exposed = format!("{:?}{:?}", result.finding, result.evidence);
        assert!(!exposed.contains("secret-token"));
        assert!(!exposed.contains("value="));
    }

    #[test]
    fn bare_required_environment_variable_in_stderr_is_diagnosed() {
        let mut runner = fixtures("");
        runner.responses[2].1.stderr = "DATABASE_URL is required".into();
        let result = collect(
            &execution(&["run", "--name", "web", "image"]),
            &mut context(&runner),
        );
        assert!(
            matches!(result.finding, Some(Finding::DockerMissingEnv { variable, .. }) if variable == "DATABASE_URL")
        );
    }

    #[test]
    fn daemon_unavailable_is_not_confused_with_unrelated_docker_errors() {
        let unavailable = ProbeOutput {
            stdout: String::new(),
            stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock".into(),
            exit_code: Some(1),
            truncated: false,
        };
        let runner = Fixture {
            responses: vec![(ProbeId::DockerAll, unavailable)],
            calls: RefCell::default(),
        };
        let mut ctx = context(&runner);
        assert!(matches!(
            collect(&execution(&["run", "--name", "web", "image"]), &mut ctx).finding,
            Some(Finding::DockerDaemonUnavailable)
        ));
    }

    #[test]
    fn modern_docker_api_connection_error_is_reported_as_unreachable() {
        let runner = Fixture {
            responses: vec![(
                ProbeId::DockerAll,
                ProbeOutput {
                    stdout: String::new(),
                    stderr: "failed to connect to the docker API at unix:///tmp/missing.sock; check if the path is correct and if the daemon is running: dial unix /tmp/missing.sock: connect: no such file or directory".into(),
                    exit_code: Some(1),
                    truncated: false,
                },
            )],
            calls: RefCell::default(),
        };
        let result = collect(
            &execution(&["run", "--name", "web", "image"]),
            &mut context(&runner),
        );
        assert!(matches!(
            result.finding,
            Some(Finding::DockerDaemonUnavailable)
        ));
    }

    #[test]
    fn no_explicit_name_means_no_container_probes() {
        let runner = fixtures("");
        let mut ctx = context(&runner);
        assert!(collect(&execution(&["run", "image"]), &mut ctx)
            .finding
            .is_none());
        assert!(runner.calls.borrow().is_empty());
    }
}
