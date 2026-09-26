use std::net::Ipv4Addr;

use serde_json::Value;

use super::{AdapterContext, AdapterEvidence, AdapterResult, Finding};
use crate::capture::CommandExecution;
use crate::probes::{ProbeId, ProbeRunner};

fn port_error_line(line: &str) -> bool {
    line.contains("Error response from daemon:")
        && (line.contains("port is already allocated") || line.contains("address already in use"))
        && (line.contains("Bind for ") || line.contains("failed to bind host port for "))
}

pub(super) fn is_port_error(stderr: &str) -> bool {
    stderr.lines().any(port_error_line)
}

/// Docker's daemon error names the host socket that it could not allocate.
/// Application stderr and generic bind errors do not establish this failure.
pub(super) fn reported_conflict(stderr: &str) -> Option<(Ipv4Addr, u16)> {
    let mut reported = None;
    for line in stderr.lines() {
        if !port_error_line(line) {
            continue;
        }
        let tail = line
            .split_once("Bind for ")
            .or_else(|| line.split_once("failed to bind host port for "))?
            .1;
        let (host, rest) = tail.split_once(':')?;
        let host = host.parse::<Ipv4Addr>().ok()?;
        let count = rest.bytes().take_while(u8::is_ascii_digit).count();
        let port = rest
            .get(..count)?
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)?;
        let suffix = rest.get(count..)?;
        if !suffix.starts_with(':') && !suffix.starts_with(" failed:") {
            return None;
        }
        if reported.replace((host, port)).is_some() {
            return None;
        }
    }
    reported
}

pub(super) fn collect<R: ProbeRunner>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'_, R>,
) -> AdapterResult {
    let mut result = AdapterResult::default();
    if failure.exit_code() != Some(125) {
        result.note = Some("Docker did not report a pre-container failure.".into());
        return result;
    }
    let (Some((reported_host, reported_port)), Some((requested_host, requested_port))) = (
        reported_conflict(&failure.stderr),
        requested_port(&failure.args),
    ) else {
        result.note = Some(
            "The failed host port could not be matched to one explicit TCP publication.".into(),
        );
        return result;
    };
    if reported_host != requested_host || reported_port != requested_port {
        result.note =
            Some("The daemon's failed host socket differs from the requested publication.".into());
        return result;
    }
    let Some(started) = failure
        .timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
    else {
        result.note = Some("The original failure time is unavailable.".into());
        return result;
    };
    let Some(running) = context.run(ProbeId::DockerRunning, None) else {
        result.note = Some("Running Docker containers could not be inspected safely.".into());
        return result;
    };
    if !running.ok() {
        result.note = Some("Running Docker container data was incomplete.".into());
        return result;
    }
    let Some(owner) = published_owner(&running.stdout, requested_host, requested_port, started)
    else {
        result.note = Some("No unambiguous running container owns the requested host port.".into());
        return result;
    };
    result.evidence.push(AdapterEvidence {
        probe: ProbeId::DockerRunning,
        observation: format!("running container {owner} publishes host TCP port {requested_port}"),
    });
    result.finding = Some(Finding::DockerPortOccupied {
        owner,
        port: requested_port,
    });
    result
}

fn requested_port(args: &[String]) -> Option<(Ipv4Addr, u16)> {
    if args.first()?.as_str() != "run" {
        return None;
    }
    let mut publication = None;
    let mut index = 1;
    while let Some(arg) = args.get(index).map(String::as_str) {
        if matches!(arg, "-p" | "--publish") {
            index += 1;
            if publication
                .replace(parse_publication(args.get(index)?)?)
                .is_some()
            {
                return None;
            }
        } else if let Some(value) = arg.strip_prefix("--publish=") {
            if publication.replace(parse_publication(value)?).is_some() {
                return None;
            }
        } else if let Some(value) = arg.strip_prefix("-p").filter(|s| !s.is_empty()) {
            if publication.replace(parse_publication(value)?).is_some() {
                return None;
            }
        } else if matches!(arg, "-d" | "--detach" | "-it" | "-i" | "-t" | "--rm") {
            // Flags without a separate value.
        } else if arg == "--network" {
            index += 1;
            if !supported_network(args.get(index)?) {
                return None;
            }
        } else if let Some(network) = arg.strip_prefix("--network=") {
            if !supported_network(network) {
                return None;
            }
        } else if matches!(
            arg,
            "--name"
                | "-e"
                | "--env"
                | "-v"
                | "--volume"
                | "--mount"
                | "--label"
                | "-w"
                | "--workdir"
                | "--entrypoint"
                | "-u"
                | "--user"
                | "--restart"
                | "--pull"
        ) {
            index += 1;
            args.get(index)?;
        } else if arg.starts_with("--name=")
            || arg.starts_with("--label=")
            || arg.starts_with("--pull=")
        {
            // Known options that do not affect the requested port.
        } else if arg.starts_with('-') {
            return None;
        } else {
            // The first positional argument is the image, not another Docker option.
            return publication;
        }
        index += 1;
    }
    None
}
fn supported_network(network: &str) -> bool {
    !network.is_empty()
        && network != "host"
        && network != "none"
        && !network.starts_with("container:")
}

fn parse_publication(value: &str) -> Option<(Ipv4Addr, u16)> {
    let mut fields = value.split(':');
    let first = fields.next()?;
    let second = fields.next()?;
    let third = fields.next();
    let (host, host_port, container_port) = match third {
        Some(container_port) => (first.parse::<Ipv4Addr>().ok()?, second, container_port),
        None => (Ipv4Addr::UNSPECIFIED, first, second),
    };
    if fields.next().is_some() {
        return None;
    }
    let host_port = host_port.parse::<u16>().ok().filter(|port| *port != 0)?;
    let container_port = container_port
        .strip_suffix("/tcp")
        .unwrap_or(container_port);
    container_port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .map(|_| (host, host_port))
}

fn published_owner(
    output: &str,
    requested_host: Ipv4Addr,
    requested_port: u16,
    started: u64,
) -> Option<String> {
    let mut owner = None;
    for line in output.lines() {
        let row: Value = serde_json::from_str(line).ok()?;
        let ports = row.get("Ports").and_then(Value::as_str).unwrap_or_default();
        let matches = ports.split(',').any(|binding| {
            let Some((host_port, container_port)) = binding.trim().split_once("->") else {
                return false;
            };
            if !container_port.ends_with("/tcp") {
                return false;
            }
            let Some((host, port)) = host_port.rsplit_once(':') else {
                return false;
            };
            host.parse::<Ipv4Addr>().ok().is_some_and(|host| {
                (host == requested_host || host.is_unspecified() || requested_host.is_unspecified())
                    && port.parse::<u16>().ok() == Some(requested_port)
            })
        });
        if !matches {
            continue;
        }
        let created = row
            .get("CreatedAt")?
            .as_str()
            .and_then(super::docker::parse_docker_time)?;
        if created >= started {
            return None;
        }
        let name = row.get("Names")?.as_str()?.trim_start_matches('/');
        if !row.get("Status")?.as_str()?.starts_with("Up ")
            || name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            || owner.replace(name.to_owned()).is_some()
        {
            return None;
        }
    }
    owner
}
