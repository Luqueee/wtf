use std::path::Path;
use std::time::UNIX_EPOCH;

use super::{AdapterContext, AdapterEvidence, AdapterResult, Finding};
use crate::capture::CommandExecution;
use crate::probes::{systemd_unit, ProbeId, ProbeRunner};

pub(super) fn collect<R: ProbeRunner>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'_, R>,
) -> AdapterResult {
    let mut result = AdapterResult::default();
    if !cfg!(target_os = "linux")
        || Path::new(&failure.command)
            .file_name()
            .and_then(|s| s.to_str())
            != Some("systemctl")
        || failure.exit_code().is_none_or(|code| code == 0)
    {
        return result;
    }
    let [action, name] = failure.args.as_slice() else {
        result.note =
            Some("Only a single explicitly named systemctl start unit can be inspected.".into());
        return result;
    };
    if action != "start" {
        result.note = Some("Only systemctl start is supported for unit diagnosis.".into());
        return result;
    }
    let Some(unit) = systemd_unit(name) else {
        result.note = Some("The requested service unit is not safe to inspect.".into());
        return result;
    };
    let Some(show) = context.run(ProbeId::SystemdShow, Some(&unit)) else {
        result.note = Some("Unit state could not be inspected safely.".into());
        return result;
    };
    if !show.ok() {
        result.note = Some("Unit state is incomplete or unavailable.".into());
        return result;
    }
    let Some(state) = parse_state(&show.stdout, &unit) else {
        result.note = Some("Unit state did not match the requested service.".into());
        return result;
    };
    if state.load == "not-found" {
        result.evidence.push(AdapterEvidence {
            probe: ProbeId::SystemdShow,
            observation: format!("{unit} has LoadState=not-found"),
        });
        result.finding = Some(Finding::SystemdUnitNotFound { unit });
        return result;
    }
    if state.load != "loaded"
        || state.active != "failed"
        || state.result == "success"
        || state.result.is_empty()
    {
        result.note =
            Some("The requested unit is not currently in a verified failed state.".into());
        return result;
    }
    result.evidence.push(AdapterEvidence {
        probe: ProbeId::SystemdShow,
        observation: format!("{unit} is in a failed state"),
    });
    let mut cause = None;
    if let (Some(invocation), Some((start, end))) = (state.invocation, failure_window(failure)) {
        if invocation.len() == 32 && invocation.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            let target = format!("{unit}|{invocation}|{start}|{end}");
            if let Some(logs) = context.run(ProbeId::SystemdLogs, Some(&target)) {
                if logs.ok() {
                    cause = known_cause(&logs.stdout);
                    if let Some(cause) = cause {
                        result.evidence.push(AdapterEvidence {
                            probe: ProbeId::SystemdLogs,
                            observation: format!(
                                "the matching unit invocation reported {cause} during the failed start"
                            ),
                        });
                    }
                }
            }
        }
    }
    result.finding = Some(Finding::SystemdFailed { unit, cause });
    result
}

struct UnitState<'a> {
    load: &'a str,
    active: &'a str,
    result: &'a str,
    invocation: Option<&'a str>,
}

fn parse_state<'a>(output: &'a str, expected: &str) -> Option<UnitState<'a>> {
    let (mut id, mut load, mut active, mut result, mut invocation) = (None, None, None, None, None);
    for line in output.lines() {
        let (key, value) = line.split_once('=')?;
        let slot = match key {
            "Id" => &mut id,
            "LoadState" => &mut load,
            "ActiveState" => &mut active,
            "Result" => &mut result,
            "InvocationID" => &mut invocation,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return None;
        }
    }
    (id? == expected).then_some(UnitState {
        load: load?,
        active: active?,
        result: result?,
        invocation,
    })
}

fn failure_window(failure: &CommandExecution) -> Option<(u64, u64)> {
    let timestamp = failure.timestamp.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let elapsed = failure.duration.as_secs();
    if elapsed > 3596 {
        return None;
    }
    // Explicit capture stores start time; the shell hook stores finish time.
    // The union covers both without trusting unrecorded output or running the action again.
    Some((
        timestamp.saturating_sub(elapsed + 1),
        timestamp.saturating_add(elapsed + 1),
    ))
}

fn known_cause(log: &str) -> Option<&'static str> {
    for line in log.lines().rev() {
        if contains_ascii_case(line, b"no space left on device") {
            return Some("no space left on device");
        }
        if contains_ascii_case(line, b"address already in use") {
            return Some("an address already in use");
        }
    }
    None
}

fn contains_ascii_case(text: &str, needle: &[u8]) -> bool {
    text.as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
