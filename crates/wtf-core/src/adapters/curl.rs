use super::{AdapterContext, AdapterEvidence, AdapterResult, Finding};
use crate::capture::CommandExecution;
use crate::probes::{ProbeId, ProbeRunner};
use std::net::IpAddr;

pub(super) fn collect<R: ProbeRunner>(
    failure: &CommandExecution,
    context: &mut AdapterContext<'_, R>,
) -> AdapterResult {
    let mut result = AdapterResult::default();
    if !is_curl(&failure.command) || !matches!(failure.exit_code(), Some(6 | 7)) {
        return result;
    }
    let Some((host, port, local)) = request_target(&failure.args) else {
        return result;
    };

    if local && failure.exit_code() == Some(7) {
        let Some(output) = context
            .run(ProbeId::Listeners, None)
            .filter(|output| output.ok() && !output.truncated)
        else {
            return result;
        };
        let listening = listener_has_port(&output.stdout, port);
        result.evidence.push(AdapterEvidence {
            probe: ProbeId::Listeners,
            observation: if listening {
                format!("a local TCP listener is present on port {port}")
            } else {
                format!("no local TCP listener was found on port {port}")
            },
        });
        if !listening {
            result.finding = Some(Finding::CurlNoListener { port });
        }
    } else if !local && host.parse::<IpAddr>().is_err() {
        if failure.exit_code() == Some(6) {
            result.finding = Some(Finding::CurlDnsFailure { host: host.clone() });
        }
        if let Some(output) = context
            .run(ProbeId::Hosts, Some(&host))
            .filter(|output| !output.truncated)
        {
            let observation = if output.ok() && !output.stdout.trim().is_empty() {
                Some("the hostname currently resolves locally")
            } else if output.exit_code == Some(2)
                || (output.ok() && output.stdout.trim().is_empty())
            {
                Some("the local lookup returned no address")
            } else {
                None
            };
            if let Some(observation) = observation {
                result.evidence.push(AdapterEvidence {
                    probe: ProbeId::Hosts,
                    observation: observation.into(),
                });
            }
        }
    }
    result
}

fn is_curl(command: &str) -> bool {
    command
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name == "curl")
}

pub(super) fn request_target(args: &[String]) -> Option<(String, u16, bool)> {
    let mut url = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if matches!(
            arg,
            "-H" | "--header"
                | "-X"
                | "--request"
                | "-u"
                | "--user"
                | "-d"
                | "--data"
                | "--data-raw"
                | "--data-binary"
                | "--data-urlencode"
                | "-A"
                | "--user-agent"
                | "-e"
                | "--referer"
                | "-b"
                | "--cookie"
                | "-F"
                | "--form"
                | "-o"
                | "--output"
                | "-w"
                | "--write-out"
                | "--connect-timeout"
                | "--max-time"
        ) {
            index += 2;
            continue;
        }
        if arg == "--url" {
            index += 1;
            url = args.get(index).map(String::as_str);
        } else if let Some(value) = arg.strip_prefix("--url=") {
            url = Some(value);
        } else if arg.starts_with('-') {
            // Options which embed credentials or arbitrary values are not URL candidates.
        } else if url.is_none() {
            url = Some(arg);
        }
        index += 1;
    }
    parse_http_url(url?)
}

fn parse_http_url(url: &str) -> Option<(String, u16, bool)> {
    let (default_port, rest) = if let Some((scheme, rest)) = url.split_once("://") {
        let port = match scheme.to_ascii_lowercase().as_str() {
            "http" => 80,
            "https" => 443,
            _ => return None,
        };
        (port, rest)
    } else {
        (80, url)
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (address, tail) = bracketed.split_once(']')?;
        let ip = address.parse::<IpAddr>().ok()?;
        let port = match tail {
            "" => default_port,
            value => value.strip_prefix(':')?.parse::<u16>().ok()?,
        };
        (ip.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                (host.to_ascii_lowercase(), port.parse::<u16>().ok()?)
            }
            Some(_) => return None,
            None => (authority.to_ascii_lowercase(), default_port),
        }
    };
    if port == 0 || host.is_empty() || host.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    let local = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    Some((host, port, local))
}

fn listener_has_port(output: &str, port: u16) -> bool {
    let port = port.to_string();
    output.lines().any(|line| {
        line.split_ascii_whitespace().any(|field| {
            field
                .rsplit_once(':')
                .is_some_and(|(_, value)| value == port)
                || field
                    .rsplit_once('.')
                    .is_some_and(|(_, value)| value == port)
        })
    })
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
                .map(|(_, out)| out.clone())
                .ok_or_else(|| ProbeError::Unavailable(std::io::ErrorKind::NotFound.into()))
        }
        fn available(&self, _: &str) -> bool {
            true
        }
    }
    fn execution(args: &[&str], code: i32) -> CommandExecution {
        CommandExecution {
            command: "curl".into(),
            args: args.iter().map(|s| (*s).into()).collect(),
            cwd: ".".into(),
            exit_status: crate::capture::ProcessExit {
                code: Some(code),
                signal: None,
            },
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::ZERO,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
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
        AdapterContext::new(runner, Path::new("."), 4, Duration::from_secs(2))
    }

    #[test]
    fn refuses_to_replay_post_and_only_checks_verified_local_port() {
        let runner = Fixture {
            responses: vec![(ProbeId::Listeners, out(""))],
            calls: RefCell::default(),
        };
        let mut ctx = context(&runner);
        let result = collect(
            &execution(
                &[
                    "-X",
                    "POST",
                    "-H",
                    "Authorization: Bearer secret",
                    "-d",
                    "payload",
                    "http://localhost:8000/path",
                ],
                7,
            ),
            &mut ctx,
        );
        assert!(matches!(
            result.finding,
            Some(Finding::CurlNoListener { port: 8000 })
        ));
        assert_eq!(&*runner.calls.borrow(), &[ProbeId::Listeners]);
        let exposed = format!("{:?}{:?}", result.finding, result.evidence);
        assert!(!exposed.contains("secret"));
        assert!(!exposed.contains("payload"));
        assert!(!exposed.contains("/path"));
    }

    #[test]
    fn resolves_remote_host_without_retaining_url_credentials_or_path() {
        let runner = Fixture {
            responses: vec![(ProbeId::Hosts, out("192.0.2.8 example.test"))],
            calls: RefCell::default(),
        };
        let mut ctx = context(&runner);
        let result = collect(
            &execution(&["--url", "https://example.test/private?token=secret"], 7),
            &mut ctx,
        );
        assert!(result.finding.is_none());
        assert_eq!(&*runner.calls.borrow(), &[ProbeId::Hosts]);
        let exposed = format!("{:?}{:?}", result.finding, result.evidence);
        assert!(!exposed.contains("secret"));
        assert!(!exposed.contains("private"));
    }

    #[test]
    fn bare_localhost_and_dns_error_have_distinct_safe_checks() {
        let listener = Fixture {
            responses: vec![(ProbeId::Listeners, out(""))],
            calls: RefCell::default(),
        };
        let mut local = context(&listener);
        assert!(matches!(
            collect(&execution(&["localhost:8080"], 7), &mut local).finding,
            Some(Finding::CurlNoListener { port: 8080 })
        ));
        let dns = Fixture {
            responses: vec![(
                ProbeId::Hosts,
                ProbeOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: Some(2),
                    truncated: false,
                },
            )],
            calls: RefCell::default(),
        };
        let mut remote = context(&dns);
        assert!(matches!(
            collect(
                &execution(&["https://unresolved.example.test/path"], 6),
                &mut remote
            )
            .finding,
            Some(Finding::CurlDnsFailure { .. })
        ));
        assert_eq!(&*dns.calls.borrow(), &[ProbeId::Hosts]);
    }

    #[test]
    fn ignores_non_connect_failures_and_unparseable_secret_authority() {
        let runner = Fixture {
            responses: vec![],
            calls: RefCell::default(),
        };
        let mut ctx = context(&runner);
        assert!(
            collect(&execution(&["http://user:pass@example.test/"], 7), &mut ctx)
                .finding
                .is_none()
        );
        assert!(collect(&execution(&["http://localhost:80/"], 22), &mut ctx)
            .finding
            .is_none());
        assert!(runner.calls.borrow().is_empty());
    }
}
