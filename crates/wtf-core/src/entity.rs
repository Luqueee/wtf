use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::capture::CommandExecution;
use crate::normalizer::NormalizedOutput;

static PORT_KEYWORD_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bport\s*(?:is|\:|=|\b)\s*(\d{1,5})\b").expect("valid port keyword regex")
});

static HOST_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::):(\d{1,5})\b")
        .expect("valid host:port regex")
});

static DOCKER_PORT_ARG_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)-p\s*(\d{1,5}):(\d{1,5})").expect("valid docker port regex")
});

static BIND_ERROR_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:bind|listen|address).*?:(\d{1,5})\b").expect("valid bind port regex")
});

static UNIX_ERROR_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches GNU and BSD utilities:
    // "cat: /foo/bar: No such file or directory"
    // "ls: cannot access '/foo/bar': No such file or directory"
    // "cat: ‘/foo/bar’: No such file or directory"
    // "rm: cannot remove '/foo/bar': Permission denied"
    Regex::new(r#"(?:^|[a-zA-Z0-9_\-\.]+:\s*(?:cannot\s+[a-zA-Z]+\s+)?)(?:['"`\\‘“])?([/~][a-zA-Z0-9_\-./]+)(?:['"`\\’”:])?:\s*(?:No such file|Permission denied|Is a directory|Not a directory|File exists)"#)
        .expect("valid unix error path regex")
});

static QUOTED_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"`\\‘“]([/~.][a-zA-Z0-9_\-./]+)['"`\\’”]"#).expect("valid quoted path regex")
});

static UNQUOTED_ABSOLUTE_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|\s)(/[a-zA-Z0-9_\-./]+)(?:[\s:,;]|$)"#).expect("valid unquoted path regex")
});

static PROCESS_PID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b([a-zA-Z0-9_\-\.]+)\s*\((?:PID|pid)\s*\d+\)"#)
        .expect("valid process pid regex")
});

/// Extracted entities from execution and output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedEntities {
    pub ports: Vec<u16>,
    pub paths: Vec<PathBuf>,
    pub processes: Vec<String>,
    pub services: Vec<String>,
    pub containers: Vec<String>,
}

impl ExtractedEntities {
    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
            && self.paths.is_empty()
            && self.processes.is_empty()
            && self.services.is_empty()
            && self.containers.is_empty()
    }

    pub fn primary_port(&self) -> Option<u16> {
        self.ports.first().copied()
    }

    pub fn primary_path(&self) -> Option<&PathBuf> {
        self.paths.first()
    }

    pub fn primary_process(&self) -> Option<&str> {
        self.processes.first().map(|s| s.as_str())
    }

    pub fn primary_container(&self) -> Option<&str> {
        self.containers.first().map(|s| s.as_str())
    }
}

/// Entity extractor for finding ports, paths, and processes.
pub struct EntityExtractor;

impl EntityExtractor {
    pub fn extract(exec: &CommandExecution, norm: &NormalizedOutput) -> ExtractedEntities {
        let mut entities = ExtractedEntities::default();

        let full_text = format!(
            "{} {}\n{}\n{}",
            exec.command,
            exec.args.join(" "),
            norm.clean_stdout,
            norm.clean_stderr
        );

        // 1. Extract ports
        Self::extract_ports(&full_text, exec, &mut entities.ports);

        // 2. Extract paths
        Self::extract_paths(&full_text, exec, norm, &mut entities.paths);

        // 3. Extract processes, services, containers
        Self::extract_processes_and_services(exec, &full_text, &mut entities);

        entities
    }

    fn extract_ports(text: &str, exec: &CommandExecution, ports: &mut Vec<u16>) {
        // Check docker -p 8080:80 in args
        for i in 0..exec.args.len() {
            if exec.args[i] == "-p" || exec.args[i] == "--publish" {
                if let Some(spec) = exec.args.get(i + 1) {
                    if let Some((host_part, _)) = spec.split_once(':') {
                        if let Ok(p) = host_part.parse::<u16>() {
                            if p > 0 && !ports.contains(&p) {
                                ports.push(p);
                            }
                        }
                    }
                }
            } else if let Some(caps) = DOCKER_PORT_ARG_REGEX.captures(&exec.args[i]) {
                if let Some(p_str) = caps.get(1) {
                    if let Ok(p) = p_str.as_str().parse::<u16>() {
                        if p > 0 && !ports.contains(&p) {
                            ports.push(p);
                        }
                    }
                }
            }
        }

        // Check keyword "port 8080"
        for caps in PORT_KEYWORD_REGEX.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                if let Ok(p) = m.as_str().parse::<u16>() {
                    if p > 0 && !ports.contains(&p) {
                        ports.push(p);
                    }
                }
            }
        }

        // Check host:port pattern
        for caps in HOST_PORT_REGEX.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                if let Ok(p) = m.as_str().parse::<u16>() {
                    if p > 0 && !ports.contains(&p) {
                        ports.push(p);
                    }
                }
            }
        }

        // Check bind / address :8080 pattern
        for caps in BIND_ERROR_PORT_REGEX.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                if let Ok(p) = m.as_str().parse::<u16>() {
                    if p > 0 && !ports.contains(&p) {
                        ports.push(p);
                    }
                }
            }
        }
    }

    fn extract_paths(
        text: &str,
        exec: &CommandExecution,
        norm: &NormalizedOutput,
        paths: &mut Vec<PathBuf>,
    ) {
        // High priority: check relevant error lines
        for line in &norm.relevant_lines {
            if let Some(caps) = UNIX_ERROR_PATH_REGEX.captures(line) {
                if let Some(m) = caps.get(1) {
                    if let Some(path) = Self::sanitize_path(m.as_str()) {
                        if !paths.contains(&path) {
                            paths.push(path);
                        }
                    }
                }
            }
        }

        // Check unix error path pattern in full text
        for caps in UNIX_ERROR_PATH_REGEX.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                if let Some(path) = Self::sanitize_path(m.as_str()) {
                    if !paths.contains(&path) {
                        paths.push(path);
                    }
                }
            }
        }

        // Check quoted paths
        for caps in QUOTED_PATH_REGEX.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                if let Some(path) = Self::sanitize_path(m.as_str()) {
                    if !paths.contains(&path) {
                        paths.push(path);
                    }
                }
            }
        }

        // If command is a file utility like cat, ls, rm, stat, etc., check arguments
        let file_cmds = [
            "cat", "ls", "head", "tail", "stat", "rm", "cp", "mv", "touch", "nano", "vim",
        ];
        let cmd_base = std::path::Path::new(&exec.command)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&exec.command);

        if file_cmds.contains(&cmd_base) {
            for arg in &exec.args {
                if !arg.starts_with('-') {
                    if let Some(p) = Self::sanitize_path(arg) {
                        if !paths.contains(&p) {
                            paths.push(p);
                        }
                    }
                }
            }
        }

        // Fallback: check unquoted absolute paths in output text if none found yet
        if paths.is_empty() {
            for caps in UNQUOTED_ABSOLUTE_PATH_REGEX.captures_iter(&norm.clean_stderr) {
                if let Some(m) = caps.get(1) {
                    if let Some(p) = Self::sanitize_path(m.as_str()) {
                        if !paths.contains(&p) {
                            paths.push(p);
                        }
                    }
                }
            }
            if paths.is_empty() {
                for caps in UNQUOTED_ABSOLUTE_PATH_REGEX.captures_iter(&norm.clean_stdout) {
                    if let Some(m) = caps.get(1) {
                        if let Some(p) = Self::sanitize_path(m.as_str()) {
                            if !paths.contains(&p) {
                                paths.push(p);
                            }
                        }
                    }
                }
            }
        }
    }

    fn sanitize_path(raw: &str) -> Option<PathBuf> {
        let trimmed = raw.trim().trim_matches([
            '\'', '"', '`', '\\', ':', ';', ',', '(', ')', '[', ']', '‘', '’', '“', '”',
        ]);
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.starts_with('/')
            || trimmed.starts_with('~')
            || trimmed.starts_with("./")
            || trimmed.starts_with("../")
            || trimmed.contains('/')
        {
            Some(PathBuf::from(trimmed))
        } else {
            None
        }
    }

    fn extract_processes_and_services(
        exec: &CommandExecution,
        text: &str,
        entities: &mut ExtractedEntities,
    ) {
        let cmd_base = std::path::Path::new(&exec.command)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&exec.command)
            .to_string();

        // 1. Process from command
        if !entities.processes.contains(&cmd_base) {
            entities.processes.push(cmd_base.clone());
        }

        // 2. Process mentioned in error output: e.g. "node (PID 18291)"
        for caps in PROCESS_PID_REGEX.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                let proc_name = m.as_str().to_string();
                if !entities.processes.contains(&proc_name) {
                    entities.processes.push(proc_name);
                }
            }
        }

        // 3. Docker container / image extraction
        if cmd_base == "docker" {
            if let Some(sub) = exec.args.first() {
                match sub.as_str() {
                    "run" => {
                        // Only consume known option values; an unknown option leaves the
                        // image ambiguous, so do not report a container in that case.
                        let mut args = exec.args.iter().skip(1);
                        while let Some(arg) = args.next() {
                            if arg == "--" {
                                if let Some(image) = args.next() {
                                    entities.containers.push(image.clone());
                                }
                                break;
                            }
                            if matches!(
                                arg.as_str(),
                                "-p" | "--publish"
                                    | "-v"
                                    | "--volume"
                                    | "-e"
                                    | "--env"
                                    | "--env-file"
                                    | "--name"
                                    | "--network"
                                    | "--pull"
                                    | "--label"
                                    | "--platform"
                                    | "-w"
                                    | "--workdir"
                                    | "-u"
                                    | "--user"
                                    | "--entrypoint"
                                    | "--restart"
                            ) {
                                if args.next().is_none() {
                                    break;
                                }
                                continue;
                            }
                            if matches!(
                                arg.as_str(),
                                "-d" | "--detach" | "-i" | "-t" | "-it" | "--rm"
                            ) || arg.starts_with("--") && arg.contains('=')
                                || ["-p", "-v", "-e"]
                                    .iter()
                                    .any(|flag| arg.starts_with(flag) && arg.len() > flag.len())
                            {
                                continue;
                            }
                            if !arg.starts_with('-') {
                                entities.containers.push(arg.clone());
                            }
                            break;
                        }
                    }
                    "stop" | "start" | "restart" | "rm" | "logs" | "exec" => {
                        for arg in exec.args.iter().skip(1) {
                            if !arg.starts_with('-') {
                                entities.containers.push(arg.clone());
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // 4. systemd service extraction
        if cmd_base == "systemctl" {
            for arg in exec.args.iter().skip(1) {
                if !arg.starts_with('-') {
                    let mut svc = arg.clone();
                    if !svc.ends_with(".service") {
                        svc.push_str(".service");
                    }
                    entities.services.push(svc);
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::ProcessExit;
    use std::time::{Duration, SystemTime};

    fn make_exec(
        cmd: &str,
        args: &[&str],
        stdout: &str,
        stderr: &str,
    ) -> (CommandExecution, NormalizedOutput) {
        let exec = CommandExecution {
            command: cmd.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: PathBuf::from("/tmp"),
            exit_status: ProcessExit {
                code: Some(1),
                signal: None,
            },
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            duration: Duration::from_millis(10),
            timestamp: SystemTime::now(),
            spawn_error: None,
        };
        let norm = NormalizedOutput {
            clean_stdout: stdout.to_string(),
            clean_stderr: stderr.to_string(),
            relevant_lines: vec![stderr.lines().next().unwrap_or("").to_string()],
            collapsed_count: 0,
        };
        (exec, norm)
    }

    #[test]
    fn test_extract_port_from_docker_args() {
        let (exec, norm) = make_exec(
            "docker",
            &["run", "-p", "8080:80", "nginx"],
            "",
            "bind: address already in use",
        );
        let entities = EntityExtractor::extract(&exec, &norm);
        assert_eq!(entities.primary_port(), Some(8080));
        assert_eq!(entities.primary_container(), Some("nginx"));
    }

    #[test]
    fn docker_run_options_are_not_mistaken_for_the_image() {
        let (exec, norm) = make_exec(
            "docker",
            &[
                "run",
                "--name",
                "wtf-test",
                "--network",
                "none",
                "--pull",
                "never",
                "--label",
                "wtf.phase4.test=true",
                "busybox:latest",
                "sh",
                "-c",
                "exit 42",
            ],
            "",
            "",
        );
        let entities = EntityExtractor::extract(&exec, &norm);
        assert_eq!(entities.primary_container(), Some("busybox:latest"));
    }

    #[test]
    fn test_extract_port_from_error_message() {
        let (exec, norm) = make_exec(
            "curl",
            &["localhost:5432"],
            "",
            "curl: (7) Failed to connect to localhost port 5432: Connection refused",
        );
        let entities = EntityExtractor::extract(&exec, &norm);
        assert_eq!(entities.primary_port(), Some(5432));
    }

    #[test]
    fn test_extract_path_from_cat_error() {
        let (exec, norm) = make_exec(
            "cat",
            &["/foo/bar"],
            "",
            "cat: /foo/bar: No such file or directory",
        );
        let entities = EntityExtractor::extract(&exec, &norm);
        assert_eq!(entities.primary_path(), Some(&PathBuf::from("/foo/bar")));
    }

    #[test]
    fn test_extract_process_from_pid_line() {
        let (exec, norm) = make_exec(
            "node",
            &["server.js"],
            "",
            "Error: listen EADDRINUSE :::8000\nnode (PID 18291)",
        );
        let entities = EntityExtractor::extract(&exec, &norm);
        assert_eq!(entities.primary_port(), Some(8000));
        assert!(entities.processes.contains(&"node".to_string()));
    }
}
