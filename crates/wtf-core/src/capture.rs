use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

/// Maximum bytes kept per stream by default (1 MiB).
pub const DEFAULT_MAX_STREAM_BYTES: usize = 1024 * 1024;

/// Configuration for child process execution and capture.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    pub cwd: PathBuf,
    pub max_stream_bytes: usize,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
        }
    }
}

/// Represents the process exit status, supporting standard exit codes and signals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ProcessExit {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub fn code(&self) -> Option<i32> {
        self.code
    }

    pub fn signal(&self) -> Option<i32> {
        self.signal
    }

    pub fn display(&self) -> String {
        match (self.code, self.signal) {
            (Some(c), _) => format!("exit code {c}"),
            (None, Some(s)) => format!("terminated by signal {s}"),
            (None, None) => "unknown exit status".to_string(),
        }
    }
}

/// Information captured from a command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandExecution {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub exit_status: ProcessExit,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub timestamp: SystemTime,
    pub spawn_error: Option<String>,
}

impl CommandExecution {
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_status.code
    }

    pub fn is_success(&self) -> bool {
        self.exit_status.success() && self.spawn_error.is_none()
    }

    pub fn full_command(&self) -> String {
        if self.args.is_empty() {
            self.command.clone()
        } else {
            format!("{} {}", self.command, self.args.join(" "))
        }
    }
}

/// Drains a reader concurrently up to `max_bytes`, continuing to consume all remaining
/// bytes to prevent child process deadlocks.
///
/// If the output exceeds `max_bytes`, the head (25%) and tail (75%) are preserved,
/// and an omission marker is inserted in between.
pub fn drain_stream_bounded<R: Read + Send + 'static>(
    reader: R,
    max_bytes: usize,
) -> io::Result<String> {
    drain_stream_with_truncation(reader, max_bytes).map(|(text, _)| text)
}

fn drain_stream_with_truncation<R: Read + Send + 'static>(
    reader: R,
    max_bytes: usize,
) -> io::Result<(String, bool)> {
    drain_stream_with_truncation_while(reader, max_bytes, |_| Ok(()))
}

fn drain_stream_with_truncation_to_writer<R: Read + Send + 'static, W: Write>(
    reader: R,
    max_bytes: usize,
    writer: &mut W,
) -> io::Result<(String, bool)> {
    drain_stream_with_truncation_while(reader, max_bytes, |bytes| {
        writer.write_all(bytes)?;
        writer.flush()
    })
}

fn drain_stream_with_truncation_while<R, F>(
    mut reader: R,
    max_bytes: usize,
    mut forward: F,
) -> io::Result<(String, bool)>
where
    R: Read + Send + 'static,
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let mut total_bytes = 0usize;
    let head_limit = max_bytes / 4;
    let tail_limit = max_bytes.saturating_sub(head_limit);

    let mut head = Vec::new();
    let mut ring = RingBuffer::new(tail_limit);

    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total_bytes += n;

        // A broken destination should close the read end of the child pipe.
        // Otherwise a pipeline consumer can exit while the child keeps running
        // indefinitely instead of observing its ordinary broken-pipe failure.
        forward(&buf[..n])?;

        let chunk = &buf[..n];
        if head.len() < head_limit {
            let available = head_limit - head.len();
            let to_head = chunk.len().min(available);
            head.extend_from_slice(&chunk[..to_head]);
            let remaining = &chunk[to_head..];
            if !remaining.is_empty() {
                ring.push_slice(remaining);
            }
        } else {
            ring.push_slice(chunk);
        }
    }

    if total_bytes <= max_bytes {
        let mut all_bytes = head;
        all_bytes.extend_from_slice(&ring.into_vec());
        Ok((String::from_utf8_lossy(&all_bytes).into_owned(), false))
    } else {
        let omitted = total_bytes - (head.len() + ring.len());
        let head_str = String::from_utf8_lossy(&head);
        let tail_bytes = ring.into_vec();
        let tail_str = String::from_utf8_lossy(&tail_bytes);
        Ok((
            format!(
                "{}\n[... {} bytes omitted ...]\n{}",
                head_str, omitted, tail_str
            ),
            true,
        ))
    }
}

/// Simple rolling byte buffer for the stream tail.
struct RingBuffer {
    capacity: usize,
    buffer: Vec<u8>,
    start: usize,
    len: usize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buffer: vec![0u8; capacity],
            start: 0,
            len: 0,
        }
    }

    fn push_slice(&mut self, slice: &[u8]) {
        if self.capacity == 0 {
            return;
        }

        if slice.len() >= self.capacity {
            let start_idx = slice.len() - self.capacity;
            self.buffer.copy_from_slice(&slice[start_idx..]);
            self.start = 0;
            self.len = self.capacity;
            return;
        }

        for &b in slice {
            let write_pos = (self.start + self.len) % self.capacity;
            self.buffer[write_pos] = b;
            if self.len < self.capacity {
                self.len += 1;
            } else {
                self.start = (self.start + 1) % self.capacity;
            }
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn into_vec(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len);
        for i in 0..self.len {
            let idx = (self.start + i) % self.capacity;
            out.push(self.buffer[idx]);
        }
        out
    }
}

/// Executes a command directly (without a shell) and captures all metadata,
/// stdout, stderr, and exit status.
pub fn execute_command(
    command: &str,
    args: &[String],
    config: &ExecutionConfig,
) -> CommandExecution {
    execute_command_with_capture(command, args, config).0
}

/// Like `execute_command`, but returns whether either captured stream was truncated.
/// This fact comes from the byte counter, never from process-controlled output text.
pub fn execute_command_with_capture(
    command: &str,
    args: &[String],
    config: &ExecutionConfig,
) -> (CommandExecution, bool) {
    execute_command_with_capture_and_output(
        command,
        args,
        config,
        None::<io::Sink>,
        None::<io::Sink>,
    )
}

/// Executes the command once, forwarding raw stdout and stderr bytes as they arrive while
/// retaining bounded excerpts for diagnosis.
pub fn execute_command_with_live_capture(
    command: &str,
    args: &[String],
    config: &ExecutionConfig,
) -> (CommandExecution, bool) {
    execute_command_with_capture_and_output(
        command,
        args,
        config,
        Some(io::stdout()),
        Some(io::stderr()),
    )
}

fn execute_command_with_capture_and_output<StdoutWriter, StderrWriter>(
    command: &str,
    args: &[String],
    config: &ExecutionConfig,
    stdout_output: Option<StdoutWriter>,
    stderr_output: Option<StderrWriter>,
) -> (CommandExecution, bool)
where
    StdoutWriter: Write + Send + 'static,
    StderrWriter: Write + Send + 'static,
{
    let start_time = Instant::now();
    let timestamp = SystemTime::now();

    let mut cmd = Command::new(command);
    cmd.args(args);
    cmd.current_dir(&config.cwd);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            let duration = start_time.elapsed();
            let exit_code = match err.kind() {
                io::ErrorKind::NotFound => 127,
                io::ErrorKind::PermissionDenied => 126,
                _ => 1,
            };
            return (
                CommandExecution {
                    command: command.to_string(),
                    args: args.to_vec(),
                    cwd: config.cwd.clone(),
                    exit_status: ProcessExit {
                        code: Some(exit_code),
                        signal: None,
                    },
                    stdout: String::new(),
                    stderr: format!("wtf: failed to execute '{command}': {err}"),
                    duration,
                    timestamp,
                    spawn_error: Some(err.to_string()),
                },
                false,
            );
        }
    };

    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let max_stream_bytes = config.max_stream_bytes;

    let stdout_thread = thread::spawn(move || {
        let output = if let Some(reader) = stdout_handle {
            match stdout_output {
                Some(mut writer) => {
                    drain_stream_with_truncation_to_writer(reader, max_stream_bytes, &mut writer)
                }
                None => drain_stream_with_truncation(reader, max_stream_bytes),
            }
        } else {
            Ok((String::new(), false))
        };
        output.unwrap_or_else(|e| (format!("<error reading stdout: {e}>"), false))
    });

    let stderr_thread = thread::spawn(move || {
        let output = if let Some(reader) = stderr_handle {
            match stderr_output {
                Some(mut writer) => {
                    drain_stream_with_truncation_to_writer(reader, max_stream_bytes, &mut writer)
                }
                None => drain_stream_with_truncation(reader, max_stream_bytes),
            }
        } else {
            Ok((String::new(), false))
        };
        output.unwrap_or_else(|e| (format!("<error reading stderr: {e}>"), false))
    });

    let wait_res = child.wait();
    let duration = start_time.elapsed();

    let (stdout, stdout_truncated) = stdout_thread
        .join()
        .unwrap_or_else(|_| ("<stdout thread panicked>".to_string(), false));
    let (stderr, stderr_truncated) = stderr_thread
        .join()
        .unwrap_or_else(|_| ("<stderr thread panicked>".to_string(), false));

    let exit_status = match wait_res {
        Ok(status) => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                ProcessExit {
                    code: status.code(),
                    signal: status.signal(),
                }
            }
            #[cfg(not(unix))]
            {
                ProcessExit {
                    code: status.code(),
                    signal: None,
                }
            }
        }
        Err(_err) => ProcessExit {
            code: Some(1),
            signal: None,
        },
    };

    (
        CommandExecution {
            command: command.to_string(),
            args: args.to_vec(),
            cwd: config.cwd.clone(),
            exit_status,
            stdout,
            stderr,
            duration,
            timestamp,
            spawn_error: None,
        },
        stdout_truncated || stderr_truncated,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Write};
    use std::path::PathBuf;
    use std::sync::mpsc::{self, Sender};

    struct CapturedOutput {
        sender: Sender<Vec<u8>>,
        signal_on_flush: Option<PathBuf>,
    }

    impl Write for CapturedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.sender
                .send(bytes.to_vec())
                .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if let Some(path) = self.signal_on_flush.take() {
                std::fs::write(path, b"forwarded")?;
            }
            Ok(())
        }
    }

    #[test]
    fn test_drain_stream_within_limit() {
        let data = b"Hello, world!\nLine 2";
        let cursor = Cursor::new(data.to_vec());
        let res = drain_stream_bounded(cursor, 1024).unwrap();
        assert_eq!(res, "Hello, world!\nLine 2");
    }

    #[test]
    fn test_drain_stream_exceeding_limit() {
        // Create 2000 bytes
        let mut data = Vec::new();
        for i in 0..200 {
            data.extend_from_slice(format!("line {:04}\n", i).as_bytes());
        }
        let cursor = Cursor::new(data);
        // limit to 200 bytes
        let res = drain_stream_bounded(cursor, 200).unwrap();
        assert!(res.contains("bytes omitted"));
        assert!(res.starts_with("line 0000"));
        assert!(res.ends_with("line 0199\n"));
    }

    #[test]
    fn test_invalid_utf8_lossy() {
        let data = vec![b'f', b'o', b'o', 0xFF, 0xFE, b'b', b'a', b'r'];
        let cursor = Cursor::new(data);
        let res = drain_stream_bounded(cursor, 1024).unwrap();
        assert!(res.contains("foo"));
        assert!(res.contains("bar"));
    }

    #[test]
    fn test_execute_echo_success() {
        let config = ExecutionConfig::default();
        let args = vec!["hello world".to_string()];
        let exec = execute_command("echo", &args, &config);
        assert!(exec.is_success());
        assert_eq!(exec.exit_code(), Some(0));
        assert!(exec.stdout.contains("hello world"));
        assert!(exec.stderr.is_empty());
    }

    #[test]
    fn test_execute_nonexistent_command() {
        let config = ExecutionConfig::default();
        let args = vec![];
        let exec = execute_command(
            "this_command_definitely_does_not_exist_12345",
            &args,
            &config,
        );
        assert!(!exec.is_success());
        assert_eq!(exec.exit_code(), Some(127));
        assert!(exec.spawn_error.is_some());
        assert!(exec.stderr.contains("failed to execute"));
    }

    #[test]
    fn test_execute_large_output_no_deadlock() {
        // Output 500,000 bytes to stdout and stderr
        let config = ExecutionConfig {
            max_stream_bytes: 4096,
            ..Default::default()
        };
        let script = "for i in $(seq 1 1000); do echo \"out $i\"; echo \"err $i\" >&2; done";
        let args = vec!["-c".to_string(), script.to_string()];
        // using sh directly here only as a test child generating simultaneous large streams
        let exec = execute_command("sh", &args, &config);
        assert!(exec.stdout.contains("bytes omitted") || exec.stdout.contains("out"));
        assert!(exec.stderr.contains("bytes omitted") || exec.stderr.contains("err"));
    }

    #[test]
    fn live_capture_streams_both_raw_outputs_once_and_bounds_diagnosis() {
        let dir = tempfile::tempdir().unwrap();
        let config = ExecutionConfig {
            cwd: dir.path().to_path_buf(),
            max_stream_bytes: 8,
        };
        let (stdout_sender, stdout_receiver) = mpsc::channel();
        let (stderr_sender, stderr_receiver) = mpsc::channel();
        let stdout_writer = CapturedOutput {
            sender: stdout_sender,
            signal_on_flush: Some(dir.path().join("forwarded")),
        };
        let stderr_writer = CapturedOutput {
            sender: stderr_sender,
            signal_on_flush: None,
        };
        let script = "printf 'stdout\\000once'; printf 'stderr\\377once' >&2; attempts=0; while [ ! -e forwarded ] && [ \"$attempts\" -lt 100 ]; do sleep 0.01; attempts=$((attempts + 1)); done; if [ -e forwarded ]; then exit 23; else exit 24; fi";
        let args = vec!["-c".to_owned(), script.to_owned()];

        let (execution, truncated) = execute_command_with_capture_and_output(
            "sh",
            &args,
            &config,
            Some(stdout_writer),
            Some(stderr_writer),
        );

        assert_eq!(execution.command, "sh");
        assert_eq!(execution.args, args);
        assert_eq!(execution.exit_code(), Some(23));
        assert_eq!(execution.exit_status.signal(), None);
        assert!(execution.spawn_error.is_none());
        assert!(truncated);
        let stdout_bytes = stdout_receiver.try_iter().flatten().collect::<Vec<_>>();
        let stderr_bytes = stderr_receiver.try_iter().flatten().collect::<Vec<_>>();
        assert_eq!(stdout_bytes.as_slice(), b"stdout\0once");
        assert_eq!(stderr_bytes.as_slice(), b"stderr\xffonce");
        assert!(execution.stdout.contains("bytes omitted"));
        assert!(execution.stdout.starts_with("st"));
        assert!(execution.stdout.ends_with("once"));
        assert!(execution.stderr.contains("bytes omitted"));
        assert!(execution.stderr.starts_with("st"));
        assert!(execution.stderr.ends_with("once"));
    }

    #[cfg(unix)]
    #[test]
    fn live_capture_preserves_signal_termination() {
        let args = vec!["-c".to_owned(), "kill -TERM $$".to_owned()];
        let (execution, truncated) =
            execute_command_with_live_capture("sh", &args, &ExecutionConfig::default());

        assert_eq!(execution.exit_code(), None);
        assert_eq!(execution.exit_status.signal(), Some(15));
        assert!(execution.spawn_error.is_none());
        assert!(!truncated);
    }
}
