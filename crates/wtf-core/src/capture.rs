use std::io::{self, Read};
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
    mut reader: R,
    max_bytes: usize,
) -> io::Result<String> {
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
        // Everything fit without truncation
        let mut all_bytes = head;
        all_bytes.extend_from_slice(&ring.into_vec());
        Ok(String::from_utf8_lossy(&all_bytes).into_owned())
    } else {
        let omitted = total_bytes - (head.len() + ring.len());
        let head_str = String::from_utf8_lossy(&head);
        let tail_bytes = ring.into_vec();
        let tail_str = String::from_utf8_lossy(&tail_bytes);
        Ok(format!(
            "{}\n[... {} bytes omitted ...]\n{}",
            head_str, omitted, tail_str
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
    let start_time = Instant::now();
    let timestamp = SystemTime::now();

    let mut cmd = Command::new(command);
    cmd.args(args);
    cmd.current_dir(&config.cwd);
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
            return CommandExecution {
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
            };
        }
    };

    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let max_stream_bytes = config.max_stream_bytes;

    let stdout_thread = thread::spawn(move || {
        if let Some(reader) = stdout_handle {
            drain_stream_bounded(reader, max_stream_bytes)
                .unwrap_or_else(|e| format!("<error reading stdout: {e}>"))
        } else {
            String::new()
        }
    });

    let stderr_thread = thread::spawn(move || {
        if let Some(reader) = stderr_handle {
            drain_stream_bounded(reader, max_stream_bytes)
                .unwrap_or_else(|e| format!("<error reading stderr: {e}>"))
        } else {
            String::new()
        }
    });

    let wait_res = child.wait();
    let duration = start_time.elapsed();

    let stdout = stdout_thread
        .join()
        .unwrap_or_else(|_| "<stdout thread panicked>".to_string());
    let stderr = stderr_thread
        .join()
        .unwrap_or_else(|_| "<stderr thread panicked>".to_string());

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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
}
