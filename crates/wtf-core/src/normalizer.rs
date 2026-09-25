use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

static ANSI_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches standard ANSI CSI sequences and single ESC controls
    Regex::new(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\([B0])").expect("valid ANSI regex")
});

static OSC_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches Operating System Command (OSC) escape sequences
    Regex::new(r"\x1B\][^\x07\x1B]*(\x07|\x1B\\)").expect("valid OSC regex")
});

/// Strips all ANSI escape sequences (colors, cursor movements, OSC commands) from text.
pub fn strip_ansi(input: &str) -> String {
    let without_osc = OSC_REGEX.replace_all(input, "");
    ANSI_REGEX.replace_all(&without_osc, "").to_string()
}

/// Normalizes lines by handling carriage returns (e.g. progress bar overwrites `\r`),
/// normalizing `\r\n` to `\n`.
pub fn normalize_line_endings(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let normalized_newlines = input.replace("\r\n", "\n");

    for raw_line in normalized_newlines.split('\n') {
        // If a line contains carriage returns (in-place terminal overwriting)
        if raw_line.contains('\r') {
            // Keep the last non-empty segment after carriage returns
            let segments: Vec<&str> = raw_line.split('\r').filter(|s| !s.is_empty()).collect();
            if let Some(last) = segments.last() {
                out.push_str(last);
            }
        } else {
            out.push_str(raw_line);
        }
        out.push('\n');
    }

    // Strip trailing newline if input didn't have one
    if !input.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Collapses runs of identical consecutive lines if they repeat 3 or more times.
/// Returns the collapsed text and the number of collapsed lines eliminated.
pub fn collapse_repeated_lines(text: &str) -> (String, usize) {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return (String::new(), 0);
    }

    let mut result_lines = Vec::new();
    let mut collapsed_count = 0usize;

    let mut i = 0;
    while i < lines.len() {
        let current = lines[i];
        let mut count = 1;
        while i + count < lines.len() && lines[i + count] == current {
            count += 1;
        }

        result_lines.push(current.to_string());
        if count >= 3 && !current.trim().is_empty() {
            result_lines.push(format!("  [repeated {} more times]", count - 1));
            collapsed_count += count - 1;
        } else if count > 1 {
            // If only repeated twice, or empty line, keep them verbatim
            for _ in 1..count {
                result_lines.push(current.to_string());
            }
        }

        i += count;
    }

    let mut output = result_lines.join("\n");
    if text.ends_with('\n') {
        output.push('\n');
    }
    (output, collapsed_count)
}

/// Checks whether a single line is an indicator of an error, failure, or panic.
pub fn is_error_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_lowercase();

    // High confidence error keywords
    let error_keywords = [
        "error:",
        "error ",
        "fatal:",
        "fatal error",
        "panic:",
        "panicked at",
        "failed:",
        "failure:",
        "failed to",
        "cannot open",
        "cannot find",
        "cannot connect",
        "could not",
        "permission denied",
        "operation not permitted",
        "no such file or directory",
        "file not found",
        "not found",
        "address already in use",
        "port is already allocated",
        "bind: address already in use",
        "connection refused",
        "failed to connect",
        "no space left on device",
        "disk is full",
        "disk full",
        "out of memory",
        "command not found",
        "traceback (most recent call last):",
        "unhandled exception",
        "errno",
        "eacces",
        "enoent",
        "eaddrinuse",
        "econnrefused",
        "enospc",
        "eperm",
    ];

    for kw in &error_keywords {
        if lower.contains(kw) {
            return true;
        }
    }

    // Common CLI error prefixes like "cat: ", "curl: (7)", "docker: Error response"
    if trimmed.starts_with("cat:")
        || trimmed.starts_with("ls:")
        || trimmed.starts_with("curl:")
        || trimmed.starts_with("docker:")
        || trimmed.starts_with("git:")
        || trimmed.starts_with("node:")
        || trimmed.starts_with("python:")
        || trimmed.starts_with("sh:")
        || trimmed.starts_with("bash:")
        || trimmed.starts_with("zsh:")
        || trimmed.starts_with("wtf:")
    {
        return true;
    }

    false
}

/// Extracts relevant error lines from output, preserving context and removing duplicate noise.
pub fn extract_relevant_lines(stdout: &str, stderr: &str) -> Vec<String> {
    let mut relevant = Vec::new();

    // Stderr usually has higher priority for errors
    for line in stderr.lines() {
        let cleaned = line.trim();
        if is_error_line(cleaned) && !relevant.iter().any(|r| r == cleaned) {
            relevant.push(cleaned.to_string());
        }
    }

    // Then check stdout
    for line in stdout.lines() {
        let cleaned = line.trim();
        if is_error_line(cleaned) && !relevant.iter().any(|r| r == cleaned) {
            relevant.push(cleaned.to_string());
        }
    }

    // If no explicit error keyword line was matched, but stderr has content,
    // take the first few lines of stderr as relevant
    if relevant.is_empty() {
        for line in stderr.lines().take(5) {
            let cleaned = line.trim();
            if !cleaned.is_empty() && !relevant.iter().any(|r| r == cleaned) {
                relevant.push(cleaned.to_string());
            }
        }
    }

    relevant
}

/// Normalized output representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedOutput {
    pub clean_stdout: String,
    pub clean_stderr: String,
    pub relevant_lines: Vec<String>,
    pub collapsed_count: usize,
}

/// Output normalizer that cleans ANSI escapes, collapses noise, and extracts relevant lines.
pub struct OutputNormalizer;

impl OutputNormalizer {
    pub fn normalize(stdout: &str, stderr: &str) -> NormalizedOutput {
        let stdout_stripped = strip_ansi(stdout);
        let stderr_stripped = strip_ansi(stderr);

        let stdout_normalized = normalize_line_endings(&stdout_stripped);
        let stderr_normalized = normalize_line_endings(&stderr_stripped);

        let (clean_stdout, stdout_collapsed) = collapse_repeated_lines(&stdout_normalized);
        let (clean_stderr, stderr_collapsed) = collapse_repeated_lines(&stderr_normalized);

        let relevant_lines = extract_relevant_lines(&clean_stdout, &clean_stderr);

        NormalizedOutput {
            clean_stdout,
            clean_stderr,
            relevant_lines,
            collapsed_count: stdout_collapsed + stderr_collapsed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi_codes() {
        let raw = "\x1B[31;1mError:\x1B[0m \x1B[32mFile /foo/bar not found\x1B[0m\n";
        let stripped = strip_ansi(raw);
        assert_eq!(stripped, "Error: File /foo/bar not found\n");
    }

    #[test]
    fn test_strip_osc_codes() {
        let raw = "\x1B]0;Terminal Title\x07Some actual content\n";
        let stripped = strip_ansi(raw);
        assert_eq!(stripped, "Some actual content\n");
    }

    #[test]
    fn test_normalize_line_endings_and_carriage_return() {
        let raw = "Progress: 10%\rProgress: 50%\rProgress: 100%\nDone\r\nNext";
        let normalized = normalize_line_endings(raw);
        assert_eq!(normalized, "Progress: 100%\nDone\nNext");
    }

    #[test]
    fn test_collapse_repeated_lines() {
        let raw = "starting\nretrying\nretrying\nretrying\nretrying\nfailed\n";
        let (collapsed, count) = collapse_repeated_lines(raw);
        assert_eq!(count, 3);
        assert!(collapsed.contains("retrying\n  [repeated 3 more times]\nfailed"));
    }

    #[test]
    fn test_extract_relevant_lines() {
        let stdout = "All tests passed (32)";
        let stderr = "cat: /foo/bar: No such file or directory\nSome ignored info\n";
        let relevant = extract_relevant_lines(stdout, stderr);
        assert_eq!(relevant, vec!["cat: /foo/bar: No such file or directory"]);
    }
}
