use std::process::Command;

fn wtf_bin() -> &'static str {
    env!("CARGO_BIN_EXE_wtf")
}

#[test]
fn test_cli_cat_file_not_found() {
    let output = Command::new(wtf_bin())
        .args(["--no-color", "--", "cat", "/foo/bar"])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ File does not exist."));
    assert!(stdout.contains("Evidence:"));
    assert!(stdout.contains("cat: /foo/bar: No such file or directory"));
    assert!(stdout.contains("Detected:"));
    assert!(stdout.contains("path: /foo/bar"));
    assert!(stdout.contains("category: filesystem/not-found"));
}

#[test]
fn test_cli_cat_file_not_found_with_fix() {
    let output = Command::new(wtf_bin())
        .args(["--no-color", "--fix", "--", "cat", "/foo/bar"])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Fix:"));
    assert!(stdout.contains("Check that the path '/foo/bar' exists"));
}

#[test]
fn test_cli_command_not_found() {
    let output = Command::new(wtf_bin())
        .args(["--no-color", "--", "command_that_does_not_exist_98765"])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(127));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ Command 'command_that_does_not_exist_98765' was not found."));
    assert!(stdout.contains("category: command/not-found"));
}

#[test]
fn test_cli_success_command() {
    let output = Command::new(wtf_bin())
        .args(["--no-color", "--", "echo", "hello", "world"])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello world"));
}

#[test]
fn test_cli_json_output() {
    let output = Command::new(wtf_bin())
        .args(["--json", "--", "cat", "/foo/bar"])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");

    assert_eq!(json["status"], "Confirmed");
    assert_eq!(json["summary"], "File does not exist.");
    assert_eq!(json["category"], "filesystem/not-found");
    assert_eq!(json["entities"]["paths"][0], "/foo/bar");
}

#[test]
fn test_cli_port_conflict_simulation() {
    // Simulate docker port conflict failure via a child process output
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "sh",
            "-c",
            "echo 'docker: Error response from daemon: driver failed programming external connectivity: Bind for 0.0.0.0:8080 failed: port is already allocated' >&2; echo 'bind: address already in use' >&2; exit 1",
        ])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ Port 8080 is already in use."));
    assert!(stdout.contains("category: network/port-conflict"));
    assert!(stdout.contains("port: 8080"));
}

#[test]
fn test_cli_permission_denied_simulation() {
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "sh",
            "-c",
            "echo 'cat: /etc/shadow: Permission denied' >&2; exit 1",
        ])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ Permission denied."));
    assert!(stdout.contains("category: filesystem/permission-denied"));
    assert!(stdout.contains("path: /etc/shadow"));
}

#[test]
fn test_cli_connection_refused_simulation() {
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "sh",
            "-c",
            "echo 'curl: (7) Failed to connect to localhost port 5432: Connection refused' >&2; exit 7",
        ])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(7));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ Connection to port 5432 was refused."));
    assert!(stdout.contains("category: network/connection-refused"));
    assert!(stdout.contains("port: 5432"));
}

#[test]
fn test_cli_disk_full_simulation() {
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "sh",
            "-c",
            "echo 'write error: No space left on device' >&2; exit 1",
        ])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ No space left on device."));
    assert!(stdout.contains("category: filesystem/disk-full"));
}

#[test]
fn test_cli_large_simultaneous_streams_deadlock_prevention() {
    // Generate 50,000 lines on stdout and stderr simultaneously to prove no pipe deadlock occurs
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "sh",
            "-c",
            "python3 -c 'import sys\nfor i in range(20000):\n    sys.stdout.write(\"out \" + str(i) + \"\\n\")\n    sys.stderr.write(\"err \" + str(i) + \"\\n\")\nsys.stderr.write(\"cat: /var/log/missing.log: No such file or directory\\n\")\nsys.exit(1)'",
        ])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ File does not exist."));
    assert!(stdout.contains("path: /var/log/missing.log"));
}

#[test]
fn test_cli_invalid_utf8_output_handling() {
    // Output raw non-UTF8 bytes along with a file error
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "python3",
            "-c",
            "import sys\nsys.stderr.buffer.write(b'\\xff\\xfe\\x80cat: /bad/path.txt: No such file or directory\\n')\nsys.exit(1)",
        ])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ File does not exist."));
    assert!(stdout.contains("path: /bad/path.txt"));
}

#[test]
fn test_cli_unknown_failure_fallback() {
    let output = Command::new(wtf_bin())
        .args([
            "--no-color",
            "--",
            "sh",
            "-c",
            "echo 'unexpected mystery failure occurred' >&2; exit 42",
        ])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(42));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("? Command failed with exit code 42."));
    assert!(stdout.contains("Evidence:"));
    assert!(stdout.contains("unexpected mystery failure occurred"));
    assert!(stdout.contains("category: unknown"));
}

#[test]
fn test_cli_argv_spaces_preserved_without_shell_injection() {
    // Verify arguments with spaces and quotes are passed directly to binary
    let output = Command::new(wtf_bin())
        .args(["--no-color", "--", "cat", "/path with spaces/file.txt"])
        .output()
        .expect("failed to run wtf");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✗ File does not exist."));
    assert!(stdout.contains("path: /path with spaces/file.txt"));
}
