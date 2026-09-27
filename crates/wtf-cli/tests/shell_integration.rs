use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn wtf_bin() -> &'static str {
    env!("CARGO_BIN_EXE_wtf")
}

#[derive(Clone, Copy)]
enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    fn executable(self) -> PathBuf {
        match self {
            Self::Bash => PathBuf::from("/bin/bash"),
            Self::Zsh => PathBuf::from("/bin/zsh"),
            Self::Fish => fish_executable().expect("Fish was checked as available"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }

    fn rc_path(self, home: &Path, config_home: &Path) -> PathBuf {
        match self {
            Self::Bash => home.join(".bashrc"),
            Self::Zsh => home.join(".zshrc"),
            Self::Fish => config_home.join("fish/conf.d/wtf.fish"),
        }
    }

    fn command(self, home: &Path, config_home: &Path, runtime: &Path, script: &str) -> Output {
        let executable = self.executable();
        let mut command = match self {
            Self::Fish => {
                let script_bin = script_executable().expect("Fish PTY requires script utility");
                let mut command = Command::new(script_bin);
                if cfg!(target_os = "macos") {
                    command.args(["-q", "/dev/null"]).arg(&executable).arg("-i");
                } else {
                    let fish_command = format!("{} -i", shell_quote(&executable));
                    command
                        .arg("-q")
                        .arg("-c")
                        .arg(&fish_command)
                        .arg("/dev/null");
                }
                command
            }
            Self::Bash => {
                let mut command = Command::new(&executable);
                command.args(["--noprofile", "--rcfile"]);
                command.arg(self.rc_path(home, config_home));
                command.arg("-i");
                command
            }
            Self::Zsh => {
                let mut command = Command::new(&executable);
                command.arg("-i");
                command
            }
        };
        let mut child = command
            .env_clear()
            .env("WTF_NO_MODEL", "1")
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", config_home)
            .env("XDG_RUNTIME_DIR", runtime)
            .env("SHELL", &executable)
            .env("ZDOTDIR", home)
            .env("PATH", test_path())
            .env("TERM", "dumb")
            .env("LC_ALL", "C")
            .current_dir(home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("failed to launch {}: {error}", self.name()));
        let mut stdin = child.stdin.take().expect("interactive shell stdin");
        stdin
            .write_all(script.as_bytes())
            .expect("write script to interactive shell");
        if matches!(self, Self::Fish) {
            let output = child
                .wait_with_output()
                .expect("wait for interactive Fish shell");
            drop(stdin);
            output
        } else {
            drop(stdin);
            child
                .wait_with_output()
                .expect("wait for interactive shell")
        }
    }
}
fn shell_quote(value: &Path) -> String {
    format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
}

fn fish_executable() -> Option<PathBuf> {
    let is_file = |path: PathBuf| path.is_file().then_some(path);
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join("fish"))
        .find(|path| path.is_file())
        .or_else(|| {
            [
                "/opt/homebrew/bin/fish",
                "/usr/local/bin/fish",
                "/usr/bin/fish",
                "/bin/fish",
            ]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        })
        .and_then(is_file)
}
fn script_executable() -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join("script"))
        .find(|path| path.is_file())
        .or_else(|| {
            ["/usr/bin/script", "/bin/script"]
                .into_iter()
                .map(PathBuf::from)
                .find(|path| path.is_file())
        })
}

fn test_path() -> String {
    let bin_dir = Path::new(wtf_bin())
        .parent()
        .expect("Cargo binary path has a parent");
    let mut paths = vec![bin_dir.to_path_buf(), PathBuf::from("/opt/homebrew/bin")];
    paths.extend(std::env::split_paths(OsStr::new(
        "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    )));
    std::env::join_paths(paths)
        .expect("test PATH should be representable")
        .to_string_lossy()
        .into_owned()
}

struct IsolatedShell {
    _temp: TempDir,
    home: PathBuf,
    config_home: PathBuf,
    runtime: PathBuf,
    shell: Shell,
}

impl IsolatedShell {
    fn new(shell: Shell) -> Self {
        let temp = tempfile::tempdir().expect("create isolated shell directory");
        let home = temp.path().join("home");
        let config_home = temp.path().join("config");
        let runtime = temp.path().join("runtime");
        fs::create_dir(&home).expect("create isolated HOME");
        fs::create_dir(&config_home).expect("create isolated XDG_CONFIG_HOME");
        fs::create_dir(&runtime).expect("create isolated XDG_RUNTIME_DIR");
        for directory in [&home, &config_home, &runtime] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("secure isolated shell directory");
        }
        let state = runtime.join("wtf");
        fs::create_dir(&state).expect("create isolated WTF state");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("secure isolated WTF state");
        Self {
            _temp: temp,
            home,
            config_home,
            runtime,
            shell,
        }
    }

    fn install(&self) {
        let output = Command::new(wtf_bin())
            .arg("install")
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("SHELL", self.shell.executable())
            .env("ZDOTDIR", &self.home)
            .env("PATH", test_path())
            .env("TERM", "dumb")
            .current_dir(&self.home)
            .output()
            .expect("run wtf install");
        assert!(
            output.status.success(),
            "wtf install for {} failed: {}{}",
            self.shell.name(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run(&self, script: &str) -> Output {
        self.shell
            .command(&self.home, &self.config_home, &self.runtime, script)
    }

    fn json_path(&self) -> PathBuf {
        self.home.join("result.json")
    }

    fn read_json(&self, path: &Path, shell_output: &Output) -> Value {
        let output_context = format!(
            "shell stdout: {}\nshell stderr: {}",
            String::from_utf8_lossy(&shell_output.stdout),
            String::from_utf8_lossy(&shell_output.stderr)
        );
        let bytes = fs::read(path).unwrap_or_else(|error| {
            panic!(
                "{} did not write JSON result {}: {error}\n{output_context}",
                self.shell.name(),
                path.display()
            )
        });
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "{} `wtf --json` produced invalid JSON ({error}): {}\n{output_context}",
                self.shell.name(),
                String::from_utf8_lossy(&bytes)
            )
        })
    }
    fn run_wtf(&self, args: &[String], ttl: Option<&str>) -> Output {
        let mut command = Command::new(wtf_bin());
        command
            .args(args)
            .env_clear()
            .env("WTF_NO_MODEL", "1")
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("SHELL", "/bin/bash")
            .env("PATH", test_path())
            .current_dir(&self.home);
        if let Some(ttl) = ttl {
            command.env("WTF_FAILURE_TTL_SECS", ttl);
        }
        command.output().expect("run wtf with isolated shell state")
    }

    fn record_failure_at(&self, finished_at: u64) {
        let cwd = self.home.to_string_lossy().into_owned();
        let args = vec![
            "__record".to_owned(),
            "bash".to_owned(),
            "1".to_owned(),
            finished_at.to_string(),
            finished_at.to_string(),
            cwd,
            "false".to_owned(),
        ];
        let output = self.run_wtf(&args, None);
        assert!(
            output.status.success(),
            "failed to seed shell failure state: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn base_shells() -> Vec<Shell> {
    [Shell::Bash, Shell::Zsh]
        .into_iter()
        .filter(|shell| Path::new(&shell.executable()).is_file())
        .collect()
}

fn available_shells() -> Vec<Shell> {
    let mut shells = base_shells();
    if fish_executable().is_some() && script_executable().is_some() {
        shells.push(Shell::Fish);
    }
    shells
}

fn assert_no_recent_failure(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "wtf should exit 1 when no valid failure exists: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "No recent failed command found."
    );
}

#[test]
fn installed_opt_in_live_wrapper_runs_once_without_recording_duplicate_failure() {
    for shell in available_shells() {
        let isolated = IsolatedShell::new(shell);
        isolated.install();
        let output = isolated.run(
            "wtfr sh -c 'printf x >> launched; printf \"live-tag\\\\n\"; exit 23'\ntrue\nexit 0\n",
        );
        assert_eq!(
            fs::read(isolated.home.join("launched")).unwrap_or_else(|error| {
                panic!(
                    "{} did not run wtfr: {error}; stdout={} stderr={}",
                    shell.name(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            }),
            b"x",
            "{} invoked the command more than once",
            shell.name()
        );
        let visible = String::from_utf8_lossy(&output.stdout);
        assert!(visible.contains("live-tag"), "{}: {visible}", shell.name());
        assert!(visible.contains("sh  23"), "{}: {visible}", shell.name());
        assert_no_recent_failure(&isolated.run_wtf(&[], None));
    }
}

#[test]
fn fish_preserves_direct_live_exit_status_at_the_next_prompt() {
    if fish_executable().is_none() || script_executable().is_none() {
        return;
    }
    for installed in [false, true] {
        let isolated = IsolatedShell::new(Shell::Fish);
        if installed {
            isolated.install();
        }
        let wrapper_check = if installed {
            "wtfr sh -c 'exit 29'\nprintf 'wrapper-status=%s\\n' $status > wrapper-status.txt\n"
        } else {
            ""
        };
        let script = format!(
            "wtf --no-color --live -- sh -c 'exit 23'\nprintf 'shell-status=%s\\n' $status > status.txt\n{wrapper_check}exit 0\n"
        );
        let output = isolated.run(&script);
        let status = fs::read_to_string(isolated.home.join("status.txt")).unwrap_or_else(|error| {
            panic!(
                "fish status file missing: {error}; {}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        assert_eq!(
            status,
            "shell-status=23\n",
            "installed={installed}; {}",
            String::from_utf8_lossy(&output.stdout)
        );
        if installed {
            assert_eq!(
                fs::read_to_string(isolated.home.join("wrapper-status.txt")).unwrap(),
                "wrapper-status=29\n"
            );
        }
    }
}

#[test]
fn cli_reports_missing_invalid_and_expired_shell_failure_records() {
    let isolated = IsolatedShell::new(Shell::Bash);
    assert_no_recent_failure(&isolated.run_wtf(&[], None));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_secs();
    isolated.record_failure_at(now);
    let record_path = isolated.runtime.join("wtf/last-failure.json");
    fs::write(&record_path, b"{invalid JSON").expect("corrupt isolated failure record");
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))
        .expect("secure corrupted failure record");
    assert_no_recent_failure(&isolated.run_wtf(&[], None));

    isolated.record_failure_at(now.saturating_sub(60));
    assert_no_recent_failure(&isolated.run_wtf(&[], Some("1")));
}

fn available_install_shells() -> Vec<Shell> {
    let mut shells = base_shells();
    if fish_executable().is_some() {
        shells.push(Shell::Fish);
    }
    shells
}

fn assert_json_failure(json: &Value, command: &str, exit_code: i64) {
    assert_eq!(json["command"], command, "JSON diagnosis command: {json}");
    assert_eq!(
        json["exit_status"]["code"], exit_code,
        "JSON exit status: {json}"
    );
    assert_ne!(
        json["status"], "Success",
        "failure should be diagnosed: {json}"
    );
    assert!(
        json.get("investigation").is_some(),
        "failure should include diagnosis investigation: {json}"
    );
}

fn assert_working_directory(isolated: &IsolatedShell) {
    let bytes = fs::read(isolated.home.join("context.txt")).expect("read verbose shell context");
    let output = String::from_utf8_lossy(&bytes);
    let displayed_path = output
        .lines()
        .find_map(|line| line.strip_prefix("   working directory: "))
        .expect("verbose diagnosis should include the working directory");
    let displayed_path = Path::new(displayed_path)
        .canonicalize()
        .expect("canonicalize displayed working directory");
    let expected_path = isolated
        .home
        .canonicalize()
        .expect("canonicalize isolated HOME");
    assert_eq!(
        displayed_path, expected_path,
        "verbose diagnosis should retain shell cwd: {output}"
    );
}
fn run_bash_pty(isolated: &IsolatedShell, commands: &[String]) -> Output {
    const PROMPT: &[u8] = b"__WTF_PROMPT_SYNC__";
    let bash_path = PathBuf::from("/bin/bash");
    let rc = Shell::Bash.rc_path(&isolated.home, &isolated.config_home);
    let script_bin = script_executable().expect("Bash PTY requires script utility");
    let mut command = Command::new(script_bin);
    if cfg!(target_os = "macos") {
        command
            .args(["-q", "/dev/null"])
            .arg(&bash_path)
            .args(["--noprofile", "--rcfile"])
            .arg(&rc)
            .arg("-i");
    } else {
        let shell_command = format!(
            "{} --noprofile --rcfile {} -i",
            shell_quote(&bash_path),
            shell_quote(&rc)
        );
        command
            .arg("-q")
            .arg("-c")
            .arg(shell_command)
            .arg("/dev/null");
    }
    let mut child = command
        .env_clear()
        .env("WTF_NO_MODEL", "1")
        .env("HOME", &isolated.home)
        .env("XDG_CONFIG_HOME", &isolated.config_home)
        .env("XDG_RUNTIME_DIR", &isolated.runtime)
        .env("SHELL", &bash_path)
        .env("ZDOTDIR", &isolated.home)
        .env("PATH", test_path())
        .env("TERM", "dumb")
        .env("LC_ALL", "C")
        .current_dir(&isolated.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch interactive Bash through script PTY");
    let mut stdin = child.stdin.take().expect("Bash PTY stdin");
    let stdout = child.stdout.take().expect("Bash PTY stdout");
    let (sender, receiver) = mpsc::channel();
    let stdout_reader = thread::spawn(move || {
        let mut stdout = stdout;
        let mut buffer = [0u8; 1024];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(bytes_read) if sender.send(buffer[..bytes_read].to_vec()).is_err() => break,
                Ok(_) => {}
            }
        }
    });
    let mut transcript = Vec::new();
    wait_for_prompt(&mut child, &receiver, &mut transcript, PROMPT);
    for line in commands {
        stdin
            .write_all(line.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .expect("send command to interactive Bash");
        wait_for_prompt(&mut child, &receiver, &mut transcript, PROMPT);
    }
    stdin
        .write_all(b"exit 0\n")
        .and_then(|_| stdin.flush())
        .expect("exit interactive Bash cleanly");
    drop(stdin);
    let mut output = child.wait_with_output().expect("wait for interactive Bash");
    stdout_reader.join().expect("join Bash PTY stdout reader");
    output.stdout = transcript;
    output
}

fn wait_for_prompt(
    child: &mut Child,
    receiver: &Receiver<Vec<u8>>,
    transcript: &mut Vec<u8>,
    prompt: &[u8],
) {
    if let Err(error) = read_until_prompt(receiver, transcript, prompt) {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "interactive Bash failed to reach prompt: {error}; transcript={}",
            String::from_utf8_lossy(transcript)
        );
    }
}

fn read_until_prompt(
    receiver: &Receiver<Vec<u8>>,
    transcript: &mut Vec<u8>,
    prompt: &[u8],
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let timeout = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(timeout) {
            Ok(bytes) => {
                transcript.extend_from_slice(&bytes);
                if transcript.ends_with(prompt) {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err("timed out waiting for prompt".to_owned())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("Bash PTY stdout closed before prompt".to_owned())
            }
        }
    }
    Err("timed out waiting for prompt".to_owned())
}

#[test]
fn bash_real_pty_tracks_latest_failure_after_wtf_and_success() {
    if script_executable().is_none() {
        return;
    }
    let isolated = IsolatedShell::new(Shell::Bash);
    fs::write(isolated.home.join(".bashrc"), "PS1='__WTF_PROMPT_SYNC__'\n")
        .expect("set isolated Bash prompt marker");
    isolated.install();

    let after_latest = isolated.home.join("after-latest.json");
    let after_repeat_wtf = isolated.home.join("after-repeat-wtf.json");
    let commands = vec![
        "false".to_owned(),
        "wtf > /dev/null".to_owned(),
        "sh -c 'exit 42'".to_owned(),
        "true".to_owned(),
        format!("wtf --json > {}", shell_quote(&after_latest)),
        format!("wtf --json > {}", shell_quote(&after_repeat_wtf)),
    ];
    let output = run_bash_pty(&isolated, &commands);
    assert!(
        output.status.success(),
        "Bash PTY session failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_json_failure(
        &isolated.read_json(&after_latest, &output),
        "sh -c exit 42",
        42,
    );
    assert_json_failure(
        &isolated.read_json(&after_repeat_wtf, &output),
        "sh -c exit 42",
        42,
    );
}

#[test]
fn interactive_shell_hooks_diagnose_false_with_json() {
    for shell in available_shells() {
        let isolated = IsolatedShell::new(shell);
        isolated.install();
        let script = format!(
            "false\nwtf --json > {}\nwtf --verbose > \"$HOME/context.txt\"\nexit 0\n",
            shell_quote(&isolated.json_path())
        );
        let output = isolated.run(&script);
        assert!(
            output.status.success(),
            "{} interactive shell failed: stdout={} stderr={}",
            shell.name(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_json_failure(
            &isolated.read_json(&isolated.json_path(), &output),
            "false",
            1,
        );
        assert_working_directory(&isolated);
    }
}

#[test]
fn interactive_shell_hooks_preserve_nonzero_exit_and_recent_failure() {
    for shell in available_shells() {
        let isolated = IsolatedShell::new(shell);
        isolated.install();
        let script = format!(
            "sh -c 'exit 42'\ntrue\nwtf --json > {}\nwtf --verbose > \"$HOME/context.txt\"\nexit 0\n",
            shell_quote(&isolated.json_path())
        );
        let output = isolated.run(&script);
        assert!(
            output.status.success(),
            "{} interactive shell failed: stdout={} stderr={}",
            shell.name(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_json_failure(
            &isolated.read_json(&isolated.json_path(), &output),
            "sh -c exit 42",
            42,
        );
        assert_working_directory(&isolated);
    }
}

#[test]
fn bash_hook_keeps_failed_commands_with_wtf_in_an_argument() {
    let isolated = IsolatedShell::new(Shell::Bash);
    isolated.install();
    let script = format!(
        "sh -c 'echo wtf.e2e.owner >&2; exit 42'\nwtf --json > {}\nexit 0\n",
        shell_quote(&isolated.json_path())
    );
    let output = isolated.run(&script);
    assert!(output.status.success(), "Bash session failed: {output:?}");
    let json = isolated.read_json(&isolated.json_path(), &output);
    assert_eq!(json["exit_status"]["code"], 42, "{json}");
    assert!(
        json["command"]
            .as_str()
            .is_some_and(|command| command.contains("wtf.e2e.owner")),
        "the failed command should remain available: {json}"
    );
}

#[test]
fn interactive_shell_wtf_does_not_replace_the_recent_failure() {
    for shell in available_shells() {
        let isolated = IsolatedShell::new(shell);
        isolated.install();
        let first = isolated.home.join("first.json");
        let second = isolated.home.join("second.json");
        let script = format!(
            "false\nwtf --json > {}\nwtf --json > {}\nexit 0\n",
            shell_quote(&first),
            shell_quote(&second)
        );
        let output = isolated.run(&script);
        assert!(
            output.status.success(),
            "{} interactive shell failed: stdout={} stderr={}",
            shell.name(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for path in [first, second] {
            let json = isolated.read_json(&path, &output);
            assert_json_failure(&json, "false", 1);
        }
        let context_output = isolated.run("wtf --verbose > \"$HOME/context.txt\"\nexit 0\n");
        assert!(
            context_output.status.success(),
            "{} interactive shell failed: stdout={} stderr={}",
            shell.name(),
            String::from_utf8_lossy(&context_output.stdout),
            String::from_utf8_lossy(&context_output.stderr)
        );
        assert_working_directory(&isolated);
    }
}

#[test]
fn shell_install_and_uninstall_are_idempotent_and_preserve_rc_content() {
    for shell in available_install_shells() {
        let isolated = IsolatedShell::new(shell);
        let rc = shell.rc_path(&isolated.home, &isolated.config_home);
        if matches!(shell, Shell::Fish) {
            let unrelated_rc = isolated.config_home.join("fish/config.fish");
            fs::create_dir_all(unrelated_rc.parent().expect("Fish config parent"))
                .expect("create isolated Fish config directory");
            let prior = "# unrelated Fish configuration\nset -gx WTF_TEST_SENTINEL preserved\n";
            fs::write(&unrelated_rc, prior).expect("write unrelated Fish config");
            isolated.install();
            let first_install = fs::read_to_string(&rc).expect("read installed Fish hook");
            isolated.install();
            assert_eq!(
                fs::read_to_string(&rc).expect("read repeated Fish install"),
                first_install,
                "repeated Fish install should not duplicate the hook"
            );
            for _ in 0..2 {
                let output = Command::new(wtf_bin())
                    .arg("uninstall")
                    .env_clear()
                    .env("HOME", &isolated.home)
                    .env("XDG_CONFIG_HOME", &isolated.config_home)
                    .env("XDG_RUNTIME_DIR", &isolated.runtime)
                    .env("SHELL", shell.executable())
                    .env("ZDOTDIR", &isolated.home)
                    .env("PATH", test_path())
                    .current_dir(&isolated.home)
                    .output()
                    .expect("run Fish wtf uninstall");
                assert!(
                    output.status.success(),
                    "Fish uninstall failed: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert!(
                !rc.exists(),
                "Fish uninstall should remove its managed hook file"
            );
            assert_eq!(
                fs::read_to_string(unrelated_rc).expect("read unrelated Fish config"),
                prior,
                "Fish install/uninstall should preserve unrelated config"
            );
            continue;
        }

        let prior =
            "# unrelated user shell configuration\nexport SHELL_INTEGRATION_SENTINEL=preserved\n";
        fs::write(&rc, prior).expect("write isolated shell rc content");
        isolated.install();
        let first_install = fs::read_to_string(&rc).expect("read first installed shell rc");
        isolated.install();
        let installed = fs::read_to_string(&rc).expect("read installed shell rc");
        assert_eq!(
            installed, first_install,
            "repeated install should not duplicate the hook"
        );
        assert!(
            installed.contains(prior),
            "install must preserve existing rc content"
        );
        assert!(
            installed.len() > prior.len(),
            "install should add the shell hook"
        );

        let output = Command::new(wtf_bin())
            .arg("uninstall")
            .env_clear()
            .env("HOME", &isolated.home)
            .env("XDG_CONFIG_HOME", &isolated.config_home)
            .env("SHELL", shell.executable())
            .env("ZDOTDIR", &isolated.home)
            .env("PATH", test_path())
            .current_dir(&isolated.home)
            .output()
            .expect("run wtf uninstall");
        assert!(
            output.status.success(),
            "wtf uninstall for {} failed: {}{}",
            shell.name(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(wtf_bin())
            .arg("uninstall")
            .env_clear()
            .env("HOME", &isolated.home)
            .env("XDG_CONFIG_HOME", &isolated.config_home)
            .env("SHELL", shell.executable())
            .env("ZDOTDIR", &isolated.home)
            .env("PATH", test_path())
            .current_dir(&isolated.home)
            .output()
            .expect("run repeated wtf uninstall");
        assert!(output.status.success(), "repeated uninstall should succeed");
        let uninstalled = fs::read_to_string(&rc).expect("read uninstalled shell rc");
        assert_eq!(uninstalled, prior, "uninstall should remove its hook only");
    }
}
