#[path = "support/e2e.rs"]
mod support;

use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use support::{shell_quote, Sandbox};

struct CurlFixture<'a> {
    sandbox: &'a Sandbox,
    fake_bin: PathBuf,
    curl_log: PathBuf,
    getent_log: PathBuf,
}

impl<'a> CurlFixture<'a> {
    fn new(sandbox: &'a Sandbox) -> Self {
        let fake_bin = sandbox.home.join("private-bin");
        fs::create_dir_all(&fake_bin).expect("create private fixture PATH");
        symlink(&sandbox.bin, fake_bin.join("wtf")).expect("make wtf available on private PATH");
        Self {
            sandbox,
            fake_bin,
            curl_log: sandbox.home.join("curl-invocations.log"),
            getent_log: sandbox.home.join("getent-invocations.log"),
        }
    }

    fn install_curl(&self, reported_host: &str) {
        let script = format!(
            "#!/bin/sh\n{{\n  printf 'CALL\\n'\n  for arg do printf 'ARG:%s\\n' \"$arg\"; done\n}} >> {}\nprintf 'curl: (6) Could not resolve host: %s\\n' {} >&2\nexit 6\n",
            shell_quote(&self.curl_log.to_string_lossy()),
            shell_quote(reported_host),
        );
        write_executable(&self.fake_bin.join("curl"), &script);
    }

    fn install_getent(&self, stdout: &str, exit_code: i32) {
        let script = format!(
            "#!/bin/sh\n{{\n  printf 'CALL\\n'\n  for arg do printf 'ARG:%s\\n' \"$arg\"; done\n}} >> {}\nprintf '%s\\n' {}\nexit {}\n",
            shell_quote(&self.getent_log.to_string_lossy()),
            shell_quote(stdout.trim_end_matches('\n')),
            exit_code,
        );
        write_executable(&self.fake_bin.join("getent"), &script);
    }

    fn install_fake_date(&self) {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after the Unix epoch")
            .as_secs();
        let script = format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", epoch);
        write_executable(&self.fake_bin.join("date"), &script);
    }

    fn private_path(&self) -> OsString {
        std::env::join_paths([self.fake_bin.as_path()])
            .expect("construct private PATH with only fixture commands and wtf")
    }

    fn run_explicit(&self, url: &str) -> Output {
        let path = self.private_path();
        Command::new("wtf")
            .args(["--json", "--", "curl", url])
            .env_clear()
            .env("WTF_NO_MODEL", "1")
            .env("HOME", &self.sandbox.home)
            .env("XDG_CONFIG_HOME", self.sandbox.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &self.sandbox.runtime)
            .env("SHELL", "/bin/bash")
            .env("PATH", path)
            .env("LC_ALL", "C")
            .current_dir(&self.sandbox.work)
            .output()
            .expect("run explicit wtf curl diagnostic")
    }

    fn assert_one_curl_call(&self, url: &str) {
        let log = fs::read_to_string(&self.curl_log).expect("read fake curl invocation log");
        assert_eq!(log, format!("CALL\nARG:{url}\n"));
    }

    fn assert_one_getent_call(&self, host: &str) {
        let log = fs::read_to_string(&self.getent_log).expect("read fake getent invocation log");
        assert_eq!(log, format!("CALL\nARG:hosts\nARG:{host}\n"));
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fake command");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make fake command executable");
}

fn assert_dns_symptom(json: &Value, command: &str) {
    assert_eq!(json["command"], command);
    assert_eq!(json["exit_status"]["code"], 6);
    assert_eq!(json["status"], "Likely");
    assert_eq!(json["category"], "network/dns");
    assert!(json["investigation"]["root_cause"].is_null(), "{json}");
}

fn has_hosts_probe(items: &Value) -> bool {
    items.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["probe"].as_str() == Some("Hosts"))
    })
}

fn assert_hosts_attempted(json: &Value) {
    assert!(
        has_hosts_probe(&json["investigation"]["attempts"]),
        "expected a Hosts probe attempt: {json}"
    );
}

fn assert_hosts_evidence(json: &Value) {
    assert!(
        has_hosts_probe(&json["investigation"]["evidence"]),
        "expected Hosts probe evidence: {json}"
    );
}

#[test]
fn explicit_dns_failure_records_local_lookup_without_confirming_root_cause() {
    let sandbox = Sandbox::new();
    let fixture = CurlFixture::new(&sandbox);
    let host = "failure.fixture.invalid";
    let url = format!("https://{host}/path-without-secrets");
    fixture.install_curl(host);
    fixture.install_getent("", 2);

    let output = fixture.run_explicit(&url);
    assert_eq!(output.status.code(), Some(6));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid CLI JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_dns_symptom(&json, &format!("curl {url}"));
    assert_hosts_attempted(&json);
    assert_hosts_evidence(&json);
    fixture.assert_one_curl_call(&url);
    fixture.assert_one_getent_call(host);
}

#[test]
fn explicit_successful_current_lookup_does_not_confirm_the_past_curl_symptom() {
    let sandbox = Sandbox::new();
    let fixture = CurlFixture::new(&sandbox);
    let host = "now-resolves.fixture.invalid";
    let url = format!("https://{host}/current-check");
    fixture.install_curl(host);
    fixture.install_getent("192.0.2.41 now-resolves.fixture.invalid", 0);

    let output = fixture.run_explicit(&url);
    assert_eq!(output.status.code(), Some(6));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid CLI JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_dns_symptom(&json, &format!("curl {url}"));
    assert_hosts_attempted(&json);
    assert_hosts_evidence(&json);
    fixture.assert_one_curl_call(&url);
    fixture.assert_one_getent_call(host);
}

#[test]
fn missing_getent_is_an_unavailable_probe_not_a_dns_confirmation() {
    let sandbox = Sandbox::new();
    let fixture = CurlFixture::new(&sandbox);
    let host = "probe-unavailable.fixture.invalid";
    let url = format!("https://{host}/unavailable-check");
    fixture.install_curl(host);
    // private_path contains only the fixture directory, which has no getent executable here.

    let output = fixture.run_explicit(&url);
    assert_eq!(output.status.code(), Some(6));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid CLI JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_dns_symptom(&json, &format!("curl {url}"));
    assert_hosts_attempted(&json);
    assert_eq!(
        json["investigation"]["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|attempt| attempt["probe"] == "Hosts")
            .unwrap()["result"],
        "unavailable"
    );
    fixture.assert_one_curl_call(&url);
    assert!(
        !fixture.getent_log.exists(),
        "real or fake getent must not run"
    );
}

#[test]
fn bash_hook_uses_hosts_probe_without_storing_output_or_replaying_curl() {
    let sandbox = Sandbox::new();
    sandbox.install_bash();
    let fixture = CurlFixture::new(&sandbox);
    let host = "hook.fixture.invalid";
    let url = format!("https://{host}/hook-check");
    fixture.install_curl(host);
    fixture.install_getent("", 2);
    fixture.install_fake_date();

    let json_path = sandbox.home.join("hook-diagnosis.json");
    let script = format!(
        "curl {}\nwtf --json > {}\n",
        shell_quote(&url),
        shell_quote(&json_path.to_string_lossy()),
    );
    let path = fixture.private_path().to_string_lossy().into_owned();
    let output = sandbox.run_bash(&sandbox.work, &script, &[("PATH", path.as_str())]);
    assert!(
        output.status.success(),
        "isolated Bash failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = sandbox.read_json(&json_path, &output);
    assert_dns_symptom(&json, &format!("curl {url}"));
    assert_hosts_attempted(&json);
    assert_hosts_evidence(&json);
    assert_eq!(json["normalized"]["clean_stdout"], "");
    assert_eq!(json["normalized"]["clean_stderr"], "");
    assert!(
        !serde_json::to_string(&json)
            .expect("serialize shell diagnosis")
            .contains("Could not resolve host"),
        "shell hook must reconstruct from metadata without persisting command output"
    );
    fixture.assert_one_curl_call(&url);
    fixture.assert_one_getent_call(host);
}

#[test]
fn mismatched_reported_host_withholds_the_hosts_probe() {
    let sandbox = Sandbox::new();
    let fixture = CurlFixture::new(&sandbox);
    let url_host = "requested.fixture.invalid";
    let reported_host = "different.fixture.invalid";
    let url = format!("https://{url_host}/mismatch-check");
    fixture.install_curl(reported_host);
    fixture.install_getent("192.0.2.77 different.fixture.invalid", 0);

    let output = fixture.run_explicit(&url);
    assert_eq!(output.status.code(), Some(6));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid CLI JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_dns_symptom(&json, &format!("curl {url}"));
    assert!(
        !has_hosts_probe(&json["investigation"]["attempts"]),
        "mismatched curl host must not be probed: {json}"
    );
    assert!(
        !has_hosts_probe(&json["investigation"]["evidence"]),
        "mismatched curl host must not produce Hosts evidence: {json}"
    );
    fixture.assert_one_curl_call(&url);
    assert!(
        !fixture.getent_log.exists(),
        "getent must be withheld when its target does not match curl's reported host"
    );
}
