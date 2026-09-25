#[path = "support/e2e.rs"]
mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use support::{shell_quote, Sandbox};

static NEXT_RUN: AtomicU64 = AtomicU64::new(0);

struct OwnedContainers {
    docker_host: String,
    docker_config: PathBuf,
    label: String,
    names: Vec<String>,
}

impl OwnedContainers {
    fn cleanup(&self) {
        for name in &self.names {
            let inspected = docker_command(&self.docker_host, &self.docker_config)
                .args([
                    "container",
                    "inspect",
                    "--format",
                    "{{.Id}} {{index .Config.Labels \"wtf.e2e.owner\"}}",
                    name,
                ])
                .output();
            let Ok(inspected) = inspected else { continue };
            if !inspected.status.success() {
                continue;
            }
            let result = String::from_utf8_lossy(&inspected.stdout);
            let mut fields = result.split_whitespace();
            let (Some(id), Some(label)) = (fields.next(), fields.next()) else {
                continue;
            };
            if label != self.label {
                continue;
            }
            let _ = docker_command(&self.docker_host, &self.docker_config)
                .args(["container", "rm", "--force", id])
                .output();
        }
    }
}

impl Drop for OwnedContainers {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn clear_docker_endpoint_overrides(command: &mut Command) {
    for key in [
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_API_VERSION",
    ] {
        command.env_remove(key);
    }
}

fn docker_command(docker_host: &str, docker_config: &Path) -> Command {
    let mut command = Command::new("docker");
    clear_docker_endpoint_overrides(&mut command);
    command
        .env("DOCKER_HOST", docker_host)
        .env("DOCKER_CONFIG", docker_config);
    command
}

fn current_context_command() -> Command {
    let mut command = Command::new("docker");
    clear_docker_endpoint_overrides(&mut command);
    command
}

fn docker_output(output: Output, description: &str) -> String {
    assert!(
        output.status.success(),
        "{description} failed ({}): stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("{description} returned non-UTF-8 output: {error}"))
        .trim()
        .to_owned()
}

fn assert_probe(json: &Value, expected: &str) {
    let evidence = json["investigation"]["evidence"]
        .as_array()
        .expect("investigation evidence is present");
    assert!(
        evidence.iter().any(|item| item["probe"] == expected),
        "expected {expected} evidence in {evidence:?}"
    );
}

#[test]
#[ignore = "requires opt-in Docker E2E runner"]
fn docker_shell_hook_diagnoses_real_failed_container_and_recovery() {
    assert_eq!(
        std::env::var("WTF_E2E_DOCKER").as_deref(),
        Ok("1"),
        "set WTF_E2E_DOCKER=1 to run the Docker E2E test"
    );

    let sandbox = Sandbox::new();
    sandbox.install_bash();

    // Read the active context once, then pin all Docker operations to its local socket.
    let endpoint = docker_output(
        current_context_command()
            .args([
                "context",
                "inspect",
                "--format",
                "{{.Endpoints.docker.Host}}",
            ])
            .output()
            .expect("run docker context inspect"),
        "resolve current Docker context endpoint",
    );
    assert!(
        endpoint.starts_with("unix://"),
        "Docker E2E requires a local Unix socket endpoint; got {endpoint:?}"
    );

    let docker_config = sandbox.home.join("docker-config");
    std::fs::create_dir(&docker_config).expect("create isolated Docker config");
    let image_id = docker_output(
        docker_command(&endpoint, &docker_config)
            .args(["image", "inspect", "busybox:latest", "--format", "{{.Id}}"])
            .output()
            .expect("inspect cached busybox:latest"),
        "inspect cached busybox:latest (network and pulls are disabled)",
    );
    assert!(
        image_id.starts_with("sha256:"),
        "Docker returned a non-immutable image ID: {image_id:?}"
    );

    let run_id = format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos(),
        NEXT_RUN.fetch_add(1, Ordering::Relaxed)
    );
    let owner_label = format!("wtf-e2e-{run_id}");
    let label = format!("wtf.e2e.owner={owner_label}");
    let first_name = format!("wtf-e2e-fail-{run_id}");
    let recovery_name = format!("wtf-e2e-recovery-{run_id}");
    let owned = OwnedContainers {
        docker_host: endpoint.clone(),
        docker_config: docker_config.clone(),
        label: owner_label,
        names: vec![first_name.clone(), recovery_name.clone()],
    };

    let command_args = |name: &str| {
        format!(
            "docker run --name {} --label {} --env DATABASE_URL --pull never --network none {} sh -c {}",
            shell_quote(name),
            shell_quote(&label),
            shell_quote(&image_id),
            shell_quote("if [ -z \"${DATABASE_URL:-}\" ]; then echo 'DATABASE_URL is required' >&2; exit 42; fi; echo app-started")
        )
    };
    let json_path = sandbox.work.join("docker-failure.json");

    let script = format!(
        "{}\nwtf --json > {}\nDATABASE_URL=local {}\nrecovery_status=$?\nprintf 'RECOVERY_STATUS=%s\\n' \"$recovery_status\"\nexit 0\n",
        command_args(&first_name),
        shell_quote(&json_path.to_string_lossy()),
        command_args(&recovery_name),
    );
    let output = sandbox.run_bash(
        &sandbox.work,
        &script,
        &[
            ("DOCKER_HOST", endpoint.as_str()),
            (
                "DOCKER_CONFIG",
                docker_config.to_str().expect("Docker config path is UTF-8"),
            ),
        ],
    );
    assert!(
        output.status.success(),
        "isolated Bash failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DATABASE_URL is required"),
        "Docker app failure must emit genuine stderr; stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("RECOVERY_STATUS=0"),
        "DATABASE_URL=local recovery did not succeed: stdout={stdout} stderr={stderr}"
    );

    let json = sandbox.read_json(&json_path, &output);
    assert_eq!(json["status"], "Confirmed", "diagnosis: {json}");
    assert_eq!(
        json["category"], "container/configuration",
        "diagnosis: {json}"
    );
    assert_eq!(json["exit_status"]["code"], 42, "diagnosis: {json}");
    assert_eq!(
        json["investigation"]["adapter"], "docker",
        "diagnosis: {json}"
    );
    assert!(
        json["investigation"]["root_cause"]
            .as_str()
            .is_some_and(|root| root.contains("DATABASE_URL")),
        "root cause should identify DATABASE_URL: {json}"
    );
    for probe in ["DockerAll", "DockerInspect", "DockerLogs"] {
        assert_probe(&json, probe);
    }

    drop(owned);
}
