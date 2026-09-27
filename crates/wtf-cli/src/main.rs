use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wtf_core::capture::{
    execute_command_with_capture, execute_command_with_live_capture, CommandExecution,
    ExecutionConfig,
};
use wtf_core::diagnosis::{Diagnosis, DiagnosisEngine, DiagnosisStatus};
use wtf_core::investigation::{Investigation, InvestigationEngine};
use wtf_core::probes::LocalProbeRunner;

mod interpreter;
mod model;
mod model_cache;
mod report;
mod shell_install;
mod shell_state;
#[derive(Parser, Debug)]
#[command(
    name = "wtf",
    author,
    version,
    about = "Local evidence for failed terminal commands",
    after_help = "Example:\n  wtf -- cat /foo/bar\n  wtf -- docker run -p 8080:80 nginx"
)]
struct Cli {
    /// Output a versioned, structured evidence report in JSON
    #[arg(long)]
    json: bool,

    /// Disable colored terminal output
    #[arg(long)]
    no_color: bool,

    /// Print bounded, escaped and redacted captured stdout/stderr
    #[arg(long)]
    show_output: bool,
    /// Show the command's stdout/stderr live while retaining bounded diagnostic excerpts
    #[arg(long, conflicts_with_all = ["show_output", "json", "replay_snapshot"])]
    live: bool,

    /// Include suggested fix/remedy in diagnosis output
    #[arg(long)]
    fix: bool,

    /// Include probe provenance and captured metadata
    #[arg(long)]
    verbose: bool,
    /// Opt into a local Laya advisory (downloads a pinned bundle on first use)
    #[arg(long, conflicts_with = "no_model")]
    model: bool,
    /// Use an explicitly selected local Laya model for advisory hypothesis ranking
    #[arg(long, value_name = "DIR", conflicts_with = "no_model")]
    model_dir: Option<std::path::PathBuf>,

    /// Disable local model inference even if a bundle is selected
    #[arg(long)]
    no_model: bool,
    /// Opt into generic local GGUF interpretation; no weights are downloaded
    #[arg(long, value_name = "GGUF", conflicts_with_all = ["model", "model_dir"])]
    interpreter_model: Option<std::path::PathBuf>,

    /// Path to local llama.cpp unified executable (defaults to llama on PATH)
    #[arg(long, value_name = "PATH")]
    interpreter_runtime: Option<std::path::PathBuf>,

    /// Evaluation-only evidence replay; never executes the command or probes
    #[arg(long, hide = true, value_name = "SNAPSHOT")]
    replay_snapshot: Option<std::path::PathBuf>,

    /// Command and arguments to execute and diagnose
    #[arg(last = true)]
    command: Vec<String>,

    #[command(subcommand)]
    action: Option<Action>,
}

#[derive(Subcommand, Debug)]
enum Action {
    Install,
    Uninstall,
    #[command(name = "__record", hide = true)]
    Record {
        shell: String,
        exit_code: i32,
        start_epoch_seconds: u64,
        finish_epoch_seconds: u64,
        cwd: String,
        #[arg(allow_hyphen_values = true)]
        command_line: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.action {
        Some(Action::Install) => return shell_command(shell_install::install()),
        Some(Action::Uninstall) => return shell_command(shell_install::uninstall()),
        Some(Action::Record {
            shell,
            exit_code,
            start_epoch_seconds,
            finish_epoch_seconds,
            cwd,
            command_line,
        }) => {
            // Recording is best-effort: it must never change the status of the shell command.
            let _ = shell_state::record_failure(
                &command_line,
                &cwd,
                exit_code,
                start_epoch_seconds,
                finish_epoch_seconds,
                &shell,
            );
            return ExitCode::SUCCESS;
        }
        None => {}
    }
    if cli.live && cli.command.is_empty() {
        eprintln!("--live requires an explicit command after --");
        return ExitCode::from(2);
    }

    let explicit_command = !cli.command.is_empty() || cli.replay_snapshot.is_some();
    let (execution, capture_truncated) = if let Some(path) = &cli.replay_snapshot {
        #[derive(serde::Deserialize)]
        struct Snapshot {
            execution: CommandExecution,
            capture_truncated: bool,
        }
        let snapshot: Snapshot = match std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        {
            Some(snapshot) => snapshot,
            None => {
                eprintln!("Invalid local replay snapshot.");
                return ExitCode::from(1);
            }
        };
        (snapshot.execution, snapshot.capture_truncated)
    } else if !cli.command.is_empty() {
        let cmd = &cli.command[0];
        if cli.live {
            execute_command_with_live_capture(cmd, &cli.command[1..], &ExecutionConfig::default())
        } else {
            execute_command_with_capture(cmd, &cli.command[1..], &ExecutionConfig::default())
        }
    } else if let Some(execution) = shell_state::load_recent() {
        (execution, false)
    } else {
        println!("No recent failed command found.");
        return ExitCode::from(1);
    };

    if explicit_command && cli.show_output && !cli.json {
        let (stdout, stderr) = report::Report::sanitized_output(&execution);
        print!("{stdout}");
        eprint!("{stderr}");
    }

    let (diagnosis, investigation) = if cli.replay_snapshot.is_some() {
        (DiagnosisEngine::new().diagnose(&execution), None)
    } else {
        diagnose(&execution)
    };
    let no_model = cli.no_model || std::env::var("WTF_NO_MODEL").as_deref() == Ok("1");
    let model_result = ((cli.model || cli.model_dir.is_some()) && !no_model).then(|| {
        investigation.as_ref().map_or(Ok(None), |investigation| {
            if diagnosis.status == DiagnosisStatus::Confirmed {
                Ok(None)
            } else {
                model::decide(cli.model_dir.as_deref(), &diagnosis, investigation)
            }
        })
    });
    let mut report = report::Report::build(
        &execution,
        &diagnosis,
        investigation.as_ref(),
        if explicit_command {
            report::SourceMode::Explicit
        } else {
            report::SourceMode::ShellRecord
        },
        cli.fix,
        capture_truncated,
    );
    let interpretation = cli
        .interpreter_model
        .as_ref()
        .filter(|_| !no_model && !execution.is_success())
        .map(|model| {
            let runtime = cli
                .interpreter_runtime
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("llama"));
            interpreter::infer(
                runtime,
                model,
                &execution,
                investigation.as_ref(),
                capture_truncated,
            )
        });
    if let Some(Ok(value)) = &interpretation {
        report.add_interpretation(value);
    }
    render_result(
        &execution,
        &diagnosis,
        investigation.as_ref(),
        model_result.as_ref(),
        &report,
        interpretation.as_ref(),
        &cli,
    );

    match (diagnosis.exit_status.code, diagnosis.exit_status.signal) {
        (Some(code), _) => ExitCode::from((code & 0xFF) as u8),
        (None, Some(signal)) => ExitCode::from(((128 + signal) & 0xFF) as u8),
        _ => ExitCode::from(1),
    }
}

fn shell_command(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn diagnose(execution: &CommandExecution) -> (Diagnosis, Option<Investigation>) {
    let mut diagnosis = DiagnosisEngine::new().diagnose(execution);
    let investigation = if diagnosis.status == DiagnosisStatus::Success {
        None
    } else {
        let investigation = InvestigationEngine::new(LocalProbeRunner)
            .investigate_reconstructed(execution, &mut diagnosis);
        if investigation.root_cause.is_some() {
            diagnosis.status = DiagnosisStatus::Confirmed;
        }
        Some(investigation)
    };
    (diagnosis, investigation)
}

fn render_result(
    execution: &CommandExecution,
    diagnosis: &Diagnosis,
    investigation: Option<&Investigation>,
    model_result: Option<&Result<Option<model::ModelDecision>, String>>,
    report: &report::Report,
    interpretation: Option<&Result<interpreter::Interpretation, String>>,
    cli: &Cli,
) {
    if cli.json {
        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            schema_version: u32,
            report: &'a report::Report,
            #[serde(flatten)]
            diagnosis: &'a Diagnosis,
            investigation: Option<&'a Investigation>,
            #[serde(skip_serializing_if = "Option::is_none")]
            model_decision: Option<&'a model::ModelDecision>,
            #[serde(skip_serializing_if = "Option::is_none")]
            model_error: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            interpretation: Option<&'a interpreter::Interpretation>,
            #[serde(skip_serializing_if = "Option::is_none")]
            interpretation_error: Option<&'a str>,
        }
        let output = JsonOutput {
            schema_version: 1,
            report,
            diagnosis,
            investigation,
            model_decision: model_result.and_then(|result| result.as_ref().ok()?.as_ref()),
            model_error: model_result.and_then(|result| result.as_ref().err().map(String::as_str)),
            interpretation: interpretation.and_then(|result| result.as_ref().ok()),
            interpretation_error: interpretation
                .and_then(|result| result.as_ref().err().map(String::as_str)),
        };
        match serde_json::to_value(&output) {
            Ok(mut value) => {
                report::sanitize_json(&mut value);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("valid JSON value")
                );
            }
            Err(error) => println!("{}", serde_json::json!({ "error": error.to_string() })),
        }
        return;
    }

    let use_color = !cli.no_color
        && std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").as_deref() != Ok("dumb");
    print!(
        "{}",
        report.render(use_color, cli.verbose, execution, investigation)
    );
    if cli.verbose {
        if let Some(Err(error)) = interpretation {
            eprintln!("Local interpretation unavailable: {error}");
        }
    }
    if cli.verbose {
        if let Some(result) = model_result {
            match result {
                Ok(Some(decision)) => {
                    if let Some(preferred) = &decision.preferred {
                        println!(
                            "Local model ranked {preferred} (advisory; not a verified cause)."
                        );
                    } else {
                        println!("Local model abstained.");
                    }
                }
                Err(error) => eprintln!("Local model unavailable: {error}"),
                Ok(None) => {}
            }
        }
    }
}
