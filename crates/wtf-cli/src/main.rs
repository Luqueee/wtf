use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wtf_core::capture::{execute_command, CommandExecution, ExecutionConfig};
use wtf_core::diagnosis::{Diagnosis, DiagnosisEngine, DiagnosisStatus, RenderOptions};
use wtf_core::investigation::{Investigation, InvestigationEngine};
use wtf_core::probes::LocalProbeRunner;

mod shell_install;
mod shell_state;

#[derive(Parser, Debug)]
#[command(
    name = "wtf",
    author,
    version,
    about = "A root-cause debugger for your terminal",
    after_help = "Example:\n  wtf -- cat /foo/bar\n  wtf -- docker run -p 8080:80 nginx"
)]
struct Cli {
    /// Output diagnosis in JSON format
    #[arg(long)]
    json: bool,

    /// Disable colored terminal output
    #[arg(long)]
    no_color: bool,

    /// Print raw stdout and stderr produced by the command
    #[arg(long)]
    show_output: bool,

    /// Include suggested fix/remedy in diagnosis output
    #[arg(long)]
    fix: bool,

    /// Include investigation hypotheses, probes, evidence, and captured metadata
    #[arg(long)]
    verbose: bool,

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

    let explicit_command = !cli.command.is_empty();
    let execution = if explicit_command {
        let cmd = &cli.command[0];
        execute_command(cmd, &cli.command[1..], &ExecutionConfig::default())
    } else if let Some(execution) = shell_state::load_recent() {
        execution
    } else {
        println!("No recent failed command found.");
        return ExitCode::from(1);
    };

    if explicit_command && cli.show_output && !cli.json {
        if !execution.stdout.is_empty() {
            print!("{}", execution.stdout);
        }
        if !execution.stderr.is_empty() {
            eprint!("{}", execution.stderr);
        }
    }

    let (diagnosis, investigation) = diagnose(&execution);
    render_result(&execution, &diagnosis, investigation.as_ref(), &cli);

    match diagnosis.exit_status.code {
        Some(code) => ExitCode::from((code & 0xFF) as u8),
        None => ExitCode::from(1),
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
        Some(
            InvestigationEngine::new(LocalProbeRunner)
                .investigate_reconstructed(execution, &mut diagnosis),
        )
    };
    (diagnosis, investigation)
}

fn render_result(
    execution: &CommandExecution,
    diagnosis: &Diagnosis,
    investigation: Option<&Investigation>,
    cli: &Cli,
) {
    if cli.json {
        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            #[serde(flatten)]
            diagnosis: &'a Diagnosis,
            investigation: Option<&'a Investigation>,
        }

        let output = JsonOutput {
            diagnosis,
            investigation,
        };
        let json_str = serde_json::to_string_pretty(&output)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {e}\"}}"));
        println!("{json_str}");
        return;
    }

    if diagnosis.status == DiagnosisStatus::Success && !cli.show_output {
        if !execution.stdout.is_empty() {
            print!("{}", execution.stdout);
        }
        if !execution.stderr.is_empty() {
            eprint!("{}", execution.stderr);
        }
    } else if let Some(investigation) = investigation {
        if cli.verbose {
            println!(
                "Captured command: {}\nWorking directory: {}\nExit code: {}\nDuration: {:?}",
                execution.full_command(),
                execution.cwd.display(),
                execution.exit_status.code.map_or_else(
                    || "terminated by signal".to_string(),
                    |code| code.to_string()
                ),
                execution.duration
            );
        }
        let use_color = !cli.no_color
            && std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();

        let render_options = RenderOptions {
            color: use_color,
            show_fix: cli.fix,
        };
        let rendered = investigation.render(diagnosis, &render_options, cli.verbose);
        print!("{rendered}");
    }
}
