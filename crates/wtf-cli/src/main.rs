use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;
use wtf_core::capture::{execute_command, ExecutionConfig};
use wtf_core::diagnosis::{DiagnosisEngine, DiagnosisStatus, RenderOptions};

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

    /// Command and arguments to execute and diagnose
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.command.is_empty() {
        eprintln!("Error: no command provided to execute.\nUsage: wtf -- <command> [args...]");
        return ExitCode::from(2);
    }

    let cmd = &cli.command[0];
    let args = &cli.command[1..];

    let config = ExecutionConfig::default();
    let execution = execute_command(cmd, args, &config);

    if cli.show_output {
        if !execution.stdout.is_empty() {
            print!("{}", execution.stdout);
        }
        if !execution.stderr.is_empty() {
            eprint!("{}", execution.stderr);
        }
    }

    let engine = DiagnosisEngine::new();
    let diagnosis = engine.diagnose(&execution);

    if cli.json {
        let json_str = serde_json::to_string_pretty(&diagnosis)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {e}\"}}"));
        println!("{json_str}");
    } else {
        // If command succeeded and --show-output was not used, print stdout if present
        if diagnosis.status == DiagnosisStatus::Success && !cli.show_output {
            if !execution.stdout.is_empty() {
                print!("{}", execution.stdout);
            }
            if !execution.stderr.is_empty() {
                eprint!("{}", execution.stderr);
            }
        } else {
            let use_color = !cli.no_color
                && std::io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none();

            let render_options = RenderOptions {
                color: use_color,
                show_fix: cli.fix,
            };

            let rendered = DiagnosisEngine::render(&diagnosis, &render_options);
            print!("{rendered}");
        }
    }

    match diagnosis.exit_status.code {
        Some(code) => {
            // Normal process exit
            ExitCode::from((code & 0xFF) as u8)
        }
        None => {
            // Process terminated by signal
            ExitCode::from(1)
        }
    }
}
