mod replay_disk;
mod replay_git;
mod replay_unix_socket;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use wtf_train::{validate_checkpoint, validate_dataset, validate_output_path, validate_split};

#[derive(Debug, Parser)]
#[command(
    name = "wtf-train",
    about = "Validate data and train the local Laya probe chooser"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Validate one probe-choice JSONL dataset.
    Validate { path: PathBuf },
    /// Replay offline disk-capacity fixtures through the deterministic core investigation API.
    #[command(name = "replay-disk")]
    ReplayDisk,
    /// Replay offline Git push fixtures through the deterministic core investigation API.
    #[command(name = "replay-git")]
    ReplayGit,
    /// Replay local Unix-socket fixtures through the experimental core API.
    #[command(name = "replay-unix-socket")]
    ReplayUnixSocket,
    /// Fine-tune a local Laya checkpoint using disjoint training and validation families.
    Train {
        #[arg(long, value_name = "PATH")]
        train: PathBuf,
        #[arg(long, value_name = "PATH")]
        validation: PathBuf,
        #[arg(long, value_name = "DIR")]
        checkpoint: PathBuf,
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
        #[arg(long, value_name = "EXE", default_value = "python3")]
        python: PathBuf,
        #[arg(long, value_name = "N", default_value_t = 100)]
        steps: u64,
        #[arg(long = "learning-rate", value_name = "F", default_value_t = 1e-5)]
        learning_rate: f64,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("wtf-train: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    match Cli::parse().command {
        Action::Validate { path } => {
            let summary = validate_dataset(&path)?;
            println!(
                "validated {} examples ({} selected probes, {} abstentions) across {} families in {}",
                summary.examples,
                summary.selected,
                summary.examples - summary.selected,
                summary.families,
                path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Action::ReplayDisk => replay_disk::run(),
        Action::ReplayUnixSocket => replay_unix_socket::run(),
        Action::ReplayGit => replay_git::run(),
        Action::Train {
            train,
            validation,
            checkpoint,
            output,
            python,
            steps,
            learning_rate,
        } => {
            if steps == 0 {
                return Err("--steps must be greater than zero".into());
            }
            if !learning_rate.is_finite() || learning_rate <= 0.0 {
                return Err("--learning-rate must be finite and greater than zero".into());
            }

            let (train_summary, validation_summary) = validate_split(&train, &validation)?;
            validate_checkpoint(&checkpoint)?;
            validate_output_path(&output)?;

            let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("train.py");
            if !script.is_file() {
                return Err(format!("training script is missing: {}", script.display()));
            }

            let status = Command::new(&python)
                .arg(script)
                .arg("--train")
                .arg(&train)
                .arg("--validation")
                .arg(&validation)
                .arg("--checkpoint")
                .arg(&checkpoint)
                .arg("--output")
                .arg(&output)
                .arg("--steps")
                .arg(steps.to_string())
                .arg("--learning-rate")
                .arg(learning_rate.to_string())
                .env("HF_HUB_OFFLINE", "1")
                .env("TRANSFORMERS_OFFLINE", "1")
                .env("HF_DATASETS_OFFLINE", "1")
                .status()
                .map_err(|error| {
                    format!(
                        "could not start Python executable {}: {error}",
                        python.display()
                    )
                })?;

            if status.success() {
                eprintln!(
                    "trained with {} training examples and {} validation examples",
                    train_summary.examples, validation_summary.examples
                );
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(
                    status.code().unwrap_or(1).clamp(1, 255) as u8
                ))
            }
        }
    }
}
