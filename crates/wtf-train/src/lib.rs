use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};
use wtf_core::probes::{ProbeId, ProbeSafety, ProbeSpec};

const SCHEMA: &str = "wtf.probe-choice.v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrainingRow {
    schema: String,
    example_id: String,
    family_id: String,
    state: State,
    offered: Vec<ProbeId>,
    target: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    category: String,
    hypotheses: Vec<Hypothesis>,
    probe_results: Vec<ProbeResult>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Hypothesis {
    id: String,
    status: HypothesisStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HypothesisStatus {
    Candidate,
    Likely,
    Confirmed,
    Rejected,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeResult {
    id: ProbeId,
    outcome: ProbeOutcome,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeOutcome {
    Available,
    Unavailable,
    Timeout,
    Truncated,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetSummary {
    pub examples: usize,
    pub selected: usize,
    pub families: usize,
}

struct DatasetIndex {
    summary: DatasetSummary,
    example_ids: HashSet<String>,
    family_ids: HashSet<String>,
    decisions: HashMap<String, (String, String)>,
}

/// Validate one versioned JSONL file without retaining example text or probe state.
pub fn validate_dataset(path: &Path) -> Result<DatasetSummary, String> {
    Ok(read_dataset(path)?.summary)
}

/// Validate both files and enforce globally unique example IDs and family isolation.
pub fn validate_split(
    train_path: &Path,
    validation_path: &Path,
) -> Result<(DatasetSummary, DatasetSummary), String> {
    let train = read_dataset(train_path)?;
    let validation = read_dataset(validation_path)?;

    if let Some(example_id) = train
        .example_ids
        .intersection(&validation.example_ids)
        .next()
    {
        return Err(format!(
            "example_id {example_id:?} occurs in both training and validation data"
        ));
    }
    if let Some(family_id) = train.family_ids.intersection(&validation.family_ids).next() {
        return Err(format!(
            "family_id {family_id:?} occurs in both training and validation data"
        ));
    }
    if train.summary.selected == 0 {
        return Err("training data contains no selected probe; an all-abstain model cannot improve probe ordering".into());
    }
    for (visible_input, (label, example_id)) in &validation.decisions {
        if let Some((other_label, other_id)) = train.decisions.get(visible_input) {
            if label != other_label {
                return Err(format!("conflicting labels for model-visible input: {other_id:?} ({other_label}) and {example_id:?} ({label})"));
            }
        }
    }

    Ok((train.summary, validation.summary))
}

/// Check the required local, trainable Laya checkpoint layout.
pub fn validate_checkpoint(path: &Path) -> Result<(), String> {
    let metadata = path.metadata().map_err(|error| {
        format!(
            "cannot access checkpoint directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "checkpoint path is not a directory: {}",
            path.display()
        ));
    }

    for name in ["model.safetensors", "rl_agent_config.json", "rl_common.py"] {
        let file = path.join(name);
        let metadata = file.metadata().map_err(|error| {
            format!(
                "missing required checkpoint file {}: {error}",
                file.display()
            )
        })?;
        if !metadata.is_file() {
            return Err(format!(
                "required checkpoint path is not a file: {}",
                file.display()
            ));
        }
    }

    for name in ["encoder", "tokenizer"] {
        let directory = path.join(name);
        let metadata = directory.metadata().map_err(|error| {
            format!(
                "missing required checkpoint directory {}: {error}",
                directory.display()
            )
        })?;
        if !metadata.is_dir() {
            return Err(format!(
                "required checkpoint path is not a directory: {}",
                directory.display()
            ));
        }
    }
    Ok(())
}

/// Refuse existing output paths, including dangling symlinks.
pub fn validate_output_path(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(format!("output path already exists: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect output path {}: {error}",
            path.display()
        )),
    }
}

fn read_dataset(path: &Path) -> Result<DatasetIndex, String> {
    let file = File::open(path)
        .map_err(|error| format!("cannot open dataset {}: {error}", path.display()))?;
    let mut example_ids = HashSet::new();
    let mut decisions = HashMap::new();
    let mut selected = 0usize;
    let mut family_ids = HashSet::new();
    let mut examples = 0usize;

    for (line_index, line) in BufReader::new(file).lines().enumerate() {
        let line_number = line_index + 1;
        let line = line.map_err(|error| {
            format!(
                "cannot read dataset {} line {line_number}: {error}",
                path.display()
            )
        })?;
        let row: TrainingRow = serde_json::from_str(&line).map_err(|error| {
            format!(
                "invalid dataset {} line {line_number}: {error}",
                path.display()
            )
        })?;
        validate_row(&row).map_err(|reason| {
            format!(
                "invalid dataset {} line {line_number}: {reason}",
                path.display()
            )
        })?;

        if !example_ids.insert(row.example_id.clone()) {
            return Err(format!(
                "duplicate example_id {:?} in {} line {line_number}",
                row.example_id,
                path.display()
            ));
        }
        let visible_input = serde_json::to_string(&(&row.state, &row.offered))
            .map_err(|error| format!("cannot project model-visible input: {error}"))?;
        if let Some((label, other_id)) = decisions.get(&visible_input) {
            if label != &row.target {
                return Err(format!("conflicting labels for model-visible input: {other_id:?} ({label}) and {:?} ({})", row.example_id, row.target));
            }
        } else {
            decisions.insert(visible_input, (row.target.clone(), row.example_id.clone()));
        }
        selected += usize::from(row.target != "abstain");
        family_ids.insert(row.family_id);
        examples += 1;
    }

    if examples == 0 {
        return Err(format!("dataset {} contains no examples", path.display()));
    }

    Ok(DatasetIndex {
        summary: DatasetSummary {
            examples,
            families: family_ids.len(),
            selected,
        },
        example_ids,
        family_ids,
        decisions,
    })
}

fn validate_row(row: &TrainingRow) -> Result<(), String> {
    if row.schema != SCHEMA {
        return Err(format!("schema must be {SCHEMA:?}"));
    }
    if !is_opaque_id(&row.example_id) {
        return Err("example_id must be 1-64 ASCII letters, digits, '_', '-', or '.'".into());
    }
    if !is_opaque_id(&row.family_id) {
        return Err("family_id must be 1-64 ASCII letters, digits, '_', '-', or '.'".into());
    }
    if !is_identifier(&row.state.category, |byte| {
        byte.is_ascii_lowercase() || matches!(byte, b'_' | b'-' | b'/')
    }) {
        return Err("category must contain 1-64 lowercase ASCII letters, '_', '-', or '/'".into());
    }
    for hypothesis in &row.state.hypotheses {
        if !is_identifier(&hypothesis.id, |byte| {
            byte.is_ascii_lowercase() || byte == b'_'
        }) {
            return Err("hypothesis IDs must contain 1-64 lowercase ASCII letters or '_'".into());
        }
    }
    // Touch the enum fields so malformed statuses/outcomes are rejected by serde and these
    // fields remain part of the validated schema rather than being silently ignored.
    for hypothesis in &row.state.hypotheses {
        let _ = &hypothesis.status;
    }
    for result in &row.state.probe_results {
        if result.id == ProbeId::UnixListeners {
            return Err(
                "probe_results contains an experimental probe that is not eligible for training"
                    .into(),
            );
        }
        let _ = (result.id, &result.outcome);
    }

    if row.offered.len() < 2 {
        return Err("offered must contain at least two distinct safe probes".into());
    }
    let mut offered = HashSet::with_capacity(row.offered.len());
    for probe in &row.offered {
        if !offered.insert(*probe) {
            return Err(format!("offered contains duplicate probe {probe:?}"));
        }
        if !is_safe_offer(*probe) {
            return Err(format!(
                "offered contains unsafe or disallowed probe {probe:?}"
            ));
        }
    }
    if row.target != "abstain" {
        let target: ProbeId = serde_json::from_value(serde_json::Value::String(row.target.clone()))
            .map_err(|_| "target must be an offered ProbeId or the literal 'abstain'".to_owned())?;
        if !offered.contains(&target) {
            return Err("target must be one of the offered probes".into());
        }
    }
    Ok(())
}

fn is_safe_offer(probe: ProbeId) -> bool {
    if probe == ProbeId::CargoCheck {
        return false;
    }
    let target = match probe {
        ProbeId::UnixListeners => return false,
        ProbeId::Listeners
        | ProbeId::Route
        | ProbeId::DockerRunning
        | ProbeId::DockerAll
        | ProbeId::GitStatus
        | ProbeId::GitDiff
        | ProbeId::GitPorcelain
        | ProbeId::GitBranch
        | ProbeId::GitUpstream
        | ProbeId::GitTopLevel
        | ProbeId::GitRemote => None,
        ProbeId::Hosts => Some("training.invalid"),
        ProbeId::Filesystem | ProbeId::FilesystemInodes | ProbeId::Stat => Some("/"),
        ProbeId::Process => Some("1"),
        ProbeId::DockerInspect | ProbeId::DockerLogs => Some("wtf-train"),
        ProbeId::SystemdShow => Some("wtf-train.service"),
        ProbeId::SystemdLogs => Some("wtf-train.service|0123456789abcdef0123456789abcdef|0|1"),
        ProbeId::CargoCheck => return false,
    };
    // An unavailable platform-specific spec is not proof of an unsafe probe. Dataset
    // validation checks the closed ProbeId policy, not live executable/readiness state.
    ProbeSpec::new(probe, Path::new("."), target)
        .is_none_or(|spec| spec.safety == ProbeSafety::Safe)
}

fn is_opaque_id(value: &str) -> bool {
    is_identifier(value, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
    })
}

fn is_identifier(value: &str, valid_byte: impl Fn(u8) -> bool) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(valid_byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn row(example_id: &str, family_id: &str) -> String {
        format!(
            r#"{{"schema":"wtf.probe-choice.v1","example_id":"{example_id}","family_id":"{family_id}","state":{{"category":"network/dns","hypotheses":[{{"id":"dns_failure","status":"likely"}}],"probe_results":[{{"id":"Hosts","outcome":"failed"}}]}},"offered":["Hosts","Route"],"target":"Hosts"}}"#
        )
    }

    fn write_rows(dir: &Path, name: &str, rows: &[String]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, rows.join("\n") + "\n").unwrap();
        path
    }

    fn validate_record(record: &str) -> Result<(), String> {
        let row: TrainingRow = serde_json::from_str(record).map_err(|error| error.to_string())?;
        validate_row(&row)
    }

    #[test]
    fn accepts_valid_rows_and_boundary_length_identifiers() {
        let example_id = "e".repeat(64);
        let family_id = "f".repeat(64);
        let record = row(&example_id, &family_id);
        assert!(validate_record(&record).is_ok());

        let dir = tempfile::tempdir().unwrap();
        let path = write_rows(dir.path(), "valid.jsonl", &[record]);
        assert_eq!(validate_dataset(&path).unwrap().examples, 1);
    }

    #[test]
    fn rejects_unknown_fields_at_every_object_level() {
        let valid = row("ex-1", "fam-1");
        for record in [
            valid.replacen(
                "\"target\":\"Hosts\"",
                "\"extra\":1,\"target\":\"Hosts\"",
                1,
            ),
            valid.replacen(
                "\"category\":\"network/dns\"",
                "\"category\":\"network/dns\",\"extra\":1",
                1,
            ),
            valid.replacen(
                "\"id\":\"dns_failure\"",
                "\"id\":\"dns_failure\",\"extra\":1",
                1,
            ),
            valid.replacen(
                "\"outcome\":\"failed\"",
                "\"outcome\":\"failed\",\"extra\":1",
                1,
            ),
        ] {
            assert!(validate_record(&record).is_err(), "accepted {record}");
        }
    }

    #[test]
    fn rejects_identifier_overflow_and_non_ascii_or_invalid_characters() {
        let valid = row("ex-1", "fam-1");
        let overflow = "e".repeat(65);
        for (needle, replacement) in [
            ("ex-1", overflow.as_str()),
            ("fam-1", "bad/family"),
            ("network/dns", "Network/dns"),
            ("dns_failure", "dns-failure"),
            ("dns_failure", "déns_failure"),
        ] {
            let record = valid.replacen(needle, replacement, 1);
            assert!(validate_record(&record).is_err(), "accepted {record}");
        }

        let category_at_limit = valid.replacen("network/dns", &"a".repeat(64), 1);
        let hypothesis_at_limit = valid.replacen("dns_failure", &"a".repeat(64), 1);
        assert!(validate_record(&category_at_limit).is_ok());
        assert!(validate_record(&hypothesis_at_limit).is_ok());
        let category_over_limit = valid.replacen("network/dns", &"a".repeat(65), 1);
        let hypothesis_over_limit = valid.replacen("dns_failure", &"a".repeat(65), 1);
        assert!(validate_record(&category_over_limit).is_err());
        assert!(validate_record(&hypothesis_over_limit).is_err());
    }

    #[test]
    fn requires_safe_distinct_offers_and_a_matching_target() {
        let valid = row("ex-1", "fam-1");
        for record in [
            valid.replacen("\"Hosts\",\"Route\"", "\"Hosts\"", 1),
            valid.replacen("\"Hosts\",\"Route\"", "\"Hosts\",\"Hosts\"", 1),
            valid.replacen("\"Hosts\",\"Route\"", "\"CargoCheck\",\"Route\"", 1),
            valid.replacen("\"target\":\"Hosts\"", "\"target\":\"GitRemote\"", 1),
            valid.replacen("\"target\":\"Hosts\"", "\"target\":\"HOSTS\"", 1),
        ] {
            assert!(validate_record(&record).is_err(), "accepted {record}");
        }
        let abstain = valid.replacen("\"target\":\"Hosts\"", "\"target\":\"abstain\"", 1);
        assert!(validate_record(&abstain).is_ok());

        let safe_git_remote = valid
            .replacen("\"Hosts\",\"Route\"", "\"GitRemote\",\"Route\"", 1)
            .replacen("\"target\":\"Hosts\"", "\"target\":\"GitRemote\"", 1);
        assert!(validate_record(&safe_git_remote).is_ok());
    }

    #[test]
    fn rejects_unknown_schema_status_outcome_and_probe_names() {
        let valid = row("ex-1", "fam-1");
        for record in [
            valid.replacen("wtf.probe-choice.v1", "wtf.probe-choice.v2", 1),
            valid.replacen("\"likely\"", "\"LIKELY\"", 1),
            valid.replacen("\"failed\"", "\"FAILED\"", 1),
            valid.replacen("\"Hosts\",\"Route\"", "\"NotAProbe\",\"Route\"", 1),
        ] {
            assert!(validate_record(&record).is_err(), "accepted {record}");
        }
    }

    #[test]
    fn rejects_experimental_unix_listener_probes_from_training_inputs() {
        let valid = row("ex-1", "fam-1");
        let offered = valid
            .replacen("\"Hosts\",\"Route\"", "\"UnixListeners\",\"Route\"", 1)
            .replacen("\"target\":\"Hosts\"", "\"target\":\"UnixListeners\"", 1);
        assert!(validate_record(&offered)
            .unwrap_err()
            .contains("offered contains unsafe or disallowed probe"));

        let observed = valid.replacen(
            "\"id\":\"Hosts\",\"outcome\":\"failed\"",
            "\"id\":\"UnixListeners\",\"outcome\":\"failed\"",
            1,
        );
        assert!(validate_record(&observed)
            .unwrap_err()
            .contains("probe_results contains an experimental probe"));
    }

    #[test]
    fn rejects_empty_files_and_duplicate_example_ids() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.jsonl");
        fs::write(&empty, "").unwrap();
        assert!(validate_dataset(&empty).is_err());

        let duplicate = write_rows(
            dir.path(),
            "duplicate.jsonl",
            &[row("same", "family-a"), row("same", "family-b")],
        );
        assert!(validate_dataset(&duplicate).is_err());
    }

    #[test]
    fn rejects_family_leaks_and_example_id_overlap_between_splits() {
        let dir = tempfile::tempdir().unwrap();
        let train = write_rows(
            dir.path(),
            "train.jsonl",
            &[row("train-1", "shared-family")],
        );
        let validation = write_rows(
            dir.path(),
            "validation.jsonl",
            &[row("validation-1", "shared-family")],
        );
        assert!(validate_split(&train, &validation).is_err());

        let validation = write_rows(
            dir.path(),
            "validation.jsonl",
            &[row("train-1", "different-family")],
        );
        assert!(validate_split(&train, &validation).is_err());
    }

    #[test]
    fn accepts_isolated_family_split_and_reports_unique_family_count() {
        let dir = tempfile::tempdir().unwrap();
        let train = write_rows(
            dir.path(),
            "train.jsonl",
            &[row("train-1", "family-a"), row("train-2", "family-a")],
        );
        let validation = write_rows(
            dir.path(),
            "validation.jsonl",
            &[row("validation-1", "family-b")],
        );
        let (train_summary, validation_summary) = validate_split(&train, &validation).unwrap();
        assert_eq!(
            train_summary,
            DatasetSummary {
                examples: 2,
                families: 1,
                selected: 2,
            }
        );
        assert_eq!(
            validation_summary,
            DatasetSummary {
                examples: 1,
                families: 1,
                selected: 1,
            }
        );
    }

    #[test]
    fn rejects_all_abstain_training_but_allows_validating_its_records() {
        let dir = tempfile::tempdir().unwrap();
        let train = write_rows(
            dir.path(),
            "train.jsonl",
            &[row("a", "f1").replace("\"target\":\"Hosts\"", "\"target\":\"abstain\"")],
        );
        let validation = write_rows(dir.path(), "validation.jsonl", &[row("b", "f2")]);
        assert_eq!(validate_dataset(&train).unwrap().selected, 0);
        assert!(validate_split(&train, &validation)
            .unwrap_err()
            .contains("all-abstain"));
    }

    #[test]
    fn rejects_conflicting_targets_for_the_same_model_visible_input() {
        let dir = tempfile::tempdir().unwrap();
        let positive = row("positive", "family-a");
        let negative =
            row("negative", "family-b").replace("\"target\":\"Hosts\"", "\"target\":\"abstain\"");
        let same_file = write_rows(
            dir.path(),
            "same.jsonl",
            &[positive.clone(), negative.clone()],
        );
        assert!(validate_dataset(&same_file)
            .unwrap_err()
            .contains("conflicting labels"));

        let train = write_rows(dir.path(), "train.jsonl", &[positive]);
        let validation = write_rows(dir.path(), "validation.jsonl", &[negative]);
        assert!(validate_split(&train, &validation)
            .unwrap_err()
            .contains("conflicting labels"));
    }

    #[test]
    fn output_path_must_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("output");
        assert!(validate_output_path(&missing).is_ok());
        fs::create_dir(&missing).unwrap();
        assert!(validate_output_path(&missing).is_err());
    }

    #[test]
    fn checks_exact_local_checkpoint_layout() {
        let dir = tempfile::tempdir().unwrap();
        let checkpoint = dir.path().join("checkpoint");
        fs::create_dir(&checkpoint).unwrap();
        for file in ["model.safetensors", "rl_agent_config.json", "rl_common.py"] {
            fs::write(checkpoint.join(file), "").unwrap();
        }
        fs::create_dir(checkpoint.join("encoder")).unwrap();
        fs::create_dir(checkpoint.join("tokenizer")).unwrap();
        assert!(validate_checkpoint(&checkpoint).is_ok());
        fs::remove_file(checkpoint.join("model.safetensors")).unwrap();
        assert!(validate_checkpoint(&checkpoint).is_err());
    }
}
