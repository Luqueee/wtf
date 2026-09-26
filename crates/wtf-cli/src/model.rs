//! Local Laya decision ranking. Only fixed diagnostic labels and statuses reach ONNX;
//! captured commands, output, paths, and probe observations never become model inputs.
use std::collections::HashMap;
use std::path::Path;

use ort::{session::Session, value::Tensor};
use serde::{Deserialize, Serialize};
use tokenizers::Tokenizer;
use wtf_core::diagnosis::Diagnosis;
use wtf_core::investigation::{HypothesisStatus, Investigation};

#[derive(Debug, Serialize)]
pub struct ModelDecision {
    pub model: &'static str,
    pub preferred: Option<String>,
    pub probabilities: Vec<ModelOption>,
    pub advisory_only: bool,
}

#[derive(Debug, Serialize)]
pub struct ModelOption {
    pub hypothesis: String,
    pub probability: f32,
}

#[derive(Deserialize)]
struct ModelConfig {
    max_len: usize,
    head_max_len: usize,
    temperature: Vec<f32>,
    temperature_by_options: HashMap<String, f32>,
}

fn encode(tokenizer: &Tokenizer, text: &str) -> Result<Vec<i64>, String> {
    tokenizer
        .encode(text, false)
        .map(|encoding| encoding.get_ids().iter().map(|id| i64::from(*id)).collect())
        .map_err(|error| format!("Laya tokenizer rejected input: {error}"))
}

fn special(tokenizer: &Tokenizer, token: &str) -> Result<i64, String> {
    tokenizer
        .token_to_id(token)
        .map(i64::from)
        .ok_or_else(|| format!("Laya tokenizer is missing {token}"))
}

/// Upstream `buildSequence`: choice header, one [MASK] per option, then state.
fn sequence(
    tokenizer: &Tokenizer,
    config: &ModelConfig,
    state: &str,
    options: &[&str],
) -> Result<(Vec<i64>, Vec<i64>), String> {
    let cls = special(tokenizer, "[CLS]")?;
    let sep = special(tokenizer, "[SEP]")?;
    let mask = special(tokenizer, "[MASK]")?;
    let mut header = encode(
        tokenizer,
        "choice question: Which hypothesis best explains the observed failure?",
    )?;
    let mut option_ids = options
        .iter()
        .map(|option| {
            let mut ids = vec![mask];
            ids.extend(
                encode(tokenizer, &format!(" {}", option.replace("[MASK]", " ")))?
                    .into_iter()
                    .take(48),
            );
            Ok::<_, String>(ids)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut budget = config
        .head_max_len
        .saturating_sub(option_ids.iter().map(Vec::len).sum::<usize>());
    if budget < 16 {
        let per = (config.head_max_len.saturating_sub(16) / options.len()).max(4);
        for option in &mut option_ids {
            option.truncate(per);
        }
        budget = config
            .head_max_len
            .saturating_sub(option_ids.iter().map(Vec::len).sum::<usize>());
    }
    header.truncate(budget.max(8));
    let mut ids = Vec::with_capacity(config.max_len);
    ids.push(cls);
    ids.extend(header);
    ids.push(sep);
    let mut markers = Vec::with_capacity(options.len());
    for option in option_ids {
        markers.push(ids.len() as i64);
        ids.extend(option);
    }
    ids.push(sep);
    let room = config.max_len.saturating_sub(ids.len() + 1);
    ids.extend(
        encode(tokenizer, &state.replace("[MASK]", " "))?
            .into_iter()
            .take(room),
    );
    ids.push(sep);
    ids.truncate(config.max_len);
    if markers.iter().any(|index| *index as usize >= ids.len()) || ids.len() < 8 {
        return Err("Laya configuration cannot fit the choice markers".into());
    }
    Ok((ids, markers))
}

fn temperature(config: &ModelConfig, count: usize) -> Result<f32, String> {
    let bucket = if count <= 2 {
        "2"
    } else if count <= 5 {
        "3-5"
    } else if count <= 10 {
        "6-10"
    } else {
        "11+"
    };
    let value = config
        .temperature_by_options
        .get(&format!("choice:{bucket}"))
        .or_else(|| config.temperature.first())
        .copied()
        .ok_or("Laya configuration has no choice temperature")?;
    if !value.is_finite() || value <= 0.0 {
        return Err("Laya choice temperature must be positive and finite".into());
    }
    Ok(value)
}

/// Diagnostic facts are reduced to allowlisted labels; no free-form observations
/// or captured output cross this boundary, even though inference is local.
fn structured_state(diagnosis: &Diagnosis, investigation: &Investigation) -> String {
    let category = diagnosis.category.as_deref().unwrap_or("unknown");
    let category = if category.len() <= 64
        && category
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'/' || b == b'-')
    {
        category
    } else {
        "unknown"
    };
    let mut state = format!("Category: {category}. The original root cause is not confirmed.");
    for hypothesis in &investigation.hypotheses {
        let id = hypothesis.id;
        if id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            let status = match hypothesis.status {
                HypothesisStatus::Candidate => "candidate",
                HypothesisStatus::Likely => "likely",
                HypothesisStatus::Confirmed => "currently supported",
                HypothesisStatus::Rejected => "contradicted",
            };
            state.push_str(&format!(" Hypothesis {id}: {status}."));
        }
    }
    for attempt in investigation.attempts.iter().take(5) {
        let outcome = match attempt.result.as_str() {
            "ok" => "available",
            "unavailable" => "unavailable",
            "timeout" => "timeout",
            "truncated" => "truncated",
            _ => "failed",
        };
        state.push_str(&format!(" Probe {:?}: {outcome}.", attempt.probe));
    }
    state
}

fn confident_choice(options: &[ModelOption]) -> Option<String> {
    let best = options
        .iter()
        .max_by(|a, b| a.probability.total_cmp(&b.probability))?;
    (best.hypothesis != "unknown" && best.probability >= 0.80).then(|| best.hypothesis.clone())
}

/// Use the local packaged graph, automatically provisioning the pinned default bundle.
/// No download occurs when there is no candidate hypothesis or an explicit directory is used.
pub fn decide(
    dir: Option<&Path>,
    diagnosis: &Diagnosis,
    investigation: &Investigation,
) -> Result<Option<ModelDecision>, String> {
    let candidates: Vec<&str> = investigation
        .hypotheses
        .iter()
        .filter(|hypothesis| hypothesis.status != HypothesisStatus::Rejected)
        .map(|hypothesis| hypothesis.id)
        .filter(|id| id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        .take(18)
        .collect();
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut options = candidates;
    let downloaded = if dir.is_none() {
        Some(super::model_cache::ensure_default()?)
    } else {
        None
    };
    let dir = dir.unwrap_or_else(|| downloaded.as_deref().expect("default model path resolved"));
    options.push("unknown");
    let state = structured_state(diagnosis, investigation);

    let config: ModelConfig = serde_json::from_slice(
        &std::fs::read(dir.join("laya_config.json"))
            .map_err(|error| format!("cannot read Laya configuration: {error}"))?,
    )
    .map_err(|error| format!("invalid Laya configuration: {error}"))?;
    if !(8..=4096).contains(&config.max_len)
        || !(16..=config.max_len).contains(&config.head_max_len)
    {
        return Err("unsupported Laya sequence limits".into());
    }
    let tokenizer = Tokenizer::from_file(dir.join("tokenizer/tokenizer.json"))
        .map_err(|error| format!("cannot load Laya tokenizer: {error}"))?;
    let (ids, markers) = sequence(&tokenizer, &config, &state, &options)?;
    let count = markers.len();
    let attention = vec![1_i64; ids.len()];
    let session_file = dir.join("laya.onnx");
    let mut session = Session::builder()
        .and_then(|mut builder| builder.commit_from_file(&session_file))
        .map_err(|error| format!("cannot load Laya ONNX graph: {error}"))?;
    let output = session
        .run(ort::inputs![
            "input_ids" => Tensor::from_array(([1, ids.len()], ids)).map_err(|error| error.to_string())?,
            "attention_mask" => Tensor::from_array(([1, attention.len()], attention)).map_err(|error| error.to_string())?,
            "marker_pos" => Tensor::from_array(([1, count], markers)).map_err(|error| error.to_string())?,
            "marker_mask" => Tensor::from_array(([1, count], vec![true; count])).map_err(|error| error.to_string())?,
            "qtype" => Tensor::from_array(([1], vec![0_i64])).map_err(|error| error.to_string())?,
        ])
        .map_err(|error| format!("Laya inference failed: {error}"))?;
    let (_, logits) = output
        .get("logits")
        .ok_or("Laya model did not return choice logits")?
        .try_extract_tensor::<f32>()
        .map_err(|error| format!("invalid Laya logits: {error}"))?;
    if logits.len() != count || logits.iter().any(|value| !value.is_finite()) {
        return Err("Laya model returned invalid choice scores".into());
    }
    let scale = temperature(&config, count)?;
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let weights: Vec<f32> = logits
        .iter()
        .map(|score| ((score - max) / scale).exp())
        .collect();
    let total: f32 = weights.iter().sum();
    if !total.is_finite() || total <= 0.0 {
        return Err("Laya model returned invalid choice probabilities".into());
    }
    let probabilities: Vec<_> = options
        .iter()
        .zip(weights)
        .map(|(hypothesis, weight)| ModelOption {
            hypothesis: (*hypothesis).to_owned(),
            probability: weight / total,
        })
        .collect();
    let preferred = confident_choice(&probabilities);
    Ok(Some(ModelDecision {
        model: "Laya ONNX",
        preferred,
        probabilities,
        advisory_only: true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use wtf_core::capture::{CommandExecution, ProcessExit};
    use wtf_core::diagnosis::DiagnosisEngine;
    use wtf_core::investigation::{Hypothesis, ProbeAttempt, ProbeEvidence};
    use wtf_core::probes::ProbeId;

    #[test]
    fn model_state_keeps_bounded_facts_without_captured_secrets_or_probe_output() {
        let execution = CommandExecution {
            command: "curl".into(),
            args: vec!["https://secret.example/path?token=SECRET123".into()],
            cwd: PathBuf::from("/private/SECRET123"),
            exit_status: ProcessExit {
                code: Some(7),
                signal: None,
            },
            stdout: String::new(),
            stderr: "Connection refused: Authorization: Bearer SECRET123".into(),
            duration: Duration::ZERO,
            timestamp: SystemTime::now(),
            spawn_error: None,
        };
        let diagnosis = DiagnosisEngine::new().diagnose(&execution);
        let investigation = Investigation {
            hypotheses: vec![Hypothesis {
                id: "no_local_listener",
                confidence: 0.7,
                evidence_for: vec!["SECRET123 probe output".into()],
                evidence_against: Vec::new(),
                status: HypothesisStatus::Likely,
            }],
            attempts: vec![ProbeAttempt {
                probe: ProbeId::Listeners,
                result: "exit SECRET123".into(),
            }],
            evidence: vec![ProbeEvidence {
                probe: ProbeId::Listeners,
                source: "secret source".into(),
                observation: "SECRET123".into(),
            }],
            ..Investigation::default()
        };
        let state = structured_state(&diagnosis, &investigation);
        assert!(state.contains("Hypothesis no_local_listener: likely"));
        assert!(state.contains("Probe Listeners: failed"));
        assert!(!state.contains("SECRET123"));
        assert!(!state.contains("secret.example"));
        assert!(!state.contains("/private/"));
        let mut contradicted = investigation;
        contradicted.hypotheses[0].status = HypothesisStatus::Rejected;
        assert!(decide(
            Some(Path::new("/bundle-not-required")),
            &diagnosis,
            &contradicted
        )
        .expect("rejected candidates must not load the model")
        .is_none());
    }
    #[test]
    fn uncertain_or_unknown_model_scores_never_recommend_a_cause() {
        let options = |first| {
            vec![
                ModelOption {
                    hypothesis: "no_local_listener".into(),
                    probability: first,
                },
                ModelOption {
                    hypothesis: "unknown".into(),
                    probability: 1.0 - first,
                },
            ]
        };
        assert_eq!(confident_choice(&options(0.79)), None);
        assert_eq!(
            confident_choice(&options(0.80)).as_deref(),
            Some("no_local_listener")
        );
        assert_eq!(confident_choice(&options(0.19)), None);
    }
}
