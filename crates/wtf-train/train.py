#!/usr/bin/env python3
"""Offline fine-tuning of the local Laya checkpoint for safe probe selection.

The model/data API follows convaiinnovations/laya's rl_common.py at
https://huggingface.co/convaiinnovations/laya/tree/00c37c405e3c3ad73ee070227614c89cda06b99e.
This script consumes only Rust-validated JSONL records; it never downloads,
installs packages, or generates training data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

SCHEMA = "wtf.probe-choice.v1"
QUESTION = "Which safe diagnostic check should be performed next?"
STATUSES = {"candidate", "likely", "confirmed", "rejected"}
OUTCOMES = {"available", "unavailable", "timeout", "truncated", "failed"}
# Exact serde ProbeId names from wtf-core. CargoCheck is intentionally excluded;
# GitRemote is currently classified Safe by ProbeSpec::new.
SAFE_PROBES = {
    "Listeners",
    "Hosts",
    "Route",
    "Filesystem",
    "FilesystemInodes",
    "Stat",
    "Process",
    "DockerRunning",
    "DockerAll",
    "DockerInspect",
    "DockerLogs",
    "SystemdShow",
    "SystemdLogs",
    "GitStatus",
    "GitDiff",
    "GitPorcelain",
    "GitBranch",
    "GitUpstream",
    "GitTopLevel",
    "GitRemote",
}
PROBE_IDS = SAFE_PROBES | {"CargoCheck"}
BUCKETS = ("2", "3-5", "6-10", "11+")


class DatasetError(ValueError):
    """A JSONL record does not satisfy the versioned training contract."""


def _object_without_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DatasetError("duplicate JSON object key: {!r}".format(key))
        result[key] = value
    return result


def _require_fields(value: Any, expected: set, where: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise DatasetError("{} must be an object".format(where))
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise DatasetError(
            "{} has wrong fields (missing={!r}, unknown={!r})".format(where, missing, extra)
        )
    return value


def _ascii_identifier(value: Any, pattern: str, where: str) -> str:
    if not isinstance(value, str) or len(value) > 64 or re.fullmatch(pattern, value) is None:
        raise DatasetError("{} must be a nonempty allowed ASCII identifier of at most 64 characters".format(where))
    return value


def validate_row(row: Any, where: str) -> Dict[str, Any]:
    row = _require_fields(
        row,
        {"schema", "example_id", "family_id", "state", "offered", "target"},
        where,
    )
    if row["schema"] != SCHEMA:
        raise DatasetError("{} has unsupported schema".format(where))
    _ascii_identifier(row["example_id"], r"[A-Za-z0-9_.-]+", where + ".example_id")
    _ascii_identifier(row["family_id"], r"[A-Za-z0-9_.-]+", where + ".family_id")

    state = _require_fields(row["state"], {"category", "hypotheses", "probe_results"}, where + ".state")
    _ascii_identifier(state["category"], r"[a-z_/-]+", where + ".state.category")
    if not isinstance(state["hypotheses"], list):
        raise DatasetError(where + ".state.hypotheses must be an array")
    for index, hypothesis in enumerate(state["hypotheses"]):
        item_where = "{}.state.hypotheses[{}]".format(where, index)
        hypothesis = _require_fields(hypothesis, {"id", "status"}, item_where)
        _ascii_identifier(hypothesis["id"], r"[a-z_]+", item_where + ".id")
        if not isinstance(hypothesis["status"], str) or hypothesis["status"] not in STATUSES:
            raise DatasetError("{}.status is not an allowed hypothesis status".format(item_where))

    if not isinstance(state["probe_results"], list):
        raise DatasetError(where + ".state.probe_results must be an array")
    for index, result in enumerate(state["probe_results"]):
        item_where = "{}.state.probe_results[{}]".format(where, index)
        result = _require_fields(result, {"id", "outcome"}, item_where)
        probe = result["id"]
        if not isinstance(probe, str) or probe not in PROBE_IDS:
            raise DatasetError("{}.id is not an allowed ProbeId".format(item_where))
        if not isinstance(result["outcome"], str) or result["outcome"] not in OUTCOMES:
            raise DatasetError("{}.outcome is not an allowed probe outcome".format(item_where))

    offered = row["offered"]
    if not isinstance(offered, list) or len(offered) < 2:
        raise DatasetError(where + ".offered must contain at least two safe ProbeIds")
    if any(not isinstance(probe, str) or probe not in SAFE_PROBES for probe in offered):
        raise DatasetError(where + ".offered contains a non-safe or unknown ProbeId")
    if len(set(offered)) != len(offered):
        raise DatasetError(where + ".offered must contain distinct ProbeIds")
    target = row["target"]
    if not isinstance(target, str) or (target != "abstain" and target not in offered):
        raise DatasetError(where + ".target must be one offered ProbeId or 'abstain'")
    return row


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise DatasetError("cannot read UTF-8 dataset {}: {}".format(path, error)) from error
    rows = []
    seen_ids = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise DatasetError("{}:{} is an empty JSONL record".format(path, line_number))
        where = "{}:{}".format(path, line_number)
        try:
            row = json.loads(line, object_pairs_hook=_object_without_duplicate_keys)
        except (json.JSONDecodeError, DatasetError) as error:
            raise DatasetError("{}: {}".format(where, error)) from error
        row = validate_row(row, where)
        if row["example_id"] in seen_ids:
            raise DatasetError("{} duplicates example_id {!r}".format(where, row["example_id"]))
        seen_ids.add(row["example_id"])
        rows.append(row)
    if not rows:
        raise DatasetError("{} contains no examples".format(path))
    return rows


def load_split(train_path: Path, validation_path: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    train = load_jsonl(train_path)
    validation = load_jsonl(validation_path)
    train_ids = {row["example_id"] for row in train}
    duplicate_ids = train_ids & {row["example_id"] for row in validation}
    if duplicate_ids:
        raise DatasetError("train and validation contain duplicate example_id values")
    train_families = {row["family_id"] for row in train}
    validation_families = {row["family_id"] for row in validation}
    if train_families & validation_families:
        raise DatasetError("train and validation family_id values must be disjoint")
    return train, validation


def render_state(state: Dict[str, Any]) -> str:
    """Render only fixed IDs/statuses, in the exact shared-contract order."""
    rendered = ["Category: {}.".format(state["category"])]
    rendered.extend(
        "Hypothesis {}: {}.".format(item["id"], item["status"])
        for item in state["hypotheses"]
    )
    rendered.extend(
        "Probe {}: {}.".format(item["id"], item["outcome"])
        for item in state["probe_results"]
    )
    return " ".join(rendered)


def _validate_model_visible_labels(
    train_rows: Sequence[Dict[str, Any]], validation_rows: Sequence[Dict[str, Any]]
) -> None:
    seen: Dict[Tuple[str, Tuple[str, ...]], Tuple[str, str, str]] = {}
    for split_name, rows in (("train", train_rows), ("validation", validation_rows)):
        for row in rows:
            rendered_state = render_state(row["state"])
            choices = tuple(row["offered"]) + ("abstain",)
            model_input = (rendered_state, choices)
            previous = seen.get(model_input)
            if previous is not None and previous[0] != row["target"]:
                previous_split, previous_id, previous_target = previous
                raise DatasetError(
                    "contradictory target labels for identical model-visible input: "
                    "{} example_id={!r} targets {!r}, but {} example_id={!r} targets {!r} "
                    "(rendered state and ordered choices are identical)".format(
                        previous_split,
                        previous_id,
                        previous_target,
                        split_name,
                        row["example_id"],
                        row["target"],
                    )
                )
            seen.setdefault(model_input, (split_name, row["example_id"], row["target"]))


def _non_abstain_target_count(rows: Sequence[Dict[str, Any]]) -> int:
    return sum(row["target"] != "abstain" for row in rows)



def _bucket(option_count: int) -> str:
    if option_count <= 2:
        return "2"
    if option_count <= 5:
        return "3-5"
    if option_count <= 10:
        return "6-10"
    return "11+"


def encode_rows(rows: Sequence[Dict[str, Any]], tokenizer: Any, config: Dict[str, Any], rl_common: Any) -> List[Dict[str, Any]]:
    items = []
    for row in rows:
        choices = list(row["offered"]) + ["abstain"]
        question = {"t": "choice", "ins": QUESTION, "crit": {choice: None for choice in choices}}
        ids, markers = rl_common.build_sequence(
            tokenizer,
            render_state(row["state"]),
            question,
            int(config["max_len"]),
            int(config["head_max_len"]),
        )
        if len(markers) != len(choices):
            raise DatasetError(
                "upstream Laya sequence truncates a safe probe choice; all markers must fit"
            )
        target_index = choices.index(row["target"])
        target = [1.0 if index == target_index else 0.0 for index in range(len(choices))]
        # example_id/family_id are intentionally not copied into model items.
        items.append(
            {
                "ids": ids,
                "markers": markers,
                "qtype": rl_common.QTYPES["choice"],
                "target": target,
                "label": target_index,
                "episode": 0,
                "ep_step": 0,
                "ep_len": 1,
                "src": "wtf-probe-choice",
            }
        )
    return items


def checkpoint_files(checkpoint: Path) -> None:
    required = {
        "weights": checkpoint / "model.safetensors",
        "config": checkpoint / "rl_agent_config.json",
        "common": checkpoint / "rl_common.py",
        "encoder_config": checkpoint / "encoder" / "config.json",
        "tokenizer_json": checkpoint / "tokenizer" / "tokenizer.json",
    }
    missing = [str(path) for path in required.values() if not path.is_file()]
    if not (checkpoint / "encoder").is_dir():
        missing.append(str(checkpoint / "encoder"))
    if not (checkpoint / "tokenizer").is_dir():
        missing.append(str(checkpoint / "tokenizer"))
    if missing:
        raise ValueError("local trainable Laya checkpoint is incomplete: " + ", ".join(missing))
    return None


def _offline_environment() -> None:
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_DATASETS_OFFLINE"] = "1"


def _load_upstream(checkpoint: Path) -> Tuple[Any, Any, Any, Dict[str, Any]]:
    """Load upstream Python API and strictly restore the trainable safetensors weights."""
    _offline_environment()
    try:
        import importlib
        import torch
        from safetensors.torch import load_file
        from transformers import AutoTokenizer
        for module_name in ("numpy", "onnx", "onnxruntime"):
            importlib.import_module(module_name)
    except ImportError as error:
        raise RuntimeError(
            "training requires preinstalled torch, transformers, safetensors, onnx, and onnxruntime; "
            "this command never installs dependencies"
        ) from error

    config_path = checkpoint / "rl_agent_config.json"
    with config_path.open("r", encoding="utf-8") as source:
        config = json.load(source)
    for key in ("encoder", "head_layers", "max_len", "head_max_len", "act_costs"):
        if key not in config:
            raise ValueError("Laya checkpoint configuration is missing {!r}".format(key))
    if not isinstance(config["max_len"], int) or not isinstance(config["head_max_len"], int):
        raise ValueError("Laya max_len and head_max_len must be integers")
    if not (8 <= config["max_len"] <= 4096 and 16 <= config["head_max_len"] <= config["max_len"]):
        raise ValueError("Laya checkpoint sequence limits are incompatible with wtf-cli")

    import importlib.util

    common_path = checkpoint / "rl_common.py"
    spec = importlib.util.spec_from_file_location("wtf_laya_rl_common", common_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load rl_common.py from the supplied local checkpoint")
    rl_common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rl_common)

    tokenizer = AutoTokenizer.from_pretrained(
        str(checkpoint / "tokenizer"), local_files_only=True, trust_remote_code=False
    )
    model = rl_common.build_model(config, encoder_dir=str(checkpoint / "encoder"))
    state_dict = load_file(str(checkpoint / "model.safetensors"), device="cpu")
    model.load_state_dict(state_dict, strict=True)
    if hasattr(model.encoder.config, "reference_compile"):
        model.encoder.config.reference_compile = False
    return torch, rl_common, (tokenizer, model), config


def _parameter_fingerprints(torch: Any, model: Any) -> Dict[str, str]:
    fingerprints = {}
    for name, parameter in model.named_parameters():
        if not parameter.requires_grad:
            continue
        tensor = parameter.detach().to(device="cpu").contiguous()
        raw = tensor.view(dtype=torch.uint8).numpy()
        digest = hashlib.sha256()
        digest.update(memoryview(raw))
        fingerprints[name] = digest.hexdigest()
    return fingerprints


def _model_batch(rl_common: Any, item: Dict[str, Any], pad_id: int, device: Any) -> Dict[str, Any]:
    batch = rl_common.collate_items([[item]], pad_id)
    return {
        key: batch[key].to(device)
        for key in ("input_ids", "attention_mask", "marker_pos", "marker_mask", "target", "qtype", "label")
    }

def _forward(torch: Any, model: Any, batch: Dict[str, Any], device: Any, amp_dtype: Any) -> Any:
    with torch.autocast(device_type=device.type, dtype=amp_dtype, enabled=device.type == "cuda"):
        logits, _ = model(
            batch["input_ids"],
            batch["attention_mask"],
            batch["marker_pos"],
            batch["marker_mask"],
            batch["qtype"],
        )
    return logits


def optimize(
    torch: Any,
    rl_common: Any,
    model: Any,
    train_items: Sequence[Dict[str, Any]],
    pad_id: int,
    device: Any,
    steps: int,
    learning_rate: float,
    amp_dtype: Any,
) -> Tuple[int, float, Dict[str, str], Dict[str, str]]:
    if not train_items:
        raise ValueError("training dataset contains no encoded examples")
    parameters = [parameter for parameter in model.parameters() if parameter.requires_grad]
    if not parameters:
        raise RuntimeError("Laya model has no trainable parameters")
    before = _parameter_fingerprints(torch, model)
    optimizer = torch.optim.AdamW(parameters, lr=learning_rate)
    use_scaler = device.type == "cuda" and amp_dtype == torch.float16
    scaler = torch.amp.GradScaler("cuda", enabled=use_scaler)
    rl_common.seed_all(0)
    order = list(range(len(train_items)))
    random_generator = random.Random(0)
    random_generator.shuffle(order)
    cursor = 0
    losses = []
    model.train()
    completed = 0
    while completed < steps:
        if cursor == len(order):
            random_generator.shuffle(order)
            cursor = 0
        item = train_items[order[cursor]]
        cursor += 1
        batch = _model_batch(rl_common, item, pad_id, device)
        optimizer.zero_grad(set_to_none=True)
        logits = _forward(torch, model, batch, device, amp_dtype)
        masked_logits = logits.masked_fill(~batch["marker_mask"], -1.0e4)
        log_probabilities = torch.nn.functional.log_softmax(masked_logits.float(), dim=-1)
        loss = -(batch["target"] * log_probabilities).sum(dim=-1).mean()
        if not bool(torch.isfinite(loss).item()):
            raise RuntimeError("non-finite Laya training loss; no output checkpoint was written")
        old_scale = scaler.get_scale()
        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        grad_norm = torch.nn.utils.clip_grad_norm_(parameters, float("inf"), error_if_nonfinite=True)
        if not bool(torch.isfinite(grad_norm).item()):
            raise RuntimeError("non-finite Laya gradients; no output checkpoint was written")
        scaler.step(optimizer)
        scaler.update()
        if use_scaler and scaler.get_scale() < old_scale:
            raise RuntimeError("AMP skipped an optimizer update; requested step count was not reached")
        losses.append(float(loss.detach().float().cpu().item()))
        completed += 1
    if completed != steps or completed == 0:
        raise RuntimeError("training completed {} optimizer steps, expected {}".format(completed, steps))
    after = _parameter_fingerprints(torch, model)
    if before.keys() != after.keys():
        raise RuntimeError("Laya parameter set changed during fine-tuning")
    changed = {name: after[name] for name in before if before[name] != after[name]}
    if not changed:
        raise RuntimeError("{} optimizer steps changed no Laya parameters".format(completed))
    return completed, sum(losses) / len(losses), before, after


def evaluate_validation(
    torch: Any,
    rl_common: Any,
    model: Any,
    items: Sequence[Dict[str, Any]],
    pad_id: int,
    device: Any,
    amp_dtype: Any,
) -> List[Dict[str, Any]]:
    if not items:
        raise ValueError("validation dataset contains no encoded examples")
    model.eval()
    predictions = []
    with torch.inference_mode():
        for item in items:
            batch = _model_batch(rl_common, item, pad_id, device)
            logits = _forward(torch, model, batch, device, amp_dtype)
            count = len(item["markers"])
            valid_logits = logits[0, :count].detach().float().cpu()
            if valid_logits.numel() != count or not bool(torch.isfinite(valid_logits).all().item()):
                raise RuntimeError("Laya returned invalid validation logits")
            predictions.append({"logits": valid_logits, "target": int(item["label"]), "count": count})
    return predictions


def _fit_temperature(torch: Any, examples: Sequence[Dict[str, Any]]) -> float:
    if not examples:
        return 1.0
    max_count = max(example["count"] for example in examples)
    logits = torch.stack(
        [torch.nn.functional.pad(example["logits"], (0, max_count - example["count"]), value=-1.0e4) for example in examples]
    )
    targets = torch.tensor([example["target"] for example in examples], dtype=torch.long)
    log_temperature = torch.zeros((), dtype=torch.float32, requires_grad=True)
    optimizer = torch.optim.LBFGS(
        [log_temperature], lr=0.25, max_iter=100, tolerance_grad=1.0e-9, line_search_fn="strong_wolfe"
    )

    def closure() -> Any:
        optimizer.zero_grad(set_to_none=True)
        temperature = log_temperature.clamp(min=math.log(0.05), max=math.log(20.0)).exp()
        loss = torch.nn.functional.cross_entropy(logits / temperature, targets)
        loss.backward()
        return loss

    optimizer.step(closure)
    fitted = float(log_temperature.detach().clamp(min=math.log(0.05), max=math.log(20.0)).exp().item())
    if not math.isfinite(fitted) or fitted <= 0:
        raise RuntimeError("validation temperature fit did not produce a finite positive value")
    return fitted


def calibrate(torch: Any, predictions: Sequence[Dict[str, Any]]) -> Tuple[Dict[str, float], float]:
    grouped = {bucket: [] for bucket in BUCKETS}
    for prediction in predictions:
        grouped[_bucket(prediction["count"])].append(prediction)
    global_temperature = _fit_temperature(torch, predictions)
    per_bucket = {
        bucket: _fit_temperature(torch, grouped[bucket]) if grouped[bucket] else global_temperature
        for bucket in BUCKETS
    }
    return per_bucket, global_temperature


def validation_metrics(
    torch: Any, predictions: Sequence[Dict[str, Any]], per_bucket: Dict[str, float]
) -> Dict[str, Any]:
    raw_losses = []
    calibrated_losses = []
    correct = []
    for prediction in predictions:
        scores = prediction["logits"]
        target = torch.tensor([prediction["target"]], dtype=torch.long)
        raw_losses.append(float(torch.nn.functional.cross_entropy(scores.unsqueeze(0), target).item()))
        temperature = per_bucket[_bucket(prediction["count"])]
        calibrated_losses.append(
            float(torch.nn.functional.cross_entropy((scores / temperature).unsqueeze(0), target).item())
        )
        correct.append(int(int(scores.argmax().item()) == prediction["target"]))
    return {
        "examples": len(predictions),
        "negative_log_likelihood_before_calibration": sum(raw_losses) / len(raw_losses),
        "negative_log_likelihood_after_calibration": sum(calibrated_losses) / len(calibrated_losses),
        "top1_accuracy": sum(correct) / len(correct),
    }


def _logits_only(torch: Any, model: Any) -> Any:
    class LogitsOnly(torch.nn.Module):
        """Expose just choice logits with the wtf-cli ONNX signature."""

        def __init__(self, decision_model: Any) -> None:
            super().__init__()
            self.decision_model = decision_model

        def forward(self, input_ids: Any, attention_mask: Any, marker_pos: Any, marker_mask: Any, qtype: Any) -> Any:
            return self.decision_model(input_ids, attention_mask, marker_pos, marker_mask, qtype)[0]

    return LogitsOnly(model)


def export_and_check_onnx(
    torch: Any,
    model: Any,
    tokenizer: Any,
    validation_items: Sequence[Dict[str, Any]],
    onnx_dir: Path,
) -> Dict[str, Any]:
    try:
        import numpy as np
        import onnx
        import onnxruntime as ort
    except ImportError as error:
        raise RuntimeError(
            "ONNX export and parity require preinstalled onnx and onnxruntime; this command never installs dependencies"
        ) from error

    model.encoder.config.reference_compile = False
    wrapper = _logits_only(torch, model).to("cpu").eval()
    if not onnx_dir.is_dir() or (onnx_dir / "laya.onnx").exists():
        raise RuntimeError("ONNX output directory is not ready for a new graph")
    graph_path = onnx_dir / "laya.onnx"
    sample_indices = []
    ordered = sorted(
        range(len(validation_items)),
        key=lambda index: (len(validation_items[index]["ids"]), len(validation_items[index]["markers"])),
    )
    for index in (ordered[0], ordered[-1]):
        if index not in sample_indices:
            sample_indices.append(index)
    if len(ordered) > 2:
        middle = ordered[len(ordered) // 2]
        if middle not in sample_indices:
            sample_indices.append(middle)

    sample = validation_items[sample_indices[0]]
    # Trace with batch size two so the dynamo exporter preserves a symbolic batch axis.
    ids = torch.tensor([sample["ids"], sample["ids"]], dtype=torch.long)
    attention = torch.ones_like(ids)
    markers = [sample["markers"], sample["markers"]]
    marker_pos = torch.tensor(markers, dtype=torch.long)
    marker_mask = torch.ones_like(marker_pos, dtype=torch.bool)
    qtype = torch.zeros((2,), dtype=torch.long)
    input_names = ["input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype"]
    output_names = ["logits"]
    batch_dim = torch.export.Dim("batch", min=1)
    sequence_dim = torch.export.Dim("sequence_length", min=8)
    options_dim = torch.export.Dim("num_choices", min=2)
    dynamic_shapes = {
        "input_ids": {0: batch_dim, 1: sequence_dim},
        "attention_mask": {0: batch_dim, 1: sequence_dim},
        "marker_pos": {0: batch_dim, 1: options_dim},
        "marker_mask": {0: batch_dim, 1: options_dim},
        "qtype": {0: batch_dim},
    }
    onnx_program = torch.onnx.export(
        wrapper,
        (ids, attention, marker_pos, marker_mask, qtype),
        opset_version=18,
        dynamo=True,
        optimize=True,
        input_names=input_names,
        output_names=output_names,
        dynamic_shapes=dynamic_shapes,
    )
    onnx_program.save(str(graph_path), external_data=False)
    onnx.checker.check_model(str(graph_path))
    session = ort.InferenceSession(str(graph_path), providers=["CPUExecutionProvider"])
    input_signature = [value.name for value in session.get_inputs()]
    output_signature = [value.name for value in session.get_outputs()]
    if input_signature != input_names or output_signature != output_names:
        raise RuntimeError(
            "exported ONNX signature mismatch: inputs={!r}, outputs={!r}".format(input_signature, output_signature)
        )

    max_absolute_error = 0.0
    checked = 0
    with torch.no_grad():
        for index in sample_indices:
            item = validation_items[index]
            case_ids = torch.tensor([item["ids"]], dtype=torch.long)
            case_attention = torch.ones_like(case_ids)
            case_marker_pos = torch.tensor([item["markers"]], dtype=torch.long)
            case_marker_mask = torch.ones_like(case_marker_pos, dtype=torch.bool)
            case_qtype = torch.tensor([0], dtype=torch.long)
            reference = wrapper(case_ids, case_attention, case_marker_pos, case_marker_mask, case_qtype).cpu().numpy()
            actual = session.run(
                output_names,
                {
                    "input_ids": case_ids.numpy(),
                    "attention_mask": case_attention.numpy(),
                    "marker_pos": case_marker_pos.numpy(),
                    "marker_mask": case_marker_mask.numpy(),
                    "qtype": case_qtype.numpy(),
                },
            )[0]
            if reference.shape != actual.shape or not np.isfinite(actual).all():
                raise RuntimeError("ONNX returned invalid probe-choice logits")
            error = float(np.max(np.abs(reference - actual)))
            max_absolute_error = max(max_absolute_error, error)
            if not np.allclose(reference, actual, rtol=1.0e-3, atol=1.0e-4):
                raise RuntimeError(
                    "PyTorch/ONNX parity failed (max absolute logit error {:.8g})".format(error)
                )
            checked += 1

    tokenizer_dir = onnx_dir / "tokenizer"
    tokenizer.save_pretrained(str(tokenizer_dir))
    if not (tokenizer_dir / "tokenizer.json").is_file():
        raise RuntimeError("saved tokenizer is missing tokenizer/tokenizer.json required by wtf-cli")
    return {
        "input_names": input_signature,
        "output_names": output_signature,
        "parity_cases": checked,
        "max_absolute_logit_error": max_absolute_error,
        "rtol": 1.0e-3,
        "atol": 1.0e-4,
    }


def _write_json(path: Path, value: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as destination:
        json.dump(value, destination, ensure_ascii=False, indent=2, allow_nan=False)
        destination.write("\n")


def _save_checkpoint(
    model: Any,
    source: Path,
    staging: Path,
    config: Dict[str, Any],
    temperatures: Dict[str, float],
    global_temperature: float,
    steps: int,
    learning_rate: float,
    changed_names: Sequence[str],
) -> None:
    from safetensors.torch import save_file

    checkpoint_dir = staging / "checkpoint"
    checkpoint_dir.mkdir(parents=True, exist_ok=False)
    (staging / "onnx").mkdir(exist_ok=False)
    for name in ("encoder", "tokenizer"):
        shutil.copytree(source / name, checkpoint_dir / name)
    shutil.copy2(source / "rl_common.py", checkpoint_dir / "rl_common.py")

    output_config = dict(config)
    old_temperatures = list(output_config.get("temperature", [1.0, 1.0, 1.0]))
    while len(old_temperatures) < 3:
        old_temperatures.append(1.0)
    old_temperatures[0] = global_temperature
    output_config["temperature"] = old_temperatures
    old_by_options = dict(output_config.get("temperature_by_options", {}))
    old_by_options = {key: value for key, value in old_by_options.items() if not key.startswith("choice:")}
    old_by_options.update({"choice:" + bucket: value for bucket, value in temperatures.items()})
    output_config["temperature_by_options"] = old_by_options
    training_metadata = dict(output_config.get("training", {}))
    training_metadata.update(
        {
            "fine_tuned_from_checkpoint": True,
            "task": SCHEMA,
            "optimizer": "AdamW",
            "updates": steps,
            "learning_rate": learning_rate,
            "changed_parameter_tensors": len(changed_names),
        }
    )
    output_config["training"] = training_metadata
    _write_json(checkpoint_dir / "rl_agent_config.json", output_config)

    state = {name: tensor.detach().to(device="cpu").contiguous() for name, tensor in model.state_dict().items()}
    save_file(state, str(checkpoint_dir / "model.safetensors"), metadata={"format": "pt"})

    onnx_config = {
        "max_len": int(config["max_len"]),
        "head_max_len": int(config["head_max_len"]),
        "temperature": output_config["temperature"],
        "temperature_by_options": output_config["temperature_by_options"],
    }
    _write_json(staging / "onnx" / "laya_config.json", onnx_config)


def _metrics_json(
    *,
    steps: int,
    learning_rate: float,
    mean_training_loss: float,
    before: Dict[str, str],
    after: Dict[str, str],
    validation: Dict[str, Any],
    temperatures: Dict[str, float],
    global_temperature: float,
    predictions: Sequence[Dict[str, Any]],
    parity: Dict[str, Any],
    device: str,
) -> Dict[str, Any]:
    changed_names = sorted(name for name in before if before[name] != after[name])
    bucket_counts = {
        bucket: sum(1 for prediction in predictions if _bucket(prediction["count"]) == bucket)
        for bucket in BUCKETS
    }
    return {
        "schema": SCHEMA,
        "upstream": "convaiinnovations/laya@00c37c405e3c3ad73ee070227614c89cda06b99e",
        "optimization": {
            "optimizer": "AdamW",
            "requested_steps": steps,
            "completed_steps": steps,
            "learning_rate": learning_rate,
            "mean_training_loss": mean_training_loss,
            "device": device,
            "trainable_parameter_tensors": len(before),
            "changed_parameter_tensors": len(changed_names),
            "changed_parameter_names": changed_names,
            "parameter_hashes_before": hashlib.sha256("".join(before[name] for name in sorted(before)).encode("ascii")).hexdigest(),
            "parameter_hashes_after": hashlib.sha256("".join(after[name] for name in sorted(after)).encode("ascii")).hexdigest(),
        },
        "validation": validation,
        "calibration": {
            "method": "held-out choice negative-log-likelihood temperature scaling",
            "global_temperature": global_temperature,
            "temperatures_by_option_count": {
                "choice:" + bucket: {"temperature": temperatures[bucket], "examples": bucket_counts[bucket]}
                for bucket in BUCKETS
            },
        },
        "onnx_parity": parity,
    }


def run(args: argparse.Namespace) -> None:
    if args.steps <= 0:
        raise ValueError("--steps must be greater than zero")
    if not math.isfinite(args.learning_rate) or args.learning_rate <= 0:
        raise ValueError("--learning-rate must be finite and greater than zero")
    train_path = Path(args.train)
    validation_path = Path(args.validation)
    checkpoint = Path(args.checkpoint)
    output = Path(args.output)
    train_rows, validation_rows = load_split(train_path, validation_path)
    _validate_model_visible_labels(train_rows, validation_rows)
    if _non_abstain_target_count(train_rows) == 0:
        raise DatasetError(
            "training split contains zero non-abstain targets; refusing to train on an all-abstain dataset"
        )
    validation_non_abstain_targets = _non_abstain_target_count(validation_rows)
    checkpoint_files(checkpoint)
    if output.exists() or output.is_symlink():
        raise ValueError("output directory already exists: {}".format(output))

    torch, rl_common, loaded, config = _load_upstream(checkpoint)
    tokenizer, model = loaded
    if tokenizer.pad_token_id is None:
        raise ValueError("local Laya tokenizer has no pad_token_id")
    if not isinstance(model, torch.nn.Module):
        raise RuntimeError("upstream rl_common.build_model did not return a PyTorch module")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    dtype = rl_common.amp_dtype(config.get("amp_dtype", "fp16"))
    if device.type == "cuda" and torch.cuda.get_device_capability(device)[0] < 8:
        dtype = torch.float16
    model.to(device)
    train_items = encode_rows(train_rows, tokenizer, config, rl_common)
    validation_items = encode_rows(validation_rows, tokenizer, config, rl_common)
    steps, mean_training_loss, before, after = optimize(
        torch,
        rl_common,
        model,
        train_items,
        tokenizer.pad_token_id,
        device,
        args.steps,
        args.learning_rate,
        dtype,
    )
    predictions = evaluate_validation(
        torch, rl_common, model, validation_items, tokenizer.pad_token_id, device, dtype
    )
    temperatures, global_temperature = calibrate(torch, predictions)
    val_metrics = validation_metrics(torch, predictions, temperatures)
    val_metrics["non_abstain_target_examples"] = validation_non_abstain_targets
    if validation_non_abstain_targets == 0:
        val_metrics["limitation"] = (
            "All validation targets are abstain; these metrics do not assess non-abstain choice selection."
        )

    output_parent = output.parent if str(output.parent) else Path(".")
    output_parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise ValueError("output directory already exists: {}".format(output))
    staging = Path(tempfile.mkdtemp(prefix="." + output.name + ".training-", dir=str(output_parent)))
    try:
        model.to("cpu").eval()
        del train_items
        if device.type == "cuda":
            torch.cuda.empty_cache()
        changed_names = sorted(name for name in before if before[name] != after[name])
        _save_checkpoint(
            model,
            checkpoint,
            staging,
            config,
            temperatures,
            global_temperature,
            steps,
            args.learning_rate,
            changed_names,
        )
        parity = export_and_check_onnx(torch, model, tokenizer, validation_items, staging / "onnx")
        metrics = _metrics_json(
            steps=steps,
            learning_rate=args.learning_rate,
            mean_training_loss=mean_training_loss,
            before=before,
            after=after,
            validation=val_metrics,
            temperatures=temperatures,
            global_temperature=global_temperature,
            predictions=predictions,
            parity=parity,
            device=str(device),
        )
        _write_json(staging / "metrics.json", metrics)
        if output.exists() or output.is_symlink():
            raise ValueError("output directory appeared while training: {}".format(output))
        os.replace(staging, output)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    print(
        "Training complete: {} optimizer steps; {} parameter tensors changed; ONNX parity checked on {} cases.".format(
            steps, len(changed_names), parity["parity_cases"]
        )
    )
    if validation_non_abstain_targets == 0:
        print(
            "Warning: validation targets are all abstain; held-out metrics do not assess non-abstain choice selection.",
            file=sys.stderr,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True, help="Rust-validated train JSONL")
    parser.add_argument("--validation", required=True, help="Rust-validated held-out validation JSONL")
    parser.add_argument("--checkpoint", required=True, help="local trainable convaiinnovations/laya checkpoint")
    parser.add_argument("--output", required=True, help="new directory for checkpoint, ONNX bundle, and metrics")
    parser.add_argument("--steps", required=True, type=int, help="number of optimizer updates (must be positive)")
    parser.add_argument("--learning-rate", required=True, type=float, help="AdamW learning rate")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        run(args)
    except Exception as error:
        print("wtf-train: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
