#!/usr/bin/env python3
"""Sealed, once-only follow-up fixtures and paired no-model/model replay.

Run and evaluate are separate steps so the executable/model/configuration can be
frozen before fixtures are opened. Replays do not repeat source commands/probes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import evaluate
import run

SUITE = "followup"


def execute_fixtures() -> int:
    manifest_hash, oracle_hash = run.verify_seal(SUITE)
    manifest = run.load_json(run.LAB_DIR / f"{SUITE}-manifest.json")
    cases = run.validate_suite(manifest, SUITE)
    oracle = run.read_oracle(SUITE, cases)
    binaries = run.preflight_programs(cases)
    artifact = run.create_run_dir(SUITE)
    records = []
    output_limit = manifest["capture_limit_bytes_per_stream"]
    with tempfile.TemporaryDirectory(prefix=".wtf-lab-", dir=artifact) as temporary:
        root = Path(temporary).resolve(strict=True)
        for case in cases:
            cwd = root / case["id"]
            cwd.mkdir(mode=0o700)
            run.setup_case(case, cwd)
            result = run.run_once(
                binaries[case["program"]], case["args"], cwd, root,
                float(case["timeout_seconds"]), manifest["resource_limits"], output_limit,
            )
            snapshot = run.snapshot_for(result, cwd, binaries[case["program"]], output_limit)
            name = f"{case['id']}.snapshot.json"
            dest = artifact / name
            run.write_private_json(dest, snapshot)
            row = {
                "case_id": case["id"], "family": case["family"],
                "snapshot": name, "snapshot_sha256": hashlib.sha256(dest.read_bytes()).hexdigest(),
                "launch_attempts": 1, "status": result["exit_status"],
                "timed_out": result["timed_out"],
                "oracle_status_match": run.oracle_matches(result, oracle[case["id"]]),
            }
            records.append(row)
            print(f"{case['id']}: {row['status']} oracle_status_match={row['oracle_status_match']}")
    if run.verify_seal(SUITE) != (manifest_hash, oracle_hash):
        raise run.LabError("follow-up fixture or oracle changed during execution")
    run.write_private_json(artifact / "postrecord.json", {
        "suite": SUITE, "manifest_sha256": manifest_hash,
        "oracle_sha256": oracle_hash, "launch_attempts_total": len(records),
        "cases": records,
    })
    print(f"run: {artifact}")
    return 0 if all(row["oracle_status_match"] for row in records) else 2


def paired_replay(run_dir: Path, cli: Path, model: Path, runtime: Path) -> int:
    run_dir = run_dir.resolve(strict=True)
    artifact_root = (run.ARTIFACT_ROOT / SUITE).resolve(strict=True)
    if run_dir.parent != artifact_root or run_dir.is_symlink():
        raise evaluate.EvaluationError("run must be an isolated follow-up artifact directory")
    manifest_hash, oracle_hash = run.verify_seal(SUITE)
    postrecord = run.load_json(run_dir / "postrecord.json")
    if (postrecord.get("suite"), postrecord.get("manifest_sha256"), postrecord.get("oracle_sha256")) != (SUITE, manifest_hash, oracle_hash):
        raise evaluate.EvaluationError("run does not match sealed fixtures and oracle")
    manifest = run.load_json(run.LAB_DIR / f"{SUITE}-manifest.json")
    cases = run.validate_suite(manifest, SUITE)
    source = postrecord.get("cases")
    if not isinstance(source, list) or [row.get("case_id") for row in source] != [case["id"] for case in cases] or any(row.get("launch_attempts") != 1 for row in source):
        raise evaluate.EvaluationError("postrecord does not prove once-only source execution")
    cli = evaluate.resolve_file(cli, "CLI", executable=True)
    model = evaluate.resolve_file(model, "model")
    runtime = evaluate.resolve_file(runtime, "runtime", executable=True)
    eval_dir = run_dir / "evaluations"
    eval_dir.mkdir(mode=0o700, exist_ok=False)
    results = []
    valid = True
    for case, source_row in zip(cases, source):
        snapshot_path = run_dir / source_row["snapshot"]
        if snapshot_path.is_symlink() or snapshot_path.name != f"{case['id']}.snapshot.json" or hashlib.sha256(snapshot_path.read_bytes()).hexdigest() != source_row["snapshot_sha256"]:
            raise evaluate.EvaluationError("invalid snapshot or hash")
        snapshot = json.loads(snapshot_path.read_text())
        expected = evaluate.expected_cli_status(snapshot)
        calls = []
        for profile in ("no-model", "interpreter"):
            for format_name in ("visible", "json"):
                result = evaluate.capture_cli(cli, snapshot_path, profile, format_name, model, runtime, 180, eval_dir)
                check = evaluate.outcome(result, expected)
                text = result["stdout"]
                name = f"{case['id']}.{profile}.{format_name}.{'json' if format_name == 'json' else 'txt'}"
                evaluate.write_private(eval_dir / name, text)
                valid_json = None
                if format_name == "json":
                    try:
                        decoded = json.loads(text)
                        valid_json = isinstance(decoded.get("report"), dict) and decoded.get("schema_version") == 1
                    except (UnicodeError, json.JSONDecodeError, AttributeError):
                        valid_json = False
                calls.append({"profile": profile, "format": format_name, "file": name,
                              "result": check, "json_valid": valid_json, "duration_ms": result["duration_ms"],
                              "stderr": result["stderr"].decode(errors="replace")})
                valid &= check == "exit-status-matches-execution" and valid_json is not False
                print(f"{case['id']} {profile} {format_name}: {check} {result['duration_ms']:.1f} ms")
        results.append({"case_id": case["id"], "family": case["family"], "oracle_status_match": source_row["oracle_status_match"], "calls": calls})
    run.write_private_json(eval_dir / "paired-results.json", {
        "suite": SUITE, "manifest_sha256": manifest_hash, "oracle_sha256": oracle_hash,
        "cli_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
        "model_sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
        "runtime_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
        "source_commands_rerun": False, "probes_rerun": False,
        "cases": results,
    })
    print(f"paired artifacts: {eval_dir}")
    return 0 if valid else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run-once", action="store_true")
    group.add_argument("--paired", type=Path)
    parser.add_argument("--wtf", type=Path)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--runtime", type=Path)
    args = parser.parse_args()
    try:
        if args.run_once:
            return execute_fixtures()
        if args.wtf is None or args.model is None or args.runtime is None:
            parser.error("--paired requires --wtf, --model and --runtime")
        return paired_replay(args.paired, args.wtf, args.model, args.runtime)
    except (OSError, ValueError, KeyError, run.LabError, evaluate.EvaluationError) as error:
        print(f"follow-up error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
