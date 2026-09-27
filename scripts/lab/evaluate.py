#!/usr/bin/env python3
"""Compare no-model and local-interpreter CLI reports from the same replay snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run import LabError, drain_limited, load_json, stop_process_group, validate_suite, verify_seal

MAX_REPORT_BYTES_PER_STREAM = 262144
DEFAULT_TIMEOUT_SECONDS = 180.0


class EvaluationError(Exception):
    pass


def write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def resolve_file(path: Path, label: str, executable: bool = False) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise EvaluationError(f"{label} does not exist: {path}") from exc
    if not resolved.is_file() or (executable and not os.access(resolved, os.X_OK)):
        requirement = "an executable file" if executable else "a regular file"
        raise EvaluationError(f"{label} must be {requirement}: {resolved}")
    return resolved


def validate_run(run_path: Path, allow_reserved: bool) -> tuple[Path, str, dict[str, Any], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    try:
        run_dir = run_path.resolve(strict=True)
    except OSError as exc:
        raise EvaluationError(f"run directory does not exist: {run_path}") from exc
    artifact_root = (Path(__file__).resolve().parent / "artifacts").resolve(strict=True)
    if not run_dir.is_relative_to(artifact_root):
        raise EvaluationError("--run must be inside scripts/lab/artifacts")
    post_path = run_dir / "postrecord.json"
    if post_path.is_symlink():
        raise EvaluationError("postrecord must not be a symlink")
    postrecord = load_json(post_path)
    suite = postrecord.get("suite")
    if suite not in {"dev", "reserved"} or run_dir.parent.name != suite:
        raise EvaluationError("run directory must be a dev or reserved lab run")
    if suite == "reserved" and not allow_reserved:
        raise EvaluationError("reserved replay requires the explicit --allow-reserved flag after configuration freeze")
    try:
        manifest_hash, oracle_hash = verify_seal(suite)
    except LabError as exc:
        raise EvaluationError(str(exc)) from exc
    if postrecord.get("manifest_sha256") != manifest_hash or postrecord.get("oracle_sha256") != oracle_hash:
        raise EvaluationError("run postrecord does not match the currently sealed manifest and oracle")
    manifest = load_json(Path(__file__).resolve().parent / f"{suite}-manifest.json")
    cases = validate_suite(manifest, suite)
    post_cases = postrecord.get("cases")
    if (
        not isinstance(post_cases, list)
        or any(not isinstance(row, dict) for row in post_cases)
        or [row.get("case_id") for row in post_cases] != [case["id"] for case in cases]
    ):
        raise EvaluationError("postrecord case order/ids do not match the sealed manifest")
    if postrecord.get("launch_attempts_total") != len(cases):
        raise EvaluationError("source run must have exactly one launch attempt per case")
    if suite == "reserved" and postrecord.get("reserved_cases_executed") != len(cases):
        raise EvaluationError("reserved run postrecord does not prove a complete reserved execution")
    snapshots: dict[str, dict[str, Any]] = {}
    post_by_id = {row["case_id"]: row for row in post_cases}
    for case in cases:
        case_id = case["id"]
        row = post_by_id[case_id]
        if row.get("launch_attempts") != 1:
            raise EvaluationError(f"{case_id}: source command was not recorded as exactly-once")
        snapshot_name = row.get("snapshot")
        if snapshot_name != f"{case_id}.snapshot.json":
            raise EvaluationError(f"{case_id}: unsafe or unexpected snapshot filename")
        snapshot_path = run_dir / snapshot_name
        if snapshot_path.is_symlink() or not snapshot_path.resolve(strict=True).is_relative_to(run_dir):
            raise EvaluationError(f"{case_id}: snapshot must be a regular file inside the run directory")
        snapshot_bytes = snapshot_path.read_bytes()
        if hashlib.sha256(snapshot_bytes).hexdigest() != row.get("snapshot_sha256"):
            raise EvaluationError(f"{case_id}: snapshot checksum mismatch")
        try:
            snapshot = json.loads(snapshot_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise EvaluationError(f"{case_id}: replay snapshot is not valid UTF-8 JSON") from exc
        if not isinstance(snapshot, dict):
            raise EvaluationError(f"{case_id}: replay snapshot must be a JSON object")
        if snapshot.get("source_mode") != "explicit" or not isinstance(snapshot.get("capture_truncated"), bool):
            raise EvaluationError(f"{case_id}: invalid replay snapshot wrapper")
        execution = snapshot.get("execution")
        required = {"command", "args", "cwd", "exit_status", "stdout", "stderr", "duration", "timestamp", "spawn_error"}
        status = execution.get("exit_status") if isinstance(execution, dict) else None
        timestamp = execution.get("timestamp") if isinstance(execution, dict) else None
        duration = execution.get("duration") if isinstance(execution, dict) else None
        if (
            not isinstance(execution, dict)
            or not required.issubset(execution)
            or not isinstance(execution.get("command"), str)
            or not isinstance(execution.get("args"), list)
            or any(not isinstance(arg, str) for arg in execution["args"])
            or not isinstance(execution.get("cwd"), str)
            or not isinstance(execution.get("stdout"), str)
            or not isinstance(execution.get("stderr"), str)
            or (execution.get("spawn_error") is not None and not isinstance(execution.get("spawn_error"), str))
            or not isinstance(status, dict)
            or not {"code", "signal"}.issubset(status)
            or any(status.get(field) is not None and (not isinstance(status[field], int) or isinstance(status[field], bool)) for field in ("code", "signal"))
            or not isinstance(duration, dict)
            or any(not isinstance(duration.get(field), int) or isinstance(duration[field], bool) for field in ("secs", "nanos"))
            or not isinstance(timestamp, dict)
            or any(not isinstance(timestamp.get(field), int) or isinstance(timestamp[field], bool) for field in ("secs_since_epoch", "nanos_since_epoch"))
        ):
            raise EvaluationError(f"{case_id}: incomplete or invalid CommandExecution snapshot")
        snapshots[case_id] = {
            "path": snapshot_path,
            "snapshot": snapshot,
            "snapshot_bytes": snapshot_bytes,
            "postrecord": row,
        }
    return run_dir, suite, postrecord, cases, snapshots


def expected_cli_status(snapshot: dict[str, Any]) -> int:
    execution = snapshot["execution"]
    status = execution["exit_status"]
    if status.get("code") is not None:
        return int(status["code"]) & 0xFF
    if status.get("signal") is not None:
        return (128 + int(status["signal"])) & 0xFF
    return 1


def capture_cli(
    cli: Path,
    snapshot_path: Path,
    profile: str,
    output_format: str,
    model: Path,
    runtime: Path,
    timeout_seconds: float,
    eval_dir: Path,
) -> dict[str, Any]:
    command = [str(cli), "--no-color"]
    if output_format == "json":
        command.append("--json")
    if profile == "no-model":
        command.append("--no-model")
    else:
        command.extend(["--interpreter-model", str(model), "--interpreter-runtime", str(runtime)])
    command.extend(["--replay-snapshot", str(snapshot_path)])
    started_ns = time.monotonic_ns()
    stdout_capture: tuple[bytes, int] = (b"", 0)
    stderr_capture: tuple[bytes, int] = (b"", 0)
    timed_out = False
    spawn_error: str | None = None
    exit_status: int | None = None
    with tempfile.TemporaryDirectory(prefix=".eval-home-", dir=eval_dir) as home:
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "TERM": "dumb",
            "NO_COLOR": "1",
            "HOME": home,
            "TMPDIR": home,
            "XDG_CACHE_HOME": home,
        }
        if profile == "no-model":
            env["WTF_NO_MODEL"] = "1"
        try:
            process = subprocess.Popen(
                command,
                cwd=home,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            spawn_error = str(exc)
            process = None
        if process is not None:
            assert process.stdout is not None and process.stderr is not None
            captured: dict[str, tuple[bytes, int]] = {}
            readers = [
                threading.Thread(
                    target=lambda key=key, pipe=pipe: captured.__setitem__(
                        key, drain_limited(pipe, MAX_REPORT_BYTES_PER_STREAM)
                    ),
                    daemon=True,
                )
                for key, pipe in (("stdout", process.stdout), ("stderr", process.stderr))
            ]
            for reader in readers:
                reader.start()
            try:
                try:
                    exit_status = process.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    stop_process_group(process)
                    exit_status = process.returncode
            except BaseException:
                if process.poll() is None:
                    stop_process_group(process)
                raise
            for reader in readers:
                reader.join(timeout=5)
            if any(reader.is_alive() for reader in readers):
                stop_process_group(process)
                for reader in readers:
                    reader.join(timeout=5)
                if any(reader.is_alive() for reader in readers):
                    raise EvaluationError(f"replay output pipe did not close for {snapshot_path.name}")
            stdout_capture = captured["stdout"]
            stderr_capture = captured["stderr"]
    elapsed_ns = time.monotonic_ns() - started_ns
    stdout_bytes, stdout_total = stdout_capture
    stderr_bytes, stderr_total = stderr_capture
    return {
        "command": command,
        "profile": profile,
        "format": output_format,
        "exit_status": exit_status,
        "timed_out": timed_out,
        "spawn_error": spawn_error,
        "duration_ms": round(elapsed_ns / 1_000_000, 3),
        "stdout": stdout_bytes,
        "stderr": stderr_bytes,
        "stdout_total_bytes": stdout_total,
        "stderr_total_bytes": stderr_total,
        "stdout_truncated": stdout_total > MAX_REPORT_BYTES_PER_STREAM,
        "stderr_truncated": stderr_total > MAX_REPORT_BYTES_PER_STREAM,
    }


def outcome(result: dict[str, Any], expected_status: int) -> str:
    if result["spawn_error"] is not None:
        return "spawn-failed"
    if result["timed_out"]:
        return "timed-out"
    if result["exit_status"] != expected_status:
        return "exit-status-mismatch"
    return "exit-status-matches-execution"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wtf", required=True, type=Path, help="already-built wtf executable")
    parser.add_argument("--run", required=True, type=Path, help="one development or reserved lab run directory")
    parser.add_argument("--model", required=True, type=Path, help="local GGUF path; no downloads are performed")
    parser.add_argument("--runtime", required=True, type=Path, help="local llama-cli executable path")
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--allow-reserved", action="store_true", help="required for held-out replay after explicit freeze approval")
    args = parser.parse_args()
    try:
        if not 5 <= args.timeout_seconds <= 900:
            raise EvaluationError("--timeout-seconds must be between 5 and 900")
        cli = resolve_file(args.wtf, "wtf CLI", executable=True)
        model = resolve_file(args.model, "model", executable=False)
        runtime = resolve_file(args.runtime, "runtime", executable=True)
        run_dir, suite, source_postrecord, cases, snapshots = validate_run(args.run, args.allow_reserved)
        evals_dir = run_dir / "evaluations"
        if evals_dir.is_symlink():
            raise EvaluationError("refusing to write evaluations through a symlink")
        evals_dir.mkdir(mode=0o700, exist_ok=True)
        eval_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%S.%fZ") + f"-{os.getpid()}"
        eval_dir = evals_dir / eval_id
        eval_dir.mkdir(mode=0o700)
        replay_inputs = eval_dir / "replay-snapshots"
        replay_inputs.mkdir(mode=0o700)
        call_rows: list[dict[str, Any]] = []
        all_ok = True
        started_at = datetime.now(timezone.utc).isoformat()
        for case in cases:
            case_id = case["id"]
            snapshot_info = snapshots[case_id]
            snapshot_path = snapshot_info["path"]
            snapshot = snapshot_info["snapshot"]
            replay_snapshot_path = replay_inputs / snapshot_path.name
            write_private(replay_snapshot_path, snapshot_info["snapshot_bytes"])
            if hashlib.sha256(replay_snapshot_path.read_bytes()).hexdigest() != snapshot_info["postrecord"]["snapshot_sha256"]:
                raise EvaluationError(f"{case_id}: private replay copy checksum mismatch")
            expected_status = expected_cli_status(snapshot)
            results: dict[str, dict[str, Any]] = {}
            files: dict[str, dict[str, str]] = {}
            for profile in ("no-model", "interpreter"):
                for output_format in ("visible", "json"):
                    result = capture_cli(
                        cli, replay_snapshot_path, profile, output_format, model, runtime,
                        args.timeout_seconds, eval_dir,
                    )
                    prefix = f"{case_id}.{profile}"
                    output_name = f"{prefix}.{output_format}.{'txt' if output_format == 'visible' else 'json'}"
                    error_name = f"{prefix}.{output_format}.stderr.txt"
                    write_private(eval_dir / output_name, result["stdout"])
                    write_private(eval_dir / error_name, result["stderr"])
                    key = f"{profile}_{output_format}"
                    files[key] = {"stdout": output_name, "stderr": error_name}
                    json_valid: bool | None = None
                    json_schema_version: int | None = None
                    if output_format == "json":
                        try:
                            decoded = json.loads(result["stdout"].decode("utf-8"))
                            json_valid = isinstance(decoded, dict) and type(decoded.get("schema_version")) is int and decoded.get("schema_version") == 1 and isinstance(decoded.get("report"), dict)
                            schema = decoded.get("schema_version") if isinstance(decoded, dict) else None
                            json_schema_version = schema if type(schema) is int else None
                        except (UnicodeError, json.JSONDecodeError):
                            json_valid = False
                    call_outcome = outcome(result, expected_status)
                    if call_outcome != "exit-status-matches-execution" or (output_format == "json" and not json_valid):
                        all_ok = False
                    results[key] = {
                        "outcome": call_outcome,
                        "cli_exit_status": result["exit_status"],
                        "expected_cli_exit_status": expected_status,
                        "timed_out": result["timed_out"],
                        "spawn_error": result["spawn_error"],
                        "duration_ms": result["duration_ms"],
                        "stdout_total_bytes": result["stdout_total_bytes"],
                        "stderr_total_bytes": result["stderr_total_bytes"],
                        "stdout_truncated": result["stdout_truncated"],
                        "stderr_truncated": result["stderr_truncated"],
                        "json_valid": json_valid,
                        "json_schema_version": json_schema_version,
                        "stdout_sha256": hashlib.sha256(result["stdout"]).hexdigest(),
                        "stderr_sha256": hashlib.sha256(result["stderr"]).hexdigest(),
                    }
                    print(f"{case_id} {key}: {call_outcome}; {result['duration_ms']:.3f} ms")
            call_rows.append({
                "case_id": case_id,
                "family": case["family"],
                "snapshot": snapshot_path.name,
                "private_replay_snapshot": replay_snapshot_path.relative_to(eval_dir).as_posix(),
                "snapshot_sha256": snapshot_info["postrecord"]["snapshot_sha256"],
                "captured_execution_status": snapshot["execution"]["exit_status"],
                "calls": results,
                "reports": files,
                "paired_reports_equal": {
                    "visible_stdout": results["no-model_visible"]["stdout_sha256"] == results["interpreter_visible"]["stdout_sha256"],
                    "json_stdout": results["no-model_json"]["stdout_sha256"] == results["interpreter_json"]["stdout_sha256"],
                    "visible_stderr": results["no-model_visible"]["stderr_sha256"] == results["interpreter_visible"]["stderr_sha256"],
                    "json_stderr": results["no-model_json"]["stderr_sha256"] == results["interpreter_json"]["stderr_sha256"],
                },
            })
        evaluation = {
            "schema_version": 1,
            "suite": suite,
            "source_run_id": source_postrecord["run_id"],
            "manifest_sha256": source_postrecord["manifest_sha256"],
            "oracle_sha256": source_postrecord["oracle_sha256"],
            "started_at_utc": started_at,
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
            "wtf_cli": str(cli),
            "model_path": str(model),
            "runtime_path": str(runtime),
            "timeout_seconds_per_replay": args.timeout_seconds,
            "max_report_bytes_per_stream": MAX_REPORT_BYTES_PER_STREAM,
            "invariants": {
                "source_commands_rerun": False,
                "probes_rerun": False,
                "hosted_inference": False,
                "inference_mode": "local GGUF",
                "reserved_cases_authorized": suite != "reserved" or args.allow_reserved,
            },
            "cli_replay_invocations": len(call_rows) * 4,
            "calls_with_timeout_or_spawn_or_status_error": sum(
                result["outcome"] != "exit-status-matches-execution"
                for row in call_rows for result in row["calls"].values()
            ),
            "invalid_json_reports": sum(
                result["json_valid"] is False
                for row in call_rows for key, result in row["calls"].items() if key.endswith("_json")
            ),
            "cases": call_rows,
        }
        post_path = eval_dir / "evaluation-postrecord.json"
        write_private(post_path, (json.dumps(evaluation, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        print(f"evaluation artifacts: {eval_dir.relative_to(run_dir)}")
        return 0 if all_ok else 2
    except (EvaluationError, LabError, OSError, ValueError, KeyError) as exc:
        print(f"evaluation error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
