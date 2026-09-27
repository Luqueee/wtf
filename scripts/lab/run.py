#!/usr/bin/env python3
"""Run frozen WTF laboratory cases once and write redacted replay snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

LAB_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAB_DIR.parents[1]
ARTIFACT_ROOT = LAB_DIR / "artifacts"
SYSTEM_PATH = "/usr/bin:/bin"
SECRET_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|password|passwd|secret|token)\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})\b"), "[REDACTED]"),
)


class LabError(Exception):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LabError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise LabError(f"{path.name} must contain a JSON object")
    return value


def verify_seal(name: str) -> tuple[str, str]:
    hashes: dict[str, str] = {}
    for kind in ("manifest", "oracle"):
        source_path = LAB_DIR / f"{name}-{kind}.json"
        seal_path = LAB_DIR / f"{name}-{kind}.sha256"
        try:
            expected = seal_path.read_text(encoding="ascii").strip().split()[0]
            actual = hashlib.sha256(source_path.read_bytes()).hexdigest()
        except (OSError, UnicodeError, IndexError) as exc:
            raise LabError(f"cannot verify frozen {name} {kind}: {exc}") from exc
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or actual != expected:
            raise LabError(f"{name} {kind} SHA-256 mismatch; refusing to execute")
        hashes[kind] = actual
    return hashes["manifest"], hashes["oracle"]


def safe_relative_path(raw: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or "\0" in raw:
        raise LabError("fixture path must be a non-empty relative path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise LabError(f"unsafe fixture path: {raw!r}")
    return path


def validate_suite(manifest: dict[str, Any], suite: str) -> list[dict[str, Any]]:
    if manifest.get("schema_version") != 1 or manifest.get("suite") != suite:
        raise LabError(f"invalid {suite} manifest header")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise LabError(f"{suite} manifest has no cases")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise LabError("each case must be a JSON object")
        case_id = case.get("id")
        family = case.get("family")
        program = case.get("program")
        args = case.get("args")
        setup = case.get("setup")
        timeout = case.get("timeout_seconds")
        if not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", case_id) or case_id in seen:
            raise LabError(f"invalid or duplicate case id: {case_id!r}")
        seen.add(case_id)
        if not isinstance(family, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", family):
            raise LabError(f"case {case_id}: invalid family")
        if not isinstance(program, str) or not re.fullmatch(r"[A-Za-z0-9._+-]+", program):
            raise LabError(f"case {case_id}: program must be a simple executable name")
        if not isinstance(args, list) or any(not isinstance(arg, str) or "\0" in arg for arg in args):
            raise LabError(f"case {case_id}: args must be strings without NUL")
        if not isinstance(timeout, (int, float)) or not 0.05 <= timeout <= 30:
            raise LabError(f"case {case_id}: timeout_seconds must be in [0.05, 30]")
        if not isinstance(setup, list):
            raise LabError(f"case {case_id}: setup must be a list")
        for item in setup:
            if not isinstance(item, dict) or item.get("op") not in {"write_text", "write_bytes_hex", "mkdir"}:
                raise LabError(f"case {case_id}: unsupported fixture operation")
            safe_relative_path(item.get("path"))
            if item["op"] == "write_text" and not isinstance(item.get("content"), str):
                raise LabError(f"case {case_id}: write_text requires string content")
            if item["op"] == "write_bytes_hex":
                try:
                    bytes.fromhex(item.get("hex", ""))
                except (TypeError, ValueError) as exc:
                    raise LabError(f"case {case_id}: invalid fixture hex") from exc
    limits = manifest.get("resource_limits")
    if not isinstance(limits, dict):
        raise LabError(f"{suite} manifest has no resource limits")
    for key in ("cpu_seconds_soft", "cpu_seconds_hard", "address_space_bytes", "file_size_bytes", "open_files", "core_dumps"):
        if not isinstance(limits.get(key), int) or limits[key] < 0:
            raise LabError(f"{suite} manifest has invalid resource limit {key}")
    if limits["cpu_seconds_soft"] == 0 or limits["cpu_seconds_hard"] < limits["cpu_seconds_soft"]:
        raise LabError(f"{suite} manifest has invalid CPU limits")
    capture_limit = manifest.get("capture_limit_bytes_per_stream")
    if not isinstance(capture_limit, int) or not 256 <= capture_limit <= 65536:
        raise LabError(f"{suite} manifest has invalid capture limit")
    return cases


def preflight_programs(cases: list[dict[str, Any]]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for case in cases:
        program = case["program"]
        if program in resolved:
            continue
        found = shutil.which(program, path=SYSTEM_PATH)
        if not found:
            raise LabError(f"required system executable is unavailable: {program}")
        absolute = str(Path(found).resolve(strict=True))
        if not any(Path(absolute).is_relative_to(root) for root in (Path("/usr/bin"), Path("/bin"))):
            raise LabError(f"executable resolved outside /usr/bin or /bin: {program}")
        if not os.access(absolute, os.X_OK):
            raise LabError(f"required executable is not executable: {program}")
        resolved[program] = absolute
    return resolved


def target_in_case(case_dir: Path, raw: str) -> Path:
    relative = safe_relative_path(raw)
    target = case_dir.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = case_dir.resolve(strict=True)
    resolved_parent = target.parent.resolve(strict=True)
    if not resolved_parent.is_relative_to(root):
        raise LabError(f"fixture path escapes isolated directory: {raw!r}")
    if target.exists() or target.is_symlink():
        raise LabError(f"fixture path already exists: {raw!r}")
    return target


def setup_case(case: dict[str, Any], case_dir: Path) -> None:
    for item in case["setup"]:
        target = target_in_case(case_dir, item["path"])
        operation = item["op"]
        if operation == "mkdir":
            target.mkdir(mode=0o700)
        elif operation == "write_text":
            content = item["content"]
            if len(content.encode("utf-8")) > 1_048_576:
                raise LabError(f"case {case['id']}: fixture text exceeds 1 MiB")
            target.write_text(content, encoding="utf-8")
            target.chmod(0o600)
        else:
            data = bytes.fromhex(item["hex"])
            if len(data) > 1_048_576:
                raise LabError(f"case {case['id']}: fixture bytes exceed 1 MiB")
            target.write_bytes(data)
            target.chmod(0o600)


def apply_limits(limits: dict[str, int]) -> None:
    pairs = (
        (resource.RLIMIT_CPU, limits["cpu_seconds_soft"], limits["cpu_seconds_hard"]),
        (resource.RLIMIT_AS, limits["address_space_bytes"], limits["address_space_bytes"]),
        (resource.RLIMIT_FSIZE, limits["file_size_bytes"], limits["file_size_bytes"]),
        (resource.RLIMIT_NOFILE, limits["open_files"], limits["open_files"]),
        (resource.RLIMIT_CORE, limits["core_dumps"], limits["core_dumps"]),
    )
    for kind, soft, hard in pairs:
        resource.setrlimit(kind, (soft, hard))
    os.umask(0o077)


def drain_limited(stream: Any, limit: int) -> tuple[bytes, int]:
    head_limit = limit // 4
    tail_limit = limit - head_limit
    first = bytearray()
    tail = bytearray()
    total = 0
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        total += len(chunk)
        if len(first) < head_limit:
            take = min(head_limit - len(first), len(chunk))
            first.extend(chunk[:take])
            chunk = chunk[take:]
        if chunk:
            tail.extend(chunk)
            if len(tail) > tail_limit:
                del tail[:len(tail) - tail_limit]
    if total <= limit:
        return bytes(first + tail), total
    omitted = total - len(first) - len(tail)
    marker = f"\n[... {omitted} bytes omitted ...]\n".encode("ascii")
    return bytes(first) + marker + bytes(tail), total


def stop_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_once(
    executable: str,
    args: list[str],
    case_dir: Path,
    temp_root: Path,
    timeout: float,
    limits: dict[str, int],
    output_limit: int,
) -> dict[str, Any]:
    start_wall_ns = time.time_ns()
    start_mono_ns = time.monotonic_ns()
    env = {
        "PATH": SYSTEM_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TERM": "dumb",
        "HOME": str(case_dir),
        "TMPDIR": str(case_dir),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CEILING_DIRECTORIES": str(temp_root),
    }
    process: subprocess.Popen[bytes] | None = None
    spawn_error: str | None = None
    timed_out = False
    status_code: int | None = None
    status_signal: int | None = None
    captures: dict[str, tuple[bytes, int]] = {}
    threads: list[threading.Thread] = []

    try:
        process = subprocess.Popen(
            [executable, *args],
            cwd=case_dir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            preexec_fn=lambda: apply_limits(limits),
        )
    except OSError as exc:
        spawn_error = str(exc)
    if process is not None:
        assert process.stdout is not None and process.stderr is not None
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            thread = threading.Thread(target=lambda n=name, s=stream: captures.__setitem__(n, drain_limited(s, output_limit)), daemon=True)
            thread.start()
            threads.append(thread)
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_process_group(process)
            return_code = process.returncode
        except BaseException:
            stop_process_group(process)
            raise
        finally:
            for thread in threads:
                thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            raise LabError("child output pipe did not close after process-group termination")
        if return_code is not None and return_code < 0:
            status_signal = -return_code
        else:
            status_code = return_code
    duration_ns = time.monotonic_ns() - start_mono_ns
    output = {name: captures.get(name, (b"", 0)) for name in ("stdout", "stderr")}
    timestamp_secs, timestamp_nanos = divmod(start_wall_ns, 1_000_000_000)
    duration_secs, duration_nanos = divmod(duration_ns, 1_000_000_000)
    return {
        "command": executable,
        "args": args,
        "cwd": "<LAB_TMP>",
        "exit_status": {"code": status_code, "signal": status_signal},
        "stdout_bytes": output["stdout"][0],
        "stderr_bytes": output["stderr"][0],
        "stdout_total_bytes": output["stdout"][1],
        "stderr_total_bytes": output["stderr"][1],
        "duration": {"secs": duration_secs, "nanos": duration_nanos},
        "timestamp": {"secs_since_epoch": timestamp_secs, "nanos_since_epoch": timestamp_nanos},
        "spawn_error": spawn_error,
        "timed_out": timed_out,
    }


def redact_text(text: str, temp_path: str) -> str:
    if temp_path:
        text = text.replace(temp_path, "<LAB_TMP>")
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def snapshot_for(result: dict[str, Any], case_dir: Path, executable: str, output_limit: int) -> dict[str, Any]:
    temp_path = str(case_dir)
    args = [redact_text(arg, temp_path) for arg in result["args"]]
    stdout = redact_text(result["stdout_bytes"].decode("utf-8", errors="replace"), temp_path)
    stderr = redact_text(result["stderr_bytes"].decode("utf-8", errors="replace"), temp_path)
    spawn_error = result["spawn_error"]
    if spawn_error is not None:
        spawn_error = redact_text(spawn_error, temp_path)
    return {
        "execution": {
            "command": executable,
            "args": args,
            "cwd": "<LAB_TMP>",
            "exit_status": result["exit_status"],
            "stdout": stdout,
            "stderr": stderr,
            "duration": result["duration"],
            "timestamp": result["timestamp"],
            "spawn_error": spawn_error,
        },
        "capture_truncated": (
            result["stdout_total_bytes"] > output_limit
            or result["stderr_total_bytes"] > output_limit
        ),
        "source_mode": "explicit",
    }
def oracle_matches(result: dict[str, Any], truth: dict[str, Any]) -> bool:
    return (
        result["exit_status"]["code"] == truth.get("expected_exit_code")
        and result["exit_status"]["signal"] == truth.get("expected_signal")
        and result["timed_out"] == truth.get("expected_timeout", False)
    )


def write_private_json(path: Path, value: Any) -> None:
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def read_oracle(suite: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    oracle = load_json(LAB_DIR / f"{suite}-oracle.json")
    if oracle.get("schema_version") != 1 or oracle.get("suite") != suite:
        raise LabError(f"invalid {suite} oracle header")
    truths = oracle.get("cases")
    if not isinstance(truths, dict) or set(truths) != {case["id"] for case in cases}:
        raise LabError(f"{suite} oracle ids do not exactly match the case manifest")
    for case_id, truth in truths.items():
        if (
            not isinstance(truth, dict)
            or not isinstance(truth.get("established_truth"), str)
            or not isinstance(truth.get("evidence_basis"), str)
            or not {"expected_exit_code", "expected_signal"}.issubset(truth)
            or any(truth.get(field) is not None and (not isinstance(truth[field], int) or isinstance(truth[field], bool)) for field in ("expected_exit_code", "expected_signal"))
            or not isinstance(truth.get("expected_timeout", False), bool)
        ):
            raise LabError(f"oracle entry {case_id} is incomplete or malformed")
    return truths



def create_run_dir(suite: str) -> Path:
    if ARTIFACT_ROOT.is_symlink():
        raise LabError("refusing to write artifacts through a symlink")
    suite_root = ARTIFACT_ROOT / suite
    suite_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved_suite_root = suite_root.resolve(strict=True)
    if not resolved_suite_root.is_relative_to(ARTIFACT_ROOT.resolve(strict=True)):
        raise LabError("artifact directory escapes the repository lab directory")
    run_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%S.%fZ") + f"-{os.getpid()}"
    run_dir = suite_root / run_id
    run_dir.mkdir(mode=0o700)
    return run_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-reserved", action="store_true", help="run the frozen held-out suite (never enabled by default)")
    options = parser.parse_args()
    suite = "reserved" if options.run_reserved else "dev"
    try:
        manifest_hash, oracle_hash = verify_seal(suite)
        manifest = load_json(LAB_DIR / f"{suite}-manifest.json")
        cases = validate_suite(manifest, suite)
        oracle = read_oracle(suite, cases)
        resolved = preflight_programs(cases)
        run_dir = create_run_dir(suite)
        records: list[dict[str, Any]] = []
        completed_results: dict[str, dict[str, Any]] = {}
        limits = manifest["resource_limits"]
        output_limit = manifest["capture_limit_bytes_per_stream"]
        with tempfile.TemporaryDirectory(prefix=".wtf-lab-", dir=run_dir) as temporary:
            temp_root = Path(temporary).resolve(strict=True)
            for case in cases:
                case_dir = temp_root / case["id"]
                case_dir.mkdir(mode=0o700)
                setup_case(case, case_dir)
                executable = resolved[case["program"]]
                result = run_once(executable, case["args"], case_dir, temp_root, float(case["timeout_seconds"]), limits, output_limit)
                completed_results[case["id"]] = result
                snapshot = snapshot_for(result, case_dir, executable, output_limit)
                snapshot_name = f"{case['id']}.snapshot.json"
                snapshot_path = run_dir / snapshot_name
                write_private_json(snapshot_path, snapshot)
                snapshot_hash = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
                records.append({
                    "case_id": case["id"],
                    "family": case["family"],
                    "program": case["program"],
                    "launch_attempts": 1,
                    "timed_out": result["timed_out"],
                    "exit_status": result["exit_status"],
                    "spawn_error": result["spawn_error"] is not None,
                    "truncated_streams": [
                        stream for stream in ("stdout", "stderr")
                        if result[f"{stream}_total_bytes"] > output_limit
                    ],
                    "observed_output_bytes": {
                        "stdout": result["stdout_total_bytes"],
                        "stderr": result["stderr_total_bytes"],
                    },
                    "duration": result["duration"],
                    "snapshot": snapshot_name,
                    "snapshot_sha256": snapshot_hash,
                })
                print(f"captured {case['id']}: status={result['exit_status']} timeout={result['timed_out']} truncated={snapshot['capture_truncated']}")
        if verify_seal(suite) != (manifest_hash, oracle_hash):
            raise LabError(f"{suite} frozen manifest or oracle changed during the run")
        for record in records:
            record["oracle_status_match"] = oracle_matches(
                completed_results[record["case_id"]], oracle[record["case_id"]]
            )
        postrecord = {
            "schema_version": 1,
            "suite": suite,
            "manifest_sha256": manifest_hash,
            "oracle_sha256": oracle_hash,
            "run_id": run_dir.name,
            "launch_attempts_total": sum(record["launch_attempts"] for record in records),
            "reserved_cases_executed": len(records) if suite == "reserved" else 0,
            "resource_limits": limits,
            "capture_limit_bytes_per_stream": output_limit,
            "cleanup": "case tempdirs removed by TemporaryDirectory before postrecord write",
            "cases": records,
        }
        write_private_json(run_dir / "postrecord.json", postrecord)
        mismatches = [record["case_id"] for record in records if not record["oracle_status_match"]]
        print(f"artifacts: {run_dir.relative_to(REPO_ROOT)}")
        print(f"cases: {len(records)}; oracle status mismatches: {len(mismatches)}")
        return 2 if mismatches else 0
    except (LabError, OSError, ValueError, KeyError) as exc:
        print(f"lab error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
