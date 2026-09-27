#!/usr/bin/env python3
"""Freeze visible no-model reports by replaying development snapshots only."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from run import drain_limited, stop_process_group

MAX_REPORT_BYTES = 65536
CLI_TIMEOUT_SECONDS = 15


class FreezeError(Exception):
    pass


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FreezeError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise FreezeError(f"{path.name} is not a JSON object")
    return value


def write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def capture_cli(cli: Path, snapshot: Path) -> tuple[int, bytes, bytes, bool]:
    command = [str(cli), "--no-model", "--no-color", "--replay-snapshot", str(snapshot)]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TERM": "dumb", "NO_COLOR": "1", "WTF_NO_MODEL": "1"}
    process = subprocess.Popen(
        command,
        cwd=snapshot.parent,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    captured: dict[str, tuple[bytes, int]] = {}
    import threading

    readers = [
        threading.Thread(target=lambda key=key, pipe=pipe: captured.__setitem__(key, drain_limited(pipe, MAX_REPORT_BYTES)), daemon=True)
        for key, pipe in (("stdout", process.stdout), ("stderr", process.stderr))
    ]
    for reader in readers:
        reader.start()
    try:
        try:
            status = process.wait(timeout=CLI_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            stop_process_group(process)
            raise FreezeError(f"CLI replay timed out for {snapshot.name}")
    except BaseException:
        if process.poll() is None:
            stop_process_group(process)
        raise
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        raise FreezeError(f"CLI report pipe did not close for {snapshot.name}")
    truncated = any(total > MAX_REPORT_BYTES for _, total in captured.values())
    return status, captured["stdout"][0], captured["stderr"][0], truncated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wtf", required=True, type=Path, help="already-built wtf executable; this script never builds it")
    parser.add_argument("--run", required=True, type=Path, help="one scripts/lab/artifacts/dev/run-* directory")
    args = parser.parse_args()
    try:
        cli = args.wtf.resolve(strict=True)
        run_dir = args.run.resolve(strict=True)
        if not cli.is_file() or not os.access(cli, os.X_OK):
            raise FreezeError("--wtf must name an executable file")
        if run_dir.parent.name != "dev" or not run_dir.name.startswith("run-"):
            raise FreezeError("baseline freezing accepts development artifacts only")
        postrecord = read_json(run_dir / "postrecord.json")
        if postrecord.get("suite") != "dev" or not isinstance(postrecord.get("cases"), list):
            raise FreezeError("postrecord is not a development run")
        reports_root = run_dir / "baseline-no-model"
        reports_root.mkdir(mode=0o700)
        report_records: list[dict[str, Any]] = []
        for case in postrecord["cases"]:
            case_id = case.get("case_id")
            snapshot_name = case.get("snapshot")
            if not isinstance(case_id, str) or not isinstance(snapshot_name, str) or Path(snapshot_name).name != snapshot_name:
                raise FreezeError("invalid snapshot reference in postrecord")
            snapshot_path = run_dir / snapshot_name
            if hashlib.sha256(snapshot_path.read_bytes()).hexdigest() != case.get("snapshot_sha256"):
                raise FreezeError(f"snapshot checksum mismatch: {snapshot_name}")
            snapshot = read_json(snapshot_path)
            if snapshot.get("source_mode") != "explicit" or not isinstance(snapshot.get("execution"), dict):
                raise FreezeError(f"invalid replay snapshot: {snapshot_name}")
            status, stdout, stderr, truncated = capture_cli(cli, snapshot_path)
            report_path = reports_root / f"{case_id}.txt"
            write_private(report_path, stdout + stderr)
            report_records.append({
                "case_id": case_id,
                "snapshot_sha256": case["snapshot_sha256"],
                "report": report_path.name,
                "cli_exit_status": status,
                "report_truncated": truncated,
            })
            print(f"froze {case_id}: CLI exit={status} report={report_path.relative_to(run_dir)}")
        baseline = {
            "schema_version": 1,
            "suite": "development",
            "mode": "no-model visible replay",
            "model_enabled": False,
            "cli": str(cli),
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "cases": report_records,
        }
        write_private(reports_root / "postrecord.json", (json.dumps(baseline, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        print(f"baseline: {reports_root.relative_to(run_dir)}")
        return 0
    except (FreezeError, OSError, ValueError, KeyError) as exc:
        print(f"baseline error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
