# Offline failure laboratory

The lab builds replay snapshots from real local system executables, freezes a no-model CLI baseline, and supports paired replay with the local generic interpreter. Case fixtures are isolated from the repository state; the harness does not use a shared Docker daemon, a shell, network requests, or external inference.

## Reproduce the development run

From the repository root:

```sh
python3 scripts/lab/run.py
```

The default runs only `scripts/lab/dev-manifest.json`. The runner verifies the pinned manifest and independent oracle SHA-256 seals before launch, validates fixture paths, and preflights every executable under `/usr/bin` or `/bin`. Every case gets a new mode-`0700` temporary working directory and a minimal environment; it invokes the checked-in argv directly once, with stdin closed. Two readers drain stdout/stderr concurrently. They retain no more than 4 KiB per stream and keep the truncation marker/flag while discarding excess bytes.

Each command has RLIMIT_CPU soft/hard 3/4 seconds, RLIMIT_AS 512 MiB, RLIMIT_FSIZE 8 MiB, RLIMIT_NOFILE 64, and core dumps disabled. The wall limit is per case (3 seconds except the deliberate `sleep` timeout at 0.25 seconds). A timed-out process group is killed; the `TemporaryDirectory` context removes only the lab-owned case directories. These controls bound fixture processes but are not a hardened kernel sandbox; run only the reviewed manifests.

The command prints a new artifact path such as:

```text
scripts/lab/artifacts/dev/run-20260926T220628.201559Z-1376969/
```

Each `<case-id>.snapshot.json` is a redacted, bounded `CommandExecution` replay artifact:

```json
{"execution":{"command":"/usr/bin/cp","args":["--","missing-input.txt","copied.txt"],"cwd":"<LAB_TMP>","exit_status":{"code":1,"signal":null},"stdout":"","stderr":"...","duration":{"secs":0,"nanos":1},"timestamp":{"secs_since_epoch":0,"nanos_since_epoch":1},"spawn_error":null},"capture_truncated":false,"source_mode":"explicit"}
```

Temporary paths become `<LAB_TMP>` and common credential forms are redacted before persistence. Raw output is not persisted. Snapshots and postrecords are mode `0600` within mode-`0700` artifact directories. The separate pre-authored oracle is never included in the snapshot or CLI/model input; the postrecord records outcomes, resource limits and snapshot SHA-256 digests. The current development run completed 9 exactly-once launches with zero oracle status mismatches; its temporary case directories were removed.

## Freeze the no-model baseline

Use an already-built CLI that supports the hidden eval-only replay flag. This does not build the CLI or execute captured commands/probes:

```sh
python3 scripts/lab/freeze_baseline.py \
  --wtf target/debug/wtf \
  --run scripts/lab/artifacts/dev/<run-id>
```

The freezer accepts only `dev` runs, checks each snapshot digest, and records the ordinary `--no-model --no-color --replay-snapshot` visible report per case. The successful no-model baseline for the current run is under `scripts/lab/artifacts/dev/run-20260926T220628.201559Z-1376969/baseline-no-model/`. Its postrecord has all 9 snapshot digests and the replayed CLI exit outcomes; the `sleep` snapshot correctly maps signal 9 to CLI status 137. A stale binary that reports `Invalid local replay snapshot` is not a baseline; rebuild only through the integration owner's normal validation flow, then run the freezer again.

## Paired no-model / interpreter evaluation

The evaluator checks the source run's manifest and oracle seals, case list, exactly-once source launch counts and each per-case snapshot hash before starting any CLI replay. It accepts a local GGUF and a local llama.cpp unified `llama` executable; it does not download weights. For each same snapshot it calls the CLI four times: no-model visible, no-model JSON, interpreter visible, and interpreter JSON. Each invocation uses `--replay-snapshot`, so it does not execute the recorded command or run probes. It captures latency/outcome, bounded stdout/stderr, JSON validity and report digests. Private reports and an `evaluation-postrecord.json` are written below that source run's `evaluations/<run-id>/` directory.

Development evaluation:

```sh
python3 scripts/lab/evaluate.py \
  --wtf target/debug/wtf \
  --run scripts/lab/artifacts/dev/<run-id> \
  --model /local/path/model.gguf \
  --runtime /local/path/llama
```

The default wall timeout is 180 seconds per CLI replay; set `--timeout-seconds` between 5 and 900 to change it. Captured report output is capped at 256 KiB per stream. Each replay gets a private temporary HOME/TMPDIR which is removed immediately afterward. The local inference process is wall-bounded and process-group-killed on timeout; the fixture resource limits above apply to source commands, not to the model runtime.

## Rejected evidence-ID prompt experiment (development only)

After the historical reserved and follow-up runs, an experimental prompt listed the exact available evidence IDs, removed timestamps from model input, and used `generic-evidence-2`. It was replayed against the **same nine development snapshots**, not against a new held-out set. [Phi reports](../scripts/lab/artifacts/dev/run-20260926T220628.201559Z-1376969/evaluations/run-20260927T100124.392066Z-253581/) and [Granite reports](../scripts/lab/artifacts/dev/run-20260926T220628.201559Z-1376969/evaluations/run-20260927T100315.098951Z-262487/) include per-case JSON, visible output, statuses and elapsed times; no fixture command or probe was rerun.

Granite's five informative cases went from **5/5 invalid evidence IDs** in the original development run to **0/5 invalid IDs**, but all five newly displayed model claims. Its adversarial fixture falsely suggested a permission/sudo problem, and its tar explanation was only a program path. Phi had **0/5 invalid IDs** both before and after; its accepted responses fell from **5/5 to 3/5** (two `unsupported suggestion` fallbacks), and the adversarial fixture still asserted a false missing-program explanation. Neither candidate added a demonstrated, independently supported explanation or discriminating check. An ID-valid model statement is not necessarily true: the prompt change was **reverted**, leaving `generic-evidence-1` and strict rejection of invalid IDs in place. These records are a development comparison of a rejected binary, not a current release measurement or fresh held-out result.

## Reserved suite

Development and reserved families are distinct. The reserved manifest and independent oracle were sealed before any reserved execution:

- Manifest SHA-256: `4a2d91d3c2497e3585998842c49d1534bf6efb61cac258aa53c153e6192c5c2c` (`scripts/lab/reserved-manifest.sha256`)
- Oracle SHA-256: `73a8a81c1ce5757fdd012288b64a2a7ad0a19fb8cb689cdd4e118ecb4c2493cc` (`scripts/lab/reserved-oracle.sha256`)

The runner checked both seals before and after its historical run; the evaluator independently checked them against the source postrecord. The original reserved cases **were run once** after the original [configuration freeze](generic-freeze.json); their [paired results](reserved-evaluation.md) found no supported promotion. Do not use those seven cases to tune another prompt/model and claim a fresh held-out result.

Historical reserved-suite invocation (re-running it cannot create a new held-out evaluation):

```sh
python3 scripts/lab/run.py --run-reserved
python3 scripts/lab/evaluate.py \
  --wtf target/debug/wtf \
  --run scripts/lab/artifacts/reserved/<run-id> \
  --model /local/path/model.gguf \
  --runtime /local/path/llama \
  --allow-reserved
```

## Independent follow-up after shell/core changes

The six `followup` fixture families are disjoint from both original suites. Their independently authored manifest and oracle have separate SHA-256 seals (`scripts/lab/followup-{manifest,oracle}.sha256`). `followup.py` reuses the original runner's preflight, isolated single-launch execution, bounded redaction and private snapshots without editing the original frozen runner/evaluator. The **new** CLI binary/model/runtime and scoring criteria were [frozen before these cases ran](followup-freeze.json). To reproduce the mechanics (not create another fresh held-out result):

```sh
python3 scripts/lab/followup.py --run-once
python3 scripts/lab/followup.py --paired scripts/lab/artifacts/followup/<run-id> \
  --wtf target/debug/wtf --model /local/path/model.gguf --runtime /local/path/llama
```

Paired replay invokes no source command or probe: four CLI renderings per saved snapshot, with status, latency, full visible and JSON reports under `evaluations/`. It must report oracle exit-status mismatches rather than revising the sealed oracle or rerunning a fixture. Follow-up scoring uses the original [criteria](generic-evaluation.md): a paraphrase or an evidence-ID-valid but false claim is **not** an improvement. The original GPU tournament was measured before the current CPU-only `--device none` policy; do not compare its GPU latency as if it described the follow-up CLI.

The [observed six-case paired adjudication](followup-evaluation.md) links every report; the single source run is under `scripts/lab/artifacts/followup/run-20260927T092707.709601Z-182557/`. All six preauthored status predictions matched. The old seven reserved cases were **not** rerun or used to choose an improved prompt.

