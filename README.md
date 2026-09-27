# WTF

WTF's goal is to explain a failed terminal command **from its captured error output, regardless of the executable**: what likely happened, what the evidence actually supports and what to check next. It is not meant to become a catalogue of adapters. A tentative cause is not a proven root; output-free failures may remain unknown. [SPEC.md](SPEC.md) defines the product and its [nine-hour generic-diagnosis task](SPEC.md#9-autonomous-research-focus).

## Status

The CLI produces a generic result for unfamiliar programs. An **opt-in** local GGUF interpreter can suggest a tentative explanation, missing fact and manual next check from bounded redacted output, irrespective of executable name. It does not confirm historical causes, run model-proposed commands, or replace the deterministic fallback. **Do not enable it by default:** the reserved within-project sample found at most 1/7 new supported tentative explanations and 1/7 false MISSING claims; among five informative development failures, both Phi and Qwen treated a deliberately misleading permission message as real. See [the three-model tournament](docs/model-candidates.md), [the frozen protocol](docs/generic-freeze.json), and [all seven reserved paired reports](docs/reserved-evaluation.md). Generalization outside the corpus is not established.

A second [fresh six-family paired evaluation](docs/followup-evaluation.md), frozen before execution after the generic-probe/live-capture cutover, found **0/6 supported new explanations or discriminating NEXT**, five invalid model evidence IDs and one misleading distinction between an invalid *date format* and an invalid *calendar value*. That historical run also exposed `diff` exit 1 being called a failure; unknown nonzero exits now report a neutral result and preserve the status. Neither evaluation supports default model activation.

A later [development-only evidence-ID prompt experiment](docs/lab.md#rejected-evidence-id-prompt-experiment-development-only) removed Granite's five fabricated-ID fallbacks but displayed a false permission/sudo claim, while Phi lost two valid responses without eliminating its false claim. The experiment was reverted; strict validation and the opt-in default are unchanged.

A separately sealed [semantic development comparison](docs/lab.md#semantic-development-comparison-not-held-out) covered four new failure conditions and a success control. All four Phi responses cited valid IDs, but **0/4 added a supported explanation or discriminating NEXT**, while two introduced false causes and two false MISSING claims. This is development evidence, not a new held-out promotion result; inference remains opt-in.

`wtf -- PROGRAM` captures bounded output; `wtf --live -- PROGRAM` and the opt-in installed `wtfr PROGRAM` additionally show the child's raw output while diagnosing it. Bare `wtf` after the shell hook still retains bounded redacted **metadata only**, not stdout/stderr; it cannot interpret an unseen error message. Cargo, Git, curl, Docker and systemd adapters remain narrow optional evidence specializations, not a requirement for a basic unfamiliar-command report. JSON `schema_version: 1` contains a structured `report`. See [SPEC.md](SPEC.md) for target semantics.

## Requirements

- Rust toolchain with Cargo
- Bash, Zsh, or Fish for shell integration
- Linux or macOS for currently implemented platform-specific probes; the specification's initial target is Linux
- Optional local tools such as `git`, `cargo`, `curl`, `docker`, and (on Linux) `systemctl`/`journalctl` for relevant diagnostics

Python is not needed to run WTF.

The `Makefile` provides the common workspace tasks:

```sh
make help
make build
make check
make test
make calibration                  # Isolated CLI, shell, and probe matrices with metrics
make report-eval                  # Isolated generic-report acceptance corpus and metrics
make fmt-check
make lint
```

`make fmt` applies formatting. `make test` runs the workspace suite, including isolated fake-Docker E2E; real Docker E2E is opt-in because it uses the shared Docker daemon:

```sh
make e2e                         # Cargo, Git, curl, isolated systemd and Docker bind/port scenarios
make e2e E2E_FILTER=cargo_build_failure
make e2e-docker                  # Docker scenarios
make e2e-all                     # Both E2E groups
```

Real Docker E2E requires a local Unix Docker endpoint and a cached `busybox:latest` image; it never pulls. The failed-container recovery and rejected-bind tests disable container networking. The published-port test instead uses the default bridge and transiently publishes one TCP port on `127.0.0.1` (set `WTF_E2E_PORT` to choose it). Tests give their temporary containers unique names and an ownership label; cleanup removes only containers with the matching label.

The reproducible calibration sample covers the original 29 scenarios, five
isolated DNS CLI cases, three core DNS tests, and 12 CLI cases for systemd,
Docker bind mounts, Docker published ports, and the local Docker daemon.
Each of those four families has matching, contradictory, and unavailable evidence. The sample spans
explicit execution, Bash-hook reconstruction, and scripted multi-probe paths.
Run:

```sh
make calibration
```

The CLI matrices report category/status/root matches, false confirmations,
unknowns, probe counts, and median wall time. In the 15-case general CLI
sample, all 15 outcomes matched fixture truth, four remained unknown, and
none was falsely confirmed. In the 12-case service/container sample, all
12 matched, eight remained unknown, none was falsely confirmed, and 13 probes
were attempted. The core matrix reports ten probe paths, including four
corroborated causes and 22 scripted probe attempts. DNS fixtures cover
successful, failed, unavailable, and mismatched local lookups. These are
regression results, **not** an estimate of accuracy on real-world failures or
20–30 distinct failure families. Calibration never uses the shared Docker
daemon; real Docker E2E remains opt-in.

The generic-report acceptance corpus runs separately from adapter calibration:

```sh
make report-eval
```

It exercises isolated command families with externally established fixture facts, including unfamiliar executables, shell metadata without output, contradictory/unavailable probes, truncation, signal and hostile output. It checks claim provenance and time scope, specific or omitted next steps, a three-row limit, output sanitization, no replay and preserved exit status. Reported coverage and latency describe only those fixtures; a later probe is never an oracle for the original failure. The suite does not contact live services, use a shared Docker daemon or download a model. Real-world readability and next-step utility still need observation with users; the fixture corpus cannot establish those by itself.
In the current local run: 12 cases across nine fixture families, **11/11** displayed observations matched their recorded execution/probe source, and 3/3 unfamiliar failures received a report (one without original evidence). No NEXT was displayed (0/0 supported); this corpus therefore does **not** establish next-step utility. There were two independently supported confirmations and four bounded read-only probe attempts; the largest default report had **three** claim rows. Median CLI wall time was **12.447 ms**, p95 **311.066 ms**. These are acceptance-fixture measurements, not real-world accuracy, calibrated probabilities or user-rated usefulness.
Additional local smoke observations used real `false`, `cat` on a missing file and a directory, `git -C` outside a repository, and `curl` to loopback port 1. These are author-controlled failures, **not** a user study or a representative sample of user workflows. They exposed a misleading generic MISSING row when stderr already gave a useful error, and unrelated Git status/diff probes when `git -C` targeted another directory. Both are corrected and covered by regression tests; unrelated working-tree state is no longer presented as evidence for that Git failure. The loopback refusal offered a port-specific NEXT, but its usefulness to another person remains unmeasured.

An opt-in, offline paired evaluation compares the same isolated evidence
with `--no-model` and an already cached Laya bundle. It is ignored by normal
tests and never downloads the model:

```sh
WTF_MODEL_EVAL_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/wtf/laya/68f27dfe5a27a54fb2b1fefc432f43f972e90868" \
  cargo test --locked -p wtf --test model_evaluation -- --ignored --nocapture
```

The seven-case exploratory sample has two confirmed fixture roots, one
scripted quota failure with a known alternative cause, and three cases
eligible for Laya. In the quota case, Laya initially advised
`filesystem_full` at 0.854 despite current block and inode usage being
below full. Adding those facts to its input did not reliably remove that
advice, so the input experiment was discarded. The investigation now
rejects that hypothesis only when complete `df -P` and `df -Pi` reports
for the same mount both show usage below full. The quota case then
remains unconfirmed and Laya is not invoked. The smoke sample now separates filesystem fixtures from held-out DNS/connection fixtures. On the latest local paired run, both independently known roots remained correct, no unsupported root was confirmed, all three eligible advisories abstained, and median eligible-model overhead was 0.762 s. This is not evidence of better root-cause accuracy or generic-report utility than the deterministic baseline; model inference remains opt-in.

Run the CLI from the workspace:

```sh
cargo run -p wtf -- --help
```

To make `wtf` available in your `PATH`, install the binary:

```sh
cargo install --path crates/wtf-cli
```

## Usage

### Diagnose the last failed shell command

Install the hook from an interactive supported shell, then start a new shell:

```sh
wtf install
```

After a command fails, run:

```sh
wtf
```

The hook stores bounded, redacted command metadata—not stdout or stderr—and does not run diagnoses or probes automatically. The saved failure is available for 15 minutes by default. Set `WTF_FAILURE_TTL_SECS` to change that lifetime. `wtf uninstall` removes the WTF-owned hook. Re-running either install or uninstall is safe.

Hooks are written to `~/.bashrc`, `${ZDOTDIR:-$HOME}/.zshrc`, or `${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/wtf.fish`. They require the shell's interactive startup configuration and a usable `wtf` executable. Fish's event hook requires an interactive terminal. Multiline and heredoc commands are not recorded. Common credential-like arguments are redacted, but do not rely on redaction for arbitrary secrets.

Shell-mode reconstruction can use safe generic checks without requiring an adapter; specialized Git, curl, Docker and Linux `systemctl` adapters may add target-specific bounded observations. Cargo build/check commands are never run as automatic probes: build scripts and procedural macros can change state. The original shell command is never replayed.

For a failed local `curl` connection (including commands using `--noproxy`), WTF can inspect current TCP listeners when `ss` is available. That observation is about the inspection time, not proof of the connection's earlier cause. A plain `curl` failure does not trigger Docker discovery or an automatic NEXT step to identify a service on an arbitrary port; unavailable checks leave the cause unconfirmed.

For a failed `cat` with one literal absolute path, shell mode can run a bounded local `stat` check and report whether that path exists **at inspection time**. It does not establish why `cat` failed earlier; paths with shell expansions, multiple operands, or ambiguous syntax are not checked.

After installation, the opt-in `wtfr PROGRAMA [ARG ...]` function is available in a new Bash, Zsh, or Fish session. Unlike bare `wtf`, it executes that explicit argv **once**, displays the child's stdout/stderr as raw bytes while the child runs, and appends a diagnosis using only bounded, redacted excerpts. It does not intercept other commands or persist their output; the metadata hook ignores `wtfr` to avoid a duplicate recent-failure record. Raw live output is **not redacted** before display; do not use this mode when exposing the program's output to the terminal would be unsafe.

### Execute and diagnose a command explicitly

```sh
wtf -- cargo build
wtf -- curl http://127.0.0.1:8080
wtf -- systemctl start example.service  # Executes the requested start; diagnosis only inspects afterward
wtf --live -- my-tool arg            # Opt-in live output even without shell installation
```

WTF executes the program directly once without a shell, captures bounded stdout/stderr and exit status, then builds a report from the captured result and eligible current observations. It returns the command's exit status (for a signaled child, conventional `128 + signal`). Captured output is not printed by default, even for success; `--show-output` explicitly prints bounded, redacted, escaped stdout/stderr after execution. `--live` instead forwards raw stdout/stderr while the child runs, retains only bounded excerpts for diagnosis, and cannot be combined with `--json`, `--show-output` or replay. Bare `wtf` cannot recover shell-mode output. Standard input is inherited, but output is piped in both explicit modes: interactive full-screen/TTY programs are not compatible; ordinary binary bytes pass through `--live`, while diagnostic excerpts are decoded lossily. Shell builtins, pipelines, redirects, aliases, expansions and compound commands are not interpreted by `wtfr`; invoke those through a deliberate shell yourself if needed, accepting its own semantics. A command with no general timeout can hang independently of the 30-second model deadline; invoke only commands you intended to run.

Treat `--live`/`wtfr` as **terminal presentation**, not a transparent Unix pipe: the human-readable diagnosis is appended to stdout after the child's bytes. Redirecting or piping it into a binary consumer will contaminate that stream; run the original program directly when exact pipeline output and SIGPIPE semantics matter. Live forwarding cannot redact a child's terminal output or guarantee terminal-style interaction.

### Output options

```sh
wtf --verbose
wtf --json
wtf --fix
wtf --no-color
wtf --model        # opt-in download and local advisory ranking
wtf --model-dir DIR # opt-in existing local bundle
wtf --interpreter-model /private/cache/model.gguf --interpreter-runtime /private/cache/llama -- unfamiliar-tool arg
```

- Interactive terminals show a compact two-column report: RESULT, OBSERVED, MISSING, NEXT and CHECKS share aligned label and text columns, with color on the status and semantic labels. `✓` marks success, `✗` a diagnosed nonzero outcome and `?` an unknown outcome; a nonzero status such as `diff` exit 1 is not automatically labeled a failure. Plain text uses the same layout; JSON retains its structure. Output excerpts are data, not instructions; current probes are labeled “Now.”
- `--verbose` lists provenance, capture completeness, probe attempts and bounded observations. It must be requested on that invocation; WTF does not retain the original output for later inspection.
- `--json` includes `schema_version: 1` and `report` with `source_mode`, `capture`, timestamps, `command_label`, `outcome`, `summary`, `claims` (each with `kind`, `text`, `source`) and `checks`. The legacy top-level `summary` also uses neutral wording for an undiagnosed nonzero result; it does not turn `diff` exit 1 into a failure. Other diagnostic fields retain specialized details; do not infer historical causes from a probe alone.
  The `report` is the versioned claim contract. Legacy diagnostic fields may contain bounded excerpts, paths and command metadata; recognizable credentials are redacted on a best-effort basis, **not** guaranteed removed. Treat JSON and `--verbose` as potentially sensitive; review before storing or sharing. Captured command text and entity names are forced to a single safe display line when they could inject controls or headings.
- `--fix` includes a supported suggestion when one is available; it never applies it.
- `--no-color` disables color. `NO_COLOR`, non-interactive output, and `TERM=dumb` also render plain text.
- `--no-model` and `WTF_NO_MODEL=1` suppress inference, including when `--model` was selected.


### Generic local interpretation (opt-in)

`--interpreter-model GGUF` uses a **locally installed** llama.cpp unified `llama` executable (`--interpreter-runtime PATH` overrides it). For each invocation WTF starts a local model server on a Unix socket in a private temporary directory, sends a sanitized chat-completion request, then stops that server. No model weights are downloaded at runtime and no inference is sent to a hosted service. The model sees an excerpted version of captured output and up to three safe probe observations, never an executable tool interface. The engine validates JSON, evidence IDs, lengths and some certainty/temporal language; malformed, unavailable or timed-out inference leaves the no-model report unchanged. Redaction is heuristic: do not diagnose commands containing unknown secrets. Inference is opt-in; a model's POSSIBLE is never an OBSERVED historical cause. `--verbose` exposes evidence references and failures; `--json` adds `interpretation` or `interpretation_error` when selected. `--no-model` disables inference. The visible default may contain four rows when output, possibility, missing fact and NEXT are all present.

The interpreter now requests llama.cpp `--device none` for **every** opt-in GGUF, avoiding GPU model offload even for unmeasured weights. The earlier three Q4_K_M GPU peaks below 4 GB were measurements, **not** a hard cap; historical GPU comparisons are kept in [`docs/model-candidates.md`](docs/model-candidates.md). A supported runtime must honor CPU-only execution; this does not cap host RAM, protect against a malicious user-specified runtime, or control VRAM consumed by other processes. CPU-only Phi inference is slower (~9.3 s for a forced 192-token response in one post-freeze measurement). No model is enabled by default.

For reproducing the isolated evaluation, see [laboratory instructions](docs/lab.md) and [evaluation criteria](docs/generic-evaluation.md). `--replay-snapshot` is an internal evaluation switch; it never runs commands/probes, and is evidence-equivalent only for fixtures with zero eligible probes. It is not a normal capture interface.

### Local decision model (opt-in)

The default report does not load or download a model. `--model` opts into the pinned [Apache-2.0 Laya ONNX bundle](https://huggingface.co/receptron/laya-onnx/tree/68f27dfe5a27a54fb2b1fefc432f43f972e90868) on eligible unconfirmed cases; first use downloads approximately 1.7 GB to `${XDG_CACHE_HOME:-$HOME/.cache}/wtf/laya/68f27dfe5a27a54fb2b1fefc432f43f972e90868`. Downloads are size/SHA-256 checked and atomically staged in a private directory. `--model-dir DIR` instead uses an existing bundle without downloading. No captured command, output, path or raw probe observation is sent to inference: only allowlisted labels reach the local model. It ranks existing hypotheses alongside `unknown`; scores are advisory, never establish a cause, never select probes or apply a fix. JSON includes `model_decision` or `model_error` when requested; text shows the advisory/error only under `--verbose`. The default report stands independently of model availability.

### Offline Laya training (separate workspace crate)

`wtf-train` is an offline training tool, separate from `wtf-core` and the
runtime `wtf` CLI. It validates a versioned JSONL file of next-safe-probe
decisions and, when explicitly requested, fine-tunes Laya from a **local
PyTorch/Safetensors checkpoint**, calibrates on a separate family-disjoint
validation file, and exports an ONNX bundle. It does not build a dataset or
download weights, install Python packages, send examples to a service, or
change the diagnostic CLI:

```sh
cargo run -p wtf-train -- validate /path/to/decisions.jsonl
cargo run -p wtf-train -- train \
  --train /path/to/train.jsonl --validation /path/to/validation.jsonl \
  --checkpoint /path/to/laya-pytorch --output /path/to/new-training-output \
  --python /path/to/python
```

Each input record has schema `wtf.probe-choice.v1`, an opaque `example_id`
and `family_id`, a payload-free `state` (category, hypothesis IDs/statuses,
probe IDs/outcomes), at least two distinct engine-offered safe `ProbeId`s,
and a `target` equal to one offer or `abstain`. The validator rejects
`CargoCheck`, unknown fields, raw diagnostic text, invalid targets, repeated
IDs, and overlapping families between training and validation. Validation
can check the record's shape, **not** independently establish that a probe
was ready in the original failure; the producer must use engine-authorized
choices.

Training needs a separate Python environment with PyTorch, Transformers,
Safetensors, NumPy, ONNX, ONNX Script, and ONNX Runtime, plus the complete
local [Apache-2.0 Laya checkpoint](https://huggingface.co/convaiinnovations/laya)
(`model.safetensors`, `rl_agent_config.json`, `rl_common.py`, `encoder/`,
`tokenizer/`). The existing downloaded ONNX bundle is **inference-only**;
it cannot serve as this checkpoint. The trainer requires local artifacts
and forces Hugging Face offline mode. A trained next-probe model is **not
compatible with the current hypothesis-ranking task** in `wtf --model-dir`;
model-guided probe execution is not implemented and remains subject to the
evaluation and safety gate in `SPEC.md` §8.

The three existing JSONL examples all target `abstain`; they cannot
train a useful probe chooser. Opt-in offline experiments:

```sh
cargo run --locked -p wtf-train -- replay-disk
cargo run --locked -p wtf-train -- replay-git
cargo run --locked -p wtf-train -- replay-unix-socket  # Linux, requires stat and ss
```

Disk uses scripted safe-probe outputs. Git captures fixed local probes
from isolated repositories without running the synthetic failed `git push`.
The Unix-socket experiment uses local temporary listeners and compares
current observations only; its probe pair is **not** offered by the runtime
engine, and changing socket state makes observations inconsistent. None
produces training labels or changes the runtime CLI. See
[`docs/training-data.md`](docs/training-data.md) for fixture provenance,
replay boundaries, the data contract and the evidence gate.

If no valid recent shell failure exists, WTF reports that no recent failed command was found. Successful commands and WTF invocations do not replace the last recorded failure.

`Confirmed` means a direct OS execution failure or a cause corroborated by
reconstructed/local evidence. An error message alone identifies a symptom:
without corroboration it is `Likely`, even when the message names a path,
port, or permission error. `Unknown` means no supported failure pattern was
identified. A `Likely` diagnosis may suggest a check, but does not claim the
root cause is established.

## Diagnostic scope and safety

WTF gathers bounded evidence and does not upload commands, logs, source code,
environment variables, or paths to an external service. Probe commands are
selected from a fixed catalogue, bounded by output, timeout, and investigation
budget. Shell hooks persist only command metadata; probe output is transient.
A host-resolution probe can query the machine's configured DNS resolver with
the target hostname; it is not guaranteed offline.

- **Cargo:** explicitly requested `wtf -- cargo build` runs once, as requested by the user. Shell reconstruction never runs `cargo check`, `cargo build` or project code automatically; without captured compiler output it remains unconfirmed. Compilation can execute build scripts and procedural macros and write artifacts, so it is not a read-only investigation probe.
- **Git:** reads local status, branch, upstream, and remote names only for eligible metadata-only Git adapter cases. It does not invoke push, pull, merge, rebase, or commit. Upstream diagnosis requires a committed branch and configured remote; remote URLs are not inspected. Captured failures with `git -C` do not probe the surrounding working directory: it may be a different repository from the requested target.
- **curl:** never reissues the HTTP request, regardless of method. A captured
  curl `(6) Could not resolve host` error or a shell-recorded curl exit code 6
  yields `network/dns` with `Likely` status. Explicit execution probes only
  when the reported hostname matches the URL; output-free shell mode uses the
  URL's hostname. The bounded `getent hosts`/`dscacheutil` lookup can show
  current local non-resolution or successful resolution, but neither establishes
  why the original request failed. Missing, timed-out, truncated, or mismatched
  evidence never confirms a root cause. Other curl failures may check local
  listeners or host resolution instead.
- **Docker:** for an explicitly named container created by a failed `docker run`, inspects state and bounded logs; diagnostic probes never start or run containers. Separately, a captured daemon error for one explicit `--mount type=bind,source=/absolute/path,target=/absolute/path` can confirm a missing source only when its path exactly matches the command and bounded local `stat` also reports it missing. This mount failure happens before Docker creates the container, so a metadata-only shell record cannot verify it and remains unconfirmed. `-v`/`--volume`, ambiguous mounts, unsupported paths, a missing local probe, and a now-present source do not confirm this cause. The diagnosis's root and evidence omit the source path; explicit JSON diagnostic fields may include a bounded, best-effort-redacted excerpt from the captured output and command.
- **Docker published ports:** a captured `docker run -p HOST:CONTAINER` failure is eligible only for one explicit TCP/IPv4 mapping, Docker's pre-container exit code 125, and a daemon error naming that exact host address and port. A bounded `docker ps` probe must identify one running container with a conflicting published binding created before the failed command; only then does WTF confirm `container/port-conflict` and name the owner. Mismatched or ambiguous evidence, UDP, IPv6, ranges, host/none networking, and multiple mappings remain unknown. A non-Docker listener cannot be identified by this adapter, and output-free shell records cannot establish the daemon error. The diagnostic does not retry `docker run`.
- **Docker daemon socket:** a captured failure of `docker ps`, `run`, `info`, `images`, or `version` can confirm `container/daemon` only if the Docker error names a safe local Unix socket and a bounded local `stat` reports that exact path missing. Neither the root cause nor investigation evidence discloses the socket path; explicit JSON may include a bounded, best-effort-redacted excerpt from the captured output. A current socket, permission error, remote endpoint, explicit global context/host flag, mismatched path, or unavailable probe cannot confirm the cause. A later failing `docker ps` probe is not proof of what caused an output-free shell failure. WTF does not retry the failed Docker command.
- **systemd (Linux):** only a failed `systemctl start UNIT` with one explicit, safely named service is inspected. A bare name is normalized to `.service`; flags, user/remote units, and multiple units are unsupported. `systemctl show` must identify the exact unit: `LoadState=not-found` confirms a missing unit; a loaded, failed unit is only `Likely` until a recognized cause in the bounded journal for the same invocation and failure-time window corroborates it. Missing, stale, mismatched, truncated, or unavailable evidence never confirms a cause. The diagnostic runs read-only `systemctl show` and `journalctl` probes, never a second start. Explicit `wtf -- systemctl start ...` **does** execute the user's start request once; shell-mode `wtf` does not.
- **Filesystem:** a disk-space error requires `df -P` evidence; when blocks
  are not full, `df -Pi` may establish inode exhaustion. Complete, matching
  reports showing both block and inode capacity below full reject a *current*
  full-filesystem hypothesis, without establishing why the original command
  failed (for example, a quota could still be exhausted). Incomplete,
  mismatched, truncated, or unavailable probes cannot reject or confirm it.

Unavailable tools, timeouts, malformed or unsupported data, and inconclusive probes produce an unknown or unconfirmed result rather than a fabricated cause. An unknown result is an expected outcome when current evidence is insufficient. WTF does not automatically change system state or apply fixes.

## Workspace layout

- `crates/wtf-core`: command capture, normalization, entity extraction, deterministic detectors, probes, adapters, and diagnosis/investigation logic.
- `crates/wtf-cli`: CLI, shell integration and secure recent-failure state, plus integration tests.
- `crates/wtf-train`: offline dataset validation and Laya training/export; not linked into the runtime CLI.
- `scripts/e2e.sh`: end-to-end test helper.
- `SPEC.md`: target product contract, migration boundary, and acceptance criteria; this README documents current CLI behavior.
