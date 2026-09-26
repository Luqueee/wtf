# WTF

WTF is a local-first terminal diagnostic tool. It investigates a failed command using its captured output or, in shell mode, reconstructs current evidence from bounded local probes. It reports a concise finding, evidence, and—when supported—a possible remedy. Local Laya ONNX ranking is enabled by default when there are unconfirmed hypotheses; WTF is not a conversational assistant.

## Status

Implemented: command execution and diagnosis, shell hooks for Bash/Zsh/Fish, diagnostic adapters for Cargo, Git, curl, Docker, and Linux systemd services, and default local Laya ONNX hypothesis ranking. The project is an early version (`0.1.0`); support is intentionally limited to recognized failure patterns and probes available on the host.

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
remains unconfirmed and Laya is not invoked. On the observed local run,
the two confirmed roots were correct, there were no false roots, the
three remaining model decisions abstained, and median eligible-model
overhead was about 0.69 s. This is not evidence of improved root-cause
accuracy over deterministic investigation.

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

Shell-mode reconstruction selects an adapter by executable basename, including when the command was recorded with an absolute path. Cargo, Git, curl, Docker, and Linux `systemctl start` use the existing bounded, fixed-argument probe catalogue. The original shell command is never replayed.

### Execute and diagnose a command explicitly

```sh
wtf -- cargo build
wtf -- curl http://127.0.0.1:8080
wtf -- systemctl start example.service  # Executes the requested start; diagnosis only inspects afterward
```

WTF executes the program directly, without a shell, captures stdout/stderr and exit status, then applies the output-based detectors and available investigation. It returns the diagnosed command's exit status. Add `--show-output` to print captured output alongside the diagnosis.

### Output options

```sh
wtf --verbose
wtf --json
wtf --fix
wtf --no-color
wtf --no-model
```

- `--verbose` includes captured metadata for explicit execution and investigation details such as the selected adapter, probe attempts, and hypotheses.
- `--json` prints the diagnosis as JSON, including optional investigation and adapter metadata.
- `--fix` includes a supported remedy when one is available; it does not apply the remedy.
- `--no-color` disables colored output. `NO_COLOR` is also respected.
- `--no-model` disables model inference and any model download; `WTF_NO_MODEL=1` does the same for isolated/offline environments.

### Local decision model (default)

When a failed diagnosis has unresolved candidate hypotheses, WTF downloads the pinned [Apache-2.0 Laya ONNX bundle](https://huggingface.co/receptron/laya-onnx/tree/68f27dfe5a27a54fb2b1fefc432f43f972e90868) on first use (approximately 1.7 GB) and runs inference locally. Subsequent runs reuse `${XDG_CACHE_HOME:-$HOME/.cache}/wtf/laya/68f27dfe5a27a54fb2b1fefc432f43f972e90868`; downloads are size/SHA-256 checked and atomically staged in a private directory. The first download requires HTTPS access to Hugging Face/CDN and enough disk space; no command, output, path, or diagnostic data is uploaded. A missing connection or failed verification leaves the deterministic diagnosis intact and reports `model_error` in JSON (or stderr in text mode). No manual setup or model flag is required:

```sh
wtf -- curl http://127.0.0.1:8080
```

`--no-model` (or `WTF_NO_MODEL=1`) avoids any model loading or downloading. `--model-dir DIR` instead loads an existing local bundle from that directory without downloading; it cannot be combined with `--no-model`. Model weights load per eligible invocation; there is no persistent model daemon yet. Only allowlisted category/hypothesis/probe-status labels reach inference, never captured command text, output, paths, or raw probe observations. Laya ranks existing non-rejected hypotheses alongside `unknown`; scores are **advisory**, never change `Confirmed`/`Likely`/`Unknown`, never choose probes or execute fixes, and do not establish a root cause. A candidate is displayed only at or above the 0.80 threshold; JSON includes `model_decision.probabilities` and nullable `preferred`. When no candidate exists or the deterministic diagnosis is confirmed, inference and download are skipped. The ONNX Runtime dependency may download its native runtime **at build time** unless it is cached. Model scores are not calibrated for this project's failure dataset.

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

- **Cargo:** offline structured compiler diagnostics are attempted only for plain `build`, `check`, `test`, or `run` in a simple local package, without detected workspace/build-script/procedural-macro complexity. Dependency build scripts and procedural macros can still execute, and `cargo check` writes build artifacts; do not run this diagnostic in an untrusted project as if it were read-only. A successful check does not establish why a test or run failed.
- **Git:** reads local status, branch, upstream, and remote names. It does not invoke push, pull, merge, rebase, or commit. Upstream diagnosis requires a committed branch and configured remote; remote URLs are not inspected.
- **curl:** never reissues the HTTP request, regardless of method. A captured
  curl `(6) Could not resolve host` error or a shell-recorded curl exit code 6
  yields `network/dns` with `Likely` status. Explicit execution probes only
  when the reported hostname matches the URL; output-free shell mode uses the
  URL's hostname. The bounded `getent hosts`/`dscacheutil` lookup can show
  current local non-resolution or successful resolution, but neither establishes
  why the original request failed. Missing, timed-out, truncated, or mismatched
  evidence never confirms a root cause. Other curl failures may check local
  listeners or host resolution instead.
- **Docker:** for an explicitly named container created by a failed `docker run`, inspects state and bounded logs; diagnostic probes never start or run containers. Separately, a captured daemon error for one explicit `--mount type=bind,source=/absolute/path,target=/absolute/path` can confirm a missing source only when its path exactly matches the command and bounded local `stat` also reports it missing. This mount failure happens before Docker creates the container, so a metadata-only shell record cannot verify it and remains unconfirmed. `-v`/`--volume`, ambiguous mounts, unsupported paths, a missing local probe, and a now-present source do not confirm this cause. The diagnosis's root and evidence omit the source path; explicit JSON still includes the originally captured command/output.
- **Docker published ports:** a captured `docker run -p HOST:CONTAINER` failure is eligible only for one explicit TCP/IPv4 mapping, Docker's pre-container exit code 125, and a daemon error naming that exact host address and port. A bounded `docker ps` probe must identify one running container with a conflicting published binding created before the failed command; only then does WTF confirm `container/port-conflict` and name the owner. Mismatched or ambiguous evidence, UDP, IPv6, ranges, host/none networking, and multiple mappings remain unknown. A non-Docker listener cannot be identified by this adapter, and output-free shell records cannot establish the daemon error. The diagnostic does not retry `docker run`.
- **Docker daemon socket:** a captured failure of `docker ps`, `run`, `info`, `images`, or `version` can confirm `container/daemon` only if the Docker error names a safe local Unix socket and a bounded local `stat` reports that exact path missing. Neither the root cause nor investigation evidence discloses the socket path; the original captured output remains in explicit JSON. A current socket, permission error, remote endpoint, explicit global context/host flag, mismatched path, or unavailable probe cannot confirm the cause. A later failing `docker ps` probe is not proof of what caused an output-free shell failure. WTF does not retry the failed Docker command.
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
- `scripts/e2e.sh`: end-to-end test helper.
- `SPEC.md`: project specification and phase behavior.
