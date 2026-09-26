# WTF

## 1. Overview

**WTF** is a local diagnostic tool for developers that automatically tries to determine **why the last terminal command failed**.

Its goal is not to explain error messages or behave like a chatbot.

Its goal is to inspect the local environment, gather evidence, and identify the root cause of a failure with as little user interaction as possible.

The primary experience should look like this:

```bash
$ cargo run
error: connection refused

$ wtf

✗ The application cannot connect to port 5432.

Root cause:
The PostgreSQL container exited 2 minutes ago.

Cause:
No space left on device.

Evidence:
  docker ps -a       → postgres exited (1)
  docker logs        → "No space left on device"
  df -h /var/lib     → 100% used
```

WTF should reduce the usual debugging loop:

```text
error
→ copy error
→ open an AI assistant
→ explain context
→ execute suggested command
→ copy result
→ ask again
→ repeat
```

into:

```text
error
→ wtf
→ diagnosis
```

---

# 2. Project Principles

WTF is built around six core principles.

## 2.1 Investigate, Don't Explain

A message such as:

```text
Connection refused
```

does not contain enough information to determine the root cause.

WTF should inspect the system to distinguish between:

* stopped service
* stopped container
* incorrect port
* incorrect address
* crashed process
* invalid configuration
* unavailable dependency

The value of WTF comes from discovering information the user would otherwise have to collect manually.

## 2.2 Local-First

All information should be processed locally by default.

It should not be necessary to send:

* source code
* logs
* environment variables
* filesystem paths
* hostnames
* commands

to external services.

## 2.3 Read-Only by Default

WTF may automatically investigate the system.

It must not automatically modify it.

It may execute commands such as:

```text
git status
git diff
ss
ps
df
free
docker inspect
docker logs
systemctl status
journalctl
```

It must not automatically execute commands such as:

```text
rm
kill
docker rm
git reset
systemctl restart
chmod
chown
```

State-changing actions must be proposed to the user first.

## 2.4 Evidence Before Opinion

A diagnosis must be backed by concrete evidence.

Bad:

```text
It looks like PostgreSQL may not be running.
```

Good:

```text
PostgreSQL is not running.

Evidence:
  systemctl status postgresql → inactive
  ss -ltnp :5432             → no listener
```

## 2.5 Explicit Uncertainty

WTF must not pretend to know the root cause when there is insufficient evidence.

It may respond with:

```text
Root cause not confirmed.

Most likely:
  72% service not running
  19% wrong port

Next useful check:
  docker ps -a
```

## 2.6 Short Output

WTF is a terminal tool.

It should not respond like a chatbot.

A normal result should be readable within a few seconds.

---

# 3. Primary Goal

Given:

```text
executed command
+
exit code
+
stdout/stderr
+
environment state
```

WTF should produce:

```text
root cause
+
evidence
+
possible solution
```

when enough evidence is available.

---

# 4. Non-Goals

The first version of WTF is not intended to:

* replace a debugger
* automatically write code
* modify files
* execute fixes without permission
* act as a conversational assistant
* replace general-purpose LLMs
* understand every possible error
* support every operating system
* solve purely logical application bugs without sufficient observable evidence

---

# 5. Initial Platform

The first version should target:

```text
Linux
Bash / Zsh
Git
Docker
systemd
Rust
Python applications
Node.js applications
Linux networking and processes
```

macOS and Windows support are outside the MVP scope.

---

# 6. Technology Stack

The project should be primarily implemented in **Rust**.

Proposed stack:

```text
CLI                  clap
async runtime        tokio
serialization        serde
configuration        toml
regex                 regex
SQLite                rusqlite
HTTP                  reqwest
terminal              console / indicatif
PTY                   portable-pty or nix
Unix sockets          tokio::net::UnixStream
Git                   git CLI initially
process execution     tokio::process
ONNX inference        ort
logging               tracing
errors                thiserror / anyhow
```

Python must not be required to run WTF.

---

# 7. Decision Model

WTF may use **Laya** as a local model specialized in decision-making.

Laya will not be responsible for generating complete explanations.

Instead, it will be used for tasks such as:

```text
classifying the problem
selecting hypotheses
selecting the next probe
rejecting hypotheses
determining whether enough evidence exists
ranking candidates
```

Example:

```text
Input:

command:
curl localhost:8000

output:
curl: (7) Failed to connect to localhost port 8000

known facts:
- no listener on 8000
- docker container api exited

Question:

Which hypothesis best explains the failure?

A service_not_started
B wrong_port
C firewall
D dns
E unknown
```

Output:

```text
service_not_started    0.89
wrong_port             0.07
unknown                0.03
firewall               0.01
```

### Implemented default behavior

After bounded deterministic investigation, WTF runs a local Laya ONNX choice
decision by default if there are unconfirmed candidate hypotheses. On first
eligible use, it downloads the pinned model graph, external weights, tokenizer
and calibration from Hugging Face over HTTPS into a private versioned XDG
cache. Each asset is size/SHA-256 verified before atomic publication; later
uses load the cached bundle without another request. `--no-model` or
`WTF_NO_MODEL=1` disables download and inference; `--model-dir DIR` chooses a
preinstalled local bundle. Only allowlisted category, hypothesis
identifiers/statuses, and probe identifiers/outcomes are supplied to the
model; command text, captured output, paths, and raw probe observations do
not enter inference or leave the machine. Non-rejected hypotheses and
`unknown` are its only choices. Scores are advisory: a non-unknown option is
preferred only at or above 0.80, and neither diagnosis status nor root cause
changes. When there are no hypotheses or a root is confirmed, inference and
download are skipped. An unavailable download or invalid artifact yields a
visible model error without replacing the deterministic diagnosis or exit
status. The current path loads weights per eligible invocation; `wtfd` and
model-guided probe selection in the architecture below are not implemented.

Current block and inode reports below full on the same mount contradict
the *current* `filesystem_full` hypothesis. Both must be complete and
parseable; a failed, truncated, malformed, or mismatched probe does not
reject it. This does not identify the historical cause or change the
diagnosis status, but if no other non-rejected hypothesis remains,
inference is skipped rather than recommending a disproven candidate.

### Proposed recommendation target (not implemented)

The next decision task is **which safe check to perform next**, or
**abstain**. It is not a request to name an unverified root cause or
generate a fix. This task is separate from today's post-investigation
advisory hypothesis ranking:

```text
input:  current allowlisted diagnostic state + engine-offered ready ProbeIds
output: one offered ProbeId | abstain
```

The deterministic investigation engine alone constructs the offered
`ProbeSpec`s, including target, fixed arguments, working directory,
prerequisite evidence, safety, and remaining budget. Offer only probes
that the same diagnosis path could already run; never let the model
create commands, expand probe scope, select targets, replay the original
action, or bypass dependency order (for example, inspect a container
only after identifying a matching one). Exclude `CargoCheck` from this
automatic choice despite its catalogue designation: it can execute
build scripts/procedural macros and write artifacts. If there are fewer
than two independent ready checks, no model decision is needed.

An abstention, invalid/out-of-set choice, unavailable model, or inference
timeout preserves the existing deterministic probe order. Abstention
does **not** end investigation while useful authorized probes remain.
Cold-start model downloads must not occur inside the probe deadline;
inference time counts against the existing probe/time budgets. Input
remains limited to fixed identifiers and verified, payload-free facts,
never raw output, paths, logs, or free-form command text. The engine
alone interprets probe results, updates hypotheses, confirms a root,
and selects an existing structured remedy. The model cannot execute
fixes or change status, evidence, or root cause from a score.

This section creates no training examples and changes no runtime behavior.
Training-data design is a separate step. Before enabling model-guided
execution, evaluate independently labeled, family-separated failures
with deterministic baseline misses: ordering authorized checks must
improve *confirmed correct roots*, without more false confirmations,
forbidden probes, or budget overruns. A better-looking hypothesis score
or more abstentions alone is not a gain.

---

# 8. High-Level Architecture

```text
                ┌──────────────────┐
                │      Shell       │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Command Capture  │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Error Normalizer │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Error Classifier │
                │      Laya        │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Hypothesis Engine│
                └────────┬─────────┘
                         │
                    hypotheses
                         │
                         ▼
                ┌──────────────────┐
                │   Probe Engine   │
                └────────┬─────────┘
                         │
                     evidence
                         │
                         ▼
                ┌──────────────────┐
                │ Decision Engine  │
                │      Laya        │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │    Diagnosis     │
                └────────┬─────────┘
                         │
                         ▼
                       user
```

---

# 9. Components

## 9.1 Command Capture

WTF must retain information about the last executed command.

```rust
struct CommandExecution {
    command: String,
    cwd: PathBuf,
    exit_code: i32,
    duration: Duration,
    stdout: String,
    stderr: String,
    timestamp: SystemTime,
}
```

There must be configurable limits for stdout and stderr size.

Raw output must not be persisted to disk by default.

---

# 10. Shell Integration

The desired UX is:

```bash
$ cargo build
...
error

$ wtf
```

Not:

```bash
$ wtf cargo build
```

although explicit command execution may also be supported.

The initial integration may use Bash and Zsh hooks.

Conceptually:

```text
preexec
    ↓
record command

command finishes
    ↓
record exit code
```

When a command fails, WTF temporarily retains information about that execution.

### Phase 3 behavior

Run `wtf install` from an interactive Bash, Zsh, or Fish session, then start a new shell. The installer adds a marked hook to `~/.bashrc` or `${ZDOTDIR:-$HOME}/.zshrc`, or creates `${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/wtf.fish`. Repeating the install is safe; `wtf uninstall` removes only its own hook. The parent process selects the active shell when recognizable, otherwise `$SHELL` is used.

After a failed command, run `wtf` to diagnose the last failure; `wtf --verbose` includes captured metadata and investigation details, and `wtf --json` emits structured output. Successful commands and WTF invocations do not replace the last failure. If no valid recent failure exists, WTF reports that fact instead. `wtf -- <command>` remains the explicit execution mode and captures that command's stdout and stderr.

Hooks record only a bounded, redacted command line, working directory, exit code, start/finish timestamps, and shell name. The single atomic JSON record lives at `$XDG_RUNTIME_DIR/wtf/last-failure.json` when the runtime directory is secure; Linux `/run/user/$UID`, private `$HOME/.cache/wtf`, and a private temporary directory are fallbacks. The WTF directory is mode `0700`, the file mode `0600`, and records expire after 15 minutes by default (`WTF_FAILURE_TTL_SECS` overrides the lifetime). Unsafe ownership, permissions, links, missing files, malformed data, and expired records are ignored. Multiline or heredoc commands are not recorded, and common credentials, headers, URLs, and payload arguments are redacted; avoid entering secrets in arbitrary command arguments because no parser can recognize every secret.

Shell hooks do **not** retain stdout or stderr and never launch a diagnosis or probe automatically. Output-dependent detectors therefore have less evidence than in explicit execution mode; metadata-only network failures may still trigger safe local probes. `--show-output` cannot recover output from shell history. Bash, Zsh, and Fish hooks require their interactive startup configuration and a usable `wtf` executable; Fish event hooks require an interactive terminal.

### Phase 4 behavior

For output-free shell failures, `wtf` selects a built-in diagnostic adapter by executable basename (including absolute paths). Cargo, Git, curl, Docker, and Linux systemd adapters reconstruct current evidence through the existing bounded, fixed-argv probe catalogue; the original action is never replayed. Explicit `wtf -- <command>` uses captured output and the existing detectors, with safe additional probes for supported `systemctl start`, Docker bind-mount, Docker published-port, and local Docker Unix socket failures. Normal output shows the finding, supported cause (or unknown), and concise evidence; `--verbose` additionally lists the selected adapter, probe attempts, and hypotheses. JSON retains the original diagnosis shape and adds optional investigation adapter metadata.

Cargo checks compilation offline with structured rustc JSON only for plain `build`, `check`, `test`, or `run` in simple local packages without detected build scripts, procedural macros, or workspaces; flags/package selection and passing checks do not explain a failed test or run. Dependency build scripts and proc macros can still execute, and `cargo check` writes build artifacts: do not treat it as read-only in untrusted projects. Git reads porcelain status, branch, upstream, and remote **names** (never remote URLs) without invoking push/pull/merge/rebase/commit; upstream diagnosis requires a committed branch and a configured remote. Curl never reissues HTTP requests, regardless of method; it inspects local listeners or host resolution instead. Docker reads state and bounded logs only for an explicit `docker run --name` container whose creation time matches the failed command; it never starts or runs containers. Docker image entities skip known option values, and unknown option forms remain unclassified rather than being mislabeled as an image. A Docker API probe failure alone no longer diagnoses why the original command failed; only a captured local Unix socket error corroborated by bounded local `stat` can confirm an absent socket. Invalid output, unavailable tools, timeouts, and unsupported variants yield an unconfirmed cause rather than a fabricated explanation. Probe output is transient and is never persisted by the shell hook.

An explicit Docker bind-source failure is confirmed only for a single named `docker run --mount type=bind` whose captured daemon error names the exact requested absolute source and a fixed-argument local `stat` reports that source missing. Docker can reject the mount before creating a container, so output-free shell metadata cannot establish this cause. Mismatched, ambiguous, absent, unavailable, or truncated evidence remains unconfirmed; `-v`/`--volume` is not treated as equivalent because it may create a missing source directory.

An explicit `docker run` TCP/IPv4 published-port conflict requires one requested host mapping, Docker's exit code 125, a daemon bind error naming that exact host socket, and one running container with a conflicting published binding predating the command. Only then is the owner confirmed through bounded `docker ps`; unknown, mismatched, multiple, future, or unsupported bindings remain unconfirmed. Metadata-only shell failures cannot recover the daemon error, and diagnostic probes never repeat `docker run`.

An explicit failed Docker command can confirm `container/daemon` only when its captured error identifies one safe absolute Unix socket path and a bounded local `stat` independently reports that path missing. The diagnosis does not expose the socket path in its root or investigation evidence, nor repeat Docker. A currently present socket does not prove the daemon is reachable; permission errors, remote endpoints, global context/host flags, malformed or mismatched paths, and missing or truncated probe evidence remain unconfirmed. Output-free shell records do not establish the original daemon error, even if a later `docker ps` probe also fails.

---

# 11. Error Normalizer

Raw output should be transformed before inference.

Responsibilities include:

```text
remove ANSI sequences
remove progress bars
collapse repeated lines
detect tracebacks
detect ERROR/FATAL/PANIC lines
extract relevant first/last lines
extract paths
extract ports
extract PIDs
extract service names
extract container names
extract operating-system errors
```

Example:

```text
14,000 lines
```

may become:

```text
Command:
docker run -p 8000:8000 api

Exit:
125

Relevant output:
Bind for 0.0.0.0:8000 failed:
port is already allocated

Entities:
port: 8000
technology: docker
```

---

# 12. Error Classification

The first stage should classify the general failure domain.

Initial categories:

```text
network
permissions
filesystem
process
service
container
dependency
configuration
compilation
runtime
authentication
resource_exhaustion
git
unknown
```

The classification determines which diagnostic modules are activated.

---

# 13. Hypothesis Engine

An error must not immediately produce a single explanation.

The system should create several possible hypotheses.

For example:

```text
Connection refused
```

may generate:

```text
service_not_running
wrong_port
wrong_host
container_not_running
service_crashed
```

Each hypothesis maintains:

```rust
struct Hypothesis {
    id: HypothesisId,
    probability: f32,
    evidence_for: Vec<Evidence>,
    evidence_against: Vec<Evidence>,
    status: HypothesisStatus,
}
```

Possible statuses:

```text
candidate
likely
confirmed
rejected
unknown
```

---

# 14. Probe Engine

Probes are safe commands used to collect additional information.

Examples:

## Networking

```text
ss -ltnp
ip addr
ip route
getent hosts
```

## System

```text
df -h
df -i
free
uptime
ps
```

## Docker

```text
docker ps
docker ps -a
docker inspect
docker logs
```

## systemd

```text
systemctl status
systemctl show
journalctl
```

## Git

```text
git status
git diff
git log
```

## Filesystem

```text
stat
ls
readlink
```

Each probe must declare:

```text
identifier
command
timeout
risk level
type of evidence it provides
hypotheses for which it is useful
```

Example:

```rust
struct Probe {
    id: ProbeId,
    risk: ProbeRisk,
    timeout: Duration,
    executor: ProbeExecutor,
}
```

---

# 15. Probe Safety

Probes should be divided into:

```text
SAFE
CONFIRM
FORBIDDEN
```

Only `SAFE` probes may execute automatically.

Examples of `SAFE`:

```text
ss
ps
git diff
docker inspect
docker logs
df
free
```

Examples of `CONFIRM`:

```text
restart service
kill process
delete file
change permissions
```

Examples of operations that are automatically `FORBIDDEN`:

```text
rm -rf
git reset --hard
docker system prune
DROP DATABASE
```

---

# 16. Iterative Diagnosis

Diagnosis should operate as a loop.

```text
1. observe failure
2. generate hypotheses
3. determine what information is missing
4. execute a probe
5. update hypotheses
6. repeat
7. produce diagnosis
```

Example:

```text
curl → connection refused
        ↓
no listener
        ↓
container expected?
        ↓
docker ps -a
        ↓
container exited
        ↓
docker logs
        ↓
DATABASE_URL missing
        ↓
root cause confirmed
```

---

# 17. Diagnostic Budget

WTF must not execute probes indefinitely.

Initial configuration:

```toml
[diagnosis]
max_probes = 5
max_duration_ms = 2000
min_confidence = 0.80
```

A normal diagnosis should aim to finish within a few seconds.

---

# 18. Recipes

Known fixes should be represented as structured data.

Example:

```toml
id = "port_already_in_use"
title = "Port {port} is already in use"

explanation = """
Another process is already listening on port {port}.
"""

[[checks]]
command = "ss -ltnp 'sport = :{port}'"

[[suggestions]]
text = "Stop the existing process or configure another port."
```

This prevents the model from inventing arbitrary commands.

---

# 19. Output Format

Confirmed diagnosis:

```text
✗ Port 8000 is already in use.

Process:
  node (PID 18291)

Evidence:
  ss → node listening on 0.0.0.0:8000

Fix:
  Stop that process or use another port.
```

Probable diagnosis:

```text
? Likely configuration mismatch.

Confidence: 78%

Your application connects to:
  localhost:5432

PostgreSQL listens on:
  10.0.0.5:5432

Check:
  DATABASE_URL
```

Unknown diagnosis:

```text
? Root cause not found.

What I checked:
  ✓ port availability
  ✓ filesystem
  ✓ running processes
  ✓ Docker

Most useful next step:
  wtf --deep
```

---

# 20. Execution Modes

## `wtf`

Diagnose the last failed command.

```bash
wtf
```

## `wtf -- <command>`

Execute and diagnose an explicit command.

```bash
wtf -- cargo build
```

## `wtf --deep`

Run a more extensive investigation.

```bash
wtf --deep
```

This increases:

```text
number of probes
maximum diagnosis time
amount of context inspected
```

## `wtf explain`

Show the technical reasoning behind the diagnosis.

```bash
wtf explain
```

Example:

```text
Hypotheses:

service_crashed        0.91
wrong_port             0.05
firewall               0.02
unknown                0.02

Evidence:

+ container exited
+ log contains missing environment variable
- port configuration matches
```

---

# 21. Recent Change Detection

An important feature should be the ability to correlate failures with recent changes.

Inside a Git repository:

```text
git diff
```

may provide useful evidence.

For example:

```text
Before:
PORT=8000

After:
PORT=8001
```

while:

```text
Docker configuration:
8000:8000
```

WTF may detect:

```text
The failure started after changing the application port from
8000 to 8001, while the container still publishes 8000.
```

WTF must not assume that every recent change caused the failure.

Recent changes are evidence, not proof.

---

# 22. Privacy

By default, WTF:

```text
does not upload command, output, path, or probe contents (first eligible use downloads a fixed model bundle over HTTPS)
does not persist stdout
does not persist stderr
does not persist environment variables
does not persist file contents
```

It may persist:

```text
error type
normalized hash
diagnosis
probability
executed probes
diagnostic result
feedback
```

---

# 23. Secret Redaction

Before sending any context to the decision model, WTF should detect patterns such as:

```text
Authorization: Bearer ...
password=...
token=...
secret=...
AWS_SECRET_ACCESS_KEY
DATABASE_URL containing a password
private keys
```

and replace them with:

```text
<REDACTED>
```

Even when all inference is local, this prevents sensitive information from accidentally appearing in internal logs or persisted diagnostics.

---

# 24. Daemon

Laya should not be loaded every time the user runs:

```bash
wtf
```

A daemon should exist:

```text
wtfd
```

which keeps the model loaded in memory.

Communication:

```text
wtf CLI
   ↓
Unix socket
   ↓
wtfd
   ↓
Laya
```

Suggested socket path:

```text
$XDG_RUNTIME_DIR/wtf.sock
```

The daemon may be managed through:

```text
systemd --user
```

---

# 25. Proposed Repository Structure

```text
wtf/
├── crates/
│   ├── wtf-cli/
│   ├── wtf-core/
│   ├── wtf-capture/
│   ├── wtf-diagnosis/
│   ├── wtf-probes/
│   ├── wtf-laya/
│   └── wtfd/
│
├── probes/
│   ├── docker/
│   ├── network/
│   ├── systemd/
│   ├── filesystem/
│   ├── git/
│   └── process/
│
├── recipes/
│
├── models/
│
├── integrations/
│   ├── bash/
│   └── zsh/
│
└── tests/
```

---

# 26. MVP

The first functional version should focus on proving one hypothesis:

> WTF can identify a real root cause by automatically collecting local information that the user would otherwise need to gather manually.

The MVP should support approximately 20–30 common failures.

Priority failure families:

```text
port already in use
connection refused
DNS failure
permission denied
file not found
disk full
inode exhaustion
process killed by OOM
Docker container exited
Docker bind mount missing
Docker port conflict
Docker daemon unavailable
systemd service failed
missing environment variable
missing dependency
Git merge conflict
Git detached HEAD
authentication failure
certificate failure
command not found
```

---

# 27. Metrics

Success should not be measured only by classification accuracy.

Important metrics include:

```text
root-cause accuracy
false diagnosis rate
unknown rate
average probes per diagnosis
median diagnosis latency
percentage solved without user input
percentage requiring --deep
unsafe command suggestion rate
```

The primary metric should be:

```text
Percentage of failures for which WTF correctly identifies
the root cause without additional user interaction.
```

---

# 28. Test Dataset

Every reproducible bug should become a test fixture.

Example:

```text
fixtures/
  docker/
    port-conflict/
    missing-volume/
    crashed-container/

  network/
    connection-refused/
    dns-failure/

  filesystem/
    disk-full/
    permission-denied/
```

Each scenario should specify:

```text
initial state
command
expected error
root cause
available evidence
allowed probes
expected diagnosis
```

This allows the diagnostic system to be regression-tested.

## Executable local E2E scenarios

The VM-free suite installs `wtf` under a temporary root and exercises its
interactive Bash hook with a temporary HOME and XDG directories. Cargo builds
a dependency-free crate with a type error, Git pushes a local repository
without an upstream, and curl connects to an unbound loopback port. Each case
checks the failed command's diagnosis and then verifies a local correction.

```sh
bash scripts/e2e.sh quick
bash scripts/e2e.sh quick cargo_build_failure
```

The Makefile wraps the same workflows:

```sh
make help
make build
make check
make test
make fmt-check
make lint
make e2e
make e2e E2E_FILTER=cargo_build_failure
```

Use `make fmt` to format Rust sources. `make test` leaves Docker E2E ignored.

The runner installs and tests offline; run `cargo fetch --locked` first if the
Cargo dependency cache is empty. The WTF hook and fixtures write under their
temporary HOME and XDG directories, not the user's shell startup files.
Rustup's installed toolchain and the workspace build cache remain shared.

Docker is deliberately excluded from `quick` and ignored by ordinary
`cargo test`. On a host with a running local Unix-socket Docker context and a
cached `busybox:latest` image, explicitly opt in:

```sh
bash scripts/e2e.sh docker
bash scripts/e2e.sh all
```

Equivalent opt-in Make targets are `make e2e-docker` and `make e2e-all`.

This uses the host's **shared daemon**, not an isolated VM. It pins Docker
commands to that local socket, disables pulls and container networking, and
creates two uniquely named containers tagged `wtf.e2e.owner`. Cleanup
inspects that label and removes only its matching container IDs. Other daemon
resources are never pruned or removed. Obtain authorization before running
this scenario against a shared daemon.

---

# 29. MVP Acceptance Criteria

The MVP can be considered successful when:

```text
1. `wtf` can automatically analyze the last failed command.

2. It does not require manually copying stdout/stderr.

3. It can automatically execute safe probes.

4. It can follow a multi-step diagnostic path.

5. It can distinguish a symptom from the actual root cause.

6. It never automatically executes destructive commands.

7. All inference can run locally.

8. Diagnoses include concrete evidence.

9. It can explicitly admit when the root cause is unknown.

10. On the initial dataset, it achieves meaningfully better
    root-cause accuracy than deterministic heuristics alone.
```

Current evidence for criterion 10: not established. The opt-in offline
`crates/wtf-cli/tests/model_evaluation.rs` compares identical sandboxed
diagnoses with `--no-model` and an already installed Laya bundle. Its
seven-case exploratory sample has two roots already confirmed without
Laya, one scripted quota failure with a known alternative cause, and
three eligible model decisions without independently verified historical
roots. In the quota case, Laya advised `filesystem_full` at 0.854 before
the investigation rejected it with matching, non-full block and inode
reports. Adding those two facts to Laya's input did not reliably prevent
the false advice, so that input change was discarded. Model scores
remain advisory, and no root-cause accuracy gain over deterministic
investigation has been demonstrated. Before model-guided probes,
evaluate paired runs on a larger family-disjoint holdout with known
causes and deterministic baseline misses; require improved confirmed
root-cause yield without false confirmations, unauthorized probes, or
budget regressions. Only the deterministic engine may construct eligible
probes and confirm roots from their evidence; absent evidence of benefit,
retain the current fixed probe order and advisory model role.

---

# 30. Future Evolution

Once the MVP has been validated:

## External Plugins

Expose an API for adding:

```text
probes
detectors
recipes
error families
```

## `wtf watch`

Diagnose long-running processes.

```bash
wtf watch cargo test
```

## Failure History

Detect cases such as:

```text
This is the same failure you encountered yesterday.
```

## Temporal Correlation

Detect cases such as:

```text
The service started failing immediately after commit abc123.
```

## IDE Integration

Integrate with editors such as VS Code or Zed:

```text
Diagnose last failure
```

## Specialized Training

Build a local dataset containing:

```text
error
environment state
probes
root cause
```

and use it to train or fine-tune a model specifically for diagnostic decision-making.

---

# 31. Product Identity

Working name:

```text
wtf
```

Short description:

> **Find out why your last command failed.**

Alternative:

> **A root-cause debugger for your terminal.**

WTF should not primarily be marketed as an AI tool.

AI is an implementation detail.

The promise to the user is simply:

```bash
something fails

$ wtf

→ why
```

---

# 32. Long-Term Vision

The long-term goal is for WTF to behave less like a chatbot and more like an experienced developer sitting in front of your terminal.

It should not merely read:

```text
connection refused
```

and respond with:

```text
"Check whether the service is running."
```

It should check whether the service is running.

Then check the port.

Then inspect the process.

Then inspect its logs.

Then correlate the failure with recent local changes.

And finally report:

```text
Your API isn't responding because the container exited.

It exited because DATABASE_URL is missing.

The variable disappeared in your last uncommitted change to .env.

Nothing else needs fixing.
```

That is the product.

