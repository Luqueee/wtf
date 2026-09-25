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
does not send information over the Internet
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

