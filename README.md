# WTF

WTF is a local-first terminal diagnostic tool. It investigates a failed command using its captured output or, in shell mode, reconstructs current evidence from bounded local probes. It reports a concise finding, evidence, and—when supported—a possible remedy. It is deterministic; it is not a conversational assistant.

## Status

Implemented: command execution and diagnosis, shell hooks for Bash/Zsh/Fish, and diagnostic adapters for Cargo, Git, curl, and Docker. The project is an early version (`0.1.0`); support is intentionally limited to recognized failure patterns and probes available on the host.

## Requirements

- Rust toolchain with Cargo
- Bash, Zsh, or Fish for shell integration
- Linux or macOS for currently implemented platform-specific probes; the specification's initial target is Linux
- Optional local tools such as `git`, `cargo`, `curl`, and `docker` for relevant diagnostics

Python is not needed to run WTF.

The `Makefile` provides the common workspace tasks:

```sh
make help
make build
make check
make test
make fmt-check
make lint
```

`make fmt` applies formatting. `make test` runs the workspace suite; Docker E2E is opt-in because it uses the shared Docker daemon:

```sh
make e2e                         # Cargo, Git, and curl scenarios
make e2e E2E_FILTER=cargo_build_failure
make e2e-docker                  # Docker scenarios
make e2e-all                     # Both E2E groups
```

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

Shell-mode reconstruction selects an adapter by executable basename, including when the command was recorded with an absolute path. Cargo, Git, curl, and Docker use the existing bounded, fixed-argument probe catalogue. The original shell command is never replayed.

### Execute and diagnose a command explicitly

```sh
wtf -- cargo build
wtf -- curl http://127.0.0.1:8080
```

WTF executes the program directly, without a shell, captures stdout/stderr and exit status, then applies the output-based detectors and available investigation. It returns the diagnosed command's exit status. Add `--show-output` to print captured output alongside the diagnosis.

### Output options

```sh
wtf --verbose
wtf --json
wtf --fix
wtf --no-color
```

- `--verbose` includes captured metadata for explicit execution and investigation details such as the selected adapter, probe attempts, and hypotheses.
- `--json` prints the diagnosis as JSON, including optional investigation and adapter metadata.
- `--fix` includes a supported remedy when one is available; it does not apply the remedy.
- `--no-color` disables colored output. `NO_COLOR` is also respected.

If no valid recent shell failure exists, WTF reports that no recent failed command was found. Successful commands and WTF invocations do not replace the last recorded failure.

## Diagnostic scope and safety

WTF gathers local evidence and does not send commands, logs, source code, environment variables, or paths to an external service. Probe commands are selected from a fixed catalogue, bounded by output, timeout, and investigation budget. Shell hooks persist only command metadata; probe output is transient.

- **Cargo:** offline structured compiler diagnostics are attempted only for plain `build`, `check`, `test`, or `run` in a simple local package, without detected workspace/build-script/procedural-macro complexity. Dependency build scripts and procedural macros can still execute, and `cargo check` writes build artifacts; do not run this diagnostic in an untrusted project as if it were read-only. A successful check does not establish why a test or run failed.
- **Git:** reads local status, branch, upstream, and remote names. It does not invoke push, pull, merge, rebase, or commit. Upstream diagnosis requires a committed branch and configured remote; remote URLs are not inspected.
- **curl:** never reissues the HTTP request, regardless of method. It checks local listeners or host resolution instead.
- **Docker:** inspects state and bounded logs only for an explicitly named container created by the failed `docker run`; it does not start or run containers.

Unavailable tools, timeouts, malformed or unsupported data, and inconclusive probes produce an unknown or unconfirmed result rather than a fabricated cause. An unknown result is an expected outcome when current evidence is insufficient. WTF does not automatically change system state or apply fixes.

## Workspace layout

- `crates/wtf-core`: command capture, normalization, entity extraction, deterministic detectors, probes, adapters, and diagnosis/investigation logic.
- `crates/wtf-cli`: CLI, shell integration and secure recent-failure state, plus integration tests.
- `scripts/e2e.sh`: end-to-end test helper.
- `SPEC.md`: project specification and phase behavior.
