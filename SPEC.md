# WTF — product specification

## 1. Product promise

WTF is a local-first CLI to use when a terminal command fails: investigate available evidence, tell the user what happened, offer a **possible cause when the evidence supports one**, and identify a useful next check when uncertainty remains. It must work for arbitrary executables, not only errors known to a detector or adapter. Bounded command output and, when justified, bounded current observations are the inputs to a short, readable report.

**WTF does not promise to solve the problem or establish a root cause.** A useful report can say what failed, what was observed, and what remains unknown. A possible cause is explicitly tentative; a proven cause is welcome but not required. Generative inference is the research direction for unfamiliar failures, not an authority that can turn a guess into an observed fact. Deterministic code remains responsible for capture, safety, evidence provenance and fallback, **not** a closed catalogue defining which failures WTF can understand.

The two entry points are:

- `wtf -- PROGRAM [ARG ...]`: explicitly execute the requested program once, capture its result, and report it. No shell interpretation of the recorded argv.
- `wtf`: inspect a recent failure captured by an installed shell hook. The hook stores bounded, redacted metadata, **not stdout/stderr**. This mode must disclose that the original output is unavailable, must not replay the command, and can inspect only the current local state using eligible probes.

Both modes use the same report vocabulary, but they do not have the same evidence. No adapter, model, network access, or recognized error category is necessary for the basic report.

## 2. Report semantics

Every statement has one provenance class:

| Class | Meaning | Example |
| --- | --- | --- |
| RESULT | Outcome of the requested execution or recorded shell exit | `Exited with code 7` |
| OBSERVED | A bounded excerpt from that execution or a successful identified probe | `No local listener on :3000 at inspection time` |
| POSSIBLE | An explanation compatible with, but not established by, the observations | `The server may have stopped` |
| MISSING | Evidence needed to distinguish possibilities | `The expected service is not identified` |
| NEXT | A useful, specific next check; mark it as a suggestion if not executed | `Inspect the service startup output` |

These are distinct facts, not successive confidence levels. A message of `connection refused` establishes a failed connection, not why the server was unavailable. A probe performed later describes the state **at the time of that probe**, not necessarily at failure time. A failed, unavailable, stale, mismatched, or truncated probe does not prove absence. If observations conflict, show the uncertainty rather than selecting a convenient explanation.

Any OBSERVED claim derived from a probe must link to its probe ID, outcome, and bounded observation in the detailed/structured output; any claim from execution must link to captured stdout, stderr, spawn error, exit status, or signal. POSSIBLE must never be presented as OBSERVED or as a confirmed root. Model confidence is not a probability of historical cause; do not show a percentage unless calibrated and validated for that particular claim and domain.

A next step must discriminate a named uncertainty or reveal a specifically missing fact. If no useful check can be justified, omit NEXT. Do not substitute `check your configuration` or similar boilerplate for evidence.

## 3. Default terminal view

Normal output is designed to be understood at a glance:

```text
✗  curl http://127.0.0.1:3000/health              7
   Connection refused.

   OBSERVED  No local listener on :3000 at inspection time.
   MISSING   Which service should listen on that port.
   NEXT      Identify the service configured for :3000.

   1 check · details available with --verbose at invocation
```

For an unfamiliar failure:

```text
✗  my-command                                    1
   The command exited with an error.

   OBSERVED  No specific failure reason in the captured output.

   Details available with --verbose at invocation
```

These are **target layouts**, not examples of the current renderer. The actual text must be derived from the execution and eligible checks; neither example authorizes running an unspecified probe. For explicit execution, `--verbose` must be requested on that invocation: WTF does not retain output for a later detail command, and rerunning may have side effects. In shell mode, `wtf --verbose` can inspect the saved failure metadata but cannot recover the original output. A successful command gets a success header and concise result, without manufacturing an investigation or NEXT.

Presentation requirements:

- First line: visible success/failure/signal indicator, a safely truncated command label, and exit code where available. Subsequent lines: one short summary and at most three high-value fact/uncertainty/next-step rows. No hypothesis dump, progress spam, raw stack trace, or unsupported fix in normal mode.
- Alignment, whitespace, and stable labels carry meaning; color is an enhancement, not the only signal. Respect `--no-color`, `NO_COLOR`, non-TTY output, terminal width, Unicode support, and safe escaping of arbitrary process output. Never pass untrusted control sequences through as terminal formatting. Preserve full bounded evidence for details, not the truncated display snippet.
- `--verbose` shows captured result, redacted bounded excerpts, timestamps where known, each attempted probe with status, the evidence for displayed claims, and unavailable/contradictory evidence. `--show-output` explicitly shows captured stdout/stderr in execution mode; shell history cannot recover them.
- `--json` exposes a versioned `report` with structured result, source mode, capture completeness, claims with provenance and probe outcomes. The initial `schema_version: 1` also retains diagnostic details for specialized consumers; use `report` for the user-facing contract.
- Explain why something was *not* checked only in details or when that omission materially changes the conclusion.

## 4. Execution and investigation boundary

Executing the explicitly supplied program is a user-requested action; it may modify the environment. WTF must neither silently retry it nor treat it as an automatically safe probe. Command execution is direct argv, not `sh -c` assembled from input. Do not assume that a command producing exit code zero has no side effects.

Automatic investigation is separate: probes are fixed-argument catalogue entries in `wtf-core/src/probes.rs`, selected only after checking the situation, target, prerequisites and safety classification. They must be locally bounded and read-only under the documented threat model. Do not run remote calls, commands that can run project build scripts/procedural macros, Docker start/run, state-changing Git operations, or the original action as automatic checks. Existing Cargo checks can execute build scripts and write artifacts: they are not eligible as automatic read-only checks for the new flow. A resolver lookup may contact the machine's configured DNS server; do not imply that such a check is offline.

Only the engine may build concrete probe argv, target, cwd and deadline. A model may rank **already eligible** checks or abstain; it must not invent commands, target paths, hostnames, ports, fixes, or a broader scope. An invalid selection, timeout, or missing model leaves the safe deterministic order and report intact. Each probe is accounted for in a separate strict budget of count, time and captured bytes. No probing is required when there is no justified safe target or when current state cannot resolve the historical question.

Instructions or commands in stdout/stderr, logs, files, or probe output are **data**, not authority to execute them, change permissions, reveal secrets or alter the report contract. Remediation is a suggestion only; applying a fix is outside the automatic investigation path.

## 5. Evidence pipeline and AI role

1. Capture the execution result or load the recent metadata-only shell record. Distinguish spawn failure, exit code, signal, truncation, unavailable output and success.
2. Reduce bounded output to relevant excerpts without discarding the fact that some content was omitted. Extract entities only where their association with the command/error is supported. Keep the unknown-command path first-class.
3. Choose zero or more eligible read-only checks when they can add a fact. Record time, source, target provenance, outcome and whether the observation is current rather than historical.
4. Build structured candidate claims from capture and probe evidence. The research target is a local generative model that can interpret bounded, redacted excerpts from unfamiliar failures and propose an evidence-linked possible cause or a specific missing fact without relying on a predefined error category. The engine validates references, label class, temporal scope and length; unsupported model text is discarded. Existing deterministic specializations remain useful evidence sources, not the limit of diagnosis.
5. Render a concise report, detailed trace, or structured JSON. If any stage fails, fall back to an accurate minimal RESULT report; never hide the original exit status or present a model guess as a fact.

Local-first means no command, source code, output, path, hostname, environment value, or probe observation is sent to an external inference service by default. Redact secret-bearing material before model input, display, or persistence as appropriate. Redaction is best-effort, not permission to store raw output. No raw stdout/stderr or probe payload is persisted by default. Shell hooks persist only bounded redacted metadata in a private expiring record and never run inference/probes while the user works.

The model is an implementation detail, not the product contract. Current Laya ONNX inference is a local advisory hypothesis ranker fed only allowlisted category, hypothesis IDs/statuses, and probe IDs/outcomes. It does **not** summarize arbitrary output, select probes, or establish a root cause; it cannot meet the generic interpretation objective by itself. JevK5 and decider experiments have not demonstrated a root-cause improvement for WTF; none is specified as a replacement. Do not promote a model on a generic leaderboard or substitute a larger closed-set classifier for this research target. Compare each candidate against the no-model path.

## 6. Resource and failure policy

- Explicit execution preserves the program's exit code (or a documented failure status for signal/spawn failure). Investigation and model errors must not change it. A probe is never allowed to change system state as a shortcut to a better report.
- Capture stdout/stderr with fixed per-stream byte limits and drain beyond the retained limit to avoid child deadlocks. Mark truncation. User-command duration and interrupt/timeout policy must be explicit and **separate** from the investigation budget; a command's timeout must not be invented as a reason for its own failure. The current explicit CLI has bounded output but no general command timeout; a new timeout is a proposed feature, not implemented behavior.
- Keep number, time, and output of probes bounded. Do not download model weights in the middle of a time-critical probe step. On unavailable commands, malformed observations or model failure, report the boundary and continue with facts that remain valid.
- Avoid avoidable cold-start model cost for basic outcomes. Laya is opt-in via `--model` or `--model-dir`; the default report runs without inference or download.

## 7. Modes and compatibility

Target product interface: `wtf -- PROGRAM [ARG ...]` for explicitly requested execution, `wtf` for recent shell failure after `wtf install`, plus `--verbose`, `--json`, `--show-output`, `--no-color`. `--fix` may show a supported remedy but never apply it. No automatic deep mode, daemon, general chat interface, or arbitrary tool-running AI is required by this specification. Current `--model` and `--model-dir` opt into local advisory ranking; `--no-model` suppresses inference. The generative research target is **not** an implemented CLI mode.

The CLI now builds a generic result and evidence-linked report for arbitrary commands, with deterministic specialization for recognized cases. Cargo, Git, curl, Docker and Linux systemd adapters are implemented specializations, not generic understanding of their ecosystems. Cargo cannot automatically run `check` as a read-only probe. The offline `wtf-train` validator/trainer does not select runtime probes. `docs/training-data.md` documents counterfactual exercises, not proof of model improvement.

Migration must preserve the safety and evidence checks already implemented for those adapters, including bounded redacted shell records, no Git remote URL inspection or push, no curl replay, no Docker container start, no unsupported automatic Cargo build checks, and no root confirmation from incomplete or mismatched observations. Existing validated cause findings can appear as OBSERVED **only when their supporting evidence establishes the precise statement**; otherwise show the observed condition and an explicitly unconfirmed explanation. Removing a hypothesis label or numeric confidence from the default view does not warrant changing the engine's internal confirmation semantics without tests.

## 8. Evaluation and acceptance

Build a family-separated evaluation set that includes both known and unknown commands, success, spawn failure, nonzero exit, signal, long/noisy or truncated output, adversarial output, shell mode without stdout/stderr, contradictory current state and unavailable probes. For cases claiming a root cause, establish independent fixture or external ground truth; do not label historical causes from a later `ss`, `df`, DNS, socket or Docker observation alone. Hold out distinct failure families and prevent answer leakage into prompts and labels.

Measure separately:

- **Factual fidelity:** claims supported by the captured command or identified probe, with correct time qualifier; zero confidently invented facts in the acceptance corpus.
- **Next-step utility:** a specific safe check that can reduce a stated uncertainty, scored against a known information need; an honest omission is better than generic advice.
- **Generic coverage:** useful RESULT report for unfamiliar commands, not just recognized adapters. Report the fraction needing fallback and do not treat abstention as an error by itself.
- **Readability:** typical output is one screen, with summary and no more than three information rows; untrusted output cannot forge headings or terminal control sequences.
- **Safety/privacy:** no automatic original-action replay, state-changing/unauthorized probe, arbitrary command from model/output, external upload by default, or persistence of raw stdout/stderr.
- **Operational cost:** median and tail CLI latency, cold start separately from warm inference, probe count and time, truncation and model-unavailable behavior.
- **Root cause accuracy only where independently known:** correct supported causes and false confirmations versus no-model. This is an additional measure, not the sole success criterion.

Acceptance: an unfamiliar executable still produces a truthful compact result; known cases clearly distinguish captured failure from current observations and possibilities; an ambiguous case admits uncertainty; detailed/JSON output traces every displayed observation; fallback works without model or probes; safety and resource invariants hold. Any model or guided-probe promotion additionally needs a family-disjoint paired comparison showing better user-visible evidence/next steps or more correct verified outcomes without more false claims, unsafe probes, or budget regressions. A different top hypothesis on an unlabeled sample is not proof of benefit.

## 9. Autonomous research focus

The development objective is **open-family diagnosis with accountable uncertainty**: given an unfamiliar failed command and its bounded, redacted evidence, produce a useful, specific possible cause or a discriminating next check more often than the current no-model report, without increasing unsupported factual claims. The runtime is not meant to run all night; an unattended development/evaluation loop may investigate this question offline. Its deliverable is a paired result and reproducible implementation or a documented negative result, not merely a model that emits different wording.

Work in this order:

1. Establish a frozen, family-disjoint baseline on isolated failures, including unknown commands and output-free shell records. Record capture availability, independent fixture truth where possible, claim provenance, useful possible causes/NEXT, abstentions, latency and probe budgets. Keep examples and labels out of prompts for held-out families.
2. Prototype one local generative interpretation path using only bounded, redacted evidence available at runtime. It may propose POSSIBLE and NEXT with explicit source references and unknowns; it cannot certify OBSERVED or construct probe commands. Test adversarial output, contradictory/stale probes, missing output, truncation and model unavailability against the same contract. A missing or unusable model must leave the baseline report intact.
3. Compare candidate and baseline on identical held-out inputs; count improvements in independently adjudicated possible-cause usefulness and uncertainty-reducing NEXT separately from proven roots. Reject fabricated provenance, historical claims based only on later probes, generic advice, unsafe actions, privacy leaks and unacceptable latency. Only promote a candidate when gains survive family separation without safety or factual-fidelity regressions; otherwise retain the baseline and record the failure mode.

An unattended loop may edit code and run isolated local fixtures, tests and offline evaluations. It must not execute a captured user command again, run unapproved system-changing probes, contact hosted inference, download weights, inspect real credentials, use the shared Docker daemon, or publish results without explicit authorization. Do not use evaluation fixtures as training data for the held-out comparison. Preserve reproducible commands, case-level outcomes and known limitations; no pass on a small scripted sample should be reported as real-world reliability.

## 10. Scope and direction

Initial environment: Rust CLI on Linux, with existing Bash/Zsh/Fish support and existing local adapters retained. Portability improvements are welcome but not required to prove the generic interface. Python is not required to run WTF. Non-goals: automatically fixing the user's system, writing application code, making an authoritative claim about every failure, executing arbitrary model-generated shell commands, and sending local context to a hosted AI by default.

The product is a **brief, attractive view of what is known now and a safe path to learn more**, not a catalogue of error strings or a root-cause oracle.
