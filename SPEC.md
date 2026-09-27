# WTF — product specification

## 1. Product promise

WTF is a local-first CLI for a failed terminal command: **use the failure output itself to explain what likely happened, regardless of which executable produced it**, then tell the user what is observed, what remains uncertain, and which specific check could distinguish explanations. An unfamiliar command must receive the same opportunity for interpretation as Cargo, Git or curl. Bounded command output and, where justified, bounded current observations are inputs to a concise report; neither adapter recognition nor a predefined error category is a prerequisite for a possible cause.

No tool can infer every historical cause from every exit code. With informative captured output, WTF should attempt a useful evidence-linked explanation; without it, the honest result may be unknown. Generative interpretation of captured evidence is the **central product capability to build**, not a side experiment that only runs after rules fail. Deterministic code owns capture, redaction, safe probe eligibility, provenance, validation and fallback, **not** the list of failures WTF can understand. A possible cause is tentative, never a fact manufactured by a model.

The two entry points are:

- `wtf -- PROGRAM [ARG ...]`: explicitly execute the requested program once, capture its result, and report it. `wtf --live -- PROGRAM [ARG ...]` additionally forwards raw stdout/stderr while retaining bounded excerpts; the installed `wtfr PROGRAM [ARG ...]` function opts into the same path. No shell interpretation of the recorded argv.
- `wtf`: inspect a recent failure captured by an installed shell hook. The hook stores bounded, redacted metadata, **not stdout/stderr**. This mode must disclose that the original output is unavailable, must not replay the command, and can inspect only the current local state using eligible probes.

Both modes use the same report vocabulary, but they do not have the same evidence. The current `wtf` shell hook has no original stdout/stderr: it cannot explain an unseen error message. The explicit `wtfr`/`--live` path makes normal-terminal output-aware diagnosis possible **when deliberately used**, but does not intercept ordinary shell commands. Until a safe general interception mechanism exists, advertise `wtf -- PROGRAM` or `wtfr PROGRAM` as the output-aware paths and disclose the bare shell-mode limit. No adapter, recognized error category, or model is necessary for a truthful basic result.

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
4. Interpret the captured failure and any eligible probe observations for **every failed executable**, not just named adapters. The target generative interpreter receives bounded, redacted, source-identified excerpts and proposes a tentative POSSIBLE explanation, a specific MISSING fact or a discriminating NEXT; it is not limited to engine-supplied hypothesis labels. The engine validates references, label class, temporal scope and length; unsupported text is discarded. Existing adapters may contribute corroborating evidence, but must not gate the generic interpretation path.
5. Render a concise report, detailed trace, or structured JSON. If any stage fails, fall back to an accurate minimal RESULT report; never hide the original exit status or present a model guess as a fact.

Local-first means no command, source code, output, path, hostname, environment value, or probe observation is sent to an external inference service by default. Redact secret-bearing material before model input, diagnosis display, or persistence as appropriate. **Explicit live mode is an exception for the original child stream:** it forwards raw bytes to the user's existing stdout/stderr without storing them; do not mistake the forwarded stream for a redacted report. Redaction is best-effort, not permission to store raw output. No raw stdout/stderr or probe payload is persisted by default. Shell hooks persist only bounded redacted metadata in a private expiring record and never run inference/probes while the user works.

The model is an implementation detail, not the product contract. Current Laya ONNX inference is a local advisory hypothesis ranker fed only allowlisted category, hypothesis IDs/statuses, and probe IDs/outcomes. It does **not** summarize arbitrary output, select probes, or establish a root cause; it cannot meet the generic interpretation objective by itself. JevK5 and decider experiments have not demonstrated a root-cause improvement for WTF; none is specified as a replacement. Do not promote a model on a generic leaderboard or substitute a larger closed-set classifier for this research target. Compare each candidate against the no-model path.

## 6. Resource and failure policy

- Explicit execution preserves the program's exit code (or a documented failure status for signal/spawn failure). Investigation and model errors must not change it. A probe is never allowed to change system state as a shortcut to a better report.
- Capture stdout/stderr with fixed per-stream byte limits and drain beyond the retained limit to avoid child deadlocks. Mark truncation. User-command duration and interrupt/timeout policy must be explicit and **separate** from the investigation budget; a command's timeout must not be invented as a reason for its own failure. The current explicit CLI has bounded output but no general command timeout; a new timeout is a proposed feature, not implemented behavior.
- Keep number, time, and output of probes bounded. Do not download model weights in the middle of a time-critical probe step. On unavailable commands, malformed observations or model failure, report the boundary and continue with facts that remain valid.
- Avoid avoidable cold-start model cost for basic outcomes. Laya and the generic GGUF interpreter are both opt-in; the default runs without inference or download.
- Generic GGUF inference currently requests llama.cpp `--device none` for every user-supplied model instead of trusting a sampled GPU peak as a 5 GB quota. This avoids model-weight GPU offload on a compatible runtime, but does not constrain host RAM, another process's VRAM, or a malicious explicitly selected runtime; CPU latency and timeout remain part of acceptance.

## 7. Modes and compatibility

Target product interface: `wtf -- PROGRAM [ARG ...]` for explicitly requested execution, `wtf --live -- PROGRAM [ARG ...]` for once-only live stdout/stderr forwarding with bounded diagnostic capture, and `wtf` for a metadata-only recent shell failure after `wtf install`. Installation additionally defines an opt-in `wtfr PROGRAM [ARG ...]` Bash/Zsh/Fish wrapper around `wtf --live --`; it does not intercept arbitrary shell commands. `--verbose`, `--json`, `--show-output`, `--no-color` select output (live mode excludes JSON and show-output). `--fix` may show a supported remedy but never apply it. `--interpreter-model GGUF` opt-in invokes local llama.cpp `llama serve --device none` over a private Unix socket on redacted, bounded execution and eligible probe evidence; `--interpreter-runtime PATH` selects the runtime. No generic model is promoted by default. `--model` / `--model-dir` remain separate Laya advisory ranking; `--no-model` suppresses both.

The CLI builds a generic result and evidence-linked report for arbitrary commands, with deterministic specializations for recognized cases. A generic model response must cite available evidence IDs, remain POSSIBLE and may be dropped entirely on invalid JSON, uncertain temporal scope or failure. The validator enforces structure and reference/length checks, but **cannot establish semantic truth or guarantee full redaction**. Generic inference is a measured experiment, not a proven diagnosis of arbitrary failures. Cargo, Git, curl, Docker and Linux systemd adapters are specializations; Cargo cannot automatically run `check` as a read-only probe. `wtf-train` is offline and does not select runtime probes.

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

### Measured status of the opt-in interpreter

The [three-model development tournament](docs/model-candidates.md) used nine single-execution process fixtures. Phi and Qwen supplied a tentative explanation in five informative cases each, but **0/5 new supported contributions** and one misleading permission claim per model; Granite cited invalid IDs in all five. Before opening the seven family-disjoint reserved fixtures, the selected Phi model/runtime/prompt/code and scoring criteria were [frozen](docs/generic-freeze.json). The [reserved paired reports](docs/reserved-evaluation.md) show at most one new supported tentative cause in seven cases, one false MISSING, two invalid model responses, and two preauthored oracle exit-status mismatches (though the controlled fixture conditions were retained). The model remains opt-in. **Generalization outside the corpus: not established.** The validator checks syntax/provenance IDs and a few certainty phrases but cannot verify causal truth of arbitrary text; the misleading development case demonstrates this limit. With model rows displayed, the current renderer can show four information rows instead of the three-row target.

After the adapter/probe and opt-in live-capture cutover, a [fresh six-family sealed follow-up](docs/followup-evaluation.md) compared the then-current generic prompt on a CPU-only runtime against the deterministic baseline. All six oracle statuses matched their single source executions; 24 replay statuses matched. **0/6 new supported contributions, five invalid evidence-reference fallbacks, and one misleading `date` format claim** do not justify making inference default. `diff` exit 1, a normal difference status, exposed a deterministic semantic gap subsequently corrected by neutral unknown-result wording; do not present this corpus as proof of arbitrary-command diagnosis. The previous frozen binary and GPU comparisons remain historical records, not measurements of the current binary.

A later [development-only prompt comparison](docs/lab.md#rejected-evidence-id-prompt-experiment-development-only) listed allowable evidence IDs explicitly. It eliminated five Granite reference errors on the reused development cases but surfaced a false permission/sudo claim; Phi accepted fewer responses and still made a false claim. That prompt was reverted: making a reference syntactically valid is not evidence that its explanation is true. No model was promoted.

## 9. Autonomous research focus

The nine-hour development objective is a **generic, output-aware diagnosis path**, not more adapter coverage or better ranking of an adapter's candidates. For any failed executable with captured output, WTF should attempt to explain the specific failure using that output and available safe evidence, with a tentative cause or a discriminating next check when warranted. A changed model score, generic paraphrase of stderr, or a rules-only report is not success. The reported synthetic curl exit-7 case changed no user-facing result with Laya; its scores came from different candidate sets and are not a proof of accuracy.

Use the unattended window for one end-to-end vertical slice, in this priority order:

1. **Capture and baseline (first).** Trace the real `wtf -- PROGRAM` data path and freeze the current no-model output for several isolated, unfamiliar programs with independently known failures. Include stderr with meaningful clues, misleading/noisy or truncated output, success, and absent output. Record exactly what the generic path can see; no adapter-specific fixtures as substitutes for unknown commands. Keep development and held-out failure families separate.
2. **General interpreter (opt-in implemented).** The local GGUF interpreter receives bounded redacted excerpts and eligible current probe observations for every failed executable, returns tentative POSSIBLE/MISSING/NEXT fields, and is validated before display. Its fixed-argument runtime cannot execute model-generated commands; model absence/timeout/invalid response retains the deterministic report. The default remains without inference pending reserved-family evidence. This does not prove truth of generated statements or arbitrary-secret redaction.
3. **Normal-terminal experience (explicit opt-in only).** `wtf -- PROGRAM` captures output once without printing it; `wtf --live -- PROGRAM` and installed `wtfr PROGRAM` display raw child output while keeping bounded diagnostic excerpts. Neither mode replays the command. The metadata-only hook still cannot see stdout/stderr of an ordinary unwrapped shell command, and bare `wtf` is not output-aware. Explicit modes inherit stdin but pipe stdout/stderr, so TTY-dependent interactive commands are not supported. Live mode forwards binary bytes unchanged to the same output streams, while diagnosis excerpts decode lossily. Signal exits return conventional `128 + signal`.
4. **Paired proof (before promotion).** Run identical held-out failures through the current no-model path and the generic interpreter; Laya is an optional control, not the research focus. Measure case by case whether a reader learns a **new, supported** possible cause or discriminating next check, plus false claims, abstentions, privacy/safety, latency and fallback. Use independently established fixture truth for historical causes, never a later probe alone. Report denominators and the exact report delta. If generic coverage and usefulness do not improve without safety/factual regressions, keep the path opt-in and say why; never promote on a different ranking or nicer wording.

The live path is for a human terminal, not a byte-transparent pipeline: the report appends text to stdout after the child stream. Redirecting that stream into a file/consumer contaminates it, and a broken downstream pipe need not reproduce the child's direct-pipeline timing. Do not claim shell-wide interception, exact pipeline semantics, or true TTY compatibility.

The deliverable is working CLI behavior plus a family-disjoint evaluation and runnable commands, or a precise blocked/negative result with all reachable work complete. Run `make fmt-check`, `make test`, isolated evaluation and a real CLI smoke path after changes; update README to distinguish implemented behavior from the target. Time and AI-token usage may be generous; spend them iterating on observable user value, not manufacturing cases or polishing a taxonomy. No recorded command replay, model-generated shell execution, unapproved state-changing probes, real credentials, hosted inference, automatic weight downloads, shared Docker daemon or publication without explicit authorization. Held-out cases must not be used as training examples or prompt demonstrations in the same comparison.

## 10. Scope and direction

Initial environment: Rust CLI on Linux, with existing Bash/Zsh/Fish support and existing local adapters retained. Portability improvements are welcome but not required to prove the generic interface. Python is not required to run WTF. Non-goals: automatically fixing the user's system, writing application code, making an authoritative claim about every failure, executing arbitrary model-generated shell commands, and sending local context to a hosted AI by default.

The product is a **brief, attractive view of what is known now and a safe path to learn more**, not a catalogue of error strings or a root-cause oracle.
