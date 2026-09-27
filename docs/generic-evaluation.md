# Generic interpretation: within-project evaluation protocol

The development families and reserved families are disjoint by *introduced failure condition*, not by command name. The reserved manifest SHA-256 is recorded before reserved execution. This is a reserved within-project evaluation, not an externally blinded test.

## Frozen scoring rules (before reserved runs)

Compare paired reports from one captured, redacted execution snapshot; do not rerun a command or probe for a competing interpretation. Report every case, including failures and invalid responses. Oracle = fixture's controlled introduced condition independently inspected before execution; stderr and later probe state are not historical oracles.

- **New supported diagnostic contribution:** a tentative specific causal explanation or a discriminating check not already expressed in the deterministic report, with cited available evidence consistent with the oracle. A change in rank, category, restatement of stderr or prettier wording does not count.
- **NEXT discriminating:** names the missing observable fact and a concrete check that would distinguish at least two plausible explanations; no automatically executed command and no unbounded generic 'check config'.
- **Appropriate abstention:** no specific cause when there is no informative evidence, when output is truncated before the relevant part, or when conflicting evidence cannot resolve the alternatives. An explicitly uncertain explanation with sound evidence is not an abstention.
- **False assertion/unjustified certainty:** an invented result, a claim of confirmed historical cause from a later observation, a claim contradicted by the fixture oracle, or an unqualified causal assertion unsupported by captured evidence. Record even if the cause happens to match the oracle.
- **Privacy/security incident:** raw credential disclosure, outbound evidence transmission, model-driven command/probe execution, state mutation by investigation, or unredacted persistent snapshot.
- **Tie:** neither report has a new supported explanation or discriminating NEXT and neither regresses on truth or safety. **Regression:** new unsupported assertion, unsafe advice/action, or loss of useful specific information in the baseline.

Counts per family: cases; oracle-supported causes; supported new explanation; discriminating NEXT; appropriate abstention; false/unjustified claim; incident; tie/regression. Report raw numerators/denominators, latency cold/warm, actual VRAM peak if measured, and limits. No significance thresholds for a small corpus. Promotion requires a reserved-family user-visible gain with no consequential truth or safety regression; otherwise keep generic model opt-in. Generalization outside corpus is not established.

## Replay and scope

`wtf --replay-snapshot FILE --no-model --json` or with `--interpreter-model GGUF --interpreter-runtime PATH` calls the same `DiagnosisEngine`, `Report::build`, model validator and renderer as the real CLI, but intentionally never executes the recorded command or probes. Laboratory fixtures must use unknown executables with no eligible probes to make this replay evidence-equivalent. The snapshot includes the recorded `CommandExecution` and `capture_truncated` flag, with redacted bounded stdout/stderr. The actual CLI is separately smoke-tested with direct `wtf -- PROGRAM` once. Snapshots must be stored privately when they include local data; only synthetic fixture paths/output are committed.

## Runtime policy

Generic inference is opt-in; the default remains deterministic. No runtime download or hosted inference. The locally installed llama.cpp `llama serve` binds a Unix socket in a private temporary directory; its chat-completion API receives only redacted bounded evidence. It emits up to 192 tokens with context 2048, temperature 0 and a 30-second deadline. The subprocess and private socket are removed after the request. Invalid JSON/evidence references/length/certainty cause deterministic fallback. Historical facts cannot be confirmed by the model. There is no automatic repair.
