# Decision training data and counterfactual replay

`wtf-train` is separate from the diagnostic CLI. The live `wtf` CLI still uses the fixed deterministic investigation order; its ONNX model ranks hypotheses **after** investigation. Neither `replay-disk` nor a trained next-probe bundle changes that behavior.

This dataset and trainer explore **probe order**, not the open-family generative interpretation objective in [SPEC §9](../SPEC.md#9-autonomous-research-focus). The existing small, abstention-only records cannot demonstrate improvement in tentative cause or next-check usefulness. Keep this track separate from any family-disjoint, paired evaluation of a local model interpreting bounded, redacted failure evidence; a trained probe-choice bundle is not an implementation of that objective.

## Decision record

`wtf.probe-choice.v1` is JSONL: one pre-probe decision per line. Required fields are `schema`, opaque `example_id`, opaque `family_id`, `state`, `offered`, and `target`. The model sees only `state` and the ordered `offered` ProbeIds plus `abstain`; IDs/families are split metadata and never model inputs. `state` contains a category, ordered hypothesis IDs and statuses, and prior probe IDs with coarse outcomes. Raw output, commands, paths and logs are not allowed. `target` must be a currently offered probe or `abstain`.

The deterministic engine must construct the offered fixed-argument probes and establish that each one is ready, safe and within the investigation budget. The JSONL validator verifies names, shape, distinct offers, exclusion of `CargoCheck`, and target membership; it **cannot** retrospectively establish real readiness. Training rejects overlapping families, duplicate example IDs, contradictory labels on identical model-visible state/ordered offers, and an all-abstain training split. Splits must be made by failure family, not by row. `abstain` means use the existing deterministic order, not terminate investigation.

## Existing data and provenance

`crates/wtf-train/data/abstention-train.jsonl` has two Git abstentions;
`abstention-validation.jsonl` has one filesystem abstention. Their
family IDs are disjoint. These are boundary examples, not a usable
training/evaluation corpus: no positive next-probe labels are established.
Do not train on these files alone or label a fixture by whichever probe
the current engine happened to run first.

- `git-unrelated-changes` derives from
  `crates/wtf-core/tests/investigation_tests.rs`
  (`git_changes_are_not_claimed_to_cause_an_unrelated_failure`).
  `GitStatus` and `GitDiff` are runnable but neither proves causality.
- `git-upstream-needs-both` derives from the
  `push_without_upstream_is_reported_using_branch_name_only` fixture in
  `crates/wtf-core/src/adapters/git.rs`. After an absent upstream, both
  `GitRemote` and `GitPorcelain` are needed for confirmation; abstention
  preserves deterministic continuation.
- `disk-before-block-or-inode` follows the block-full fixture in
  `crates/wtf-cli/tests/model_evaluation.rs` and the inode-full
  calibration case in `crates/wtf-core/tests/calibration_matrix.rs`.
  They share the same model-visible state before probing; different
  first probes minimize probe count, but both orders can confirm
  within the default budget. Neither is a justified positive label.

## Offline replay

Run:

```sh
cargo run --locked -p wtf-train -- replay-disk
```

The `counterfactual-replay` feature of `wtf-core` is enabled by `wtf-train`, not by the ordinary `wtf` package dependency. The core computes one disk decision point with exactly `Filesystem` and `FilesystemInodes`, checks its two `ProbeSpec`s and tool availability without running a probe, and interprets either order using the **same** disk evidence logic as production. Normal investigation remains blocks-first. A fresh scripted runner and deadline are used for each order; the runner verifies actual `df -P`/`df -Pi` arguments, target, working directory and `Safe` classification. It never executes `df`, the original failed command, a shell with captured text, or a fix. JSON output includes only allowlisted pre-probe state, offered IDs, budget, attempt IDs/count and typed oracle comparisons; no target path or probe output is printed.

The four transient fixtures declare their expected outcomes separately from their scripted responses: blocks full, inodes full, both below full, and block probe timeout followed by full inodes. Each is replayed with the same two-second time limit under one- and five-probe count budgets and both first probes (16 trajectories). A one-probe budget selects opposing winners in block-full versus inode-full cases, **despite identical model-visible inputs**. With the ordinary five-probe count budget, either order reaches the correct confirmed capacity cause in the positive fixtures. Both below-full reports on the same mount reject a current-full hypothesis, not prove a quota cause. A timeout followed by inode proof can still confirm; unavailable evidence alone cannot. This scripted exercise checks engine semantics, not empirical real-world accuracy or measured latency.

### Git no-upstream choice

Run `cargo run --locked -p wtf-train -- replay-git`. This opt-in replay creates isolated temporary local Git repositories and captures only the fixed safe `git rev-parse --show-toplevel`, `git branch --show-current`, upstream lookup, `git remote` **names only**, and `git status --porcelain=v2 --branch` outputs. It does not run the original `git push`, contact a remote, inspect remote URL values, or write replay records. A synthetic output-free failed push lets the core Git adapter reach the actual point after `GitTopLevel`, `GitBranch`, and failed `GitUpstream`. The adapter verifies both follow-up probes are safe and individually runnable, captures the actual coarse pre-probe outcomes, and interprets either follow-up order with its unchanged finding logic. Each trajectory has a fresh runner and the same two-second deadline and count budget. JSON contains only typed cases, probe IDs/outcomes, root classifications and oracle comparisons; no Git output, branch name, URL, commit hash or temporary path.

The independent local oracle checks config **key names** for remote/upstream presence and whether `HEAD^{commit}` exists, without using the adapter's finding. The four repository states are committed with a remote but no upstream, committed without a remote, remote without a commit, and configured upstream. The last never reaches this choice point. At budget four, three earlier probes leave one follow-up: neither order confirms the positive no-upstream cause. At the ordinary budget five, both orders confirm that cause; neither confirms a root in the two negative cases. These 12 trajectories provide no superior first probe and no positive training label. The failure exit is synthetic rather than an independently observed failed push; these fixtures demonstrate the reconstruction decision, not a field-measured improvement.

### Experimental Unix-domain sockets (not a runtime choice)

Run `cargo run --locked -p wtf-train -- replay-unix-socket` on Linux with `stat` and `ss` installed. Temporary local fixtures hold a listening pathname socket, leave a socket inode after closing its listener, leave the path absent, or create a listener **between** the two captured probes. The independent fixture oracle uses its held listener and filesystem metadata. The fixed `Stat` probe and feature-gated `UnixListeners` probe (`ss -xlnH src <bounded absolute path>`, without process details) are captured once per fixture with bounded output, then replayed in both orders with fresh runners under one- and two-probe budgets and a two-second deadline. The original failed command is never executed; there is no network contact or modification outside the temporary fixture. JSON contains only typed observations, oracle state, coarse attempt statuses and IDs, not the target path or raw command output.

Sixteen trajectories result: with one probe, neither order can classify the current socket state; with two, both orders agree for stable active, residual-inode and absent cases. Capturing `stat` before creation and `ss` afterward produces an inconsistent pair even though the final oracle state is active. These observations **do not establish a historical failure cause**: a socket can change between the failed command and inspection or between probes. No trajectory confirms a root, and neither order improves correct confirmed roots. `UnixListeners` and this experimental pair are unavailable to the ordinary CLI and explicitly rejected by the JSONL training validator; the reported pair is **not** an engine-offered decision under SPEC §7. No training labels are generated.

## Next evidence gate

To justify positive labels, gather additional independently adjudicated failures where two or more safe probes are simultaneously ready, then replay all offered first choices from the **same pre-probe snapshot**, with the same continuation rules and budgets. Require a difference in *correct confirmed roots* that is predictable from payload-free state; neither a shorter trace nor a post-probe fact is a valid pre-probe label. Keep candidate families separate from the holdout and require no extra false confirmations, forbidden probes or budget regressions before enabling a model choice in `wtf`.

Actual Laya fine-tuning additionally needs the locally installed PyTorch/Safetensors checkpoint and Python ML dependencies; the existing ONNX download cannot be fine-tuned. No model training or new corpus generation occurs during replay.
