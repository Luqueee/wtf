# AGENTS.md

## Project objective

WTF is a local-first Rust CLI that diagnoses failed terminal commands from captured output or safe, bounded local evidence. Read `SPEC.md` before behavior changes; distinguish implemented features from planned scope.

## Project structure

- `crates/wtf-core`: execution capture, normalization, entities, deterministic detectors, probes, adapters, and investigation.
- `crates/wtf-cli`: CLI, output rendering, shell installation, and recent-failure state.
- `crates/*/tests` and module tests: core and CLI test coverage.
- `scripts/`: test helpers.
- `README.md`: user-facing setup and usage.

## Workflow

1. Read the relevant specification and existing implementation/tests before editing.
2. Keep changes within the owning crate; reuse existing patterns instead of adding parallel abstractions.
3. For behavior changes, add/update deterministic tests that exercise the observable behavior and important failure boundaries.
4. Run `make fmt-check` and `make test`. For CLI changes, smoke-test the affected command or isolated shell flow; for end-to-end coverage, use `make e2e`. Docker E2E is opt-in via `make e2e-docker` because it uses the shared daemon.
5. Update `README.md` when user-visible behavior, setup, or limitations change.

## How to work safely

- Keep diagnosis local. Shell hooks record bounded, redacted metadata only; they must not trigger probes or persist output.
- Construct probes only through the fixed-argument catalogue in `wtf-core/src/probes.rs`. Never replay the original action or invoke a shell with recorded command text.
- Preserve timeouts, output limits, and investigation budgets. Insufficient evidence means unknown/unconfirmed, not a guessed cause.
- Investigation must not apply fixes or change system state. Note that `cargo check` can run build scripts/procedural macros and writes artifacts.
- Git adapters must not inspect remote URLs; curl must not resend requests; Docker reconstruction must not start/run containers.
- Keep tests isolated from real Docker state, user shell configuration, ambient Git settings, and the network.
