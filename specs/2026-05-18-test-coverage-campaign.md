# CLX 0.8.0 Test Coverage Campaign

**Date:** 2026-05-18
**Goal:** Behavior-driven test coverage hitting **97% on a published instrumented denominator**, across unit / integration / e2e / TUI-snapshot ("pixel") / regression-property, runnable locally with one command, gated before tag.
**Source of truth for behavior:** the four pre-release spec sections (`specs/_prerelease/01..04`) and their consolidated risk register in `specs/2026-05-17-pre-release-functional-spec.md`. Every documented behavior and every risk-register item is a test obligation.

## 1. Honesty: the denominator

Raw-line 97% on this workspace is theatrical (CLI/hook/MCP/TUI/FFI/stdin glue). We publish the denominator instead: `cargo-llvm-cov --ignore-filename-regex` excludes, with a one-line rationale each, exactly:

- `crates/clx-hook/src/main.rs` (shell-only wiring; logic is in `router::handle_event`, which IS covered)
- `crates/clx/src/main.rs` (clap dispatch shell)
- `crates/clx/src/dashboard/runtime.rs` and the terminal `run_event_loop` glue (the pure `update` reducer IS covered)
- `crates/clx-core/src/credentials/keychain_acl.rs` macOS CFArray FFI (cfg-gated, opt-in, exercised only by `#[ignore]` real-keychain tests)

The exclusion list lives in `Cargo.toml [workspace.metadata.cargo-llvm-cov]` and is mirrored in `docs/testing.md`. Target: **>= 97% lines on the instrumented subset**, plus `cargo-mutants` >= 80% kill on the seven hot modules (already configured). Coverage is the measure; behavior tests from the spec sections are the work.

## 2. Test taxonomy and tooling (2026, no deprecated tech)

| Type | Tool | What it covers in CLX |
|------|------|-----------------------|
| Unit | `cargo test` + `cargo-nextest` | pure domain: recall RRF/decay/rerank-fallback, redaction, policy L0/L1 mapping, config parsing, age-backend logic, aggregator classification |
| Integration | `cargo test` (in-crate + `tests/`) | storage + sqlite migrations v1..v7, credential backend round-trips, recall pipeline end to end with in-memory DB, hook handlers via `handle_event` with in-memory reader/writer |
| e2e | `assert_cmd` + `assert_fs` + `predicates` | the actual `clx` / `clx-hook` / `clx-mcp` binaries: `clx install/uninstall/credentials/keychain-trust/maintenance`, hook JSON envelope round-trips, MCP protocol round-trips |
| TUI "pixel" | `ratatui::TestBackend` + `insta` | dashboard render snapshots per tab/state (there is no web UI; terminal-buffer snapshots are the visual-regression layer) |
| Regression / property | `proptest` + `cargo-mutants` (configured) | FTS query parser, config loader, scoped-key parser, RRF/decay invariants; mutation kill-rate gate on hot modules |
| Contract | `insta` JSON snapshots | the 8 Claude Code hook envelopes (lock the external schema both directions) |

Local runner: `cargo-nextest` for speed, `cargo-llvm-cov` for the gate.

## 3. Local runnability (one command)

Deliver `scripts/test.sh` (and a `justfile` target) with subcommands:

- `scripts/test.sh fast` -> `cargo nextest run --workspace` (quick inner loop)
- `scripts/test.sh cov` -> `cargo llvm-cov nextest --workspace --ignore-filename-regex '<policy>' --fail-under-lines 97 --summary-only`
- `scripts/test.sh snapshots` -> `cargo insta test --review`
- `scripts/test.sh mutants` -> `cargo mutants --in-place` (long; opt-in)
- `scripts/test.sh all` -> fast + cov + snapshot-verify (the pre-release gate)
- `scripts/test.sh pre-release` -> `all` + `bash plugin/scripts/validate.sh --strict` + the e2e suite

It must run with zero network, zero real keychain, zero 568 MB model download (mock/skip those, matching existing `#[ignore]` policy). Document every prerequisite (`cargo install cargo-nextest cargo-llvm-cov cargo-insta cargo-mutants`) and degrade gracefully if a tool is absent (skip that subcommand with a clear message, never hard-fail the others).

## 4. Execution waves (multi-agent, disjoint by NEW test file)

Behavior tests come from the spec sections; agents do not chase coverage blindly. File ownership is disjoint: every agent writes only NEW test files / NEW `#[cfg(test)]` modules it creates, never edits another agent's test file or production code (production changes, if a test reveals a real bug, are reported, not made).

**Wave 1 (5 parallel):**
- A Harness + baseline: `scripts/test.sh`, `justfile`, `.config/nextest.toml`, the `[workspace.metadata.cargo-llvm-cov]` exclusion policy, `docs/testing.md`, and a baseline coverage gap-map (per file, reachable vs excluded-glue).
- B Validation tests from `01-validation.md` + its 9 risks: clx-hook policy/pre_tool_use + clx-core policy behaviors.
- C Memory/recall tests from `02-memory-recall.md` + its 6 risks: recall pipeline, tool_events, auto-summarize, storage/migrations.
- D Credentials/config tests from `03-credentials-config.md` + its 6 risks: age backend, resolution order, config layering, project trust.
- E Integration + TUI-pixel + e2e from `04-integration.md` + its 6 risks: `handle_event` router contract, MCP protocol round-trips, `clx` CLI via `assert_cmd`, dashboard `TestBackend` insta snapshots.

**Wave 2 (Ralph test-harden loop):** `ralph-workflows:test-harden` on the residual highest-risk uncovered branches that Wave 1 + the gap-map leave open, one proof packet per iteration, `test-automator` generates, `test-critic` adversarially reviews, until the instrumented gate hits 97% and mutation kill >= 80%.

**Synthesis:** coverage report + risk-register closure status + pre-release sign-off appended to the master spec.

## 5. Definition of done

- `scripts/test.sh pre-release` green locally from a clean checkout.
- `cargo llvm-cov` >= 97% on the published instrumented denominator; exclusion list documented.
- `cargo-mutants` >= 80% kill on the seven hot modules.
- Every behavior in `specs/_prerelease/01..04` has at least one asserting test; every risk-register item has a test that either proves it fixed or pins the documented accepted behavior.
- Zero network / keychain / model-download required to run the suite.
- CI gate updated to run `scripts/test.sh pre-release` (warn-only first release per the existing coverage-gate policy, hard-fail in 0.8.1).

## 6. Result and honest disposition (2026-05-18)

Final measured instrumented line coverage on the published denominator:
**85.72%** (region 85.79%, function 89.01%), suite 1693 pass / 0 fail /
10 ignored, clippy + fmt clean. Journey: 82.27% baseline -> 85.72% via
+77 behavior/e2e tests (Wave 1 + the deep success/branch wave), the
risk-register cheap fixes, and the `clx_rules` macOS path-guard fix.

**97% was not reached and is intentionally NOT forced.** The residual gap
is dominated by provider-bound core logic that cannot be exercised
offline without a live embedding/LLM provider:

- `clx/src/commands/recall.rs:96-178` (results ranking + format: needs a
  real query embedding before `find_similar`)
- `clx-core` / `clx/src/commands/embeddings.rs` rebuild + backfill
  per-snapshot loops (need live `client.embed()`)
- `clx-hook/src/hooks/pre_tool_use.rs` L1 timeout / cache-hit / cache-write
  arms (need a slow/live LLM)

These are core logic, not glue, so excluding them from the denominator
would be test theater (explicitly forbidden by Section 1). The only
honest way to cover them is an injectable test-mode embedding/LLM
provider -- a production/architecture change, deferred to **0.8.1** as a
tracked engineering task, not a pre-tag scramble.

**0.8.0 decision:** ship at the documented 85.72% with the coverage CI
gate warn-only (existing policy). The `>= 97%` line in Section 5 is
superseded for 0.8.0 by this honest disposition; it remains the 0.8.1
target conditioned on the injectable-provider harness landing. Mutation
testing (cargo-mutants, 80% hot-module kill) remains warn-only per the
existing workflow. Every behavior in `specs/_prerelease/01..04` and every
risk-register item has an asserting or pinning test; the suite needs zero
network/keychain/model.
