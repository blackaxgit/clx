# CLX Coverage Campaign v2 — Injectable Provider Seams to >=97%

**Date:** 2026-05-19
**Base:** main @ v0.8.0 (post-release). Work targets the next release line.
**Goal:** lift instrumented line coverage **85.72% -> >=97%** on the existing
published denominator (NO new exclusions — that is forbidden test theater),
plus **cargo-mutants >= 80% caught** on hot modules, with the whole suite
runnable locally by one command, hermetic (no network / keychain / model
download), and gated before any future tag.
**Inputs (authoritative, already produced):**
- 2026 best-practices research: `specs/2026-05-19-coverage-research.md`
- File:line gap map: `specs/2026-05-19-coverage-gap-map.md`
- Prior campaign disposition: `specs/2026-05-18-test-coverage-campaign.md` S6
- Behavior specs + risk register: `specs/_prerelease/01..04`, `risk-triage.md`

This document is the implementation prompt. It is grounded in real
file:line refs; agents must re-verify line numbers against the working
tree before editing (the codebase moves).

---

## 1. Analysis -> the gap is three provider seams, nothing else

The 85.72% -> 97% delta is **dominated by three provider-coupled regions**,
all blocked by the same root cause: command/hook handlers construct
`Config::create_llm_client()` / call `EmbeddingStore::find_similar()` by
concrete name with no injection point. The residual non-provider gap is
negligible (risk-register items are cheap-fix-landed or accepted-and-pinned;
the only non-provider uncovered glue is already legitimately excluded).

The **seam pattern already works in production**: `clx-mcp` recall drives
everything through `RecallEngine` + the `QueryEmbedder` port +
`LlmQueryEmbedder` adapter and is fully covered offline by a wiremock
Ollama (`recall_behavior.rs:431-472`). The job is to bring `recall.rs`,
`embeddings.rs`, and `pre_tool_use.rs` to that same discipline.

## 2. Architecture decisions (from the 2026 research — non-negotiable)

1. **No test theater.** Substitute only the I/O boundary with hand-rolled
   deterministic fakes; the real RRF / cache / timeout / format logic must
   execute. `mockall` only for call-count/error-injection edge cases, never
   as the primary substitution. A test that covers a line but asserts no
   behaviour is killed by the mutation gate by design.
2. **Seam shape.** Reuse existing traits where present (`QueryEmbedder`
   port; `LocalLlmBackend`/`LlmBackend` already has `embed`/`is_available`).
   New seams use generics (`P: Trait`) monomorphized, declared
   `#[trait_variant::make(Send)]`; introduce a boxed-future `dyn` boundary
   only if a heterogeneous registry genuinely needs it (it does not here).
   Do NOT add `async-trait` (legacy/boxing tax). Architecture over
   minimalism (CLAUDE.md): prefer the port refactor over a `#[cfg(test)]`
   constructor hack.
3. **Offline guarantees.** Tests never construct `fastembed`/`ort`. Keep
   the hermetic env (`CLX_MODEL_FETCH_DRYRUN=1`, `CLX_CREDENTIALS_BACKEND=age`).
   Keep all 10 `#[ignore]` real-keychain tests ignored; never pass
   `--run-ignored`.
4. **Denominator integrity.** The `ignore-filename-regex` in `Cargo.toml`,
   `scripts/test.sh`, and `docs/testing.md` must stay byte-identical and
   unchanged. Add a CI/`just` drift guard turning that convention into an
   enforced invariant. Adding any exclusion to hit 97% is forbidden.
5. **Dual gate.** Done = `scripts/test.sh cov` >= 97% line on the published
   denominator AND `scripts/test.sh mutants` >= 80% caught on hot modules
   AND adversarial behavior-contract review passes. Line gate is the
   contract; region coverage tracked informationally; branch coverage NOT
   gated (still nightly/unstable in 2026).

## 3. The three seams (engineering surface)

### Seam A — Recall CLI (`crates/clx/src/commands/recall.rs`)
Refactor the post-embedding ranking/format out of `cmd_recall` into a pure
function driven by the existing `QueryEmbedder` port / `RecallEngine`,
mirroring `clx-mcp/src/tools/recall.rs:26-128`. Production builds
`LlmQueryEmbedder`; tests inject a fake `QueryEmbedder`. Unifies CLI+MCP
recall and deletes the duplicated raw `find_similar` path. Covers
`recall.rs:96-178` (json + human, empty + non-empty).

### Seam B — Embeddings CLI (`crates/clx/src/commands/embeddings.rs`)
Extract the per-snapshot embed loop into a pure
`rebuild_embeddings<E: EmbedClient>(...)` / backfill equivalent, where
`EmbedClient` reuses the existing `LlmBackend` surface (`embed`,
`is_available`). Production passes `&LlmClient` (close the trait with a
thin adapter); tests pass a fake. Covers `embeddings.rs:246-282` and
`:394-445` (processed/skipped/errors/dry-run permutations).

### Seam C — Hook L1 orchestration (`crates/clx-hook/src/hooks/pre_tool_use.rs`)
Lowest-risk = config-driven e2e: write a config into
`support::isolated_clx_home()` pointing the `ollama` provider `base_url`
at a wiremock server; drive the real `clx-hook` binary on an L0=Ask
command. **Zero production change** (Ollama backend already takes a base
URL). Covers `:223-545` (cache hit/write, timeout, LLM-unavailable,
allow/deny/ask side effects + audit/health writes). The cache-*hit* arm
(`:223-252`) is reachable today with NO provider by pre-seeding
`storage.cache_decision(...)` — land that sub-task first (cheap win).
If a unit seam is also wanted, add `handle_pre_tool_use_with(input,
client_factory)` and keep the public fn a thin wrapper.

## 4. Test taxonomy (2026 stack — no deprecated tech)

| Layer | Tool | Applied here |
|---|---|---|
| Unit | nextest + `#[cfg(test)]` | seam pure fns against hand fakes (RRF, loop counts, decision arms) |
| Property | proptest | RRF monotonicity, format never panics, count invariants |
| Integration | `tests/` + wiremock + in-memory sqlite | port-driven recall, embed-loop, L1 matrix |
| e2e | assert_cmd/assert_fs | real `clx`/`clx-hook` binaries via config-in-sandbox |
| Pixel | insta TestBackend | snapshot `recall.rs:143-178` human format (redact volatile) |
| Contract | insta JSON | recall JSON + hook envelopes, redacted |
| Regression/mutation | cargo-mutants | hot modules >=80% caught (the anti-overfit discriminator) |

`async-trait`-as-enabler, tarpaulin, branch-coverage gating, mockall-as-
default, non-redacted-timestamp snapshots = explicitly rejected.

## 5. Multi-agent execution (disjoint file ownership)

Orchestrator = main session (this). Streams run in parallel; each owns a
disjoint production file + its NEW test files. Production seam refactors
are reviewed four-eyes by a separate critic before merge.

- **Stream 1 (Seam A):** `commands/recall.rs` + new
  `crates/clx/tests/cli_recall_semantic_e2e.rs`.
- **Stream 2 (Seam B):** `commands/embeddings.rs` + new
  `crates/clx-core/tests/embeddings_loop_behavior.rs`.
- **Stream 3 (Seam C):** `hooks/pre_tool_use.rs` + new
  `crates/clx-hook/tests/pre_tool_use_l1_e2e.rs` (cache-hit-preseed
  sub-task first; it has no production dependency).
- **Stream 4 (harness/guard):** `just verify-denominator` drift guard +
  `testkit` feature exposing the hand fakes to `tests/` + `mutants.toml`
  hot-module scope + measurement after each merge.

Then a **Ralph test-harden loop** on whatever residual the four streams
leave: generator (`test-automator`) proposes tests + a proof packet
(failing-before/passing-after, coverage delta on the *published*
denominator, mutation-kill delta); adversarial critic (`test-critic`)
mutates the impl and rejects any test that pins implementation instead of
behavior; iterate until the dual gate is green. Hard caps: max iterations,
explicit completion gate, scoped permissions, agents never `git commit`
(orchestrator commits after synthesis + verification).

## 6. Definition of done

- `bash scripts/test.sh pre-release` green from a clean checkout, zero
  network/keychain/model.
- `scripts/test.sh cov` >= 97% line on the **unchanged** published
  denominator; `just verify-denominator` passes (regex byte-identical
  across the 3 files).
- `scripts/test.sh mutants` >= 80% caught on hot modules.
- Every behavior in `specs/_prerelease/01..04` and every risk-register
  item has an asserting-or-pinning test.
- Each seam refactor passed independent four-eyes review for layering
  (ports in `recall::`, infra in adapters) and no security-constraint
  weakening.
- `specs/2026-05-18-test-coverage-campaign.md` S6 updated with the new
  honest measured number; CHANGELOG "Known issues" coverage line updated.

## 7. Result and honest disposition (2026-05-19)

Final measured instrumented line coverage on the **unchanged** published
denominator: **89.99%** (region 90.19%, function 91.15%), suite
**1869 pass / 0 fail / 9 ignored**, clippy + fmt clean, `cargo insta
test --workspace --check` clean (snapshots machine-independent on short
and long HOME). Journey: 85.72% (0.8.0 baseline) -> 86.82% (3 reviewed
provider seams: recall port, embeddings extraction, hook-L1 e2e + the
Review-A `open_default` placement fix + dead-branch removal) -> **89.99%**
(four honest harden streams: dashboard reducers/state/data, TUI
pixel/contract snapshots, trust/rules/config/credentials e2e,
version/maintenance/model e2e). +158 net tests in the harden wave;
each stream self-validated with a fault-model mutation gate
(3-5 realistic mutants killed for the expected reason).

**97% was not reached and is intentionally NOT forced.** The gap-map's
premise (delta dominated by three provider seams) was wrong; a live
`cargo-llvm-cov` run showed the residual is a broad CLI/TUI surface. The
honest ceiling under the project's hard constraints (no test theater; no
`unsafe` env mutation since `unsafe_code = "deny"`; no `CLX_HOME`
override, deliberately rejected for credential-redirection security) is
~90%. The remaining ~4066 uncovered lines are dominated by:

- `clx/src/commands/install.rs` (~460): system-mutating install flow
  (PATH/binary/config writes) -- not hermetically exercisable; deferred
  by explicit user decision ("treat separately").
- `clx/src/commands/health.rs` (~260): live process/socket probing.
- `clx/src/dashboard/app.rs` (~170): `settings_save`/`reload` real
  `~/.clx` disk I/O, structurally non-hermetic because `unsafe_code =
  "deny"` blocks `$HOME` redirection and there is no `CLX_HOME` seam.
- smaller boundary-limited residuals (`clx-mcp` remember/credentials,
  hook session_start, rules.rs config-source arms unreachable via the
  command boundary) -- disclosed with line refs by each stream, pinned
  where a behavior contract applies, never padded with theater.

These are core/system logic, not glue, so excluding them from the
denominator would be test theater (forbidden by S2). Closing them needs
either heavy sandboxed-side-effect e2e scaffolding (install/health) or a
`CLX_HOME` testability seam whose security trade-off was rejected --
tracked, not a forced number.

**Decision:** ship the campaign at the documented **89.99%** with the
coverage CI gate warn-only (existing policy); the `>= 97%` line in S6 is
superseded for this cycle by this honest disposition. Mutation testing
remains warn-only per existing workflow (per-stream fault-model gates
applied). install.rs/health.rs heavy-e2e is the tracked follow-on.
