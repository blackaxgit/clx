# CLX v0.9.0 Fix-Completion Multi-Agent Prompt

**Date:** 2026-05-20
**Base:** `chore/v0.9.0-rgp-prerelease` (RED gate committed at `3ca855c`)
**Inputs (authoritative):**
- `specs/2026-05-20-v090-red-findings.md` (release-blocking set + residuals)
- `specs/2026-05-20-v090-rgp-prerelease.md` (RGP procedure + GREEN/PURPLE prompts)
- `specs/2026-05-20-v090-rgp-research.md` (2026 delta best-practices)
- `crates/clx-hook/tests/v090_red_r1_poc.rs` + `v090_red_r2_poc.rs` (20 PoCs, ignore-gated)
- G1 worktree `agent-a299f92a005c3056f` (pre_tool_use hardening + audit_chain doc + new e2e)
- G2 worktree `agent-af519598a16d50c15` (docs honesty + clx health WARN)

**Flow:** parallel FIX-A + FIX-B → orchestrator integrated-verify → independent PURPLE → tag decision.

## Closure rubric (HARD)

Closure of any RED-confirmed finding requires the **evidence-bundle 4-tuple**:

1. **VERDICT** — `CLOSED` / `CLOSED-WITH-RESIDUAL` / `OPEN`.
2. **COUNTEREXAMPLE-NOW-FAILS** — the corresponding RED PoC in
   `v090_red_r1_poc.rs` / `v090_red_r2_poc.rs` must now FAIL under `cargo
   nextest --ignored`. This is the regression-pin — passing a new test is
   not sufficient; the prior vulnerable behaviour must be unreproducible.
3. **REGRESSION-PIN** — `file:line` of the fix + closing test file:line.
4. **RESIDUAL-UNCERTAINTY** — concrete scenario that would still bypass,
   even after the fix; if "none known", state the threat model that
   assumes that.

Numeric confidence (`97%`, `99%`, etc.) is forbidden as fabricated
precision. Use the four fields above and an evidence-strength label
(`strong / moderate / weak`) backed by the four fields.

## Scope & RoE (all phases)

- Authorized defensive testing of CLX's own v0.9.0 candidate before tag.
- Analysis + PoC only inside repo / a temp sandbox. No external hosts.
- Never reproduce the previously-leaked Azure key or its real tenant URL.
  Synthetic placeholders only.
- Severity = CVSS v4.0 base + SSVC + security-tool hard-override.
- Agents never `git commit` / `git push`. Orchestrator commits.
- Worktree-isolated streams. Disjoint file ownership between streams.

---

## FIX-A prompt (code + integration-test contract flip)

> You are FIX-A for the CLX v0.9.0 GREEN completion. Repo
> `/Users/blackax/Projects/clx`, branch `chore/v0.9.0-rgp-prerelease`.
> READ binding: `specs/2026-05-20-v090-red-findings.md` (the
> release-blocking set is your work queue), `specs/2026-05-20-v090-rgp-prerelease.md`
> (closure rubric + scope), `specs/2026-05-20-v090-fix-completion-multiagent.md`
> (this file).
>
> Owned files (disjoint from FIX-B):
> - `crates/clx-hook/src/hooks/pre_tool_use.rs`
> - `crates/clx-hook/src/audit_chain.rs`
> - `crates/clx-hook/tests/validation_e2e.rs`
> - `crates/clx-hook/tests/v090_g1_e2e.rs` (new)
> - `crates/clx-hook/tests/integration.rs` (the 1 contract-flip test)
>
> Reference (do NOT diff-apply blindly): G1 worktree at
> `/Users/blackax/Projects/clx/.claude/worktrees/agent-a299f92a005c3056f`
> contains the working draft. It was branched from `main` so its diff
> does not apply cleanly against the v0.9.0 baseline. You must
> reconstruct the hardening on top of the v0.9.0 baseline that already
> has `layer0_enabled`.
>
> GOAL — close release-blocker #1 (silent-allow class) with the
> smallest correct change matching the closure rubric.
>
> Required fixes:
>
> 1. **T9.1 cache-bypass.** Gate the SQLite decision cache lookup
>    (`pre_tool_use.rs:368-396` pre-baseline; in current code the cache
>    block is between the L0 short-circuits and the L1 client init) on
>    BOTH `layer0_enabled` and `layer1_enabled` being true. Cache is
>    populated only by L1 verdicts; consulting it when L1 is disabled
>    or L0 is bypassed silently replays a stale L1-allow as if L0
>    cleared the command.
>
> 2. **T9.2/T9.3/T9.4 fail-open arms.** In each of the three
>    fallback branches (LLM-client construction error,
>    Ollama-unavailable, L1 timeout) when `default_decision=allow` AND
>    the command did not match L0 deterministic rules (i.e. fell
>    through to L1), force `effective_decision="ask"`. The user must
>    make the decision; silent allow with no L1 scrutiny is the
>    F7-deferred posture this fix closes. `deny` and `ask` pass
>    through unchanged. Emit a `warn!` with the rationale. Update the
>    audit row reason to include `effective_decision` and the
>    configured value (do not silently swallow the configured value).
>
> 3. **T9.5 / L1 rename dual-emit.** Change the `Some("L1 disabled")`
>    reason string at the L1-disabled audit emit (`pre_tool_use.rs`
>    around line 400 in baseline) to
>    `Some("L1-DISABLED (alias: L1 disabled)")` — the
>    parallel-change one-version deprecation window. Plan removal in
>    v0.10.0.
>
> 4. **T2 learned-rules load-before-gate.** Move the
>    `policy_engine.load_learned_rules(&storage)` call inside an `if
>    config.validator.layer1_enabled` guard. When L1 is disabled the
>    learned-rules path is functionally dead, and a single overbroad
>    learned-allow row in B1-4 must not silently suppress the
>    L1-disabled-ask prompt.
>
> 5. **Integration-test contract flip.** Update
>    `crates/clx-hook/tests/integration.rs`
>    `test_hook_default_decision_allow_on_ollama_unavailable` to
>    assert `permissionDecision == "ask"` (not `"allow"`). Update the
>    assertion message to: `default_decision=allow with L1 unreachable
>    and command falling through to L1 must force ask (F7 posture
>    v0.9.0)`. Add an inline comment citing release-blocker #1 of
>    `specs/2026-05-20-v090-red-findings.md` and noting this is a
>    deliberate breaking-change in v0.9.0 closing the silent-allow
>    class. FIX-B owns the CHANGELOG BREAKING note.
>
> 6. **New regression e2e: `tests/v090_g1_e2e.rs`.** Behavior
>    contract tests (NOT implementation tests) for each closed
>    blocker. For each: synthetic config in temp HOME, command,
>    assertion of (decision, audit-row count, audit-row reason
>    contains expected substring). Minimum cases:
>    (a) L1 disabled + cache populated with prior allow → must NOT
>        consult cache (decision = ask).
>    (b) L0 unknown command + Ollama unreachable + default=allow →
>        decision = ask.
>    (c) L0 unknown command + L1 timeout + default=allow → decision
>        = ask.
>    (d) L0 unknown command + LLM-client construction error +
>        default=allow → decision = ask.
>    (e) L1 disabled audit reason contains both `"L1-DISABLED"` and
>        `"L1 disabled"` (dual-emit assertion).
>    (f) L1 disabled + learned-rules table populated with overbroad
>        allow → does NOT silently suppress the L1-DISABLED ask.
>
> 7. **`audit_chain.rs` doc note.** Add a `//` comment on the
>    SECURITY-CFG emit path noting that env+config double-disable
>    deliberately emits both rows (dual-signal intent, not a
>    deduplication bug) — this is the T3 disposition. No code
>    change required.
>
> Required regression-pin proof (closure rubric clause 2): after your
> fixes, the following PoCs in `crates/clx-hook/tests/v090_red_r1_poc.rs`
> and `crates/clx-hook/tests/v090_red_r2_poc.rs` MUST fail (i.e. the
> formerly-reproducible vulnerability no longer reproduces):
> - R1-F1 (silent-allow under L0-off + L1-down + allow)
> - T9.1 (cache-bypass)
> - T9.2, T9.3, T9.4 (LLM-unavailable, timeout, gen-failed)
>
> Verify by running:
>     `cargo nextest run -p clx-hook --test v090_red_r1_poc --
>      --ignored`
>     `cargo nextest run -p clx-hook --test v090_red_r2_poc --
>      --ignored`
> Expected: tests above FAIL. Document tail in your deliverable.
>
> Pinned gates (must all pass):
> - `cargo nextest run --workspace` (default suite, no `--ignored`):
>   all green.
> - `cargo clippy --workspace --all-targets -- -D warnings`: green.
> - `cargo fmt --all -- --check`: green.
>
> DELIVER a tail block per gate + a per-fix evidence bundle in
> `specs/2026-05-20-v090-fix-A-evidence.md`. Do NOT git commit. Do NOT
> touch files outside the owned set. If you hit a file outside the
> set, stop and surface it.

---

## FIX-B prompt (docs honesty + clx health WARN + BREAKING note)

> You are FIX-B for the CLX v0.9.0 GREEN completion. Repo
> `/Users/blackax/Projects/clx`, branch `chore/v0.9.0-rgp-prerelease`.
> READ binding: `specs/2026-05-20-v090-red-findings.md` (T8 / R1-F4
> doc-honesty over-claim + T7 both-off observability),
> `specs/2026-05-20-v090-rgp-prerelease.md` (constraint-integrity hard
> constraint), `specs/2026-05-20-v090-fix-completion-multiagent.md`.
>
> Owned files (disjoint from FIX-A):
> - `CHANGELOG.md`
> - `README.md`
> - `crates/clx/src/commands/health.rs`
> - `specs/_prerelease/01-validation.md`
>
> Reference (do NOT diff-apply blindly): G2 worktree at
> `/Users/blackax/Projects/clx/.claude/worktrees/agent-af519598a16d50c15`
> contains the working draft. Use as guidance; reconstruct on the
> current branch HEAD.
>
> Required fixes:
>
> 1. **T8 / R1-F4 doc-honesty downgrade.** In `README.md` (around
>    line 186 in the validator config block) and `CHANGELOG.md`
>    (`[Unreleased]` Security block, around lines 30-38), replace the
>    "tamper-evident audit-chain fingerprint" claim with the honest
>    v0.8.2-reclassify language: `per-event SHA-256 fingerprint
>    emitted to tracing::warn!; tamper-evident only when an external
>    append-only sink captures the anchor (SQLite alone is not
>    tamper-evident because a same-uid attacker can rewrite the
>    database file)`. Mirror the exact qualifier in both files.
>
> 2. **T7 both-off observability — `clx health` WARN.** In
>    `crates/clx/src/commands/health.rs`, add a WARN row when
>    `config.validator.enabled == true` AND
>    `config.validator.layer0_enabled == false` AND
>    `config.validator.layer1_enabled == false` (the both-off-while-
>    enabled pattern). Match the existing CLX_VALIDATOR_* env-override
>    WARN style. WARN text: `validator.enabled=true but both
>    layer0_enabled and layer1_enabled are false — every command
>    will resolve to ask; no actual validation is running. To disable
>    validation entirely, set enabled=false.` Include both `clx health`
>    (table) and `clx health --json` paths if they share rendering;
>    if they diverge, add to both.
>
> 3. **L1-DISABLED literal cleanup in spec.** In
>    `specs/_prerelease/01-validation.md` lines 150 and 422 (and any
>    other matches — grep
>    `"L1 disabled"` and update non-comment, non-dual-emit
>    references), update the literal to `"L1-DISABLED (with v0.9.0
>    dual-emit alias 'L1 disabled' retained for one minor version)"`.
>
> 4. **CHANGELOG BREAKING note for FIX-A's contract change.** Add a
>    `### Changed (BREAKING)` subsection under the `[Unreleased]`
>    block: `Hook now refuses default_decision=allow as silent
>    fallback when an L0-unknown command falls through to L1 and L1
>    is unreachable / times out / errors. The decision is forced to
>    'ask' so the user makes the call. Closes the F7-deferred silent-
>    allow class (see specs/2026-05-20-v090-red-findings.md
>    release-blocker #1). Affects users who configured
>    default_decision=allow with the prior fail-open behaviour. To
>    restore the prior behaviour explicitly, set
>    default_decision=allow AND ensure layer1_enabled=false; the
>    L1-DISABLED ask is then the loud gate.`
>
> Required test for clx health WARN: add a behavior test in
> `crates/clx/tests/cli_e2e.rs` (or the appropriate health test file)
> asserting that `clx health` with both-off + enabled=true emits the
> WARN row. Cite this as the closing-test for T7.
>
> Pinned gates:
> - `cargo nextest run -p clx`: green.
> - `cargo clippy --workspace --all-targets -- -D warnings`: green.
> - `cargo fmt --all -- --check`: green.
>
> DELIVER `specs/2026-05-20-v090-fix-B-evidence.md` — per fix:
> file:line, before/after diff snippet, residual risk, evidence-bundle
> 4-tuple. Do NOT git commit. Do NOT touch files outside the owned
> set.

---

## Orchestrator integrated-verify (after FIX-A + FIX-B collected)

Single-threaded on `chore/v0.9.0-rgp-prerelease`:

1. `cargo nextest run --workspace` — all green.
2. `cargo clippy --workspace --all-targets -- -D warnings` — green.
3. `cargo fmt --all -- --check` — green.
4. `cargo deny check` — green.
5. `cargo insta test --workspace --check` — green.
6. **Regression-pin proof:** `cargo nextest run -p clx-hook --test
   v090_red_r1_poc -- --ignored` and `cargo nextest run -p clx-hook
   --test v090_red_r2_poc -- --ignored`. Expected: the silent-allow
   class PoCs (R1-F1, T9.1, T9.2, T9.3, T9.4) **FAIL**. Other PoCs
   (audit-tamper-as-designed, both-off opacity once `clx health`
   covers it, etc.) status documented.
7. Commit per-stream: `feat(security): close v0.9.0 release-blocker
   #1 silent-allow class` and `docs(security): v0.9.0 honesty
   downgrade + clx health WARN + BREAKING note`. Subject-only. No
   AI signatures.

---

## PURPLE prompt (independent four-eyes, anti-anchoring)

> You are the PURPLE team for the CLX v0.9.0 go/no-go. Repo
> `/Users/blackax/Projects/clx`, branch
> `chore/v0.9.0-rgp-prerelease`. READ binding:
> - `specs/2026-05-20-v090-red-findings.md`
> - `specs/2026-05-20-v090-rgp-prerelease.md`
> - `specs/2026-05-20-v090-fix-A-evidence.md`
> - `specs/2026-05-20-v090-fix-B-evidence.md`
> - `specs/2026-05-20-v090-fix-completion-multiagent.md`
>
> **Anti-anchoring (HARD):** do NOT read the FIX-A / FIX-B working
> notes, the G1/G2 worktrees, or the v0.8.x PURPLE sign-offs as
> verdict sources. You may read them only to check specific claims
> against the current code. If you catch yourself reasoning "the fix
> evidence said this is fixed, so it is", stop and re-derive the
> attack against the CURRENT post-GREEN code path.
>
> GOAL: independently verify GREEN closed RED, no regression, and
> issue an auditable release verdict.
>
> For every release-blocking + HIGH RED finding:
> 1. Re-derive the original attack against the CURRENT post-GREEN
>    code and confirm it is neutralized — not just that a test
>    passes. Read the actual `pre_tool_use.rs` code paths and walk
>    the input through them.
> 2. Identify any GREEN-introduced regression or layering / security
>    weakening (e.g. an over-broad `force ask` that breaks legitimate
>    `default_decision=deny` flows; a clx health WARN that misfires;
>    a doc downgrade that under-claims and harms users; a dual-emit
>    that lies about timeline).
> 3. Re-score residual with CVSS v4 + SSVC; apply the security-tool
>    hard-override (any validator bypass without same-uid code-exec
>    is release-blocking).
> 4. Re-run every gate and paste tails: `cargo nextest run
>    --workspace`, `cargo clippy --workspace --all-targets -- -D
>    warnings`, `cargo fmt --all -- --check`, `cargo deny check`,
>    `cargo audit` if available, `cargo insta test --workspace
>    --check`, workflow YAML parse, AND `cargo nextest run -p
>    clx-hook --test v090_red_r1_poc -- --ignored` + `--test
>    v090_red_r2_poc -- --ignored` showing the formerly-vulnerable
>    PoCs now FAIL.
> 5. Disposition every accepted residual (T*-Track / accept-DOC) —
>    confirm each is honestly owned with rationale and not a silent
>    drop.
>
> Apply the evidence-bundle 4-tuple closure rubric per finding.
> Numeric percentages forbidden.
>
> Produce `specs/2026-05-20-v090-purple-signoff.md` — the 7-item
> auditable sign-off:
> 1. Scope + commit SHAs (RED gate, FIX-A commit, FIX-B commit).
> 2. Findings table with pre/post status + independent-verification
>    evidence per finding.
> 3. Regression-proof matrix linking each GREEN test to its RED PoC,
>    with the `--ignored` run tail showing the RED PoC now fails.
> 4. Tooling-gate tails.
> 5. Residual register with owner + rationale.
> 6. CVSS / SSVC re-scores.
> 7. Final verdict: **SHIP / SHIP-WITH-CONDITIONS / NO-SHIP** with
>    the blocking list (if any) and CHANGELOG entries to add (if
>    any).
>
> Adversarial and specific. Do NOT git commit. Do NOT modify code.

---

## Exit gates (orchestrator-enforced)

- **FIX → integrated-verify:** both FIX-A and FIX-B evidence files
  present + each owned-file set untouched outside scope.
- **integrated-verify → PURPLE:** all gates green + RED PoCs (the
  release-blocker subset) FAIL on `--ignored`.
- **PURPLE → tag:** auditable sign-off with explicit verdict;
  residual is documented, owned, accepted risk. If PURPLE returns
  NO-SHIP or SHIP-WITH-CONDITIONS, orchestrator re-enters FIX with a
  narrower scope.
