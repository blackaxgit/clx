# CLX v0.9.0 Codex Independent Pre-Release Audit Prompt

**Date:** 2026-05-20
**Audience:** Codex (OpenAI), via the `codex:codex-rescue` subagent in
Claude Code. Codex is the **independent four-eyes verifier** for the
v0.9.0 release tag. Mirrors the v0.8.x precedent
(`c82ac42 docs(security): Codex independent pre-release audit prompt`).
**Base:** `chore/v0.9.0-rgp-prerelease` (RED gate `3ca855c`; FIX-A +
FIX-B commits TBD by orchestrator).
**Status when handed over:** RED complete, GREEN landed, integrated
verify green. This audit is the GO/NO-GO gate before `git tag v0.9.0`.

## Anti-anchoring (HARD, non-negotiable)

You are the independent verifier. You must NOT use the following as
verdict sources — only as claim-checking aids:

- `specs/2026-05-20-v090-red-findings.md` (Claude RED team output)
- `specs/2026-05-20-v090-fix-A-evidence.md` (Claude FIX-A self-attestation)
- `specs/2026-05-20-v090-fix-B-evidence.md` (Claude FIX-B self-attestation)
- `specs/2026-05-20-v090-rgp-prerelease.md` (Claude RGP procedure)
- The `.claude/worktrees/agent-*` directories (Claude scratch space)
- The v0.8.x Codex sign-offs (`docs/codex_*` / past PURPLE outputs)

If you catch yourself reasoning "the Claude evidence said this is
closed, so it is", STOP and re-derive the attack against the CURRENT
post-GREEN code path on disk. Research on LLM verification framing
(arXiv 2603.18740) shows treating a prior verdict as authoritative
cuts vulnerability-detection by 16-93%. The whole point of routing
this audit to Codex is to get a second-engine perspective free of
Claude's framing bias.

## Closure rubric (HARD)

Per finding, you must produce an **evidence-bundle 4-tuple**:

1. **VERDICT** — `CONFIRMED-CLOSED` / `CLOSED-WITH-RESIDUAL` /
   `NOT-CLOSED` / `INSUFFICIENT-EVIDENCE`.
2. **COUNTEREXAMPLE-NOW-FAILS** — the corresponding RED PoC in
   `crates/clx-hook/tests/v090_red_r1_poc.rs` /
   `crates/clx-hook/tests/v090_red_r2_poc.rs` must FAIL under
   `cargo nextest --ignored`. Paste the run tail showing the
   pre-fix-vulnerable behaviour no longer reproduces. A new test
   passing is NOT sufficient; the prior PoC must fail to reproduce.
3. **REGRESSION-PIN** — `file:line` of the fix in the current tree,
   and `file:line` of the closing test.
4. **RESIDUAL-UNCERTAINTY** — concrete scenario that would still
   bypass even after the fix; if "none known", state the threat model
   that assumes that.

**Numeric confidence forbidden.** No `97%`, no `99%`, no `over X% sure`.
Those fabricate precision and have been ruled out by repo policy
(see `CLAUDE.md` + memory `coverage-honest-ceiling`). Use the four
fields above plus an evidence-strength label (`strong / moderate /
weak`) backed by the four fields.

## Scope & RoE

- Authorized defensive audit of CLX's own v0.9.0 candidate before tag.
- Analysis + PoC only inside repo / temp sandbox. No external hosts
  (no real Azure, no real Ollama beyond loopback wiremock).
- Never reproduce the previously-leaked Azure key or its real tenant
  URL. Synthetic placeholders only. If you encounter the leaked
  string anywhere in the tree, surface it as a release-blocker, do
  not echo it back in your output.
- Severity = CVSS v4.0 base + SSVC decision tree + security-tool
  hard-override (any validator bypass or secret leak reachable
  without same-uid code-execution is release-blocking, regardless of
  base score).
- You may run `cargo nextest`, `cargo clippy`, `cargo fmt`, `cargo
  deny`, `cargo audit`, `cargo insta test`, and `cargo mutants` (the
  last on the fix surface only to keep runtime bounded). Hermetic:
  `CLX_MODEL_FETCH_DRYRUN=1 CLX_CREDENTIALS_BACKEND=age`.
- You may write evidence files under `specs/` and PoC files under
  `crates/*/tests/` (with `#[ignore]` gate). You may NOT modify
  production source. You may NOT `git commit` / `git push` — the
  orchestrator commits your output.

## v0.9.0 delta (what changed since v0.8.2)

So you don't re-audit the whole tree, the v0.9.0 delta is bounded:

1. `validator.layer0_enabled: bool` config + `CLX_VALIDATOR_LAYER0_ENABLED`
   env override (mirrors `layer1_enabled`).
2. `pre_tool_use.rs` L0 gate path: when L0 is disabled (config OR
   env), the engine emits SECURITY-CFG / SECURITY-ENV audit rows and
   falls through to L1.
3. Dashboard: a layer0 row at index 1 with ~15 `(0, N)` match-arm
   shifts in `config_bridge.rs`.
4. The 4 v0.9.0 commits on top of v0.8.2: `113ba3b`, `30da733`,
   `d926d6a`, plus the FIX commits the orchestrator landed
   (`feat(security): close v0.9.0 release-blocker #1 silent-allow
   class`, `docs(security): v0.9.0 honesty downgrade + clx health
   WARN + BREAKING note`).
5. The closed silent-allow class: cache lookup gated on both layers
   enabled; three L1-fallback arms force `ask` when
   `default_decision=allow`; learned-rules load gated; L1-DISABLED
   dual-emit deprecation window.
6. Doc-honesty downgrade: README + CHANGELOG no longer claim
   "tamper-evident" without the external-sink qualifier.
7. `clx health` WARN for both-layers-off-while-enabled.

## Audit work queue (priority order)

### Tier 1 — release-blocker re-derivation

For each, re-derive the attack against current code. Do NOT skip
because the FIX evidence says it's closed.

- **RB-1 silent-allow class.** Construct a fresh input where:
  (a) cache populated + L1 disabled → must NOT consult cache
  (b) L0 unknown + Ollama unreachable + default=allow → must `ask`
  (c) L0 unknown + L1 timeout + default=allow → must `ask`
  (d) L0 unknown + LLM-client construction error + default=allow →
      must `ask`
  (e) L1 disabled + learned-rules table populated with overbroad
      allow → must NOT silently suppress the L1-DISABLED ask
  (f) Same as (b)-(d) but with `default_decision=deny` → must `deny`
      (no over-application)
  (g) Same as (b)-(d) but with `default_decision=ask` → must `ask`
      with the original reason text (no over-application)
  Each case: walk the input through `pre_tool_use.rs` by reading the
  code, then confirm with a `#[ignore]`-gated test in
  `crates/clx-hook/tests/codex_v090_audit.rs`.

- **RB-2 doc-honesty.** Grep README, CHANGELOG, in-code docstrings
  for the literal `tamper-evident` / `tamper evident`. Each
  occurrence must either (i) include the external-sink qualifier in
  the same paragraph, or (ii) be a historical reference clearly
  scoped to the past. Anything unqualified is a release-blocker.

- **RB-3 L1-rename deprecation hygiene.** Confirm both literals
  `"L1-DISABLED"` AND `"L1 disabled"` are emitted in the L1-disabled
  audit reason (the dual-emit parallel-change window). Confirm there
  is a CHANGELOG entry naming v0.10.0 (or v0.9.1) as the removal
  target. Anything else is a release-blocker.

### Tier 2 — GREEN-introduced regression hunt

The fixes themselves can introduce new vulnerabilities. Adversarially
probe:

- The `default_decision=allow` force-ask: is it gated correctly so
  legitimate L0-whitelist allows still pass? (Construct a test:
  whitelisted-cmd + Ollama down + default=allow → must allow,
  because L0 already cleared the command.)
- The cache-gate: does it skip cache lookups when BOTH layers are
  enabled but cache is poisoned? (It should still read the cache;
  the gate is "skip when L1 is off", not "skip when cache is
  poisoned".)
- The learned-rules gate: are learned whitelist entries that
  legitimately benefit L0-only operators still loaded? (If you
  decide they shouldn't be loaded under L1=off, this is a
  documented contract; surface it.)
- The `clx health` WARN: does it misfire when `validator.enabled =
  false`? (It should not fire then; we want the warn only when the
  operator THINKS validation is on but no layer is running.)
- The L1-DISABLED dual-emit: does any downstream parser regex now
  match the substring "L1 disabled" in the alias-only context and
  trigger a stale code path? Grep for the literal across the
  codebase.

### Tier 3 — independent threat-model coverage

Apply STRIDE + MITRE ATT&CK/ATLAS to the v0.9.0 delta:

- **S (Spoofing):** can a hostile `.clx/config.yaml` in an
  untrusted repo flip `layer0_enabled` to false on a user's
  machine? Re-derive against the config-trust allowlist
  (`crates/clx-core/src/config/project.rs`). [Reference memory:
  `config-trust-allowlist` — new sensitive keys must be dropped for
  untrusted configs.] Confirm `layer0_enabled` is on the drop list.
- **T (Tampering):** can a same-uid attacker rewrite the SQLite
  audit DB to retroactively claim L0 was on when it was off?
  (Honest answer: yes, per the v0.8.2 reclassify. Confirm the docs
  no longer over-claim otherwise.)
- **R (Repudiation):** does the audit row identify WHICH layer was
  disabled and by what mechanism (config vs env)? Walk the
  SECURITY-CFG and SECURITY-ENV rows.
- **I (Information disclosure):** does the L0-disabled flow reach
  any of the F1 redaction sinks unmodified? Re-derive the v0.8.2 F1
  protection holds.
- **D (Denial of service):** can `layer0_enabled=false` + a flood
  of L1 calls denial the LLM provider? Note as accept-doc; not
  release-blocking.
- **E (Elevation of privilege):** can the layer0_enabled toggle be
  flipped by a non-privileged process? (The F7-deferred class.) The
  fix should have closed this; verify.

MITRE ATT&CK mappings to cover:
- T1574.002 (Hijack Execution Flow: DLL Side-Loading) — analogue:
  config injection via hostile `.clx/config.yaml`. [Tier 3]
- T1562 (Impair Defenses) — directly relevant: an attacker who can
  set `CLX_VALIDATOR_LAYER0_ENABLED=false` impairs the validator.
  Confirm this is loud (SECURITY-ENV audit row) and the F7 posture
  prevents silent allow.
- T1078 (Valid Accounts) — out of scope for v0.9.0 delta; CLX
  doesn't manage credentials in the validator flow.

MITRE ATLAS (LLM-specific) for the L1 surface:
- AML.T0051 (LLM Prompt Injection) — out of scope for v0.9.0
  delta; the validator prompt is fixed and the user command is the
  input being validated, not a prompt.

### Tier 4 — tooling gate re-run

Re-run all gates fresh. Paste the tail of each.

```
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
cargo audit  # if installed
cargo insta test --workspace --check
cargo nextest run -p clx-hook --test v090_red_r1_poc -- --ignored
cargo nextest run -p clx-hook --test v090_red_r2_poc -- --ignored
```

The last two MUST show the release-blocker subset (R1-F1, T9.1,
T9.2, T9.3, T9.4) failing. Other ignored PoCs (audit-tamper-as-
designed, both-off opacity once `clx health` covers it) status
documented case-by-case.

### Tier 5 — 2026 best-practice cross-check

You have web access. Spot-check the v0.9.0 design against 2026
best-practice references that POST-DATE January 2026 (so neither
your nor Claude's training has fully absorbed them):

- OWASP ASVS v5.x (2026) — particularly V5 Validation, V7 Errors,
  V9 Communications.
- NIST SP 800-218A (Secure Software Development Framework for
  AI-augmented systems, 2026 draft if available).
- CWE Top 25 2026 — particularly CWE-285 (Improper Authorization),
  CWE-862 (Missing Authorization), CWE-754 (Improper Check for
  Unusual or Exceptional Conditions). The silent-allow class is a
  CWE-754 + CWE-862 instance; verify the fix matches mitigation
  guidance.
- Anthropic + OpenAI joint LLM-safety guidance (2026) on fail-open
  vs fail-closed defaults — particularly the "loud-fail" principle
  for security-critical paths.
- arXiv adversarial-LLM-verification papers (>= Feb 2026) on
  reviewer-framing bias; you've been routed here specifically as an
  un-anchored reviewer; honor that.

If any 2026 reference contradicts the v0.9.0 design choices, surface
it as a release-blocker or accept-with-rationale residual. Do NOT
silently align Claude's choices to your training-data defaults.

## Deliverable

`specs/2026-05-20-v090-codex-signoff.md` — the 7-item auditable
sign-off:

1. **Scope + commit SHAs.** RED gate, FIX-A commit, FIX-B commit,
   what the audit covered, what it explicitly did not.
2. **Findings table.** Pre/post status per RED finding with
   independent-verification evidence (not just citing the FIX
   evidence file). One row per RB-* + Tier-2 + Tier-3 finding.
3. **Regression-proof matrix.** Each GREEN test linked to its RED
   PoC, with the `--ignored` run tail showing the RED PoC now
   fails.
4. **Tooling gate tails.** Verbatim last 20 lines of each gate
   listed in Tier 4.
5. **Residual register.** Per residual: owner, rationale, decision
   (track / accept-doc / re-open as new finding).
6. **CVSS / SSVC re-scores.** Per release-blocker, pre/post scores.
7. **Final verdict: SHIP / SHIP-WITH-CONDITIONS / NO-SHIP**, with
   blocking list and CHANGELOG additions (if any).

Adversarial, specific, evidence-anchored. The evidence-bundle 4-tuple
applies to every claim.

## Reporting hard rules

- Do NOT git commit. Do NOT git push. The orchestrator commits.
- Do NOT modify production source.
- Do NOT echo the leaked Azure key / tenant URL even if you find it
  in a log; surface the location and rotate-evidence and stop.
- No AI signatures, no `Co-Authored-By`, no `Generated by` trailers.
- No emdashes.
- If you discover a release-blocker not in the existing RED set,
  flag it explicitly as `NEW-FINDING` and re-rank.
- If you discover that a Claude-reported "VULN-CONFIRMED" was
  actually a false positive, flag it as `RED-FALSE-POSITIVE` with
  re-derivation showing why.

This audit's verdict gates the `git tag v0.9.0`. Be exhaustive.
