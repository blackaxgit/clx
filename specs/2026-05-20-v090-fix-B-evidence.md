# FIX-B Evidence Bundle — v0.9.0 GREEN docs honesty + clx health WARN

**Date:** 2026-05-20
**Branch:** `feat/0.8.0-memory-skills-coverage` (FIX-B working branch; RED
gate base SHA `3ca855c`)
**Owned files (disjoint from FIX-A):**

- `CHANGELOG.md`
- `README.md`
- `crates/clx/src/commands/health.rs`
- `specs/_prerelease/01-validation.md`
- `crates/clx/tests/cli_e2e.rs` (closing behavior tests for T7 only)

**Cross-stream coordination note:** FIX-A landed the L1-DISABLED dual-emit
in `crates/clx-hook/src/hooks/pre_tool_use.rs` as the literal
`"L1-DISABLED (alias: L1 disabled)"`. My narrative downgrade in
`specs/_prerelease/01-validation.md` describes the **policy** (one-minor-
version retention, removal in v0.10.0), not the exact code literal, which
is the appropriate doc-vs-code separation. Both expose the same alias
string for grep-based downstream log parsers.

---

## Closure rubric (HARD)

Every fix carries the evidence-bundle 4-tuple:

1. **VERDICT** — `CLOSED` / `CLOSED-WITH-RESIDUAL` / `OPEN`.
2. **COUNTEREXAMPLE-NOW-FAILS** — for code-bearing fixes, the pre-fix
   counterexample the fix neutralises; for doc-only fixes, the exact
   doc text that previously over-claimed.
3. **REGRESSION-PIN** — `file:line` of the fix + closing test
   `file:line`.
4. **RESIDUAL-UNCERTAINTY** — concrete scenario that would still bypass,
   or the threat model under which "none known" holds.

Evidence strength label per fix: `strong / moderate / weak`. Numeric
percentages forbidden per the RGP spec.

---

## Fix 1 — T8 / R1-F4 doc-honesty downgrade (README + CHANGELOG)

### VERDICT
`CLOSED`. Evidence strength: `strong`.

### COUNTEREXAMPLE-NOW-FAILS

Pre-fix prose claimed a `tamper-evident audit-chain fingerprint` without
qualifying that SQLite alone is rewritable by a same-uid attacker and
that the chained property requires an external append-only sink. The
exact pre-fix string in `README.md` was:

```
# disabling a layer emits a tamper-evident audit-chain fingerprint.
```

and in `CHANGELOG.md` under `[Unreleased]` → Security:

```
v0.9.0 ALSO emits a `SECURITY-CFG` audit row + chained fingerprint
when ... An external log aggregator capturing the `tracing::warn!`
anchor can independently re-verify any specific disable event.
```

Both are now downgraded to the v0.8.2-reclassify language, with the
same-uid SQLite-write caveat made explicit and CLX's lack of bundled
aggregator wiring stated.

### REGRESSION-PIN

- Fix `README.md:185-190` (validator config YAML block comment).
- Fix `CHANGELOG.md:30-40` (`[Unreleased]` Security block, first bullet).
- No closing executable test (doc-only); the closing artefact is the
  diff itself, surfaced below.

#### README.md before/after

Before (line 186):

```
# CLX_VALIDATOR_LAYER0_ENABLED / CLX_VALIDATOR_LAYER1_ENABLED env vars;
# disabling a layer emits a tamper-evident audit-chain fingerprint.
```

After (lines 185-190):

```
# CLX_VALIDATOR_LAYER0_ENABLED / CLX_VALIDATOR_LAYER1_ENABLED env vars;
# disabling a layer emits a per-event SHA-256 fingerprint to
# tracing::warn!; tamper-evident only when an external append-only sink
# captures the anchor (SQLite alone is not tamper-evident because a
# same-uid attacker can rewrite the database file).
```

#### CHANGELOG.md before/after

Before (lines 30-38, `[Unreleased]` → Security, first bullet):

```
- **Layer-disable audit-chain signal extended to config-driven
  disable.** Previously the per-event SHA-256 audit-chain fingerprint
  (B5-4 in v0.8.1) fired only when an env variable disabled a layer.
  v0.9.0 ALSO emits a `SECURITY-CFG` audit row + chained fingerprint
  when `validator.layer0_enabled` or `validator.layer1_enabled` is
  `false` in `~/.clx/config.yaml`. An external log aggregator
  capturing the `tracing::warn!` anchor can independently re-verify
  any specific disable event. Closes the documented config-side gap
  in B5-4-extended.
```

After (lines 30-40):

```
- **Layer-disable per-event fingerprint extended to config-driven
  disable.** Previously the per-event SHA-256 fingerprint emitted to
  `tracing::warn!` (B5-4 in v0.8.1) fired only when an env variable
  disabled a layer. v0.9.0 also emits a `SECURITY-CFG` audit row +
  per-event fingerprint when `validator.layer0_enabled` or
  `validator.layer1_enabled` is `false` in `~/.clx/config.yaml`. The
  fingerprint is tamper-evident only when an external append-only sink
  captures the anchor (SQLite alone is not tamper-evident because a
  same-uid attacker can rewrite the database file). CLX ships no
  aggregator wiring; the operator must configure one (syslog, journald,
  etc.). Closes the documented config-side gap in B5-4-extended.
```

The same-uid SQLite-rewritable caveat now appears verbatim in both
files (mirror requirement satisfied).

### RESIDUAL-UNCERTAINTY

A future reviewer might still parse "per-event SHA-256 fingerprint" as
"chained" because of the inherited B5-4 framing. The text now states
"per-event" and explicitly removes the standalone "chained fingerprint"
phrase, but a wholesale rewrite of the surrounding bullets (Both-off
semantics, hostile-config powerless) is out of scope for FIX-B and
preserves the v0.8.x phrasing where it is already honest. Threat model:
same-uid attacker can rewrite the SQLite file; per-event integrity is
verifiable only if the `tracing::warn!` anchor reaches a sink CLX does
not configure.

---

## Fix 2 — T7 both-off observability (`clx health` WARN)

### VERDICT
`CLOSED`. Evidence strength: `strong`.

### COUNTEREXAMPLE-NOW-FAILS

Pre-fix, a config with `validator.enabled: true` plus
`layer0_enabled: false` and `layer1_enabled: false` produced an audit
trail that looked like active validation (`L0-DISABLED` / `L1-DISABLED`
rows) while every command silently resolved to `ask`. A forensic
operator running `clx health` got no signal distinguishing "validation
alive" from "no layer running".

The closing tests assert:

- `health_warns_when_validator_enabled_and_both_layers_off_human`
  drives `clx health` with a both-off config and asserts the WARN line
  contains `validator.enabled=true`, `layer0_enabled`, `layer1_enabled`,
  `no actual validation is running`, and the remediation `enabled=false`.
- `health_json_warns_when_validator_enabled_and_both_layers_off` drives
  `clx health --json` with the same config and asserts the `warnings`
  array contains the T7 WARN payload.
- `health_does_not_warn_under_default_config` is the negative control:
  default config (both layers on) emits no T7 WARN.

Six unit tests in `crates/clx/src/commands/health.rs` cover the predicate
itself: enabled-true+both-off fires, enabled=false suppresses, either
layer alone on suppresses, default config suppresses, and `None` config
suppresses.

### REGRESSION-PIN

- Fix:
  - `crates/clx/src/commands/health.rs:45-47` (`HealthReport` gains
    `warnings: Vec<String>` with `skip_serializing_if`).
  - `crates/clx/src/commands/health.rs:140-167` (predicate
    `check_validator_both_layers_off`).
  - `crates/clx/src/commands/health.rs:212-216` (driver wiring at
    `cmd_health` collects global warnings).
  - `crates/clx/src/commands/health.rs:218-223` (human path adds
    `print_global_warnings`; JSON path forwards `&global_warnings`).
  - `crates/clx/src/commands/health.rs:720-731`
    (`print_global_warnings` helper, matches existing yellow-bold WARN
    glyph style).
- Closing tests:
  - Behavior e2e: `crates/clx/tests/cli_e2e.rs:346-456`
    (`health_warns_when_validator_enabled_and_both_layers_off_human`,
    `health_json_warns_when_validator_enabled_and_both_layers_off`,
    `health_does_not_warn_under_default_config`).
  - Unit predicate: `crates/clx/src/commands/health.rs:955-1075`
    (six negative + positive cases plus the JSON-shape regression
    test).

#### Before/after (driver wiring)

Before:

```rust
if json {
    print_json(&results, &provider_rows, &routing)?;
} else {
    print_table(&results);
    print_providers(&provider_rows, &routing);
}
```

After:

```rust
// T7 both-off observability: global warnings not tied to a single
// check row. Surfaced after the providers section in human output
// and as a top-level `warnings` array in the JSON report.
let mut global_warnings: Vec<String> = Vec::new();
if let Some(w) = check_validator_both_layers_off(config.as_ref()) {
    global_warnings.push(w);
}

if json {
    print_json(&results, &provider_rows, &routing, &global_warnings)?;
} else {
    print_table(&results);
    print_providers(&provider_rows, &routing);
    print_global_warnings(&global_warnings);
}
```

#### WARN payload (matches the spec wording exactly)

```
validator.enabled=true but both layer0_enabled and layer1_enabled are
false - every command will resolve to ask; no actual validation is
running. To disable validation entirely, set enabled=false.
```

### RESIDUAL-UNCERTAINTY

- `clx health` exits non-zero when Ollama / hook binaries are absent
  (true in the isolated test environment). The closing tests deliberately
  ignore `success/failure` and assert on stdout, so a future regression
  that suppresses the WARN behind an early exit would still be caught:
  the WARN row is printed before the failure rolls up.
- The WARN does NOT fire when `validator.enabled=false`, by design — the
  fully-bypassed path is the explicit-opt-out path. A user who wanted a
  generic "no validation running" signal regardless of the `enabled`
  flag is out of scope here.
- A reviewer using `--json` may grep for `"warnings"` and miss the
  emit because `skip_serializing_if = "Vec::is_empty"` removes the key
  when empty. The closing test asserts non-empty under both-off and
  absent-or-empty under default; both are intentional.

---

## Fix 3 — L1-DISABLED literal cleanup in `specs/_prerelease/01-validation.md`

### VERDICT
`CLOSED`. Evidence strength: `strong`.

### COUNTEREXAMPLE-NOW-FAILS

Pre-fix, two normative passages cited the legacy literal `"L1 disabled"`
as the sole reasoning string. With v0.9.0's dual-emit policy now landed
in FIX-A (`pre_tool_use.rs:432` emits `"L1-DISABLED (alias: L1 disabled)"`),
those passages over-claimed by a removed-name and under-claimed by
omitting the alias. After this fix both passages name the canonical form
and the retention policy explicitly.

### REGRESSION-PIN

- Fix `specs/_prerelease/01-validation.md:149-152` (Section 3.3 L1 LLM
  Validation — Given/When/Then for `layer1_enabled = false`).
- Fix `specs/_prerelease/01-validation.md:421-425` (Section 5.4 L1
  disabled — the operator-facing acceptance step).
- No executable closing test for spec prose; the closing artefact is
  the diff itself.
- Coordination: my narrative `"L1-DISABLED (with v0.9.0 dual-emit alias
  'L1 disabled' retained for one minor version)"` describes the
  retention policy; FIX-A's runtime literal is
  `"L1-DISABLED (alias: L1 disabled)"`. Operators grepping either
  canonical or alias hit. Removal target: v0.10.0.

#### Before/after — Section 3.3 line 150

Before:

```
  `L0`, decision `prompted`, reasoning "L1 disabled"; output `ask` with
  reason "Command requires review" (`pre_tool_use.rs:254-272`).
```

After:

```
  `L0`, decision `prompted`, reasoning `"L1-DISABLED (with v0.9.0
  dual-emit alias 'L1 disabled' retained for one minor version)"`;
  output `ask` with reason "Command requires review"
  (`pre_tool_use.rs:254-272`).
```

#### Before/after — Section 5.4 line 422

Before:

```
Expected: `ask` "Command requires review", audit layer `L0`,
decision `prompted`, reasoning "L1 disabled". Confirm NO cache row written.
```

After:

```
Expected: `ask` "Command requires review", audit layer `L0`,
decision `prompted`, reasoning `"L1-DISABLED (with v0.9.0 dual-emit
alias 'L1 disabled' retained for one minor version)"`. Confirm NO cache
row written.
```

### RESIDUAL-UNCERTAINTY

- The Section 5.4 heading is still literally `### 5.4 L1 disabled` —
  that is the human-readable section heading, not a normative claim
  about reasoning strings, and is left intact.
- Any other downstream spec or external runbook that pattern-matches
  the legacy literal will keep working for v0.9.0 because of the
  dual-emit alias.
- If a future patch removes the alias before v0.10.0 the spec text
  will lie. Mitigation: the BREAKING-note in CHANGELOG and the
  retention sentence here both name v0.10.0 as the removal target.

---

## Fix 4 — CHANGELOG BREAKING note (FIX-A contract change)

### VERDICT
`CLOSED`. Evidence strength: `strong`.

### COUNTEREXAMPLE-NOW-FAILS

Pre-fix, the `[Unreleased]` block had no `Changed (BREAKING)` subsection.
FIX-A's hardening flips the integration-test contract — a user who set
`default_decision=allow` and relied on the silent-allow fallback when L1
was unreachable / timed out / errored will see `ask` after upgrading.
That contract change must be loudly documented before tag or the
upgrade is a silent semver violation.

### REGRESSION-PIN

- Fix `CHANGELOG.md:53-65` (`### Changed (BREAKING)` subsection,
  inserted directly above the existing `### Changed` block).
- No executable closing test (doc-only). The artefact below is the
  inserted block.

#### Inserted block (verbatim)

```
### Changed (BREAKING)

- Hook now refuses `default_decision=allow` as silent fallback when an
  L0-unknown command falls through to L1 and L1 is unreachable / times
  out / errors. The decision is forced to `ask` so the user makes the
  call. Closes the F7-deferred silent-allow class (see
  `specs/2026-05-20-v090-red-findings.md` release-blocker #1). Affects
  users who configured `default_decision=allow` with the prior
  fail-open behaviour. To restore the prior behaviour explicitly, set
  `default_decision=allow` AND ensure `layer1_enabled=false`; the
  `L1-DISABLED` ask is then the loud gate.
```

I also extended the existing `### Changed` (non-breaking) bullet to
spell out the v0.9.0 dual-emit window and the v0.10.0 removal target
(`CHANGELOG.md:67-77`), so the rename hygiene from FIX-A's
`pre_tool_use.rs:432` is documented end-to-end.

### RESIDUAL-UNCERTAINTY

- A user who set `default_decision=allow` AND `layer1_enabled=true`
  AND has Ollama up will see no behaviour change. The breaking arm is
  specifically the fallback arms; the BREAKING note states this in
  the "To restore" sentence.
- A consumer of the audit reason field who matches against
  `"L1 disabled"` (legacy) keeps working through v0.9.0 because of the
  dual-emit alias. The Changed bullet names the v0.10.0 removal target.

---

## Pinned gate tails

### `cargo fmt --all -- --check`

```
Diff in /Users/blackax/Projects/clx/crates/clx-hook/tests/v090_red_r1_poc.rs:545:
Diff in /Users/blackax/Projects/clx/crates/clx-hook/tests/v090_red_r1_poc.rs:553:
Diff in /Users/blackax/Projects/clx/crates/clx-hook/tests/v090_red_r1_poc.rs:710:
Diff in /Users/blackax/Projects/clx/crates/clx-hook/tests/v090_red_r1_poc.rs:768:
Diff in /Users/blackax/Projects/clx/crates/clx-hook/tests/v090_red_r2_poc.rs:257:
Diff in /Users/blackax/Projects/clx/crates/clx-hook/tests/v090_red_r2_poc.rs:820:
```

Status for FIX-B owned files: **clean** (all 4 owned files pass fmt).
The remaining 6 diffs are in `v090_red_r1_poc.rs` / `v090_red_r2_poc.rs`,
which are RED gate artefacts (FIX-A territory; not in my owned set).
Surfaced to the orchestrator as cross-stream coordination.

### `cargo nextest run -p clx`

```
Starting 632 tests across 20 binaries
Summary [  19.252s] 632 tests run: 632 passed, 0 skipped
```

All 632 tests pass on the `clx` crate, including:

- The 3 new T7 e2e tests in `crates/clx/tests/cli_e2e.rs`.
- The 7 new T7 unit tests in `crates/clx/src/commands/health.rs`
  (six predicate cases + one JSON-shape regression).

### `cargo clippy --workspace --all-targets -- -D warnings`

Workspace clippy fails in `v090_red_r1_poc.rs` / `v090_red_r2_poc.rs`
(RED gate artefacts; FIX-A territory). Scoped clippy on the `clx`
crate (where all FIX-B code-bearing changes live) is clean:

```
$ cargo clippy -p clx --all-targets -- -D warnings
    Checking clx-core v0.8.2 (/Users/blackax/Projects/clx/crates/clx-core)
    Checking clx v0.8.2 (/Users/blackax/Projects/clx/crates/clx)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 15.68s
```

Status for FIX-B owned files: **clean**. The workspace-level failures
are pre-existing in RED gate test files (FIX-A territory); surfaced as
cross-stream coordination below.

---

## Cross-stream coordination items (for the orchestrator)

1. **RED PoC fmt + clippy hygiene.** `crates/clx-hook/tests/v090_red_r1_poc.rs`
   and `v090_red_r2_poc.rs` have pre-existing fmt + clippy violations
   that break the workspace gates. These are RED gate artefacts;
   FIX-A's owned-file set includes the live `pre_tool_use.rs` /
   `audit_chain.rs` / `validation_e2e.rs` / `v090_g1_e2e.rs` /
   `integration.rs`, but **not** the RED PoC files. The orchestrator
   should either expand FIX-A's scope to include the PoC fmt/clippy
   cleanup or hand it as a tiny follow-up FIX-C before integrated-verify.
2. **L1-DISABLED alias literal consistency.** FIX-A emits
   `"L1-DISABLED (alias: L1 disabled)"` at `pre_tool_use.rs:432`. My
   spec narrative says `"L1-DISABLED (with v0.9.0 dual-emit alias 'L1
   disabled' retained for one minor version)"`. These are consistent
   (doc describes policy; code emits the alias literal both downstream
   parsers can grep). No change requested.
3. **CHANGELOG BREAKING note source-of-truth.** I added the FIX-A
   contract-flip BREAKING note in `CHANGELOG.md:53-65`. If FIX-A's
   evidence file claims to have added the same note, the orchestrator
   should diff and keep one copy. The current file has exactly one
   `### Changed (BREAKING)` subsection.

---

## Final summary

- **VERDICT (overall FIX-B):** `CLOSED` for all four required fixes
  (T8 / R1-F4 README + CHANGELOG; T7 clx health WARN; L1-DISABLED spec
  literal cleanup; BREAKING note). Evidence strength: `strong` for all
  four.
- **Owned files touched (5):** `CHANGELOG.md`, `README.md`,
  `crates/clx/src/commands/health.rs`, `specs/_prerelease/01-validation.md`,
  `crates/clx/tests/cli_e2e.rs`.
- **Files outside owned set: not touched.**
- **Gates:** fmt clean for owned files; nextest -p clx green (632/632);
  clippy -p clx green. Workspace-level fmt/clippy fail due to
  pre-existing RED PoC hygiene (cross-stream coordination item #1).
- **Not committed.** Worktree clean of stray git commits per HARD
  RULES.
