# v0.9.0 — `validator.layer0_enabled` toggle plan

**Branch:** `feat/0.9.0-layer0-toggle` off main @ 9a0768b (post v0.8.2)
**Inputs:** `2026-05-20-layer0-recon.md` (every touch point), `2026-05-20-layer0-research.md` (2026 best-practice + decisions)
**Goal:** mirror `validator.layer1_enabled` at the L0 (deterministic-policy) layer so a user can disable the deterministic-rule layer the same way they can already disable the LLM layer.

## Architectural summary

CLX validates each Bash command through a pipeline:

```
Bash command
   |
   v
[ validator.enabled ] ---false--> auto-allow (full bypass)
   |
   v
[ L0 deterministic policy (PolicyEngine::evaluate) ]
    blacklist + whitelist + learned-rule + file-config rules
    --> Allow / Deny / Ask
   |  (when Ask)
   v
[ validator.layer1_enabled ] ---false--> output_decision("ask", ...)   <-- existing
   |
   v
[ L1 LLM policy (evaluate_with_llm) ]
    structured prompt, JSON verdict
    --> Allow / Deny / Ask
   |
   v
[ default_decision ] (on L1 timeout / error / Ask without auto-allow-reads)
```

`layer0_enabled` adds an L0 short-circuit symmetric to L1's: when
`layer0_enabled = false`, skip `PolicyEngine::evaluate` entirely and
behave as if L0 returned `Ask` so the existing L1/default_decision
pipeline takes over (or — when L1 is also disabled — the "force ask"
defined-policy posture from the L1-disabled branch is the result).

Security properties (research+recon both confirm):
- **B4-1 subtree filter** at `config/project.rs:84-89` already drops
  the whole `validator.*` from untrusted project configs; the new
  `layer0_enabled` inherits this protection at zero cost.
- **Env-override audit chain** at `config/mod.rs:1228-1254`
  (`security_env_overrides_active`) is extended with
  `CLX_VALIDATOR_LAYER0_ENABLED=false`, so disabling L0 via env emits
  the same B5-4 audit-chain WARN as L1 disable.
- **No meta-flag** (`CLX_VALIDATOR_ALLOW_LAYER_DISABLE`) is added —
  research explicitly rejects it as theatre when B4-1 already
  guarantees a hostile project config can't reach `validator.*`.

## Touch points (from recon §0/§13)

1. `crates/clx-core/src/config/mod.rs:583-585` — add field to
   `ValidatorConfig` with `#[serde(default = "default_true")]`, mirror
   doc comment.
2. `config/mod.rs:934-951` — set initial `true` in the `Default` impl.
3. `config/mod.rs:1298-1315` — `apply_env_overrides` reads
   `CLX_VALIDATOR_LAYER0_ENABLED`; reuse the same WARN-on-disable shape.
4. `config/mod.rs:1228-1254` — add `CLX_VALIDATOR_LAYER0_ENABLED` to
   `security_env_overrides_active()`. Update the 4-var assertion in
   `b5_4_all_four_weakening_vars_all_reported` at `config/mod.rs:2665-2716`
   to expect 5 vars.
5. `crates/clx-hook/src/hooks/pre_tool_use.rs:226-280` — wrap the L0
   `PolicyEngine::evaluate("Bash", command)` call: if
   `!config.validator.layer0_enabled`, **skip L0** and treat as if L0
   returned `Ask` (mirror the L1-disabled-branch at :313-332 semantics).
   Audit log entry: `"L0-DISABLED"` analogous to the existing
   `"L1-DISABLED"` reason text.
6. `crates/clx-core/src/config/project.rs:84-89` — **no change**;
   `NON_INERT_KEY_PATTERNS = [..., "validator", ...]` already drops the
   subtree.
7. **Dashboard**:
   - `crates/clx/src/dashboard/settings/fields.rs` — add the field
     definition (name, type=bool, default=true, doc).
   - `crates/clx/src/dashboard/settings/sections.rs` — VALIDATOR_FIELDS
     gets one new entry. **Placement is question 1 below.**
   - `crates/clx/src/dashboard/settings/config_bridge.rs` — add the
     `(0, N)` arms for the new index in `set_field_value` /
     `reset_field_to_default` / `get_field_value` / `toggle_field` /
     `cycle_field`. If placement is index-1 (adjacent), 15+ existing
     arms shift +1 (touch-mechanical; covered by existing tests
     `test_field_counts_match_sections`, `test_get_field_value_all_defaults`,
     `test_toggle_all_bool_fields` per recon §7).
8. `crates/clx/src/dashboard/app.rs:670-723` — `settings_save` is
   already generic over the whole `Config` (serde_yml round-trip), so
   no code change is needed.
9. Tests to add (mirror layer1 set):
   - `validation_e2e.rs` / `hooks_depth_e2e.rs`: L0-disabled flows
     through to L1 / default_decision; cache/learned-rule side effects
     of L0 are correctly **not** invoked when L0 is disabled.
   - `pre_tool_use_l1_e2e.rs` mirror: a new `pre_tool_use_l0_e2e.rs`
     covering L0 disabled + L1 enabled (LLM evaluates everything) and
     L0 disabled + L1 disabled (forced `ask`).
   - `config/mod.rs` unit tests: default-true, env-override true/false,
     `security_env_overrides_active` includes layer0 on false.
   - Update the 4 settings snapshots + 1 wave1 pixel snapshot listed in
     recon §10.
10. Docs: `README.md:178`, `CHANGELOG.md` (`### Added` for the knob
    + `### Security` for the audit-chain emission), `specs/_prerelease/01-validation.md`.

## Execution (multi-agent per CLAUDE.md)

Two streams, file-disjoint, run in parallel:

- **Stream P1 (core)** — `clx-core` config + `clx-hook` runtime + tests:
  owns `config/mod.rs`, `pre_tool_use.rs`, new `pre_tool_use_l0_e2e.rs`,
  config unit tests. Evidence bundle per change (fail-before/pass-after +
  counterexample + regression-pin + residual).
- **Stream P2 (dashboard)** — `clx/dashboard/settings/*`: owns
  fields.rs, sections.rs, config_bridge.rs, settings render diffs,
  snapshot regeneration (`cargo insta accept` after review).

Then orchestrator: integrated `cargo nextest run --workspace` + clippy
`-D warnings` + fmt + `cargo deny check` + `cargo insta test --workspace
--check`. Per-stream four-eyes review (reviewer agent). Commit atomic.
PR. v0.9.0 release via the same Auto-Tag + release.yml flow as v0.8.2.

## Decisions locked (user, 2026-05-20)

- **Placement = index 1 (adjacent).** New row order: `enabled,
  layer0_enabled, layer1_enabled, layer1_timeout_ms, default_decision,
  trust_mode, auto_allow_reads`. P2 absorbs the 15-arm shift in
  `config_bridge.rs`; existing field-count tests cover correctness.
- **Audit-chain = extend to config-driven.** P1 wires audit-chain
  fingerprint emission for env-driven AND config-driven disable of L0
  or L1, in the same PR. Closes the B5-4-extended gap research flagged.

## Open questions for the user (require answer before P1/P2 launch)

(Both questions above are answered; proceeding.)


1. **Dashboard placement.** Recon flagged a real implementation-cost
   tradeoff:
   - **A — insert at index 1** (between `enabled` and `layer1_enabled`):
     logical L0 -> L1 ordering, adjacent to L1 toggle. Cost: 15+
     `(0, N)` match arms in `config_bridge.rs` shift +1 (mechanical,
     fully covered by existing field-count tests). Recommended.
   - **B — append at end** (after `auto_allow_reads`): no index churn.
     Cost: dashboard ordering breaks the L0 -> L1 mental model.

2. **Audit-chain for config-driven disable.** Research recommends ALSO
   wiring config-driven `layer0_enabled=false` (and `layer1_enabled=false`)
   into the per-event audit-chain fingerprint, not just env-driven disable
   (closes a gap research labels B5-4-extended). This is a small extra
   change in `pre_tool_use.rs` (and matches the v0.8.2 audit_chain pattern).
   - **YES (recommended)** — ship the audit emission in the same PR.
   - **NO (minimal scope)** — defer to a follow-up PR; this PR only adds
     the toggle + env-driven audit (which the existing layer1 path
     already does).
