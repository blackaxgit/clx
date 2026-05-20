# Layer-0 Toggle Recon (`validator.layer0_enabled`)

**Date:** 2026-05-20
**Branch:** `feat/0.9.0-layer0-toggle` @ `9a0768b` (post-v0.8.2)
**Mirror target:** `validator.layer1_enabled` (existing toggle, exhaustively mapped below).
**Goal:** zero-surprise end-to-end implementation of `validator.layer0_enabled`.

Every reference to `layer1_enabled` in the repo is enumerated. Anywhere
the implementation of L0 toggle must mirror layer1, the section title says
**MIRROR** and the exact code locus is cited.

---

## 0. TL;DR Touch-Point Checklist (ranked)

| # | Where | What | File:line |
|---|---|---|---|
| 1 | `ValidatorConfig` struct | add `layer0_enabled: bool` field with doc + serde default | `crates/clx-core/src/config/mod.rs:583-585` |
| 2 | `impl Default for ValidatorConfig` | initial value `default_true()` | `crates/clx-core/src/config/mod.rs:934-951` (line 938) |
| 3 | `apply_env_overrides` | parse `CLX_VALIDATOR_LAYER0_ENABLED`, WARN on disable | `crates/clx-core/src/config/mod.rs:1298-1315` |
| 4 | `security_env_overrides_active()` | report disable as weakening | `crates/clx-core/src/config/mod.rs:1228-1254` (specifically 1237-1241) |
| 5 | Runtime gate in pre-tool-use | wrap `policy_engine.evaluate("Bash", command)` in `if config.validator.layer0_enabled` | `crates/clx-hook/src/hooks/pre_tool_use.rs:226-280` (call at :229) |
| 6 | Dashboard field def | insert `FieldDef { label: "layer0_enabled", widget: Toggle, ... }` in `VALIDATOR_FIELDS` | `crates/clx/src/dashboard/settings/fields.rs:37-73` |
| 7 | Dashboard section field_count | bump `validator` section from 6 → 7 | `crates/clx/src/dashboard/settings/sections.rs:15-19` |
| 8 | `get_field_value` | new `(0, N)` arm reading `config.validator.layer0_enabled.to_string()` | `crates/clx/src/dashboard/settings/config_bridge.rs:358-365` |
| 9 | `reset_field_to_default` | new `(0, N)` arm | `config_bridge.rs:239-245` (line 241 is the layer1 row) |
| 10 | `toggle_field` | new `(0, N)` arm (`!config.validator.layer0_enabled`) | `config_bridge.rs:471-475` (line 473 is layer1) |
| 11 | `test_toggle_all_bool_fields` | add new `(0, N)` to `bool_fields` list | `config_bridge.rs:656-669` |
| 12 | `total_field_count` test | bump 40 → 41 | `sections.rs:72-76` |
| 13 | Project-config inert filter | **NO CHANGE NEEDED** (whole `validator.*` already dropped by `NON_INERT_KEY_PATTERNS`) | `crates/clx-core/src/config/project.rs:84-89` |
| 14 | `Config::default` config-load unit test | assert default `true` | `crates/clx-core/src/config/mod.rs:2203-2247` |
| 15 | `test_env_overrides` | extend to cover `CLX_VALIDATOR_LAYER0_ENABLED=false` | `crates/clx-core/src/config/mod.rs:2500-2560` |
| 16 | B5-4 security-env-override tests | add `b5_4_security_env_overrides_active_detects_layer0_disabled` | `crates/clx-core/src/config/mod.rs:2591-2716` |
| 17 | B4-1 hostile-config drop tests | extend `b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key` forbidden list to include `layer0_enabled` | `crates/clx-core/src/config/project.rs:373-403` |
| 18 | hook validation_e2e tests | mirror `l1_disabled_*` set — `l0_disabled_*` cases | `crates/clx-hook/tests/validation_e2e.rs:108-220` |
| 19 | `hooks_depth_e2e.rs` mirror | `pre_tool_use_l0_disabled_*` | `crates/clx-hook/tests/hooks_depth_e2e.rs:200-289` |
| 20 | Insta snapshots (settings render) | regenerate 4 snapshots that show the validator section (extra row) | `crates/clx/src/dashboard/settings/snapshots/*default_section_0.snap`, `*modified_value.snap`, `*edit_u64_range.snap`, `*edit_mode_popup.snap` (or any other snapshot that paints validator section 0) |
| 21 | Insta snapshot (top-level UI) | regenerate `wave1_settings_tab_populated.snap` | `crates/clx/src/dashboard/ui/snapshots/clx__dashboard__ui__tests__wave1_pixel__wave1_settings_tab_populated.snap` |
| 22 | README.md sample config | add `layer0_enabled: true` row next to layer1_enabled | `README.md:175-181` |
| 23 | CHANGELOG.md | new 0.9.0 entry describing the toggle | `CHANGELOG.md` (top) |
| 24 | Pre-release validation spec | extend §2 capability table, §3 behavior matrix | `specs/_prerelease/01-validation.md:63, 148, 198, 417, 427` |
| 25 | Other docs mentioning sample config | `docs/runbook-llm-unavailable-fix.md:484`, `docs/plans/customizable-validator-prompt.md:105` — add line for completeness | as cited |

---

## 1. Config struct definition

`crates/clx-core/src/config/mod.rs:577-629`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorConfig {
    /// Enable command validation
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Enable layer 1 (fast) validation
    #[serde(default = "default_true")]
    pub layer1_enabled: bool,                         // line 585
    ...
}
```

**Action (MIRROR):** Add immediately above (or below) `layer1_enabled`:

```rust
/// Enable layer 0 (deterministic policy rules) validation.
/// When `false`, the static L0 allow/deny ruleset is skipped and
/// every command falls through to L1 (and `auto_allow_reads` /
/// `default_decision` if L1 is also off).  L0 is the cheap,
/// deterministic guard; disabling it weakens security posture and
/// is treated as a weakening override (see `apply_env_overrides`).
#[serde(default = "default_true")]
pub layer0_enabled: bool,
```

Doc comment must mention "deterministic" so `clx_doctor` / config show
output is self-explanatory.

---

## 2. Default impl / serde default

`crates/clx-core/src/config/mod.rs:934-951` (`impl Default for ValidatorConfig`):

```rust
Self {
    enabled: default_true(),
    layer1_enabled: default_true(),            // line 938
    layer1_timeout_ms: default_layer1_timeout(),
    ...
}
```

**Action (MIRROR line 938):** add `layer0_enabled: default_true(),`. The
`#[serde(default = "default_true")]` annotation handles the
missing-from-YAML case via `default_true()` (defined elsewhere in the
file; reused unchanged).

Default semantics: a freshly-installed CLX or any config that lacks the
key gets `layer0_enabled: true` — i.e. backwards-compatible (no
behavior change for existing users).

---

## 3. Env override (`apply_env_overrides`)

`crates/clx-core/src/config/mod.rs:1281-1416`

Existing `layer1_enabled` block (lines 1298-1315):

```rust
if let Ok(val) = env::var("CLX_VALIDATOR_LAYER1_ENABLED") {
    apply_bool_override(
        &val,
        "CLX_VALIDATOR_LAYER1_ENABLED",
        &mut self.validator.layer1_enabled,
    );
    if !self.validator.layer1_enabled {
        tracing::warn!(
            env_var = "CLX_VALIDATOR_LAYER1_ENABLED",
            value = %val,
            "SECURITY WARNING: CLX_VALIDATOR_LAYER1_ENABLED=false disables \
             the LLM-based (Layer 1) validation stage via environment variable; \
             only the static L0 ruleset will run. ..."
        );
    }
}
```

**Action (MIRROR):** add an analogous block, *adjacent* (place before
the layer1 block so env-var order matches struct order):

```rust
if let Ok(val) = env::var("CLX_VALIDATOR_LAYER0_ENABLED") {
    apply_bool_override(
        &val,
        "CLX_VALIDATOR_LAYER0_ENABLED",
        &mut self.validator.layer0_enabled,
    );
    if !self.validator.layer0_enabled {
        tracing::warn!(
            env_var = "CLX_VALIDATOR_LAYER0_ENABLED",
            value = %val,
            "SECURITY WARNING: CLX_VALIDATOR_LAYER0_ENABLED=false disables the \
             deterministic Layer-0 ruleset; allow/deny patterns (rm -rf /, \
             curl|bash, etc.) are no longer enforced. Commands fall through to \
             L1 (LLM) or default_decision. This override is intentional only \
             for trusted CI/ops contexts. Audit trail: env var weakens \
             security posture."
        );
    }
}
```

**Symmetry note:** WARN wording mirrors the `LAYER1` wording verbatim
modulo "deterministic Layer-0 ruleset" / "LLM-based (Layer 1)
validation stage".

---

## 4. `security_env_overrides_active`

`crates/clx-core/src/config/mod.rs:1228-1254` — accessor that the
pre-tool-use hook reads at every invocation to emit a hash-chained
SECURITY-ENV audit row (see `crates/clx-hook/src/hooks/pre_tool_use.rs:37-82`).

Current layer1 entry, lines 1237-1241:

```rust
if let Ok(val) = env::var("CLX_VALIDATOR_LAYER1_ENABLED")
    && matches!(val.to_lowercase().as_str(), "false" | "0" | "no" | "off")
{
    active.push(("CLX_VALIDATOR_LAYER1_ENABLED", val));
}
```

**Action (MIRROR):** add the analogous block above:

```rust
if let Ok(val) = env::var("CLX_VALIDATOR_LAYER0_ENABLED")
    && matches!(val.to_lowercase().as_str(), "false" | "0" | "no" | "off")
{
    active.push(("CLX_VALIDATOR_LAYER0_ENABLED", val));
}
```

Update the doc-comment list (lines 1218-1223) to add the bullet:
`CLX_VALIDATOR_LAYER0_ENABLED=false  — deterministic L0 ruleset disabled`.

Confirmed: the hash-chained audit log
(`pre_tool_use.rs:37-82`) iterates the returned list and emits one
`SECURITY-ENV` audit row per disable; no per-key code change needed
there.

---

## 5. Project-config-trust inert filter (B4-1)

`crates/clx-core/src/config/project.rs:84-89`:

```rust
const NON_INERT_KEY_PATTERNS: &[&str] = &[
    "providers",     // entire providers.* (no credential/endpoint redirection)
    "logging.file",  // no log exfiltration to an attacker-chosen path
    "validator",     // entire validator.* — security policy, never repo-settable
    "user_learning", // entire user_learning.* (auto_whitelist_threshold:1 = bypass)
];
```

**No code change required.** `is_non_inert` at `project.rs:177-181`
matches `path == "validator"` *or* `path.starts_with("validator.")`,
which drops *every* key under `validator.*`, including a new
`layer0_enabled` sibling. The B4-1 fix is transitive.

**Confirmation:** existing test
`b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key`
at `project.rs:373-403` already proves this for `layer1_enabled` and
the other validator keys.

**Test action (recommended, MIRROR):** extend the `forbidden` list at
`project.rs:382-391` to add `"layer0_enabled"` so the regression also
guards the new key. This is a one-line test edit, not a behavior
change.

---

## 6. Runtime evaluation (`pre_tool_use.rs`)

`crates/clx-hook/src/hooks/pre_tool_use.rs:226-280` is the L0 evaluation
site. The current flow is:

```rust
// Layer 0: Deterministic rules evaluation
let l0_decision = policy_engine.evaluate("Bash", command);      // :229

match l0_decision {
    PolicyDecision::Allow => { /* audit L0/allowed, output allow, return */ }
    PolicyDecision::Deny { reason } => { /* audit L0/blocked, output deny, return */ }
    PolicyDecision::Ask { .. } => {
        if is_read_only {
            // L0-READ fast lane
            return;
        }
        // fall through to cache + L1
    }
}
```

Then at `:313-332`:

```rust
if !config.validator.layer1_enabled {
    debug!("L1 disabled, defaulting to ask");
    log_audit_entry(..., "L0", AuditDecision::Prompted, None, Some("L1 disabled"));
    output_decision("ask", Some("Command requires review".to_string()), ...);
    return Ok(());
}
```

**Action (NEW gate):** Wrap the entire L0 block (`:226-280`) under a
guard. Proposed placement:

```rust
// Layer 0: Deterministic rules evaluation (if enabled)
if config.validator.layer0_enabled {
    let l0_decision = policy_engine.evaluate("Bash", command);
    match l0_decision {
        PolicyDecision::Allow  => { ... return Ok(()); }
        PolicyDecision::Deny { .. } => { ... return Ok(()); }
        PolicyDecision::Ask { .. } => {
            if is_read_only { ... return Ok(()); }
            // fall through to cache/L1
        }
    }
} else {
    debug!("L0 disabled, skipping deterministic ruleset for '{}'", command);
    // Audit the skip so operators can see the weakening at the row level.
    log_audit_entry(
        &input.session_id,
        command,
        &input.cwd,
        "L0",
        AuditDecision::Prompted,
        None,
        Some("L0 disabled"),
    );
    // Still honor auto_allow_reads even when L0 is off — this preserves
    // existing read-only ergonomics without requiring L1 to round-trip.
    if is_read_only {
        log_audit_entry(..., "L0-READ", AuditDecision::Allowed, None, Some("Read-only command auto-allowed (L0 off)"));
        output_decision("allow", None, Some(RULES_REMINDER), None);
        return Ok(());
    }
    // else: fall through to cache + L1 (which may itself be off)
}
```

### Composition semantics (verified by reading pre_tool_use.rs)

| `enabled` | `layer0_enabled` | `layer1_enabled` | Behavior |
|---|---|---|---|
| `false` | * | * | Immediate `allow`, no audit (early return at `:124-127`). The top-level guard short-circuits before anything. |
| `true` | `true` | `true` | Full pipeline: L0 → cache → L1 (current behavior). |
| `true` | `true` | `false` | L0 runs; on Allow/Deny return; on Ask → "Command requires review" / audit `L0`/`prompted` reasoning "L1 disabled" (`:314-332`). |
| `true` | `false` | `true` | **NEW:** L0 skipped; `is_read_only` fast lane still applies; otherwise cache lookup → L1 (LLM) runs. |
| `true` | `false` | `false` | **NEW:** L0 skipped, L1 skipped. `is_read_only` → allow; else `default_decision` should apply. **Recommendation:** in the L0-off branch, when L1 is also off, surface `default_decision` (not hardcoded `ask`). The existing L1-disabled branch hardcodes `ask`; if you want symmetric semantics, either keep hardcoded `ask` (mirror existing) or honor `default_decision` consistently in both. **Spec says:** mirror existing — emit `ask` with reasoning "L0 and L1 disabled". Note this is a behavior choice; see §11 "Open question". |

User's intended semantics confirmed: "skip L0, skip L1, every command →
default_decision". The current L1-off branch *does not* do that — it
hardcodes `ask` (`pre_tool_use.rs:325-331`). If implementing the
mirror precisely, the L0-off+L1-off composition will also emit `ask`.
If the user wants `default_decision` in the new combined branch, that's
a divergence from layer1 precedent and should be a conscious design
choice (see §11).

---

## 7. Dashboard render — field-list source

`crates/clx/src/dashboard/settings/fields.rs:37-73` (`VALIDATOR_FIELDS`):

```rust
pub const VALIDATOR_FIELDS: &[FieldDef] = &[
    FieldDef { label: "enabled",          widget: Toggle, ... },      // index 0
    FieldDef { label: "layer1_enabled",   widget: Toggle, ... },      // index 1  <-- current
    FieldDef { label: "layer1_timeout_ms",widget: NumberU64 {...} },  // index 2
    FieldDef { label: "default_decision", widget: CycleSelect{...} }, // index 3
    FieldDef { label: "trust_mode",       widget: Toggle, ... },      // index 4
    FieldDef { label: "auto_allow_reads", widget: Toggle, ... },      // index 5
];
```

**Action (MIRROR placement — user intent is "adjacent to layer1"):**
Insert `layer0_enabled` at index 1 (pushing layer1_enabled to index 2,
shifting everything else by +1):

```rust
FieldDef {
    label: "layer0_enabled",
    description: "Enable layer 0 (deterministic) validation",
    widget: FieldWidget::Toggle,
},
```

**Index shift consequence — must update every `(0, N)` arm in
`config_bridge.rs`:**

| Field | Old idx | New idx |
|---|---|---|
| enabled          | 0 | 0 |
| **layer0_enabled** (new) | — | 1 |
| layer1_enabled   | 1 | 2 |
| layer1_timeout_ms| 2 | 3 |
| default_decision | 3 | 4 |
| trust_mode       | 4 | 5 |
| auto_allow_reads | 5 | 6 |

Every `(0, 1) | (0, 2) | (0, 3) | (0, 4) | (0, 5)` match arm in
`crates/clx/src/dashboard/settings/config_bridge.rs` shifts by +1:
locations to update — `set_field_value` line 109 `(0, 2)` →`(0, 3)`;
`reset_field_to_default` lines 240-245; `get_field_value` lines 360-365;
`toggle_field` lines 472-475; `cycle_field` line 506 `(0, 3)` →
`(0, 4)`; `is_trust_mode_enabling` line 560 `section == 0 && field == 4`
→ `field == 5`; test_specific_default_values lines 617-620;
`test_toggle_nontoggle_field_is_noop` line 690 (`(0, 2)` →
`(0, 3)`); snapshot test `snapshot_settings_modified_value_yellow`
lines 914-915 unchanged (operates on `cfg.validator.layer1_timeout_ms`
directly, not index-based); `snapshot_settings_edit_popup_number_u64_range`
line 936 `app.settings_field_idx = 2` → `= 3`. **Read once, update
every site — a sed pattern over `(0, N)` is risky because Ollama
section also uses `(2, N)`.**

**Alternative (safer):** append `layer0_enabled` at the *end* of
`VALIDATOR_FIELDS` (index 6). Then no existing `(0, N)` arms shift;
the only additions are `(0, 6)`. Costs: visual placement is
non-adjacent in the UI. User explicitly asked for *adjacent to
layer1*, so accept the index-shift cost.

---

## 8. Dashboard edit popup — bool field flow

`crates/clx/src/dashboard/settings/render.rs:353-435` (`render_edit_popup`).

Bool fields with `FieldWidget::Toggle` do **not** open a popup —
toggle is handled in-place via `toggle_field(config, section, field)`
at `config_bridge.rs:469-497`. The edit popup only opens for
TextInput/Number/CycleSelect widgets (the `range_info` `match` at
`render.rs:392-401` only renders for those types).

The state-machine entry point is in
`crates/clx/src/dashboard/state.rs:386-471` (key handling) — for a
Toggle field, pressing Space/Enter calls `toggle_field` directly,
flips `settings_is_dirty` via `recompute_dirty`, no popup.

**Confirmation:** a new bool field gets the toggle flow **automatically**
once it is registered in `VALIDATOR_FIELDS` and has a `toggle_field`
arm. No special-case code.

---

## 9. Settings save round-trip

`crates/clx/src/dashboard/app.rs:670-723` — `App::settings_save`:

```rust
let yaml = serde_yml::to_string(editing)?;
std::fs::write(&tmp_path, &yaml)?;
std::fs::rename(&tmp_path, &config_path)?;
self.settings_original_config = Some(editing.clone());
self.settings_is_dirty = false;
```

**Generic over fields.** Serialization is a whole-struct
`serde_yml::to_string` of `editing: &Config`. Any new bool added to
`ValidatorConfig` round-trips automatically (it has
`#[derive(Serialize, Deserialize)]` and a `#[serde(default = ...)]`
attribute on the struct).

`settings_is_dirty` is computed at `config_bridge.rs:548-553`:

```rust
pub fn recompute_dirty(app: &mut App) {
    app.settings_is_dirty = match (&app.settings_original_config, &app.settings_editing_config) {
        (Some(orig), Some(edit)) => orig != edit,
        _ => false,
    };
}
```

`ValidatorConfig` already derives `PartialEq` (line 577), so flipping
the new field changes equality → dirty → save flow works untouched.

**Confirmation:** a new bool field's round-trip to `~/.clx/config.yaml`
requires **zero** dashboard code changes beyond field registration
(items 6, 8, 9, 10 in the checklist).

---

## 10. Tests — exhaustive enumeration

Every existing `layer1_enabled` test reference (from `git grep`):

### 10.1 Unit tests in `clx-core/src/config/mod.rs`

| Line | Test | What | Mirror needed |
|---|---|---|---|
| 2208 | `test_default_config` | `assert!(config.validator.layer1_enabled)` | YES — add `assert!(config.validator.layer0_enabled)` |
| 2254 | `test_parse_yaml_config` YAML body | sets `layer1_enabled: true` | optional — add `layer0_enabled: ...` line to widen coverage |
| 2284 | `test_parse_yaml_config` | `assert!(config.validator.layer1_enabled)` after parse | YES — mirror |
| 2325 | `test_partial_yaml_config` | asserts default propagation when YAML omits key | YES — mirror; assert `layer0_enabled: true` default |
| 2536 | `test_env_overrides` | `assert!(!config.validator.layer1_enabled)` after `CLX_VALIDATOR_LAYER1_ENABLED=false` | YES — extend test (or add new) for `CLX_VALIDATOR_LAYER0_ENABLED` |
| 2596-2612 | `b5_4_security_env_overrides_active_detects_layer1_disabled` | asserts env-WARN tracked | YES — mirror as `_detects_layer0_disabled` |
| 2665-2716 | `b5_4_all_four_weakening_vars_all_reported` | currently asserts exactly 4 vars | **EXPAND**: now expects 5, add `CLX_VALIDATOR_LAYER0_ENABLED` to the env-set block and to the assertions; update `overrides.len() == 4` → `5` (line 2713-2715) |

### 10.2 `crates/clx-core/src/config/project.rs`

| Line | Test | What | Mirror needed |
|---|---|---|---|
| 230-245 | `drops_entire_validator_subtree_from_untrusted_config` | proves `validator.layer1_enabled` is dropped | optional — add a parallel assertion for `layer0_enabled` (one-liner) |
| 346-367 | `inert_filter_drops_logging_file_and_entire_validator_subtree` (wave1_credentials_behavior) | same proof for layer1 | optional — extend raw YAML to include layer0 |
| 373-403 | `b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key` | hostile YAML includes `layer1_enabled: false`; forbidden list includes `"layer1_enabled"` | YES — append `"layer0_enabled"` to the forbidden list (line 382-391) and to the hostile YAML at line 375 |

### 10.3 hook e2e tests

| File:line | Test | Config snippet | Mirror needed |
|---|---|---|---|
| `crates/clx-hook/tests/validation_e2e.rs:112` | `enabled_true_blocks_and_audits_l0` | `validator: { enabled: true, layer1_enabled: false }` | optional |
| `validation_e2e.rs:166` | `l0_hard_allow_whitelisted_command_emits_allow` | same | optional |
| `validation_e2e.rs:180,199,451` | various L1-disabled scenarios | `layer1_enabled: false` | optional — add a mirror suite `l0_disabled_*` that disables L0 instead |
| `validation_e2e.rs:229,285,345,395` | trust_mode + L1 disabled | composite | optional |
| `crates/clx-hook/tests/integration.rs:205,273` | trust_mode legacy/expired token | `layer1_enabled: false` | optional |
| `integration.rs:366,438,510` | default_decision { allow, deny, ask } when Ollama unavailable | `layer1_enabled: true` | YES (recommended) — add a parallel "L0 disabled + L1 enabled" case to prove L1 still runs |
| `crates/clx-hook/tests/hooks_depth_e2e.rs:217,233,256,276` | depth/L1 disabled/auto_allow_reads matrix | mixed | YES — add a `pre_tool_use_l0_disabled_*` mirror (esp. lines 230-246 which is *exactly* the L1-off case to mirror) |
| `crates/clx-hook/tests/pre_tool_use_l1_e2e.rs:138,196` | L1 cache and provider arms | `layer1_enabled: true` | optional — could add an L0-off variant to prove L1 still reachable |

**Recommended new e2e tests for layer0 (MIRROR of existing layer1 cases):**

1. `l0_disabled_unknown_command_falls_through_to_l1` — `layer0_enabled: false`, `layer1_enabled: true`, deterministic deny command (`rm -rf /`) → L1 evaluates (not L0); audit row layer `L1` not `L0`.
2. `l0_disabled_blacklisted_command_no_longer_denied_at_l0` — proves the security weakening: `rm -rf /` is no longer hard-denied at L0 when `layer0_enabled: false`.
3. `l0_disabled_auto_allow_reads_still_works` — preserves read-only ergonomics.
4. `l0_disabled_audit_row_records_l0_disabled` — proves the "L0 disabled" reasoning string is written.
5. `l0_and_l1_disabled_ask_with_reasoning` — composition.

### 10.4 Dashboard tests

| File:line | Test | Notes |
|---|---|---|
| `crates/clx/src/dashboard/settings/config_bridge.rs:656-669` | `test_toggle_all_bool_fields` | add `(0, 1)` for `layer0_enabled` (after the index shift, layer1 moves to `(0, 2)`) — so the list becomes `(0, 0) (0, 1) (0, 2) (0, 5) (0, 6) ...` |
| `config_bridge.rs:614-624` | `test_specific_default_values` | values are checked by index — bump indices |
| `config_bridge.rs:690` | `test_toggle_nontoggle_field_is_noop` | uses `(0, 2)` for `layer1_timeout_ms` — becomes `(0, 3)` |
| `crates/clx/src/dashboard/settings/fields.rs:344-355` | `test_field_counts_match_sections` | uses `section.field_count` — bumping `sections.rs` to 7 keeps this passing |
| `crates/clx/src/dashboard/settings/sections.rs:66-76` | `test_sections_count`, `test_total_field_count` | bump `40 → 41` |
| `crates/clx/src/dashboard/settings/render.rs:914-915` | `snapshot_settings_modified_value_yellow` | uses `cfg.validator.layer1_timeout_ms = 12345` directly — no index churn, but the snapshot will gain a new row → regenerate |
| `crates/clx/src/dashboard/settings/render.rs:929-942` | `snapshot_settings_edit_popup_number_u64_range` | `app.settings_field_idx = 2` for `layer1_timeout_ms` — bump to 3 |
| `crates/clx/src/dashboard/app.rs:1516,1527,1585` | App-level settings save/dirty tests | use struct fields directly (`layer1_timeout_ms`) — no churn |

### 10.5 Insta snapshots that need regeneration

Any snapshot painting the Validator section row list will gain one row.
Enumerated by searching for snapshot files that render `Validator`:

- `crates/clx/src/dashboard/settings/snapshots/clx__dashboard__settings__render__render_snapshots__dashboard_ui_settings_default_section_0.snap` — contains the field list explicitly
- `...dashboard_ui_settings_modified_value.snap` — Validator section
- `...dashboard_ui_settings_edit_mode_popup.snap` — Validator + popup overlay
- `...dashboard_ui_settings_edit_u64_range.snap` — Validator + popup
- `...dashboard_ui_settings_edit_text_error.snap` — Context section (NO regen needed)
- `...dashboard_ui_settings_default_llm_section.snap` — LLM section (no regen)
- `...dashboard_ui_settings_llm_populated.snap` — LLM section (no regen)
- `...dashboard_ui_settings_mcp_tools_populated.snap` — MCP (no regen)
- `crates/clx/src/dashboard/ui/snapshots/clx__dashboard__ui__tests__wave1_pixel__wave1_settings_tab_populated.snap` — pixel-level top UI snapshot, shows validator. **REGEN.**

To regenerate: `INSTA_UPDATE=always cargo test -p clx -p clx-core dashboard` (or `cargo insta review`).

---

## 11. Documentation / CHANGELOG

| File:line | Current mention | Action |
|---|---|---|
| `README.md:175-181` | sample config `validator:` block has `layer1_enabled: true # LLM validation` | Add `layer0_enabled: true # Deterministic rules` line just above it |
| `CHANGELOG.md` (top) | last entry is v0.8.2 | Add new `## 0.9.0 — unreleased` section: "Added `validator.layer0_enabled` (env: `CLX_VALIDATOR_LAYER0_ENABLED`) — symmetric toggle for the L0 deterministic ruleset; defaults to `true` (no behavior change). Setting to `false` is treated as a security-weakening override (WARN at startup, SECURITY-ENV audit row per invocation)." |
| `CHANGELOG.md:125` | mentions B4-1 fix lists existing keys | No change needed — list is illustrative, not exhaustive |
| `specs/_prerelease/01-validation.md:63` | capability table row for layer1 | Add row: `\| L0 deterministic enable \| validator.layer0_enabled \| CLX_VALIDATOR_LAYER0_ENABLED \| true \| config/mod.rs:XXX; gate pre_tool_use.rs:226 \|` |
| `specs/_prerelease/01-validation.md:148,198` | "Given layer1_enabled = false" sections | Add parallel "Given layer0_enabled = false" specification: when L0 Ask → ...; when L0 disabled → command falls through to L1; "Note the L0-disabled branch ... " |
| `specs/_prerelease/01-validation.md:417,427` | sample configs | Mirror |
| `docs/runbook-llm-unavailable-fix.md:484` | sample config | add `layer0_enabled: true` for completeness |
| `docs/plans/customizable-validator-prompt.md:105` | sample config | add `layer0_enabled: true` |

No mention in `plugin/`, `mcp/` user-facing docs.

---

## 12. Cross-cutting observations

### A. Is `layer1_enabled` used semantically differently from a generic bool?

**No.** Reading `pre_tool_use.rs:313-332`, the layer1 disable branch is a
single gate:

```rust
if !config.validator.layer1_enabled {
    debug!("L1 disabled, defaulting to ask");
    log_audit_entry(..., "L0", AuditDecision::Prompted, None, Some("L1 disabled"));
    output_decision("ask", Some("Command requires review".to_string()), ...);
    return Ok(());
}
```

No interaction with `default_decision` (the comment in
`01-validation.md:198` confirms: "It does NOT apply when
`layer1_enabled = false` (that path hardcodes `ask`)"). No interaction
with `auto_allow_reads` (read-only handling happens earlier at L0). No
interaction with `trust_mode` (trust mode runs *before* L0 at :130).

`layer0_enabled` should mirror this: a single gate, no cross-field
coupling.

### B. Is the dashboard save flow generic over bool fields?

**Yes.** Confirmed at three layers:
1. `serde` whole-struct serialization (`app.rs:696`).
2. `recompute_dirty` is `orig != edit` over `Config` (`config_bridge.rs:548-553`).
3. `toggle_field` is a `match (section, field)` — adding one arm is
   the only code change for a new bool.

The render path is also generic (`get_field_value` `match`,
`get_default_value` same, `truncate_value`). The only special-case is
`is_trust_mode_enabling` at `config_bridge.rs:559-561` — a confirm
dialog when toggling `trust_mode` from off to on. Not needed for
`layer0_enabled`.

### C. Composition `layer0=false ∧ layer1=false` semantics

Re-reading `pre_tool_use.rs:124-127, 313-332`:

- Top-level `enabled=true` (else immediate allow);
- L0 disabled (new behavior) → skip `policy_engine.evaluate("Bash", command)`;
- L1 disabled → existing branch fires, hardcoded `output_decision("ask", ..., "Command requires review")`;
- Audit row layer `L0`, decision `prompted`, reasoning `"L1 disabled"`.

So with the recommended mirror (`if config.validator.layer0_enabled
{ ... } else { L0-READ + fall through }`), the L0-off + L1-off
composition yields:

  1. `is_read_only` true → `allow` (L0-READ fast lane).
  2. `is_read_only` false → fall through to cache, cache miss, then
     `!layer1_enabled` branch → `ask` "Command requires review".

This **does NOT** route to `default_decision`. The recon question
asks: "with the top-level enabled=true, the resulting behavior should
be: skip L0, skip L1, every command -> default_decision. Verify this
is the intended semantics by reading pre_tool_use.rs flow."

**Verification:** The *current* code does NOT do this for the L1-only
disable case (it hardcodes `ask`). Mirroring layer1 means the new
L0-disable also won't route to `default_decision` on its own; the only
path that routes to `default_decision` today is L1 enabled but provider
down (`pre_tool_use.rs:340-396` area). So:

- **If "mirror layer1 exactly":** L0-off + L1-off → `ask` with reasoning "L0 and L1 disabled". (RECOMMENDED — symmetric, minimal surprise.)
- **If "honor user's stated semantics literally":** L0-off + L1-off → emit `default_decision.as_str()`. (Divergence; would also imply changing the L1-only-off branch to do the same for consistency, which is a behavior change outside the scope of this toggle.)

This is the **single decision point** the implementer needs the user
to confirm before coding. Default to MIRROR (option A) unless told
otherwise.

---

## 13. Implementation order (recommended)

1. **Core struct + default + serde** — `config/mod.rs:583, 938` (one commit).
2. **Env override + WARN** — `config/mod.rs:1298, 1237` (`security_env_overrides_active`) (one commit).
3. **Unit tests for 1 & 2** — extend `test_default_config`, add `_detects_layer0_disabled`, expand `_all_four_weakening_vars_all_reported` to five.
4. **B4-1 forbidden-list regression test** — append `"layer0_enabled"` to `project.rs:382-391`.
5. **Runtime gate in pre_tool_use** — `crates/clx-hook/src/hooks/pre_tool_use.rs:226-280` (one commit). Document `L0 disabled` audit reasoning.
6. **e2e tests** — `validation_e2e.rs` + `hooks_depth_e2e.rs` mirror cases (one commit per test file).
7. **Dashboard field def + sections** — `fields.rs:38`, `sections.rs:18` (one commit).
8. **Dashboard config_bridge index shifts** — `config_bridge.rs` whole file pass (one commit; carefully).
9. **Regenerate insta snapshots** — `INSTA_UPDATE=always cargo test` then review.
10. **Docs + CHANGELOG** — `README.md`, `CHANGELOG.md`, `specs/_prerelease/01-validation.md` (one commit).

All commits Conventional Commits per `CLAUDE.md`.

Atomic granularity: each commit changes one concern. Build + test
green between commits to allow `git bisect`.

---

## 14. Files NOT touched

For completeness, the following modules were inspected and require **no
change**:

- `crates/clx-core/src/policy/mod.rs` — `PolicyEngine::evaluate` is the L0 evaluator; the toggle is at the call-site (pre_tool_use), not in the engine.
- `crates/clx-core/src/policy/rules.rs` — rule data, untouched.
- `crates/clx-mcp/*` — MCP tools (clx_rules, clx_remember, etc.) — no layer1 reference.
- `crates/clx-hook/src/audit*.rs` — generic over `layer` field.
- `crates/clx-hook/src/router.rs` — router doesn't peek at validator layers.
- `crates/clx/src/dashboard/ui/audit.rs` — audit tab renders layer column as opaque string ("L0", "L1", "L1-CACHE"); a new "L0" reasoning string is rendered automatically.
- `crates/clx-core/src/config/trust.rs` — file-hash trust gate; field-agnostic.

---

## 15. Risk register

| Risk | Mitigation |
|---|---|
| Index shift in `config_bridge.rs` skipping a `(0, N)` arm | Compile-time guard: `test_field_counts_match_sections`, `test_get_field_value_all_defaults`, `test_toggle_all_bool_fields` cover every cell. Run `cargo test -p clx settings` after edit. |
| Snapshot diff churn (visual regression) | All snapshots committed under `crates/clx/src/dashboard/{settings,ui}/snapshots/`; `cargo insta review` shows the diff explicitly. |
| Confusing L0+L1 off semantics | Document in field description ("L0 disabled — commands fall through to L1") and audit reasoning string. |
| Hostile project config carrying `layer0_enabled: false` | Already mitigated by B4-1 (`NON_INERT_KEY_PATTERNS` includes `validator`). One-line test guard recommended. |
| Forgotten env-WARN bypass | The `security_env_overrides_active()` accessor is the single chokepoint; the hash-chained audit emits at every PreToolUse invocation; coverage via `b5_4_*` tests. |

---

End of recon.
