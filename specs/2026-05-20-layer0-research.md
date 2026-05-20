# Layer0 Disable Toggle — 2026-Current Research

**Date:** 2026-05-20
**Scope:** Design research for `validator.layer0_enabled: bool` (default `true`) in
CLX v0.8.x, mirroring the existing `validator.layer1_enabled` toggle.
**Audience:** CLX maintainer; decision-first; 1–2h research budget.
**Methodology:** WebSearch + direct serde / serde_yaml_ng repo reads; cross-checked
against CLX's existing patterns in `crates/clx-core/src/config/mod.rs`,
`crates/clx-core/src/config/project.rs`, `crates/clx-hook/src/audit_chain.rs`,
and `crates/clx-hook/src/hooks/pre_tool_use.rs`. All external citations dated.

---

## Executive summary (decision-first)

1. **serde idiom — locked in.** Use the same pattern already in `ValidatorConfig`
   for `layer1_enabled`: `#[serde(default = "default_true")] pub layer0_enabled: bool`,
   plus `layer0_enabled: default_true()` in `Default::default()`, plus a one-line
   doc comment in CLAUDE-style imperative voice. This is the documented serde idiom
   ([serde.rs/field-attrs.html, current](https://serde.rs/field-attrs.html)) and is
   forward-compatible with the `serde_yaml_ng` migration target, which is a
   drop-in `serde_yaml` continuation
   ([acatton/serde-yaml-ng README, v0.10, July 2025 update](https://github.com/acatton/serde-yaml-ng)).
   **Reject** `Option<bool>` + manual unwrap; **reject** `#[serde(default)]` without
   an explicit `default_true` function (silently relies on `bool::default()=false`,
   which is fail-open — the exact footgun OWASP A09 warns against).

2. **Audit trail — extend the existing pattern, don't invent a new one.** When
   `layer0_enabled=false` is the *effective* runtime state, the same
   `Config::security_env_overrides_active()` + `audit_chain::build_record()`
   pipeline that already exists for `CLX_VALIDATOR_LAYER1_ENABLED=false` MUST
   fire. Add `CLX_VALIDATOR_LAYER0_ENABLED` to the env-override list AND emit
   an audit-chain record when *any* path (env or config) yields
   `layer0_enabled=false`. This satisfies OWASP A09:2025's "configuration changes
   and security-control state changes are auditable events" requirement
   ([OWASP Top 10 A09:2025](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/),
   accessed 2026-05-20) and NIST SP 800-53r5 AU-2 "security-relevant events"
   ([csf.tools AU-2 r5](https://csf.tools/reference/nist-sp-800-53/r5/au/au-2/),
   accessed 2026-05-20).

3. **Privilege gating — B4-1 is sufficient; do NOT add a second env-var gate.**
   The B4-1 subtree filter (`NON_INERT_KEY_PATTERNS = ["validator", ...]` at
   `crates/clx-core/src/config/project.rs:84`) already drops the entire
   `validator.*` subtree from any non-hash-trusted project YAML, so
   `layer0_enabled` is automatically covered the moment it lands inside
   `ValidatorConfig` — no PR changes needed to `project.rs`, just a new
   regression test row in `b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key`.
   Defense-in-depth is met by: (a) B4-1 filter (hostile repo can't set it),
   (b) global config + hash-trust (user must explicitly accept), (c) env var
   (out-of-band, audit-logged). A *fourth* gate
   (`CLX_VALIDATOR_ALLOW_LAYER_DISABLE=true` meta-flag) would be theater:
   anyone who can set `CLX_VALIDATOR_LAYER0_ENABLED=false` can set the meta-flag
   in the same shell. **Reject.**

4. **Both-off behavior — fail-closed to `ask`, not the validator's
   `default_decision`.** When `layer0_enabled=false` AND `layer1_enabled=false`
   simultaneously, refuse to bypass user judgment: emit a `validator_disabled`
   audit-chain record AND force the decision to `ask` regardless of
   `validator.default_decision`. CLX's same-uid local-trust model means a hostile
   actor with shell can set everything; the value here is *informing the user*
   that they ran with zero deterministic and zero LLM defense. Per fail-closed
   guidance ([AuthZed "Fail-Open vs Fail-Closed"](https://authzed.com/blog/fail-open),
   accessed 2026-05-20) and standard security-appliance practice
   ([Cisco/Broadcom KB on fail-closed posture](https://knowledge.broadcom.com/external/article/245938/fail-close-fail-open-policies.html),
   accessed 2026-05-20), high-security tools default to fail-closed at total
   policy loss. CLX is a security tool; treat both-off as catastrophic policy
   loss, not as "user wants `allow`".

5. **CHANGELOG — use `### Security` AND `### Added`, never `### Added` alone.**
   Per [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) (current,
   accessed 2026-05-20), the `Security` section exists "in case of
   vulnerabilities" — and a user-disablable security control IS a class of
   vulnerability surface even when the default is safe. The release-note entry
   MUST: (a) state the default is `true`, (b) name the env var, (c) name the
   audit signal users should look for if they didn't intend to disable it,
   (d) link to the both-off fail-closed behavior. Place the toggle under
   `### Added`; place the audit-trail/fail-closed safety net under `### Security`.

---

## 1. serde-driven YAML config — 2026 idioms

### 1.1 The `#[serde(default = "fn")]` field idiom

Per the [serde Field Attributes documentation](https://serde.rs/field-attrs.html)
(stable, current as of 2026-05-20):

> If the value is not present when deserializing, call a function to get a
> default value. The given function must be callable as `fn() -> T`.

Two equivalent patterns exist for booleans:

- `#[serde(default = "default_true")]` with a free `fn default_true() -> bool { true }`.
- `#[serde(default)]` *plus* a struct-level `Default` impl that returns `true`.

**CLX already uses the first pattern** (`crates/clx-core/src/config/mod.rs:583-585`)
for `layer1_enabled`. Reuse the same `default_true` helper — do not introduce a
second helper. Confirmed in-repo:

```rust
/// Enable layer 1 (fast) validation
#[serde(default = "default_true")]
pub layer1_enabled: bool,
```

**Why the explicit function and not bare `#[serde(default)]`?** `bool::default()`
is `false`. If a future refactor accidentally removes the `default = "..."`
attribute, a config file missing the key would silently disable the layer (fail
**open** for a security toggle). The explicit `default_true` function makes the
secure-by-default intent grep-able and review-able. This is the documented
"missing field" behavior in serde ([serde-rs/serde issue #2249 thread on
fallible defaults](https://github.com/serde-rs/serde/issues/2249), referenced
2026-05-20).

### 1.2 Doc-comment convention (CLX-house)

The existing `layer1_enabled` doc is one line: `/// Enable layer 1 (fast) validation`.
For `layer0_enabled`, mirror exactly and call out the deterministic-policy semantics:

```rust
/// Enable layer 0 (deterministic-policy / rule-based) validation
#[serde(default = "default_true")]
pub layer0_enabled: bool,
```

A multi-paragraph doc comment is overkill for a flag and inconsistent with the
existing struct's style. Long-form rationale belongs in CHANGELOG and in
`specs/_prerelease/01-validation.md`, not in rustdoc.

### 1.3 `serde_yaml_ng` migration compatibility

CLX currently depends on `serde_yml` (a fork that the maintainer of the
*safer* fork `serde-yaml-ng` has publicly flagged as containing "complete
nonsense or unsound" AI-generated code —
[acatton/serde-yaml-ng README](https://github.com/acatton/serde-yaml-ng), 2025).
The user has named `serde_yaml_ng` as the migration target. Confirmed:

- `serde_yaml_ng` is "an independant continuation of serde-yaml from dtolnay"
  ([acatton/serde-yaml-ng, accessed 2026-05-20](https://github.com/acatton/serde-yaml-ng)).
- Current version: **0.10.x**, with a July 2025 maintainer update noting active
  development and migration from `unsafe-libyaml` to `libyaml-safer`.
- `serde_yaml_ng` is `Serialize`/`Deserialize`-derive identical to `serde_yaml`,
  meaning `#[serde(default = "default_true")]` works **identically** across
  `serde_yml`, `serde_yaml_ng`, and original `serde_yaml`. No code change to the
  `layer0_enabled` field is required by the future migration.
- Latest community RustSec discussion ([rustsec/advisory-db#2132,
  opened 2024-11-13, accessed 2026-05-20](https://github.com/rustsec/advisory-db/issues/2132))
  lists `serde_yaml_ng` and `serde_norway` as the actively-maintained options;
  `serde_yml` has its own advisory (`RUSTSEC-2025-0068`, "unsound and
  unmaintained" — [rustsec.org](https://rustsec.org/advisories/RUSTSEC-2025-0068.html),
  accessed 2026-05-20). **The `serde_yaml_ng` migration is independently
  motivated; the layer0 work should be neutral to it.**

### 1.4 "Fail safer if absent" pattern (concrete rule for CLX)

For every `bool` in a security-sensitive config struct:

1. The serde-default function MUST return the **secure** value (here: `true`).
2. The `Default::default()` impl MUST return the same secure value via the same
   function (not a duplicated literal — single source of truth).
3. The unit-test `default_config_has_secure_validator` (already exists at
   `config/mod.rs:2200-2215` area) MUST gain a `assert!(config.validator.layer0_enabled);`
   line. Failing-path test: a YAML omitting the key entirely produces
   `layer0_enabled == true`.

---

## 2. Audit trail for disable events

### 2.1 Standards consulted

- **OWASP Top 10 A09:2025 — Security Logging and Alerting Failures**
  ([owasp.org A09:2025, current, accessed 2026-05-20](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)).
  Key requirements per the 2025 revision:
  - "auditable events, such as logins, failed logins, ... and critical
    configuration changes are not logged" is listed as a common failure pattern.
  - "Ensure all transactions have an audit trail with integrity controls to
    prevent tampering or deletion, such as append-only database tables or
    similar."
- **OWASP Logging Cheat Sheet**
  ([cheatsheetseries.owasp.org Logging Cheat Sheet, accessed 2026-05-20](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)).
- **NIST SP 800-53 r5 AU-2 (Event Logging)**
  ([csf.tools/reference/nist-sp-800-53/r5/au/au-2, accessed 2026-05-20](https://csf.tools/reference/nist-sp-800-53/r5/au/au-2/)) —
  "events that are significant and relevant to the security of systems";
  configuration changes and security-attribute changes are enumerated examples.
- **NIST SP 800-53 r5 AU-9 (Protection of Audit Information)**
  ([csf.tools AU-9 r5, accessed 2026-05-20](https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/)) —
  tamper-evidence / append-only requirements for the audit sink.

### 2.2 The published pattern: "disable = audit event"

There is no single doc that says "disabling a control MUST emit a
tamper-evident log line" in those exact words, but the intersection of OWASP
A09:2025 ("critical configuration changes" + "integrity controls") and
NIST AU-2 ("security-attribute changes" as enumerated auditable events) makes
this the de-facto 2026 standard. The Sonar audit-logging primer
([sonarsource.com/.../audit-logging, accessed 2026-05-20](https://www.sonarsource.com/resources/library/audit-logging/))
explicitly enumerates "changes to security configurations" among the events
that an audit log must preserve.

CLX already implements exactly this in `clx-hook/src/audit_chain.rs`: a
SHA-256-fingerprinted `validator_disabled` record emitted via `tracing::warn!`
to an external append-only sink. This is the same pattern; reuse it.

### 2.3 What "effective state" means for layer0

The existing `Config::security_env_overrides_active()`
(`config/mod.rs:1229-1254`) reports env-driven weakening. For layer0 we want
the audit row to fire on any weakening *source*, not just env. Two options:

- **Option A (env-only, mirrors existing):** Add `CLX_VALIDATOR_LAYER0_ENABLED`
  to `security_env_overrides_active()`. Audit fires *only* when env disables L0.
  A user who edits `~/.clx/config.yaml` to set `validator.layer0_enabled: false`
  gets **no audit row** — symmetric with current L1 behavior.

- **Option B (effective-state, new pattern):** Audit fires whenever
  `config.validator.layer0_enabled == false` at hook entry, regardless of
  source. Catches the `~/.clx/config.yaml` path that Option A misses.

**Recommendation: Option B,** and **backfill the existing L1 path to match.**
The current L1 behavior is a known gap acknowledged in
`specs/2026-05-19-rgp-purple-signoff.md` (B5-4 audit-row tracked as
"defense-in-depth degradation, NOT a re-opened bypass"). Adding L0 is the right
moment to close it for both layers in one PR.

Concrete shape: introduce
`Config::layer_disable_audit_triggers(&self) -> Vec<&'static str>` returning the
list of effective-state layer-disable identifiers (e.g.
`["layer0_disabled_by_config"]`, `["layer1_disabled_by_env"]`, or both). Wire
into the same `audit_chain::build_record()` call site in
`crates/clx-hook/src/hooks/pre_tool_use.rs` that B5-4 already established.

---

## 3. Privilege gating for security-weakening configs

### 3.1 The existing CLX defense stack

For an attacker to flip `layer0_enabled` to `false` on a victim's host, they
must clear all of:

1. **B4-1 subtree filter** (`config/project.rs:84`): `validator.*` is dropped
   from any project YAML unless the YAML's SHA-256 is in the user's
   `~/.clx/trusted_configs.json` (`config/project.rs:118-145`).
2. **Global config write**: requires write access to `~/.clx/config.yaml`,
   which is same-uid only (CLX's threat model excludes same-uid attackers).
3. **Env var**: `CLX_VALIDATOR_LAYER0_ENABLED=false` requires shell access.

### 3.2 Is the community/industry asking for a *fourth* gate?

I searched for "environment variable gate security override opt-in defense in
depth 2026 CLI". The 2026 pattern that emerged
([fast.io Hermes Agent Security Guide 2026](https://fast.io/resources/hermes-agent-security/),
[windowsforum/Azure IaaS Security 2026](https://windowsnews.ai/article/azure-iaas-security-in-2026-defense-in-depth-secure-by-default-and-operations.416531/),
accessed 2026-05-20) is "secure-by-default + explicit opt-in + audit trail",
which CLX already does at three layers (B4-1 + global-config write + env).

No published pattern requires a *meta-flag* (e.g. "you must set
`CLX_VALIDATOR_ALLOW_LAYER_DISABLE=true` *before* `CLX_VALIDATOR_LAYER0_ENABLED=false`
will be honored") for tool-level security controls. The Hermes 2026 doc and
Azure 2026 IaaS doc both stop at "explicit env var + tamper-evident audit".

### 3.3 Why a meta-flag would be theater, not defense

- The threat that a meta-flag would address is "user accidentally sets
  `CLX_VALIDATOR_LAYER0_ENABLED=false`". But anyone capable of typing one env
  var name correctly can type two. The meta-flag adds typing friction, not
  attack-cost.
- It would NOT add protection against the actual attack surface (hostile
  project YAML, hostile global YAML, or hostile shell process), because all
  three are already gated by B4-1, same-uid trust, and audit logging
  respectively.
- It increases documentation/support load and creates a new failure mode
  (forgetting the meta-flag in a legitimate CI context).

**Decision: reject the meta-flag.** Defense-in-depth is met by B4-1 + audit
chain. Document the env var, document the audit signal, ship.

---

## 4. L0-off + L1-off simultaneously: fail-closed vs fall-through

### 4.1 Industry guidance (current)

Per the AuthZed engineering blog
([authzed.com/blog/fail-open, accessed 2026-05-20](https://authzed.com/blog/fail-open))
and the broader fail-open/fail-closed body of practice
([Cisco/Broadcom KB on fail-closed posture, accessed 2026-05-20](https://knowledge.broadcom.com/external/article/245938/fail-close-fail-open-policies.html);
[OpenText Security Fundamentals Part 1, accessed 2026-05-20](https://community.opentext.com/cybersec/b/cybersecurity-blog/posts/security-fundamentals-part-1-fail-open-vs-fail-closed)):

- Security-enforcement systems with no failover and no human-in-the-loop SHOULD
  fail-closed.
- A third option exists: "fail to a defined policy state" — i.e. when all
  enforcement is unavailable, pin to a hard-coded conservative state instead of
  consulting a user-tunable policy.

### 4.2 CLX-specific application

CLX is interactive (hook-mediated; the user sees an `ask` prompt). It has the
luxury of fail-to-`ask`. Three possible policies:

| Policy | Behavior when L0=off AND L1=off | Pros | Cons |
|---|---|---|---|
| **A. Honor `default_decision`** (current logic if just L1=off) | If `default_decision=allow` → allow; if `deny` → deny; if `ask` → ask. | Consistent with current code path. | If a hostile process sets `default_decision=allow` *and* both layers off, the user is silently disarmed. |
| **B. Force `deny`** | Block all commands. | Maximally safe. | DoS on legitimate "I really did want this" use cases; breaks CI. |
| **C. Force `ask` (fail-to-defined-policy)** | User sees a prompt with a clear "both layers disabled" reason. | User is informed; preserves legitimate disable use case; matches CLX's interactive model. | Slight behavioral divergence from `default_decision`. |

**Recommendation: Policy C.** Rationale:

1. Same-uid trust model means an attacker who can set the env vars can also
   forge an interactive `y`, but the *most likely* both-off scenario is a
   user-config mistake or a misconfigured CI, where fail-to-`ask` is the
   smallest blast radius.
2. The audit-chain row from §2 captures the both-off event with a
   tamper-evident fingerprint, so forensics is intact even if the user clicks
   through.
3. Symmetric to the existing L1-disabled-only path (`pre_tool_use.rs:314-332`
   already hard-codes `ask` when only L1 is off, ignoring `default_decision`).
   The both-off path inherits the same posture for free.

Implementation: in `pre_tool_use.rs`, add a branch BEFORE the L0 evaluation:
if `!config.validator.layer0_enabled && !config.validator.layer1_enabled`, emit
the audit-chain record AND `output_decision("ask", Some("Both L0 and L1 are
disabled — review manually."), ...)`. This branch is fail-closed in the
"fail to a defined policy state" sense, not the "deny everything" sense.

---

## 5. CHANGELOG / release-note convention

### 5.1 Keep a Changelog 1.1.0 categories

Per [keepachangelog.com/en/1.1.0/, current, accessed 2026-05-20](https://keepachangelog.com/en/1.1.0/):

> - `Added` for new features.
> - `Changed` for changes in existing functionality.
> - `Deprecated` for soon-to-be removed features.
> - `Removed` for now removed features.
> - `Fixed` for any bug fixes.
> - `Security` in case of vulnerabilities.

### 5.2 Security-toggle release-note pattern (CLX-house)

A user-disablable security control creates *vulnerability surface* even when
the default is safe — the future bug class is "user disabled it and forgot,
attacker exploited the disabled state". A 2026 release note that introduces
such a control MUST include all of:

1. The new key name, default value, and YAML path: `validator.layer0_enabled` =
   `true`. Stated under `### Added`.
2. The env-var override name: `CLX_VALIDATOR_LAYER0_ENABLED`. Stated under
   `### Added`.
3. The audit-chain signal name and `tracing::warn!` field shape so users can
   grep for unintended disables. Stated under `### Security`.
4. The both-off (L0=L1=false) fail-closed-to-`ask` behavior. Stated under
   `### Security`.
5. An explicit "default is enabled; do not disable in production unless you
   have a reviewed, audited reason" sentence. Stated under `### Security`.

CLX's CHANGELOG already follows this shape for B5-4 (see
`CHANGELOG.md:47, 125, 141`) and for the file-default credential backend
(`8785295 docs(0.8.0): CHANGELOG entry for file-default credential backend`).
The layer0 entry should match that house style exactly.

---

## Concrete recommendations (CLX-specific, applicable now)

### R1. serde field (`crates/clx-core/src/config/mod.rs`)

```rust
/// Enable layer 0 (deterministic-policy / rule-based) validation
#[serde(default = "default_true")]
pub layer0_enabled: bool,
```

In `impl Default for ValidatorConfig`, add `layer0_enabled: default_true(),`
next to the existing `layer1_enabled` line at `config/mod.rs:938`. No new
helper function. One line each, three lines total in `mod.rs`.

### R2. Env override + audit (`config/mod.rs::apply_env_overrides`)

Add a `CLX_VALIDATOR_LAYER0_ENABLED` branch mirroring the
`CLX_VALIDATOR_LAYER1_ENABLED` block (`config/mod.rs:1298-1310` area). In
`security_env_overrides_active()` (`config/mod.rs:1229`), append a
`CLX_VALIDATOR_LAYER0_ENABLED` entry to the existing pattern. The audit-chain
record fires automatically via the existing B5-4 wiring.

### R3. Effective-state audit (recommended, closes B5-4 gap)

Add `Config::layer_disable_audit_triggers(&self) -> Vec<&'static str>` that
returns config-driven layer-disable identifiers (not env-driven — those go
through `security_env_overrides_active`). Wire into the same audit-chain call
site in `clx-hook/src/hooks/pre_tool_use.rs` that already emits B5-4 events.
Backfills `layer1_enabled=false` via config too. One commit, both layers
covered.

### R4. Both-off fail-closed branch (`pre_tool_use.rs`)

At the top of the validation flow, before any L0 evaluation, insert:

```rust
if !config.validator.layer0_enabled && !config.validator.layer1_enabled {
    // audit_chain record here (re-use B5-4 helper)
    log_audit_entry(&input.session_id, command, &input.cwd,
                    "BOTH_DISABLED", AuditDecision::Prompted, None,
                    Some("L0 and L1 both disabled"));
    output_decision("ask",
        Some("Both L0 and L1 are disabled — review manually.".into()),
        Some(RULES_REMINDER), None);
    return Ok(());
}
```

Force `ask`; never honor `default_decision` in this state. Mirror the existing
L1-only-disabled branch at `pre_tool_use.rs:313-332`.

### R5. CHANGELOG entry shape

Under the v0.8.x unreleased section:

```markdown
### Added
- **validator.layer0_enabled** (`bool`, default `true`): new config knob to
  disable the deterministic-policy (L0) layer. Mirrors `validator.layer1_enabled`.
  Env override: `CLX_VALIDATOR_LAYER0_ENABLED=false`. Filtered from untrusted
  project configs by the B4-1 subtree filter.

### Security
- When `validator.layer0_enabled=false` (via any source: env, global config,
  or hash-trusted project config), CLX emits a `validator_disabled` audit-chain
  record with a SHA-256 fingerprint via `tracing::warn!`, capturable by an
  external append-only sink. Same pattern as B5-4 (layer1).
- When **both** `validator.layer0_enabled=false` AND
  `validator.layer1_enabled=false`, CLX forces the decision to `ask` regardless
  of `validator.default_decision`. This is a fail-to-defined-policy state, not
  a fail-open to user-configured behavior. Do not disable both layers in
  production.
```

---

## Sources

All accessed 2026-05-20.

### Serde / Rust YAML

- [serde.rs — Field attributes](https://serde.rs/field-attrs.html) — current, no
  version pin on the doc page; reflects serde 1.x.
- [serde-rs/serde issue #2249 — Fallible defaults for non-present fields](https://github.com/serde-rs/serde/issues/2249).
- [acatton/serde-yaml-ng (GitHub)](https://github.com/acatton/serde-yaml-ng) —
  v0.10, July 2025 maintainer update.
- [rustsec/advisory-db issue #2132 — serde_yaml is unmaintained](https://github.com/rustsec/advisory-db/issues/2132)
  — opened 2024-11-13.
- [RUSTSEC-2025-0068 — serde_yml crate is unsound and unmaintained](https://rustsec.org/advisories/RUSTSEC-2025-0068.html).

### Standards / audit trail

- [OWASP Top 10 — A09:2025 Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/).
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [NIST SP 800-53 r5 — AU-2 Event Logging (csf.tools mirror)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-2/).
- [NIST SP 800-53 r5 — AU-9 Protection of Audit Information (csf.tools mirror)](https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/).
- [Sonar — Audit Logging Best Practices](https://www.sonarsource.com/resources/library/audit-logging/).

### Fail-closed / fail-open

- [AuthZed — "Understanding Failed Open and Fail Closed"](https://authzed.com/blog/fail-open).
- [Broadcom KB — Fail close & Fail Open Policies](https://knowledge.broadcom.com/external/article/245938/fail-close-fail-open-policies.html).
- [OpenText — Security Fundamentals Part 1: Fail Open vs Fail Closed](https://community.opentext.com/cybersec/b/cybersecurity-blog/posts/security-fundamentals-part-1-fail-open-vs-fail-closed).

### 2026 defense-in-depth context

- [Hermes Agent Security Guide: Isolation and Authorization (2026)](https://fast.io/resources/hermes-agent-security/).
- [Azure IaaS Security in 2026: Defense in Depth, Secure by Default](https://windowsnews.ai/article/azure-iaas-security-in-2026-defense-in-depth-secure-by-default-and-operations.416531/).

### CHANGELOG convention

- [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

### CLX in-repo cross-references

- `crates/clx-core/src/config/mod.rs:583-585` — `layer1_enabled` field declaration.
- `crates/clx-core/src/config/mod.rs:935-945` — `Default` impl for `ValidatorConfig`.
- `crates/clx-core/src/config/mod.rs:1229-1254` — `security_env_overrides_active()`.
- `crates/clx-core/src/config/mod.rs:1282-1310` — `apply_env_overrides` (L1 block).
- `crates/clx-core/src/config/project.rs:84-89` — `NON_INERT_KEY_PATTERNS` (B4-1).
- `crates/clx-core/src/config/project.rs:230-262` — B4-1 regression tests.
- `crates/clx-hook/src/audit_chain.rs:1-100` — B5-4 tamper-evident fingerprinting.
- `crates/clx-hook/src/hooks/pre_tool_use.rs:313-332` — L1-disabled fail-to-ask branch.
- `CHANGELOG.md:47, 125, 141` — B5-4 entry as house-style reference.
