# v0.9.0 Pre-Release RGP Research (2026-current)

**Date:** 2026-05-20
**Scope:** Decision-first research for the RGP pass on v0.9.0 candidate (PR #33).
**Predecessor:** [v0.8.2 RGP](2026-05-19-rgp-prerelease.md) shipped with F1/F2/F3 closed.
**v0.9.0 delta under review:**
1. `validator.layer0_enabled: bool` + `CLX_VALIDATOR_LAYER0_ENABLED` env override
2. New `SECURITY-CFG` audit row on config-driven layer disable
3. Both-L0-and-L1-disabled forces `output_decision("ask")` (fail-to-defined-policy)
4. Audit-reason normalization: `"L1 disabled"` -> `"L1-DISABLED"`
5. Dashboard `layer0_enabled` row inserted at index 1; ~15 `(0, N)` match arms shifted in `settings/config_bridge.rs`

---

## TL;DR Decisions (read this first)

| # | Question | Decision | Confidence |
|---|----------|----------|------------|
| 1 | Does L0-disable widen the threat surface beyond L1-disable? | **YES — strictly wider.** L0 is the deterministic/blacklist + sentinel layer; disabling it bypasses fixed-policy rules that L1 (heuristic/learned) cannot recover. Treat L0-disable as an MITRE T1562.001-class action and audit accordingly. | HIGH |
| 2 | Is per-process re-emission of `SECURITY-CFG` a flooding/cost risk? | **LOW for end-users, MEDIUM for fleet deployers.** Keep per-process emission (it is forensically correct) but add a one-line dedup hash field so downstream aggregators can compress on identity. | MEDIUM |
| 3 | Is "force ask when both layers off" correct in 2026? | **YES — re-confirmed.** This is textbook fail-to-defined-policy. Fail-open would be wrong for a security validator (vs. an availability service). | HIGH |
| 4 | Best test technique for the 15 shifted `(0, N)` arms? | **Triple stack:** (a) cargo-mutants "delete match arm" on the file, (b) proptest over the full `(section_idx, field_idx)` space asserting round-trip, (c) insta snapshots already in the tree freezing the post-shift order. | HIGH |
| 5 | Should we dual-emit `"L1 disabled"` AND `"L1-DISABLED"` for a window? | **YES — one-version dual-emit** (v0.9.0 emits both; v0.10.0 removes legacy). Standard parallel-change pattern; cite SemVer deprecation guidance. | HIGH |
| 6 | Does the anti-anchoring rule still apply on a second adjacent pass? | **YES — strictly.** The arxiv 2603.18740 effect (16-93 pp drop) is per-prompt framing, not per-codebase. v0.8.2 sign-off context must be withheld from v0.9.0 RED. Debiasing via metadata redaction is the published fix. | HIGH |

---

## 1. Threat-model delta: L0-disable vs. L1-disable

### What L0 enforces that L1 cannot recover

L0 in CLX is the deterministic policy layer: fixed blacklists, sentinel patterns, file-config deny rules. L1 is the heuristic/learned layer with denial-count promotion and timeout banding (per the v0.8.0 spec). They are **non-redundant**:

- Disabling **L1** removes adaptive/learned blocking but leaves the deterministic floor intact. Worst case: a learned-rule bypass for novel patterns.
- Disabling **L0** removes the deterministic floor. Three new attack classes appear simultaneously:
  1. **Blacklist bypass** — fixed sentinels (e.g., known-bad commands) no longer match.
  2. **File-config rule bypass** — project-level deny rules in `.config/` become advisory.
  3. **Sentinel/canary bypass** — anything L0 was the canonical owner of.

L1 cannot recover (1) or (3) because L1 is heuristic by design; it does not promise coverage of the deterministic set.

### Framing: this is MITRE T1562.001 territory

The new toggle is, by MITRE's taxonomy, a legitimate-but-tampered "disable or modify tools" surface. MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) explicitly covers "modifying/deleting Registry keys or configuration files so that tools do not operate properly." A config-driven `layer0_enabled: false` is functionally identical from the attacker's perspective — except that on a **same-uid local trust model** (CLX's threat model) the attacker already has the bit needed to flip it.

The threat model implication is not "prevent the flip" (you can't, given same-uid) but **make the flip loud**: that is exactly what the v0.9.0 `SECURITY-CFG` audit row does. Red Canary's T1562.001 detection guidance reinforces this: "the act of disabling or modifying the tool is often revealed in numerous different data sources" — i.e., audit the disable event, not just the bypass attempt.

### 2026 published guidance

- **OWASP Threat Modeling** treats trust boundaries as the locus of explicit controls; a security-control toggle that crosses a trust zone needs auditing on both sides of the boundary (config write + each process consumption). CLX v0.9.0 only audits the consumption side — which is correct for the same-uid model where the write side is the user themselves.
- **OWASP Proactive Controls (2026 ed.)** continues to mandate "log security-relevant events" including configuration changes that weaken controls.
- **Microsoft Security Blog (2026-05-14)** "Defense in depth for autonomous AI agents" explicitly notes that disabling one layer must not silently collapse the system to fail-open — which dovetails directly with focus area 3 below.

### Sources

- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/) — 2026 current.
- [Red Canary Threat Detection Report — T1562.001](https://redcanary.com/threat-detection-report/techniques/disable-or-modify-tools/) — 2026.
- [Microsoft Security: Defense in depth for autonomous AI agents](https://www.microsoft.com/en-us/security/blog/2026/05/14/defense-in-depth-autonomous-ai-agents/) — 2026-05-14.
- [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process) — current.
- [OWASP Top 10 Proactive Controls 2026](https://www.securityjourney.com/post/owasp-top-10-proactive-controls) — 2026.

---

## 2. SECURITY-CFG per-process re-emission: flooding risk?

### Quantitative framing

Assume worst case: a long-lived config sets `layer0_enabled = false`. Every CLX hook invocation emits one `SECURITY-CFG` row. A heavy interactive session runs O(10²) hooks/day. A CI fleet runs O(10⁴-10⁵) hooks/day across machines. Each row ~250 bytes JSON.

- Interactive: ~25 KB/day per user — **negligible**, well below any aggregator threshold.
- Fleet/CI: ~2.5–25 MB/day per fleet — **noticeable but not flooding**. At Datadog's ~$1.80/GB ingest+index this is well under $20/month per fleet. At Splunk's ~$150/GB/day this could reach ~$4/day on the high end.

### Per-process is correct; dedup is the consumer's job

The OWASP Logging Cheat Sheet's core rule ("not too much, not too little") applies *within* a process, not *across* identical processes. Forensically you want every process invocation to record the state it ran under — collapsing them server-side loses the "which invocations actually ran under disabled-L0?" answer.

**2026 best practice (per the structured-logging consensus):** emit per-process, but include a stable dedup key so the aggregator can compress. The v0.8.2 per-event fingerprint pattern is the right precedent.

### Concrete recommendation

Add a `cfg_state_hash` field to the `SECURITY-CFG` row that is the hash of `(layer0_enabled, layer1_enabled, default_decision)`. Downstream:

- Splunk: `| dedup cfg_state_hash, host, _time span=1h`
- Datadog: ingest-time exclusion filter keyed on `cfg_state_hash`
- ELK: index template with `cfg_state_hash` as the dedup key in a watcher

This keeps the per-process forensic guarantee while giving aggregators a free knob.

### What NOT to do

Do **not** rate-limit emission in-process. Per MITRE T1562.001 detection guidance, redundant emission is a feature, not a bug — if any single process invocation suppresses the row, an attacker who can trigger many invocations can also exhaust your in-process rate-limit window.

### Sources

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — current.
- [CISA Best Practices for Event Logging and Threat Detection](https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection) — current.
- [Datadog Log Management Pricing 2026](https://www.parseable.com/blog/datadog-log-management-cost) — 2026.
- [Splunk vs Datadog Cloud SIEM Cost 2026](https://siemcostcalculator.com/splunk-vs-datadog-cost) — 2026.
- [Log Management in 2026 best practices](https://logmanager.com/blog/log-management/log-management-best-practices/) — 2026.

---

## 3. Both-off fail-to-defined-policy ("force ask") re-validation

### Re-confirmed against 2026 sources

The v0.9.0 design forces `output_decision("ask")` when both L0 and L1 are disabled, ignoring `default_decision`. This is **textbook fail-to-defined-policy** — distinct from both fail-open (allow) and fail-closed (block).

Per AuthZed's "Failed Open and Fail Closed" framing (still canonical in 2026): the choice depends on whether the system is **availability-critical** (databases, authn) or **security-critical** (validators, IDS). CLX is unambiguously the latter; therefore fail-open is incorrect.

DevSecOps School's 2026 fail-safe-defaults guide reaffirms: "Fail-to-defined-policy allows organizations to specify their own baseline security policies that remain in effect during failures, rather than defaulting to either permissive or restrictive states." `ask` *is* the defined baseline for CLX when no automatic decision layer is active — it pushes the decision to the human in the loop, which is the only remaining trust anchor.

### Why `ask` (not `block`) is right

A naive read says: security tool, both layers off → fail-closed (block). But CLX's threat model is same-uid local trust. The user themselves disabled both layers; blocking outright is hostile to the user without informing them why. `ask` interrupts the workflow with a forced human decision — the user gets visibility into the fact that no automatic layer is reviewing this action. Fail-closed without notification would also be a poor user experience and could push users to bypass CLX entirely.

### Sources

- [AuthZed: Failed Open and Fail Closed](https://authzed.com/blog/fail-open) — canonical, still current in 2026.
- [DevSecOps School: Fail-Safe Defaults 2026 Guide](https://devsecopsschool.com/blog/fail-safe-defaults/) — 2026.
- [Broadcom KB: Fail close & Fail Open Policies](https://knowledge.broadcom.com/external/article/245938/fail-close-fail-open-policies.html) — current.
- [Intelligent Visibility: Security Resilience](https://intelligentvisibility.com/s/security-resilience-ensuring-policy-enforcement-survives-infrastructure-failures) — current.

---

## 4. Testing 15 shifted `(0, N)` match arms

### The classic failure mode

Inserting `layer0_enabled` at row index 1 in the settings dashboard shifts every subsequent `(section_idx, field_idx)` arm by one. Off-by-one in a single arm produces: dashboard edits the wrong field, snapshot tests catch only the rendering symptom, behavior tests catch only the field-mapping symptom — neither catches both unless tests cover the full cross-product.

### Triple-stack recommendation (in priority order)

#### A. cargo-mutants on `settings/config_bridge.rs` (highest ROI)

cargo-mutants in 2026 specifically mutates "delete match arm" (only when a wildcard arm exists, but `config_bridge.rs` typically has a fallthrough). For each of the ~15 shifted arms it will:

1. Delete the arm.
2. Run the test suite.
3. Report "MISSED" if no test caught the deletion.

Run with `cargo mutants --file crates/clx/src/dashboard/settings/config_bridge.rs`. Any MISSED arm is an under-tested arm — exactly the off-by-one risk surface. Recent (2026) cargo-mutants updates include the original arm pattern in the mutant name, so triage is fast.

#### B. proptest cross-product over `(section_idx, field_idx)`

Write one property test:

```rust
proptest! {
    #[test]
    fn config_bridge_round_trip(
        section in 0usize..NUM_SECTIONS,
        field in 0usize..MAX_FIELDS_PER_SECTION,
    ) {
        let value = sample_value_for(section, field);
        let cfg = apply_edit(section, field, &value)?;
        let read_back = read_field(&cfg, section, field);
        prop_assert_eq!(value, read_back);
    }
}
```

This catches "section 0 / field 5 writes to the wrong config key" in one property — far stronger than the 15 per-arm unit tests. proptest's `Index` strategy with bounded ranges is the idiomatic 2026 form.

#### C. insta snapshot tests for the rendered order

Already present in the tree (`wave1_settings_tab_populated.snap` was just added in the current diff). These freeze the *visual* order including the new `layer0_enabled` row at index 1. Combined with (A) and (B) this gives:

- (A) catches semantic arm errors (wrong field written)
- (B) catches index-mapping errors across the whole grid
- (C) catches display-order regressions

### Mutation testing caveat

cargo-mutants does NOT generate "swap index 1 with index 2" mutations directly — its operators are arm-deletion and constant/operator swaps. So (A) alone will not catch a pure off-by-one *between two valid arms*; you need (B) for that. This is why all three are needed.

### Sources

- [cargo-mutants — Mutation patterns](https://mutants.rs/mutants.html) — current.
- [cargo-mutants Changelog 2026](https://mutants.rs/changelog.html) — 2026.
- [proptest::sample::Index](https://docs.rs/proptest/latest/proptest/sample/struct.Index.html) — current.
- [Rust Testing Patterns for Reliable Releases](https://dasroot.net/posts/2026/03/rust-testing-patterns-reliable-releases/) — 2026-03.
- [Property-Based Mutation Testing (arxiv)](https://arxiv.org/pdf/2301.13615) — applicable.
- [Ratatui: Testing with insta snapshots](https://ratatui.rs/recipes/testing/snapshots/) — current.

---

## 5. Audit-string normalization deprecation window

### The risk

`"L1 disabled"` → `"L1-DISABLED"` is a breaking change for any log parser regex-matching the literal. CLX has no published "log fields are stable" contract yet, but the prudent default in 2026 is to treat security-audit fields as *de facto* public API.

### Published 2026 pattern: one-version dual-emit (parallel change)

The "parallel change" / "expand-contract" pattern is the consensus 2026 approach:

1. **v0.9.0 (expand):** Emit BOTH `reason: "L1-DISABLED"` AND `legacy_reason: "L1 disabled"` on the same audit row. New parsers read `reason`; old parsers keep reading `legacy_reason`. Mark `legacy_reason` "Deprecated, removed in v0.10.0" in CHANGELOG under a `### Deprecated` section.
2. **v0.10.0 (contract):** Remove `legacy_reason`. Per Keep-a-Changelog: "Always use the Deprecated category before using the Removed category. Give users at least one full version cycle of warning."

The python-semver "Displaying Deprecation Warnings" doc formalizes this for code APIs; the same principle applies to log fields treated as a contract.

### Why dual-emit, not just rename

- A pure rename in a minor version violates the principle that minor versions are backward-compatible.
- A pure rename in a major version (v1.0.0) without a deprecation window leaves consumers stranded — Keep-a-Changelog explicitly warns against this.
- Dual-emit cost is trivial (one extra string in one audit row) and bounded to a single version.

### Concrete v0.9.0 CHANGELOG entry

```markdown
### Deprecated
- `audit.reason: "L1 disabled"` log string is deprecated. Use the new
  normalized form `"L1-DISABLED"` (also emitted as `audit.reason` in v0.9.0).
  The legacy string is still emitted as `audit.legacy_reason` and will be
  removed in v0.10.0. Migrate log parsers to match on `reason`.
```

### Sources

- [Semantic Versioning 2.0.0 — deprecation guidance](https://semver.org/) — current.
- [Keep a Changelog: Definitive Guide 2026](https://quackback.io/blog/keep-a-changelog) — 2026.
- [python-semver: Displaying Deprecation Warnings](https://python-semver.readthedocs.io/en/latest/advanced/display-deprecation-warnings.html) — 2026 current.
- [structlog: Backward Compatibility](https://www.structlog.org/en/19.2.0/backward-compatibility.html) — canonical.
- [How to Implement API Versioning and Backward Compatibility (2026-03)](https://technori.com/2026/03/25054-how-to-implement-api-versioning-and-backward-compatibility/ava/) — 2026-03.

---

## 6. Anti-anchoring: does the rule still apply on an adjacent pass?

### Strict re-confirmation

The arxiv paper [2603.18740 "Measuring and Exploiting Confirmation Bias in LLM-Assisted Security Code Review"](https://arxiv.org/abs/2603.18740) (published 2026-03-19) measures the framing-effect on a *per-prompt* basis. The 16-93 pp detection-rate drop is induced by language in the prompt presented to the reviewing model — it is **not** a property of the code or the version under review.

This means:

- The v0.8.2 PURPLE sign-off, the F1-F3 closure narrative, and the v0.8.2 Codex findings would, if included verbatim in the v0.9.0 RED prompt, anchor the reviewer toward "the security posture is already validated."
- The paper's adversarial-framing result (88% success rate against autonomous agents under iterative framing) confirms that even subtle "this was already reviewed" language is sufficient to suppress detection.

### Published mitigation: metadata redaction + explicit instructions

Per the same paper: "Debiasing via metadata redaction and explicit instructions restores detection in all affected cases." The operational form for v0.9.0 RGP:

1. **RED prompt:** Receives ONLY the v0.9.0 diff + a minimal "this is unreviewed code; find vulnerabilities" framing. NO mention of v0.8.2 sign-off, NO F1/F2/F3 history, NO prior PURPLE narrative.
2. **GREEN prompt:** Receives RED findings only, with no prior-version context.
3. **PURPLE prompt:** May see prior-pass context, but only AFTER RED and GREEN have completed independently.

### Stronger form for adjacent passes

Adjacent passes increase the anchoring risk because the codebase visibly inherits prior structure (the v0.8.2 audit-chain code is right next to the v0.9.0 extension). The mitigation is **prompt-level**, not codebase-level — RED reviews the v0.9.0 diff in isolation as if v0.8.2 never happened.

### Sources

- [arxiv 2603.18740 — Measuring and Exploiting Confirmation Bias in LLM-Assisted Security Code Review](https://arxiv.org/abs/2603.18740) — 2026-03-19.
- [arxiv 2603.18740 HTML v2](https://arxiv.org/html/2603.18740v2) — 2026.
- [arxiv 2506.10280 — AI-Based Software Vulnerability Detection SLR](https://arxiv.org/abs/2506.10280) — corroborating, 2026.

---

## 2026 Deprecations to Flag

| Area | Deprecation | Source | Action for v0.9.0 |
|------|-------------|--------|-------------------|
| Log field strings | `"L1 disabled"` (free-form) | This spec § 5 | Dual-emit; remove in v0.10.0. |
| Match arm tests | Per-arm unit tests only | cargo-mutants 2026 + proptest | Add property test for the full grid. |
| Fail-open security defaults | "Allow on failure" framing | DevSecOps School 2026 | Already correct in v0.9.0 (force ask). Document the choice. |
| LLM security review | Single-shot review without metadata redaction | arxiv 2603.18740 | Apply prompt-level redaction for RED. |

No external dependency deprecations in v0.9.0's surface that block the release; all deltas are internal.

---

## 5-Line Concrete Recommendations

1. **RED probes FIRST:** the 15 shifted `(0, N)` arms in `settings/config_bridge.rs` — feed only the v0.9.0 diff, no v0.8.2 context, and look for one specific class: "editing dashboard row N writes to config field N±1." Then probe the L0-disable bypass paths (blacklist, sentinel, file-config rule).
2. **GREEN hardens** if RED finds anything: add the proptest cross-product over `(section_idx, field_idx)` as the canonical regression net (one test replaces 15), and add `cfg_state_hash` to `SECURITY-CFG` rows so re-emission stays forensic without flooding aggregators.
3. **PURPLE re-derives** the both-off-forces-ask invariant from first principles (fail-to-defined-policy, same-uid trust model) without reading the v0.8.2 PURPLE narrative; it must independently land on `ask` not `block` not `allow`.
4. **CHANGELOG** for v0.9.0 must include a `### Deprecated` section dual-emitting `"L1 disabled"` and `"L1-DISABLED"`, with explicit removal target v0.10.0 — this is the one externally-visible breaking change in the release.
5. **Run `cargo mutants --file crates/clx/src/dashboard/settings/config_bridge.rs`** before tagging v0.9.0; any MISSED arm is a release blocker, since this is the exact regression class the v0.9.0 P2 introduces.

---

## Confidence summary

- High confidence: items 1, 3, 4, 5, 6 (well-cited 2026 sources, direct mapping to CLX design).
- Medium confidence: item 2 (the dedup-key recommendation is a synthesis, not a single citation — but the underlying log-cost numbers are 2026-published).
- No contradictions encountered across sources.
