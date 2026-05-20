# v0.9.0 RED Findings — Unified Register

**Phase:** RED complete (gate 1)
**Fragments:** `v090-red-R1.md` (audit-chain/fail-open/both-off/F1-F3 carry-over), `v090-red-R2.md` (code-paths/dashboard/L1-rename/test-gaps)
**PoC inventory:** 9 in `crates/clx-hook/tests/v090_red_r1_poc.rs` + 11 in `crates/clx-hook/tests/v090_red_r2_poc.rs`, all `#[ignore]`-gated; 20/20 reproduce on `--ignored`; default suite green.

## Release-blocking set (GREEN must close, PURPLE must verify)

| # | ID | Sev | Title | Root cause file:line | Closing-PoC |
|---|---|---|---|---|---|
| 1 | **Silent-allow class** (T9.2/T9.3/T9.4 + R1-F1 + T9.1) | **CRIT/HIGH** | L0 off + (L1 unavailable/timeout/error OR poisoned cache) + `default_decision=allow` → silent allow of blacklisted commands (`rm -rf /`). The F7-deferred class from v0.8.2 re-opened by `layer0_enabled`. Four independent fallback paths. | `pre_tool_use.rs:368-396` (cache), `:472-497` (LLM-unavailable), `:518-544` (timeout), `:549-573` (gen-failed) | `v090_red_r1_poc.rs` (R1-F1), `v090_red_r2_poc.rs` (T9.1/9.2/9.3/9.4) |
| 2 | **T8 / R1-F4 doc-honesty over-claim** | HIGH (constraint-integrity) | README:186 + CHANGELOG.md:30-38 claim "tamper-evident audit-chain fingerprint" without the external-sink qualifier. The honest property is the v0.8.2 reclassify language. | `README.md:186`, `CHANGELOG.md:30-38` (the `[Unreleased]` Security block) | docs/spec (no PoC) |
| 3 | **L1-rename deprecation hygiene** | HIGH | v0.9.0 normalised `"L1 disabled"` → `"L1-DISABLED"` without the research-recommended dual-emit one-version window. `specs/_prerelease/01-validation.md:150,422` still references the legacy literal. External log parsers at risk. | `pre_tool_use.rs:~400` (the L1-DISABLED emit) | (deprecation; downstream-consumer enum in R2 §2.1) |

## Track / accepted residuals (documented, NOT release-blocking)

| ID | Source | Sev | Disposition |
|---|---|---|---|
| **T7 / R1-F3** both-off observability | R1 | MED | no `clx doctor`/health warning when both layers off + enabled=true. Close in GREEN if cheap; else accept-doc. |
| **T2** load_learned_rules pre-gate | R2 | MED | `pre_tool_use.rs:265-270` runs the load BEFORE the L0 gate at `:275`. Functionally harmless; maintenance hazard + leaky property claim. Move OR document. |
| **T3** env+config double-audit | R2 | MED | env+config double-disable emits both SECURITY-ENV and SECURITY-CFG. Decide intent (dual signal vs dedup). |
| **R1-F2 / T1** SECURITY-CFG tamper class | R1 | LOW | As-designed under same-uid threat model; the release-blocking part is doc-honesty (T8 / R1-F4) — fix there. |
| **R1-N1** event_fingerprint TEXT column | R1 | LOW | v0.10.0 schema migration to a dedicated column. |
| **R1-N2** L0-DISABLED + L0-READ pairing | R1 | LOW | read-only commands under both-off skip the L1-DISABLED row. Document. |
| **R1-N3** default_decision silent enum-default | R1 | LOW | Document. |
| 4 R2 LOW new findings | R2 | LOW | trust-mode + SECURITY-CFG ordering; pre-short-circuit SECURITY-CFG; read-only skip L1-DISABLED; pre-L0 SECURITY-CFG not transactional. Track. |

## Refuted (v0.8.2 carry-over still holds)

- **F1 redaction** — VULN-REFUTED. Source (`azure.rs:285`) and sinks (`audit.rs:38`, the 11 wrapped sites) hold under the L0-disabled flow.
- **F2 overbroad-allow gate** — VULN-REFUTED. Pure pattern-level at load, independent of `layer0_enabled`.
- **F3 audit-chain reclassify** — VULN-REFUTED. SECURITY-CFG uses identical per-event `seq=1 + GENESIS_HASH` semantics as SECURITY-ENV (consistent with v0.8.2 honest reclassify).
- **Dashboard ~15 (0, N) arm shifts** — all 15 verified consistent (R2 §4 table). No off-by-one.

## GREEN work breakdown (2 disjoint streams)

- **G1** (`pre_tool_use.rs` + new e2e regression tests) — close the silent-allow class. F7-deferred posture applied to v0.9.0: refuse / loud-gate / force-ask when `default_decision=allow` and L0 disabled (config OR env); for the cache-bypass arm, do NOT consult validation_cache when L0 is disabled (cache is only meaningful when L0 actually ran). Also: L1-DISABLED dual-emit window (`"L1 disabled"` + `"L1-DISABLED"`) per research; T2 disposition (move learned-rule load behind L0 gate OR document); T3 disposition (env+config dedup OR document). Regression tests: invert each RED PoC's assertion so it becomes a fail-after-fix guard.
- **G2** (docs + cli health) — README + CHANGELOG language downgrade (honest tamper-evidence text); `specs/_prerelease/01-validation.md` legacy-literal cleanup; `clx health` validator-layers-disabled warning (T7 close). Optionally a new `clx doctor` if scoped.
