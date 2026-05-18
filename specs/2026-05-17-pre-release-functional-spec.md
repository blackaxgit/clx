# CLX 0.8.0 Pre-Release Functional and Behavior Specification

**Date:** 2026-05-17
**Branch:** `feat/0.8.0-memory-skills-coverage`
**Purpose:** Authoritative reference for testing CLX before tagging `v0.8.0`. Every behavioral claim is grounded in the real 0.8.0 source with `file:line` citations, not aspirational design. Use this to verify the build behaves as documented and to triage the suspected gaps before release.

This document was produced by four parallel specialist passes over disjoint subsystems, then synthesized. It is split into self-contained section files plus the consolidated risk register below.

---

## 1. How to use this for pre-release testing

1. Read Section 0 (this file) for the risk register and the go/no-go view.
2. For each subsystem you are testing, open its section file and run the numbered Verification steps. Each is written to be copy-pasteable or to name the exact automated test.
3. Treat every item in the Risk Register as a test case: confirm it is either fixed, acceptable-and-documented, or a release blocker.
4. Sign-off requires: all four sections' verification steps pass, every CRITICAL/HIGH risk resolved or explicitly accepted, and the automated gates green (`cargo build/test/clippy/fmt`, `bash plugin/scripts/validate.sh --strict`).

## 2. Section index

| Section | File | Scope | Lines |
|---------|------|-------|-------|
| 01 Validation pipeline | `specs/_prerelease/01-validation.md` | PreToolUse guard, L0/L1, decision cache, audit, learned rules, trust | ~520 |
| 02 Memory and recall | `specs/_prerelease/02-memory-recall.md` | RRF + reranker + decay + gate, pin sessions, tool_events, auto-summarize, MCP recall/remember/checkpoint | ~430 |
| 03 Credentials and config | `specs/_prerelease/03-credentials-config.md` | Age file backend (default), keychain opt-in, migrate, providers, config layering, project trust, retention | ~440 |
| 04 Integration | `specs/_prerelease/04-integration.md` | 8 hook events, handle_event router, 7 MCP tools, install/uninstall, plugin + 6 skills, install-local.sh, dashboard | ~470 |

Total: ~2400 lines of grounded behavior + verification across 90+ documented features, 76 edge/failure scenarios, 50+ runnable verification procedures.

---

## 3. Consolidated Risk Register (27 suspected gaps)

These were flagged during grounding. Severity is this synthesis's assessment for the 0.8.0 release decision. Each must be resolved, accepted-and-documented, or escalated before tag.

### Validation (Section 01)

| ID | Severity | Finding | File ref |
|----|----------|---------|----------|
| V-R2 | HIGH | Dead L1 `Deny` arm: `risk_score_to_decision` never returns `Deny`, so an LLM "deny" verdict cannot hard-block. Validation is weaker than designed. | `pre_tool_use.rs:427-439` |
| V-R4 | HIGH | No timeout wrapper around `evaluate_with_llm`; a hung L1 provider can block the PreToolUse hook indefinitely despite `layer1_timeout_ms` existing as config. | `pre_tool_use.rs` L1 path |
| V-R5 | HIGH | Learned auto-blacklist `denial_count` is never incremented from the hook flow (only `approved=true` wired), so the blacklist threshold is effectively unreachable in normal use. | learned-rules flow |
| V-R3 | MEDIUM | L1 parse-failure / suspicious response yields a plain `ask`, bypassing `default_decision` (weaker than the documented fallback). | `pre_tool_use.rs` |
| V-R7 | MEDIUM | Secret redaction is heuristic; non-pattern secrets are stored verbatim in audit. The "redaction guarantee" is conditional, not absolute. | redaction path |
| V-R8 | MEDIUM | Malformed config is swallowed by `unwrap_or_default()`; validation can silently weaken with no error surfaced. | config load |
| V-R9 | MEDIUM | Legacy plaintext trust token accepts any file by `mtime < 3600s` regardless of content. | trust token |
| V-R1 | LOW | `default_decision` relies on derived `Default` with no explicit fn; confirm the live value. | `config/mod.rs` |
| V-R6 | LOW | `PromptSensitivity::Custom` silently maps to STANDARD with no warning. | sensitivity map |

### Memory and recall (Section 02)

| ID | Severity | Finding | File ref |
|----|----------|---------|----------|
| M-R1 | MEDIUM | No newer-schema/downgrade guard although the golden corpus claims one; an older binary opening a v7 DB is unguarded. | recall/storage |
| M-R6 | MEDIUM | Per-prompt `Storage`/`EmbeddingStore` open happens inside the 500 ms recall budget (latency risk under load). | `subagent.rs` do_recall |
| M-R2 | LOW | Stale MCP `clx_recall` doc comment says 0.6/0.4 linear merge; actual path is RRF. Doc-only. | `tools/recall.rs` |
| M-R3 | LOW | Inconsistent error handling between `turns_since` and the idle-check gates in auto-summarize. | `stop_auto_summary.rs` |
| M-R4 | LOW | `query_percentile_gate` logic duplicated (subagent.rs + mcp/recall.rs). | both call sites |
| M-R5 | LOW | `RERANK_FALLBACK_TOTAL` is not user-observable (no surfacing in stats/dashboard). | rerank path |

### Credentials and config (Section 03)

| ID | Severity | Finding | File ref |
|----|----------|---------|----------|
| C-R1 | MEDIUM | `clx credentials list` annotation uses `:api-key` (colon) suffix but resolver/set use `<provider>-api-key` (hyphen); colon branch is unreachable (validate_key rejects colons). Dead/misleading feature. | `commands/credentials.rs:159-160` vs `config/mod.rs:1803` |
| C-R3 | MEDIUM | `api_key_file` mode-check is TOCTOU and the file is plaintext. | `config/mod.rs:1842-1860` |
| C-R4 | MEDIUM | `load_from_file_only` (dashboard) bypasses the project layer, trust gate, and env overrides. | `config/mod.rs:1190-1200` |
| C-R2 | LOW | Figment `Env::prefixed` plus `apply_env_overrides` double-apply with no test for conflicting/out-of-range precedence. | `config/mod.rs:1164-1181` |
| C-R5 | LOW | `AgeFileBackend::get`/`list_keys` take no inter-process lock; believed safe via atomic rename but no concurrent-read-during-rename test. | `backend.rs:399-423` |
| C-R6 | LOW | `CLX_CONFIG_PROJECT` lets env select an arbitrary (filtered) config source; powerful knob for the threat model. | `config/project.rs:31-36` |

### Integration (Section 04)

| ID | Severity | Finding | File ref |
|----|----------|---------|----------|
| I-R1 | HIGH | License mismatch: `clx version` reports MIT, `plugin.json` declares MPL-2.0, workspace is MPL-2.0. Legal/packaging inconsistency, must be reconciled before a public tag. | `commands/version.rs` vs `plugin.json` |
| I-R5 | MEDIUM | `clx maintenance trim` hard-codes audit retention to 90 days, bypassing `retention` config. | `commands/maintenance.rs` |
| I-R2 | MEDIUM | No Stop-event contract fixture; `stop.json` is actually a SessionEnd envelope, so the Stop/auto-summarize wiring is not contract-tested. | `tests/fixtures/hook_envelopes/` |
| I-R4 | MEDIUM | `clx install` is non-transactional: a partial failure can leave a half-configured state with no rollback. | `commands/install.rs` |
| I-R3 | LOW | Hook provenance is forgeable by design (documented residual memory-poisoning risk under the threat model). | `router.rs` provenance |
| I-R6 | LOW | `install-local.sh` verification check #5 uses a weak substring match. | `scripts/install-local.sh` |

### Synthesis verdict on the register

- **HIGH (4): I-R1 license mismatch, V-R2 dead Deny arm, V-R4 unbounded L1, V-R5 unreachable auto-blacklist.** I-R1 is a hard pre-tag blocker (legal/packaging). V-R2/V-R4/V-R5 are validation-correctness gaps: validation still functions (L0 + ask/allow), but it is weaker than documented. Recommend fixing V-R2/V-R4 before tag or explicitly documenting the reduced guarantee; I-R1 must be fixed.
- **MEDIUM (12):** none are data-loss or security-critical given the file-backend default; each should be accepted-and-documented or fixed in a focused pass.
- **LOW (11):** doc/observability/cosmetic; fine to defer to 0.8.1 with a tracking note.

This is exactly the value of the pre-release pass: it surfaced concrete, cited issues before a public tag rather than after.

---

## 4. Automated gate (must all be green before tag)

```
cargo build --workspace --all-targets
cargo test --workspace                 # 1304 pass / 0 fail / 10 ignored at synthesis time
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
bash plugin/scripts/validate.sh --strict
bash plugin/scripts/tests/validate_test.sh
```

Manual smoke (from the section files): zero keychain prompts under default backend, 6 skills discoverable, all 8 hooks registered incl. Stop, install/uninstall symmetry, recall returns relevant context within budget, auto-summarize writes exactly one snapshot.

---

## 5. Status and next step

The four section files are the test reference. The Risk Register is the pre-release triage list. Recommended order:

1. Fix **I-R1** (license: reconcile `clx version` to MPL-2.0) — pre-tag blocker, trivial.
2. Decide **V-R2 / V-R4 / V-R5**: fix, or explicitly document the reduced validation guarantee in CHANGELOG and accept for 0.8.0.
3. Accept-and-document the MEDIUMs in a "Known issues for 0.8.1" CHANGELOG block; file the LOWs as 0.8.1 follow-ups.
4. Re-run the automated gate, then tag.

No code was changed by the spec pass; it is documentation + triage only.
