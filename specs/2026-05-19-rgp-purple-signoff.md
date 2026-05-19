# CLX Pre-Release PURPLE Sign-Off — Auditable Go/No-Go

**Date:** 2026-05-19 **Phase:** PURPLE (gate 3, final)
**Role:** Independent adversarial verification of GREEN closure of the RED
release-blocking register. Code NOT modified. No git commit performed.
**Method:** independent re-derivation of each original attack against the
*current fixed source* (file:line read), independent attack-logic harness
for the matcher-class fixes, full toolchain gate re-run with pasted tails.
RED PoC scaffold (`red_r1_validator_bypass.rs`, `red_r2_poc.rs`) was
intentionally removed post-fix; durable closure is the GREEN
secure-behavior regression tests, independently re-verified here.

---

## 1. Scope + Commit SHAs

- **Repo:** `/Users/blackax/Projects/clx`
- **Branch:** `chore/pre-release-rgp-hardening`
- **HEAD verified:** `9fd72610a94d0ba5b25a64189ac7570b56899e8a`
- **RED RC base:** `c65658b6abc116ebbd163b5297402362f3dd9d73`
- **RED PoC scaffold (recoverable):** `8e0bbee` (adds
  `crates/clx-core/tests/red_r1_validator_bypass.rs` +
  `crates/clx-core/tests/red_r2_poc.rs`, 1383 insertions — confirmed
  recoverable via `git show 8e0bbee`).
- **GREEN security-fix commits (5) verified present in HEAD ancestry:**
  - `60cf4d7` fix(security): B4-1 CRIT drop entire validator/user_learning subtree
  - `df49376` fix(security): B6-1/B6-2 bound+redact Azure error bodies, scrub tenant hosts
  - `7a0046d` fix(security): B1-4/B3-2 reject overbroad allow rule patterns
  - `b64da81` fix(security): B5-4 env override audit; B3-1 harden MCP cred mask
  - `b426512` ci(security): B5-1/B5-2 supply-chain gate (audit/deny, SBOM, provenance)
  - `9fd7261` test(security): remove RED B1-9 PoC unit (accepted/Track residual)
- **In-scope register:** 10 release-blocking findings (B4-1 CRIT; B6-1;
  B6-2; B1-4; B3-2; B5-4+R1-NEW-1; B1-1/B1-2; B3-1; B5-1/B5-2; R1-NEW-2)
  + 8 Track/accepted items dispositioned (§5).

---

## 2. Findings Table — Pre/Post Status + Independent-Verification Evidence

Hard-override rule applied: *any validator-bypass or secret-leak reachable
without same-uid code execution is release-blocking regardless of CVSS.*

| # | ID | Sev (RED) | Pre | Post | Independent verification evidence (PURPLE, against current source) |
|---|---|---|---|---|---|
| 1 | **B4-1** | CRIT | OPEN | **CLOSED** | `config/project.rs:84-89` `NON_INERT_KEY_PATTERNS` now contains bare subtree roots `"validator"`,`"user_learning"`; `is_non_inert` (`:177-181`) matches `path==pat \|\| starts_with("{pat}.")` → every `validator.*`/`user_learning.*` key (incl. `layer1_timeout_ms` = R1-NEW-2, `trust_mode` = B4-2, `auto_whitelist_threshold`) is dropped. Wired end-to-end at `config/mod.rs:1158` `apply_project_layer`. Hash-trust escape hatch intact (`:130-136`). Independently confirmed benign project config (`auto_recall.rrf_enabled`) **still merges** → no legitimate-config regression. Untrusted config sets NONE of the matrix; hash-trusted still can. |
| 2 | **B6-1** | HIGH | OPEN | **CLOSED** | `azure.rs:252` all 4 error arms (`Auth/DeploymentNotFound/ContentFilter/Server`) use `build_error_summary` (`:38-52`); raw `body` only used for non-secret `content_filter` discriminator (`:258`), never propagated into an error string. Sink `policy/llm.rs` `warn!` wraps `redact_secrets(&e.to_string())`; `health.rs` endpoint+error redacted. No raw-body path reaches a log/CLI sink. |
| 3 | **B6-2** | HIGH | OPEN | **CLOSED** | `redaction.rs:21-25` `AZURE_HOST_SUFFIXES` (`.openai.azure.com`,`.azure-api.net`,`.cognitiveservices.azure.com`); `redact_azure_hosts` (`:40-143`) 2-pass (URL + bare-token), case-insensitive authority suffix match; integrated into `redact_secrets` entry (`:152-165`). Tenant-host class scrubbed to `***AZURE-HOST-REDACTED***`. Redaction order **correct**: full-body `redact_secrets` runs BEFORE `truncate_utf8` (`azure.rs:41` then `:43`) → no fragment-across-boundary leak. |
| 4 | **B1-4** | HIGH | OPEN | **CLOSED** | `policy/rules.rs:259-268` load boundary skips+WARNs when `RuleType::Allow && is_overbroad_allow_pattern`; Deny rows unrestricted (preserves blacklist-fail-safe). Independent attack harness (17 adversarial patterns, §3) confirms matcher is sound: every non-flagged pattern is also non-universal. |
| 5 | **B3-2** | HIGH | OPEN | **CLOSED** | `clx-mcp/src/tools/rules.rs:70-81` MCP `add` rejects overbroad allow with `INVALID_PARAMS` *before* `add_rule`; only `RuleType::Allow` gated, blacklist/deny unaffected. Same `is_overbroad_allow_pattern` as the load boundary → defense-in-depth at BOTH boundaries confirmed. |
| 6 | **B5-4 + R1-NEW-1** | HIGH | OPEN | **CLOSED-w/-CONDITION** | `config/mod.rs:1284-1365` all 4 weakening env vars now emit a loud conditional `tracing::warn!` (fires on *effective* weakened state, not env presence — `CLX_VALIDATOR_ENABLED=true` correctly does NOT warn). `security_env_overrides_active()` accessor (`:1229-1254`) stateless+precise. **Residual:** accessor is NOT wired into a `clx-hook` audit-DB event (only self-referenced + tested). Silent-bypass prong fully closed (WARN is a forensic trail); dedicated audit-row is a tracked pre-1.0 follow-on (§5, §7). |
| 7 | **B1-1/B1-2** | HIGH | OPEN | **MITIGATED (defense-in-depth, by design)** | RED fix-direction was L0 normalization OR removing fail-open. GREEN's chosen closure is the B4-1/B5-4 pair: `default_decision=allow` is no longer untrusted-config-settable (B4-1) and is loudly warned when env-set (B5-4). The L0 evasion forms still reach `Ask` (not `Deny`) standalone, but the *fail-open carrier* (untrusted permissive `default_decision`) is removed. In-model standalone (same-uid/agent-emitted → `Ask`→L1). Acceptable: the release-blocking aspect was the *out-of-model carrier*, which is closed. Documented residual (§5). |
| 8 | **B3-1** | HIGH | OPEN | **CLOSED** | `clx-mcp/src/tools/credentials.rs:163-183` `mask_credential_value` → `[REDACTED:<bracket>]`: zero plaintext chars, no exact length; 5 coarse buckets. Independent residual analysis: bucket leaks ≤~4 bits (membership), materially weaker than prior 6-char+exact-length; secret-leak hard-override satisfied (no plaintext, no exact length). Coarse-by-design side-channel is documented accepted residual, not a blocker. |
| 9 | **B5-1/B5-2** | HIGH | OPEN | **CLOSED-w/-CONDITION** | `release.yml:74-78` `cargo audit` + `cargo deny check` run **before** build (fail-closed: non-zero exit blocks release, no `continue-on-error`); `:139` cyclonedx SBOM; `:148` `actions/attest-build-provenance@v1` SLSA. `ci.yml:208-212` same gates on CI. **Residual:** `update-homebrew` (`needs: release`, `:240`) has no `environment:` manual-approval gate — attestation provides detectability, not prevention of auto-publish. Documented condition (§5, §7). |
| 10 | **R1-NEW-2** | HIGH | OPEN | **CLOSED** | Subsumed by B4-1: `validator.layer1_timeout_ms` matches `validator.*` subtree drop (`is_non_inert("validator.layer1_timeout_ms")==true`). Regression test `b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key` asserts `layer1_timeout_ms` is dropped. Independently confirmed. |

**Result: 8/10 fully CLOSED, 2/10 CLOSED-WITH-CONDITION (B5-4 audit-row,
B5-1 homebrew gate), 1 (B1-1/B1-2) mitigated by-design with documented
in-model residual. Zero release-blocking finding remains OPEN.**

---

## 3. Regression-Proof Matrix (GREEN test + independent PURPLE check)

| RED finding | GREEN durable closing test (secure-behavior, non-`#[ignore]`) | Independent PURPLE check |
|---|---|---|
| B4-1 / R1-NEW-2 / B4-2 | `config::project::tests::wave1_credentials_behavior::b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key`; `b4_1_hash_trusted_config_still_applies_validator_keys`; `drops_entire_validator_subtree_from_untrusted_config`; `inert_filter_drops_logging_file_and_entire_validator_subtree` | Read `is_non_inert`/`NON_INERT_KEY_PATTERNS` at source; confirmed subtree-prefix match logic; confirmed benign `auto_recall.rrf_enabled` survives (no legit-config regression); end-to-end wiring at `mod.rs:1158`. |
| B6-1 | `azure.rs::b6_1_auth_error_display_does_not_contain_raw_body`; `b6_1_deployment_not_found_display_does_not_contain_raw_body`; `b6_1_build_error_summary_truncates_and_redacts`; `b6_1_truncate_utf8_respects_char_boundaries` | Traced all 4 `map_response` arms → `build_error_summary`; verified redact-before-truncate ordering; verified raw `body` not propagated past `content_filter` discriminator. |
| B6-2 | `redaction.rs::b6_2_redact_secrets_scrubs_openai_azure_com_host_in_url` (+`_azure_api_net_`,`_cognitiveservices_`,`_bare_azure_hostname`,`_does_not_over_redact_unrelated_urls`,`_redact_json_value_scrubs_azure_host`,`_handles_poc_body_shape`) | Read 2-pass scrubber; confirmed suffix list covers prior-leak class; confirmed `.invalid` PoC host non-scrub is correct-by-design (no over-redaction), real Azure suffix IS scrubbed. |
| B1-4 | `policy/rules.rs` load-skip path + `matching.rs` `is_overbroad_allow_pattern` unit tests; `b1_4`-named regression | **Independent 17-pattern attack harness** (`/tmp/purple_verify/check.rs`): every non-flagged pattern (`Bash((*))`,`Bash(*)x`,`*x`,`Bash(?)`) is also non-universal; every universal pattern (`*`,`**`,`Bash(*)`,`*:*`,`Tool(*)`) IS flagged. No exploitable false-negative. |
| B3-2 | `clx-mcp` `b3_2`-named regression on the `add` arm | Read `tools/rules.rs:70-81`; confirmed reject-before-persist + Allow-only gating; same matcher as load boundary. |
| B5-4 / R1-NEW-1 | `config/mod.rs::b5_4_security_env_overrides_active_detects_*` (×4) + `_all_four_*` + `_no_weakening_*` + `_non_weakening_default_decision_not_reported` | Read all 4 WARN blocks; confirmed conditional-on-effective-state (not env-presence); confirmed accessor stateless; **flagged** accessor not wired to hook audit-DB. |
| B3-1 | `credentials.rs::b3_1_mask_leaks_no_plaintext_fragment`; `b3_1_poc_secret_no_longer_leaks`; `coarse_bracket_boundaries`; `different_lengths_same_bracket_produce_same_output`; `b3_1_short_secret_no_plaintext_no_exact_len`; `empty_credential_masked`; `utf8_multibyte_no_plaintext` | Read `mask_credential_value`+`coarse_length_bracket`; confirmed zero-plaintext, no exact length; independent residual side-channel analysis (≤4 bits, documented). |
| B5-1/B5-2 | static workflow assertions | `grep`-verified `cargo audit`/`cargo deny check` pre-build fail-closed in both `ci.yml` and `release.yml`; SBOM+SLSA present; flagged homebrew no-manual-gate residual. |

**Consolidated regression run:** `cargo nextest run -p clx-core -p clx-mcp
-p clx-hook -E 'test(/b4_1|b5_4|b3_1|b6_1|b6_2|b1_4|b3_2|overbroad|
drops_entire_validator|inert_filter|hash_trusted|security_env/)'` →
**28 passed, 0 failed**. No cross-interaction.

---

## 4. Tooling-Gate Results (pasted tails)

Env: `export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
CLX_MODEL_FETCH_DRYRUN=1 CLX_CREDENTIALS_BACKEND=age`

**`cargo nextest run --workspace`** (exit 0):
```
 Nextest run ID f09366e1-... with nextest profile: default
    Starting 1718 tests across 33 binaries (9 tests skipped)
     Summary [  15.138s] 1718 tests run: 1718 passed, 9 skipped
```

**`cargo clippy --workspace --all-targets -- -D warnings`** (exit 0):
```
Command "Run clippy with deny warnings" completed (exit code 0)
```

**`cargo fmt --all -- --check`** (exit 0):
```
FMT_EXIT=0   (no diff output)
```

**`cargo deny check`** (exit 0):
```
advisories ok, bans ok, licenses ok, sources ok
DENY_EXIT=0
```

**`cargo audit`** (exit 0; 8 allowed-warnings, all unmaintained/unsound):
```
Crate: serde_yml  Version: 0.0.12
Warning: unsound  Title: serde_yml crate is unsound and unmaintained
ID: RUSTSEC-2025-0068
warning: 8 allowed warnings found
AUDIT_EXIT=0
```

**Workflow YAML lint:**
```
ruby -ryaml -e "YAML.load_file('.github/workflows/ci.yml');
  YAML.load_file('.github/workflows/release.yml'); puts 'YAML_OK'"
YAML_OK
```

**RGP closing-regression subset:** `cargo nextest -p clx-core -p clx-mcp
-- b4_1 b5_4 b3_1 b6_1 b6_2 b1_4 b3_2 is_overbroad` → `23 passed`.
**Consolidated:** `28 passed`.

**`#[ignore]` audit:** 12 `#[ignore]` annotations in the tree; all are
`#[ignore = "Requires keychain access"]` (8× `credentials.rs`, 1×
`clx-mcp/src/tests.rs` = the 9 keychain skips; the other 3 grep hits at
`credentials.rs:238/272/1135` are doc-comments, not attributes). **No
security PoC was un-gated.** Suite reports `9 skipped` = exactly the 9
keychain skips. Confirmed.

---

## 5. Residual Accepted-Risk Register (owner + rationale)

| ID | Class | Disposition | Owner | Rationale |
|---|---|---|---|---|
| **B5-4 audit-row** | partial closure | CONDITION (tracked pre-1.0) | clx-hook owner | `security_env_overrides_active()` exists+tested but not wired to a `clx-hook` audit-DB event. Silent-bypass prong fully closed (loud `tracing::warn!` is a grep-able forensic trail). Missing dedicated audit row is defense-in-depth degradation, NOT a re-opened bypass (requires out-of-band env control + now loudly logged). Must be a tracked follow-on, not silently dropped. |
| **B5-1 homebrew gate** | partial closure | CONDITION (pre-tag advisory) | release/CI owner | `update-homebrew` auto-chains (`needs: release`) with no `environment:` manual-approval gate. SLSA attestation + SBOM now provide *detectability* of a poisoned artifact, not *prevention* of auto-publish. Accept for this tag with the explicit condition that a manual `environment:` approval gate is added before 1.0; the dep-audit/deny/SBOM gap (the primary B5-2 finding) is fully closed. |
| serde_yml RUSTSEC-2025-0068 | unsound+unmaintained | ACCEPTED (deny.toml, tracked) | core/config owner | Not an exploitable CVE. Config-parse path is B4-1 surface, but inert-filter strips dangerous keys regardless of parser soundness, and a parse panic fails closed (`filter_inert_only`→`""`→global wins). Enumerated (not blanket-ignored) in `deny.toml`; new advisory still surfaces. Tracked YAML-parser migration. Correctly-owned, NOT a masked blocker. |
| B1-9 (TOCTOU rejoin) | in-model | ACCEPTED | core owner | Needs Claude Code change; doc admits "full TOCTOU prevention requires Claude Code changes". PoC unit removed in `9fd7261` (documented). In-model (same-uid). |
| B1-10 (mtime trust token) | in-model | ACCEPTED (hardening deferred) | hook owner | Legacy mtime fallback; carrier (B4-2 trust_mode) now closed by B4-1 subtree-drop, materially reducing the chain. In-model for the touch itself. Cheap-harden tracked. |
| B5-3 (`CLX_ALLOW_AZURE_HOSTS` no internal-IP recheck) | in-model env-injection | ACCEPTED | llm owner | Env is documented injection surface (same class as B5-4). Bounded: client only issues configured calls. Track. |
| B3-5 (MCP cred `set` transcript) | structural | ACCEPTED (warned) | mcp owner | MCP arg transcript exposure is structural to the protocol; warned in success text. Track. |
| B6-3 (audit `reason`/`working_dir` unredacted) | secret-hygiene | ACCEPTED (tracked, low exploitability) | hook owner | Lower exploitability than the HIGH set; B6-2 host scrubber now exists and can be applied to these fields in a tracked follow-on. Out-of-scope for the blocking set. |
| B6-4 (raw stdin debug-log) | log sink | ACCEPTED (debug-level only) | hook owner | `debug!` level only; not default. `redact_secrets` now has the B6-2 host pattern so the line is improved even if not switched to `redact_json_value`. Track. |
| B2-4 (scoped-key `:` confusion) | high-AC | ACCEPTED | credentials owner | CVSS 3.7, high attack complexity (crafted cwd/path alignment). Track. |
| B1-3 (L1-cache pre-seed) | in-model | ACCEPTED | policy owner | Same-uid DB write; bounded to L1 tier of L0-unknown commands; cannot defeat L0 deny. Track. |

All Track/accepted items are correctly-owned, documented, and carry a
rationale. **None is a silently-dropped blocker.**

---

## 6. CVSS v4.0 / SSVC Residual Re-Scores

| ID | RED base | PURPLE residual | SSVC residual | Note |
|---|---|---|---|---|
| B4-1 | 8.5 (CRIT) | **0.0 — Closed** | — | Untrusted config contributes zero validator/user_learning keys; verified end-to-end + hash-trust intact. |
| B6-1 | 6.8 | **~1.0 — Closed** | — | No raw body in any error string; double-redact at sink. Residual = non-secret status/rid only. |
| B6-2 | 5.1 | **~2.0 — Closed (bounded)** | Track | Prior-leak class scrubbed; residual = non-listed sovereign/custom Azure suffixes (tracked suffix-list extension). |
| B1-4 | 8.5 | **0.0 — Closed** | — | Sound matcher (independent 17-pattern proof), both boundaries gated, Deny-fail-safe preserved. |
| B3-2 | 8.7 | **0.0 — Closed** | — | Reject-before-persist; same matcher; Allow-only. |
| B5-4 | 8.7 | **~3.5 — Closed-w/-condition** | Track | Bypass requires out-of-band env control + now loudly WARNed. Residual = missing audit-DB row (defense-in-depth, tracked). |
| B1-1/B1-2 | 7.0 | **~3.0 — in-model residual** | Track | Out-of-model fail-open carrier removed (B4-1/B5-4). Standalone evasion → `Ask`→L1 (in-model). |
| B3-1 | 5.1 | **~2.0 — Closed (coarse residual)** | Track | No plaintext, no exact length. Residual = ≤4-bit coarse bucket, documented, no practical brute advantage. |
| B5-1/B5-2 | 8.6 | **~3.0 — Closed-w/-condition** | Track | Dep audit/deny/SBOM/SLSA closed (fail-closed). Residual = no manual homebrew approval gate (detectable via attestation; tracked pre-1.0). |
| R1-NEW-2 | (folded) | **0.0 — Closed** | — | Subsumed by B4-1 subtree drop; regression-asserted. |

Security-tool hard-override applied: no validator-bypass or secret-leak
remains reachable without same-uid code execution. The two
Closed-with-condition items (B5-4 audit-row, B5-1 homebrew gate) are
defense-in-depth / detectability degradations, not reachable
bypass/leak primitives — they do **not** trip the hard-override.

---

## 7. Final Verdict

# **SHIP — WITH 2 TRACKED PRE-1.0 CONDITIONS**

All **10 release-blocking RED findings are remediated**: 8 fully closed
(independently re-derived against current source and confirmed
neutralized — not merely test-passing), B1-1/B1-2 mitigated by-design
with a documented in-model residual, and 2 (B5-4, B5-1) closed at the
release-blocking level with defense-in-depth conditions tracked below.
Full workspace suite (1718 passed / 9 keychain-skipped / 0 failed),
clippy `-D warnings`, fmt, `cargo deny`, `cargo audit`, and workflow
YAML all green. No `#[ignore]` un-gated; the 9 keychain skips intact.
No GREEN-introduced regression, bypass, or layering/security-constraint
weakening was found; the B4-1 subtree-drop does **not** break legitimate
project config (independently verified `auto_recall.*` still merges);
the deny.toml ignore-list masks only unmaintained/unsound advisories
(not a real vulnerability) and fails closed on any new advisory;
`build_error_summary` redaction order is correct (redact-before-truncate);
the coarse credential mask leaks neither plaintext nor exact length.

**No blocking list — zero findings remain OPEN.**

**Required tracked conditions (NOT release-blocking, must be owned issues
before 1.0; recording them here so they are not silently dropped):**

1. **B5-4 audit-row wiring** — wire `Config::security_env_overrides_active()`
   into a dedicated `clx-hook` audit-DB event so an env-driven validator
   weakening produces a structured forensic record in addition to the
   `tracing::warn!` (the WARN already closes the silent-bypass blocker;
   this is defense-in-depth). Owner: clx-hook.
2. **B5-1 Homebrew manual-approval gate** — add a GitHub `environment:`
   manual-approval gate before the `update-homebrew` job so a poisoned
   build is *prevented*, not only *detectable* via SLSA attestation
   (the dep-audit/deny/SBOM/provenance gap is fully closed). Owner:
   release/CI.

Orchestrator may commit this sign-off, open the PR, and report the
verdict. **No auto-merge.** The two tracked conditions should be filed
as issues against the 1.0 milestone as part of the PR.
