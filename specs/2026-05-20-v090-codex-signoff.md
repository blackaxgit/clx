# CLX v0.9.0 Codex Independent Pre-Release Sign-Off

Date: 2026-05-21
Branch: `chore/v0.9.0-rgp-prerelease`
HEAD: `42fbf82`

Final verdict: **SHIP-WITH-CONDITIONS**

Condition: rerun the full Tier 4 gate bundle on a host that can bind loopback
ports for `wiremock` and can lock the local Cargo advisory database. This
sandbox denied loopback bind and advisory lock operations, so I cannot honestly
mark those tool gates green here. I found no open release-blocking code or doc
issue in the v0.9.0 delta.

## 1. Scope And SHAs

Audited GREEN commits: `e05059e`, `0aaf1cb`, `d02be22`, `42fbf82`.
RED baseline: `e8acd09`.
Current branch and HEAD confirmed locally: `chore/v0.9.0-rgp-prerelease` at
`42fbf82`.

Covered: v0.9.0 `validator.layer0_enabled`, L0/L1 fallback behavior, decision
cache gating, learned-rule loading, L1-disabled audit reason dual emit,
doc-honesty claims, both-layers-off health warning, untrusted project config
filtering, and credential sentinel hygiene.

Not covered as a whole-tree audit: unrelated credential, recall, dashboard,
model-fetch, and MCP surfaces outside the v0.9.0 delta except where Tier 4
tooling touched them.

Credential hygiene stop condition: no `inf-vsqt` occurrence in working tree or
all reachable git history:

```text
rg -n "inf-vsqt" . || true
git grep -n "inf-vsqt" $(git rev-list --all) || true
# both returned no matches
```

## 2. Findings Table

| Finding | Evidence bundle |
|---|---|
| RB-1 silent-allow class | VERDICT: CLOSED-WITH-RESIDUAL, evidence strength moderate. COUNTEREXAMPLE-NOW-FAILS: `v090_red_r1_poc::t9_2...` now fails with `left: "ask"` and `right: "allow"`; `v090_red_r2_poc::red_t9_2...` also fails with `left: "ask"` and `right: "allow"`. Timeout and generation-failure PoCs could not reach their body in this sandbox because `wiremock` loopback bind failed. REGRESSION-PIN: cache gate [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:383), L1-disabled ask [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:417), client error force-ask [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:464), Ollama-down force-ask [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:527), timeout force-ask [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:589), generation-failure force-ask [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:638). Closing tests: [v090_g1_e2e.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/v090_g1_e2e.rs:122), [v090_g1_e2e.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/v090_g1_e2e.rs:210), [v090_g1_e2e.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/v090_g1_e2e.rs:272), [v090_g1_e2e.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/v090_g1_e2e.rs:352), [codex_v090_audit.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/codex_v090_audit.rs:119). RESIDUAL-UNCERTAINTY: same-uid code execution can still edit config, DB, or env; closure assumes no same-uid arbitrary code execution beyond explicit operator-controlled config/env. |
| RB-2 doc-honesty | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: `v090_red_r1_poc::t8_doc_honesty...` now fails because README no longer contains the old overclaim. REGRESSION-PIN: README qualifier [README.md](/Users/blackax/Projects/clx/README.md:187), CHANGELOG qualifier [CHANGELOG.md](/Users/blackax/Projects/clx/CHANGELOG.md:36), module qualifier [audit_chain.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/audit_chain.rs:33). RESIDUAL-UNCERTAINTY: SQLite remains mutable by same-uid attackers; docs now state the external append-only sink requirement. |
| RB-3 L1-rename deprecation hygiene | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: `v090_red_r2_poc::red_t_l1_rename_no_dual_emit_window` now fails with reasoning containing `L1-DISABLED (alias: L1 disabled)`. REGRESSION-PIN: dual emit [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:419), test [v090_g1_e2e.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/v090_g1_e2e.rs:417), removal target [CHANGELOG.md](/Users/blackax/Projects/clx/CHANGELOG.md:67). RESIDUAL-UNCERTAINTY: external parsers that require an exact full-field match to only `L1 disabled` can still break; substring parsers remain compatible. |
| Tier-2 force-ask over-application | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: Codex test `tier2_whitelisted_l0_allow_still_passes_with_l1_down` passed, proving an L0 whitelist allow still exits before L1 fallback. REGRESSION-PIN: L0 allow return [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:286), test [codex_v090_audit.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/codex_v090_audit.rs:281). RESIDUAL-UNCERTAINTY: a mistaken overbroad allow rule is still dangerous if admitted to L0; overbroad learned/file allows are separately gated. |
| Tier-2 cache positive path | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: Codex test `tier2_cache_still_read_when_both_layers_enabled` passed and saw `L1-CACHE`. REGRESSION-PIN: cache gate [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:383), test [codex_v090_audit.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/codex_v090_audit.rs:302). RESIDUAL-UNCERTAINTY: cache poisoning remains possible for a same-uid DB writer; this fix only prevents cache use when a layer is disabled. |
| Tier-2 learned rules under L1-off | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: Codex test `rb1_l1_disabled_learned_rule_does_not_suppress_ask` passed; G1 test also passed. REGRESSION-PIN: load gate [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:272), tests [v090_g1_e2e.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/v090_g1_e2e.rs:460), [codex_v090_audit.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/codex_v090_audit.rs:247). RESIDUAL-UNCERTAINTY: learned allows still apply when L1 is enabled by design. |
| Tier-2 `clx health` both-off warning | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: `v090_red_r1_poc::t7_no_clx_doctor_warning...` now fails because health has layer checks; unit and CLI tests passed. REGRESSION-PIN: check [health.rs](/Users/blackax/Projects/clx/crates/clx/src/commands/health.rs:154), JSON/human wiring [health.rs](/Users/blackax/Projects/clx/crates/clx/src/commands/health.rs:209), tests [health.rs](/Users/blackax/Projects/clx/crates/clx/src/commands/health.rs:957). RESIDUAL-UNCERTAINTY: warning is diagnostic only; it does not block execution. |
| Tier-2 downstream `L1 disabled` parser scan | VERDICT: CLOSED-WITH-RESIDUAL, evidence strength moderate. COUNTEREXAMPLE-NOW-FAILS: in-tree grep found no production parser consuming exact legacy string, only debug text, docs, tests, and RED documents. REGRESSION-PIN: dual emit [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:432), CHANGELOG removal target [CHANGELOG.md](/Users/blackax/Projects/clx/CHANGELOG.md:74). RESIDUAL-UNCERTAINTY: external exact-match consumers can still need migration. |
| Tier-3 spoofing via hostile project config | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: project filter tests pass for dropping the full `validator` subtree. REGRESSION-PIN: drop list [project.rs](/Users/blackax/Projects/clx/crates/clx-core/src/config/project.rs:84), tests [project.rs](/Users/blackax/Projects/clx/crates/clx-core/src/config/project.rs:345). RESIDUAL-UNCERTAINTY: hash-trusted project configs can set validator keys by explicit operator trust. |
| Tier-3 tampering with SQLite audit DB | VERDICT: CLOSED-WITH-RESIDUAL, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: doc-honesty PoC now fails; docs qualify the external sink requirement. REGRESSION-PIN: README [README.md](/Users/blackax/Projects/clx/README.md:187), audit-chain docs [audit_chain.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/audit_chain.rs:33). RESIDUAL-UNCERTAINTY: same-uid DB rewrite remains accepted and documented. |
| Tier-3 repudiation attribution | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: L0/L1-disabled tests passed and show `SECURITY-CFG` or `SECURITY-ENV` rows with trigger keys. REGRESSION-PIN: env audit [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:56), config audit [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:95), tests [pre_tool_use_l0_e2e.rs](/Users/blackax/Projects/clx/crates/clx-hook/tests/pre_tool_use_l0_e2e.rs:360). RESIDUAL-UNCERTAINTY: env plus config dual-signal can create two rows; documented as intentional. |
| Tier-3 information disclosure | VERDICT: CONFIRMED-CLOSED, evidence strength moderate. COUNTEREXAMPLE-NOW-FAILS: redaction carry-over PoCs in `v090_red_r1_poc` passed locally where they ran; no real tenant sentinel remained. REGRESSION-PIN: redaction path remains in LLM policy and audit sinks, with fixture now synthetic. RESIDUAL-UNCERTAINTY: provider errors from new providers need the same redaction discipline. |
| Tier-3 denial of service | VERDICT: CLOSED-WITH-RESIDUAL, evidence strength moderate. COUNTEREXAMPLE-NOW-FAILS: no release-blocking PoC; `layer0_enabled=false` can increase L1 calls by design. REGRESSION-PIN: L0-disabled fallthrough [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:335), health cache [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:497), timeout [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:568). RESIDUAL-UNCERTAINTY: high command volume can still load the configured L1 provider. Decision: accept-doc. |
| Tier-3 elevation of privilege via toggle | VERDICT: CONFIRMED-CLOSED, evidence strength strong. COUNTEREXAMPLE-NOW-FAILS: untrusted project config cannot set `validator.layer0_enabled`; env disables are loud via `SECURITY-ENV`. REGRESSION-PIN: drop list [project.rs](/Users/blackax/Projects/clx/crates/clx-core/src/config/project.rs:84), env active check [config/mod.rs](/Users/blackax/Projects/clx/crates/clx-core/src/config/mod.rs:1221), hook env audit [pre_tool_use.rs](/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:56). RESIDUAL-UNCERTAINTY: same-uid env control at process launch is still powerful but no longer silent. |

## 3. Regression-Proof Matrix

| RED PoC | Current closing evidence |
|---|---|
| R1-F1 / T9.2 silent allow on L0-off, L1-down, default allow | RED PoCs now fail with actual decision `ask`; G1 and Codex tests pass for `allow`, `deny`, and `ask` default decisions. |
| T9.1 cache bypass | G1 cache-negative passed; Codex cache-negative passed; positive cache path passed when both layers enabled. Local RED PoC itself was blocked by `wiremock` bind before reaching the cache assertion. |
| T9.3 timeout fallback | Code force-asks at timeout; G1 pin exists. Local execution blocked by loopback bind. Needs condition rerun on loopback-capable host. |
| T9.4 generation failure fallback | Code force-asks at generation failure; G1 pin exists. Local execution blocked by loopback bind. Needs condition rerun on loopback-capable host. |
| T2 learned load before gate | G1 and Codex learned-rule tests pass for L1 disabled; local RED T2 was blocked by loopback bind. |
| T7 both-off opacity | RED no-warning PoC now fails; health unit and CLI tests pass. |
| T8 doc honesty | RED doc-honesty PoC now fails; README and CHANGELOG contain external-sink qualifier. |
| L1 rename dual emit | RED dual-emit PoC now fails with both substrings present. |

Important local command tails:

```text
cargo nextest run -p clx-hook --test codex_v090_audit -- --ignored
Summary [1.648s] 7 tests run: 7 passed, 0 skipped
```

```text
cargo nextest run -p clx-hook --test v090_red_r1_poc --no-fail-fast -- --ignored
Summary [1.477s] 9 tests run: 5 passed, 4 failed, 0 skipped
t9_2... left: "ask" right: "allow"
t8_doc_honesty... README must currently contain the overclaim...
t7_no_clx_doctor... got 18 mentions of layer*_enabled
```

```text
cargo nextest run -p clx-hook --test v090_red_r2_poc --no-fail-fast -- --ignored
Summary [1.491s] 11 tests run: 4 passed, 7 failed, 0 skipped
red_t9_2... left: "ask" right: "allow"
red_t_l1_rename... Got reasoning="L1-DISABLED (alias: L1 disabled)"
other failing cases in this sandbox failed before CLX assertions on wiremock bind
```

## 4. Tooling Gate Tails

```text
cargo nextest run --workspace
Summary [52.292s] 117/1967 tests run: 114 passed, 3 failed, 36 skipped
all failures were wiremock bind failures:
Failed to bind an OS port for a mock server.: PermissionDenied
warning: 1850/1967 tests were not run due to test failure
```

```text
cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.65s
```

```text
cargo fmt --all -- --check
exit 0, no output
```

```text
cargo deny check
failed to acquire advisory database lock
attempted to take an exclusive lock on a read-only path
```

```text
cargo audit
Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
failed to obtain lock file '/Users/blackax/.cargo/advisory-db..lock'
attempted to take an exclusive lock on a read-only path
```

```text
cargo insta test --workspace --check
error: 9 targets failed
failures were wiremock bind failures in loopback-backed tests
info: no snapshots to review
```

```text
cargo nextest run -p clx-hook --test validation_e2e
Summary [1.468s] 16 tests run: 16 passed, 0 skipped
```

## 5. Residual Register

| Residual | Owner | Rationale | Decision |
|---|---|---|---|
| Local sandbox cannot bind loopback ports | Release orchestrator | Required L1 timeout/generation tests need a loopback mock server. | Track as release condition, not a code finding. |
| Local Cargo advisory DB lock path is read-only | Release orchestrator | `cargo deny` and `cargo audit` could not lock advisory DB. | Track as release condition, not a code finding. |
| Same-uid DB/config/env tampering | Security owner | Same-uid arbitrary code execution is outside this release closure. Docs state SQLite is not enough for tamper evidence. | Accept-doc. |
| External exact-match parsers for legacy `L1 disabled` | Integrations owner | v0.9.0 dual-emits substrings, but exact full-field parsers may still need migration. | Track for v0.10.0 removal. |
| L0 disabled can increase L1 provider load | Security owner | This is expected when deterministic screening is disabled. Timeout and health-cache bounds remain. | Accept-doc. |

## 6. CVSS And SSVC Re-Scores

| Release blocker | Pre score | Post score | SSVC |
|---|---|---|---|
| RB-1 silent allow | CVSS v4.0 base 7.0, local attack, high integrity/availability impact when an L1 failure combines with fail-open default. | No reachable silent-allow path found for non-loopback arms; post score not applicable as vulnerability closed, with loopback retest condition for timeout/gen-fail arms. | Pre: act before release. Post: track condition. |
| RB-2 doc honesty | CVSS not directly applicable to implementation, but security-tool hard override applied because misleading audit-integrity claims can cause unsafe operator reliance. | No release-blocking overclaim remains in README/CHANGELOG/current module docs. | Pre: act before release. Post: track same-uid audit-db residual as documented. |
| RB-3 L1 rename | CVSS not directly applicable to code execution; security audit-parser compatibility risk. | Dual emit and removal target are present. | Pre: act before release. Post: track for v0.10.0 migration. |

## 7. 2026 Best-Practice Cross-Check

References checked:

- OWASP ASVS 5.0.0 current repo notes latest stable 5.0.0 and a 2026 bleeding-edge release track: https://github.com/OWASP/ASVS
- OWASP ASVS 5.0 taxonomy logging item V16.2.5 requires protection-level-aware logging and masking/hashing for sensitive data: https://cornucopia.owasp.org/taxonomy/asvs-5.0/16-security-logging-and-error-handling/02-general-logging
- NIST SP 800-218A final augments SSDF for AI model/system development and is intended for producers/acquirers of AI systems: https://csrc.nist.gov/pubs/sp/800/218/a/final
- MITRE CWE Top 25 page was updated January 29, 2026, and frames Top 25 as a guide for SDLC and architectural planning: https://cwe.mitre.org/top25/
- MITRE CWE-754 recommends accept-known-good handling for exceptional conditions: https://cwe.mitre.org/data/definitions/754
- MITRE CWE-862 examples include wildcard policy handling and unchecked policy enforcement leading to authorization bypass: https://cwe.mitre.org/data/definitions/862.html
- arXiv 2603.18740 reports contextual/framing bias in LLM-assisted security review and supports this audit's independent re-derivation posture: https://arxiv.org/abs/2603.18740
- OpenAI and Anthropic joint safety-evaluation writeup supports cross-lab, independent safety testing: https://openai.com/index/openai-anthropic-safety-evaluation/
- arXiv 2602.16977 supports fail-closed design for LLM safety under partial failures: https://arxiv.org/abs/2602.16977

Design comparison: v0.9.0 aligns with these references. The silent-allow fix
matches CWE-754 exceptional-condition handling by refusing fail-open `allow`
on L1 client, health, timeout, and generation failures. The cache and learned
rule gates reduce CWE-862-style policy bypass risk. The log redaction and
external-sink qualification align with ASVS logging guidance. The independent
counterexample-first workflow aligns with the 2026 framing-bias literature.

Blocking list: none in current code or docs.

CHANGELOG additions required: none beyond the existing v0.9.0 entries.
