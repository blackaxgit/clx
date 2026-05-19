# CLX Pre-Release RED Findings — Unified Register

**Date:** 2026-05-19  **Phase:** RED complete (gate 1)
**Detail fragments:** `rgp-red-R1.md` (validator/config-trust/supply-chain),
`rgp-red-R2.md` (secret-hygiene/learned-rule/MCP/cred). This file is the
consolidated, release-prioritized view that GREEN/PURPLE act on.

## Release-blocking set (GREEN must fix, PURPLE must verify closed)

| # | ID | Sev | Title | Root cause file:line | Closing-PoC |
|---|---|---|---|---|---|
| 1 | B4-1 | **CRIT** | Hostile project `.clx/config.yaml` merges 14 `validator.*`/`user_learning.*` keys (zero-interaction validator kill; breaks same-uid model) | `clx-core/src/config/project.rs:75-79` (3-prefix denylist) | `tests/red_r1_validator_bypass.rs`, `project.rs::red_r1_b4_1_*` |
| 2 | B6-1 | HIGH | Azure raw HTTP error body surfaced into `LlmError` → `tracing` warn + CLI, no `redact_secrets` (prior-leak tenant-URL class) | `llm/azure.rs:196-211` → `llm/mod.rs:37` → `policy/llm.rs:162`; CLI `commands/health.rs:91,102,694` | `tests/red_r2_poc.rs` |
| 3 | B6-2 | HIGH | `redact_secrets` has no `*.openai.azure.com` tenant/endpoint host pattern; `endpoint` is plain config not `SecretString` | `clx-core/src/redaction.rs:20-272`; `llm/azure.rs:19` | `tests/red_r2_poc.rs` |
| 4 | B1-4 | HIGH | `load_learned_rules` pushes DB rows into L0 whitelist with no pattern validation; `*`→`Bash(*)` makes every L0-unknown command hard-Allow, L1 skipped (builtin blacklist still wins — refined) | `clx-core/src/policy/rules.rs:244-269` | `tests/red_r1_validator_bypass.rs`, `tests/red_r2_poc.rs` |
| 5 | B3-2 | HIGH | MCP `clx_rules add` writes a learned rule with no pattern validation (remote path into B1-4 via prompt injection) | `clx-mcp/src/tools/rules.rs:49-78` | `tests/red_r2_poc.rs` |
| 6 | B5-4 + R1-NEW-1 | HIGH | `CLX_VALIDATOR_*` parent-env disable wins over hardened project/global config and is applied silently (no warn, no audit trail) | `clx-core/src/config/mod.rs:1878-1890` | `tests/red_r1_validator_bypass.rs` |
| 7 | B1-1/B1-2 | HIGH | 6 L0 blacklist evasions (double-space, `rm -fr`, `/bin/rm`, long flags, env-prefix, split flags) → `Ask` → fail-open `default_decision` when Ollama down | `clx-core/src/policy/{matching,rules,mod}.rs` (see R1-03) | `tests/red_r1_validator_bypass.rs` |
| 8 | B3-1 | HIGH | MCP `clx_credentials get/list` enumeration leaks 6 plaintext chars + exact length per key; reachable by indirect prompt injection (no same-uid code-exec → hard-override) | `clx-mcp/src/tools/credentials.rs:16-160` | `tests/red_r2_poc.rs` |
| 9 | B5-1/B5-2 | HIGH | `release.yml` auto-tag→build→Homebrew has no `cargo-audit`/`cargo-deny`/SBOM/attestation/signing and no human gate | `.github/workflows/release.yml` | static (no runtime PoC by scope) |
| + | R1-NEW-2 | HIGH | `validator.layer1_timeout_ms:1` from untrusted config is an L1-kill primitive (subsumed by the B4-1 allowlist fix) | `config/project.rs` merge + `pre_tool_use.rs` L1 timeout | covered by B4-1 PoC |

## Track / accepted (documented, NOT release-blocking)

B4-2 (trust_mode project-settable — free fix via B4-1 allowlist), B1-9
(TOCTOU rejoin divergence — needs Claude Code change), B1-10 (mtime-only
legacy trust token), B5-3 (`CLX_ALLOW_AZURE_HOSTS` no internal-IP
recheck), B3-5 (MCP cred `set` transcript exposure — warned), B6-3
(audit `reason` unredacted), B6-4 (raw stdin debug-log redactor gaps),
B2-4 (scoped-key `:` confusion — high AC), B1-3 (L1-cache pre-seed —
L0 still runs first). Each carries CVSS v4 + SSVC=Track in the fragments.

## PoC inventory (all `#[ignore]`-gated, default suite green)

- `crates/clx-core/tests/red_r1_validator_bypass.rs` — 6 (B4-1/B5-4/B1-1-2/B1-4)
- `crates/clx-core/tests/red_r2_poc.rs` — 9 (B6-1..4, B1-4, B3-1/2/5, B2-4, B1-3)
- `crates/clx-core/src/config/project.rs` — `red_r1_b4_1_*` root-cause unit
- `crates/clx-hook/src/embedding.rs` — `red_r1_b1_9_*` (Track)

## GREEN work breakdown (disjoint streams)

- **G1 (CRIT)** config-trust: `project.rs` denylist → strict **allowlist**
  of safe project-config keys (or strip entire `validator.*`/
  `user_learning.*` subtrees for untrusted) — closes B4-1, B4-2, R1-NEW-2.
- **G2** secret hygiene: stop surfacing raw Azure bodies; add tenant/host
  redaction pattern; redact at the `warn!`/CLI sinks — B6-1, B6-2.
- **G3** rule validation: reject `*`/`Bash(*)`/overbroad learned + MCP-
  added patterns — B1-4, B3-2.
- **G4** env-disable audit + MCP cred mask hardening — B5-4/R1-NEW-1, B3-1.
- **G5** supply-chain CI: `cargo-audit` + `cargo-deny` + SBOM in CI/release,
  document signing gap — B5-1, B5-2.
- B1-1/B1-2 (#7): GREEN to assess L0-normalization hardening vs documented
  defense-in-depth (fail-open is the real risk; pair with G1 since a
  hardened default_decision is global-config only post-B4-1).
