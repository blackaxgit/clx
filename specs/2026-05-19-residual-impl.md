# Residual RGP Findings — Implementation Plan

**Base:** `chore/rgp-residual-hardening` off PR#27 (HEAD `1d21d15`).
**Inputs:** `2026-05-19-residual-research.md` (2026 approach),
`2026-05-19-residual-plan.md` (grounded file:line + dispositions).
**Confidence bar (per the research, NOT a bare "97%"):** every code fix
ships an evidence bundle = (1) a regression/PoV test that FAILS on
pre-fix code and PASSES after, (2) an adversarial re-derivation of the
original attack against the fixed code, (3) proptest/cargo-fuzz where a
parser/egress boundary changed, (4) no suite/clippy/fmt/deny regression.
"Confidence" is stated as that evidence bundle, not a number.

## Already closed by PR#27 (do NOT reopen)
B4-2, the fail-open half of B1-1/B1-2, R1-NEW-2 — neutralised by B4-1's
`validator.*`/`user_learning.*` subtree drop (`config/project.rs:84-89`).

## Streams (disjoint, parallel, worktree-isolated)

**Stream A — clx-hook FIX-NOW** (owns `crates/clx-hook/src/**`):
- B5-4-audit: a typed, append-only, SHA-256 hash-chained
  `validator_disabled` audit event, written from `pre_tool_use.rs` using
  the existing `Config::security_env_overrides_active()`; record env-var
  *name* only (never value/argv/path); head-hash to a `tracing` WARN.
- B6-3: `audit.rs` — run `redact_secrets` on `reasoning` and
  `working_dir` (command is already redacted). Non-regression test:
  ordinary prose reasoning is preserved (pattern-based scrubber only
  removes key-shaped tokens).
- B6-4: `router.rs:232` — debug-log the parsed envelope via
  `redact_json_value`, not the free-text `redact_secrets(&raw)`.
- B1-10: remove the mtime-only legacy plain-text trust-token fallback
  (`pre_tool_use.rs:115-122`); only the signed JSON token grants trust.
  Fail-safe (more prompting). CHANGELOG migration note: re-run `clx trust`.

**Stream B — CI** (owns `.github/workflows/release.yml`):
- B5-1: split the auto-publish so the Homebrew-tap push sits in an
  approval-gated `environment:` job; keep `attest-build-provenance`
  unattended. Document (in the stream report) that environment
  protection rules require the release repo be public on a non-Enterprise
  plan — the repo-settings half is ACCEPT-AND-DOCUMENT.

**Stream D — llm SSRF FIX-CAREFUL** (owns `crates/clx-core/src/llm/azure.rs`):
- B5-3: after the host-suffix/`CLX_ALLOW_AZURE_HOSTS` check, re-block
  resolved loopback/link-local/RFC1918/ULA/CGNAT/IMDS — mirroring the
  Ollama path — UNLESS a new explicit second opt-in
  `CLX_ALLOW_AZURE_INTERNAL_HOSTS=true` is set (preserves legitimate
  Azure Private Link and the in-tree wiremock `127.0.0.1` test). Tests
  cover: public OK, internal blocked by default, internal allowed only
  with the new opt-in.

**Stream E — serde_yml migration FIX-CAREFUL, standalone** (owns
workspace `Cargo.toml`, the three crate manifests, `deny.toml`,
`clx-core/src/config/{project,mod}.rs`, `clx-core/src/error.rs`):
- Replace `serde_yml 0.0.12` (RUSTSEC-2025-0068 unsound/unmaintained)
  with **`serde_yaml_ng` 0.10.x**. Preserve EXACTLY the fail-closed
  contract of `filter_inert_only` (invalid YAML -> "" -> project layer
  no-op) and trust-hash behaviour. Drop the `RUSTSEC-2025-0068` line
  from `deny.toml` ignore-list after migration. Targeted tests:
  invalid-YAML still yields the empty no-op; round-trip of a real
  project config is byte-stable enough for the trust hash semantics.

## ACCEPT-AND-DOCUMENT (no code; orchestrator writes the disposition)
- **B2-4** scoped-key project-path `:` confusion: a cheap `:`-reject
  breaks a legitimate macOS cwd containing `:`; the correct fix is a
  credential storage-format migration — deferred, documented, low
  exploitability (in-model same-uid + crafted cwd).
- **B1-3** L1-cache pre-seed: HMAC is near-theater vs an in-model
  same-uid attacker who can write the rule/cache table directly, and L0
  runs before the cache — accepted, documented.
- **B5-1 repo-settings**: the GitHub environment protection rule itself
  must be configured in repo settings (out of code scope) — documented
  as a release runbook step.

## Gate / synthesis
Collect streams single-threaded; integrated `cargo nextest run
--workspace` + clippy `-D warnings` + fmt + `cargo deny` + `cargo audit`
+ workflow YAML parse; per-stream four-eyes (adversarial re-derivation);
atomic commits; PR stacked on #27; honest residual addendum.
