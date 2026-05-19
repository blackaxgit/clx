# Residual RGP Remediation — Status & Honest Disposition

**Branch:** `chore/rgp-residual-hardening` (stacked on PR #27).
**Confidence model:** evidence bundle (fail-before/pass-after test +
adversarial re-derivation + no regression), per the research — NOT a
bare numeric claim (that was explicitly rejected as false precision).

## DONE — landed & verified on this branch

- **Stream A (clx-hook FIX-NOW)** — committed, verified:
  `1739 workspace tests pass, 0 fail`, clippy clean, **no PR#27
  regression** (PR#27's CRIT/HIGH regression tests run in that suite).
  - B5-4: SHA-256 hash-chained `validator_disabled` audit event
    (`audit_chain.rs`) wired via `Config::security_env_overrides_active`.
  - B6-3: `reasoning` + `working_dir` redacted before audit persist.
  - B6-4: router debug-log via `redact_json_value`.
  - B1-10: mtime-only legacy trust-token fallback removed (signed JSON
    only; fail-safe; CHANGELOG migration note added).
  - Honest residual: B6-3 colon-terminated Azure-host tokens miss the
    Pass-2 tokenizer (documented, low-residual; B6-2 host redaction in
    PR#27 is the primary control).

## READY but NOT YET INTEGRATED — preserved in worktrees

Streams B, D, E completed their work but their worktrees forked from a
**pre-PR#27 base (`ba0ad2e`)**, so their patches conflict with the
just-shipped CRIT/HIGH fixes in `release.yml` (G5), `azure.rs` (G2),
`config/project.rs`+`config/mod.rs` (G1/G4), `deny.toml` (G5).
Force-merging under these conditions risks **silently reverting the
shipped CRIT validator-bypass fix** — not acceptable without careful,
gated resolution. Work is intact in the worktrees (not lost).

- **Stream B (B5-1 CI gate):** `release.yml` → approval-gated
  `publish-homebrew` (`environment:`); needs 3-way merge onto G5's
  current `release.yml`.
- **Stream D (B5-3 Azure SSRF):** post-allowlist internal-IP reblock +
  `CLX_ALLOW_AZURE_INTERNAL_HOSTS` opt-in; 848/848 in its worktree;
  needs 3-way merge onto G2's `azure.rs`. Residual (disclosed): host-
  string-level only — full DNS-rebind closure needs a resolve-pinned
  reqwest connector (deferred, FIX-CAREFUL).
- **Stream E (serde_yml→serde_yaml_ng):** core migration done (840 tests
  passed in worktree, `RUSTSEC-2025-0068` ignore removed) but the agent
  stopped before the 2 evidence tests + `cargo tree -i serde_yml` proof
  + spec; needs the tail finished AND 3-way merge onto G1/G4's
  `config/{project,mod}.rs`.

**Recommended safe path (do NOT force-merge):** rebase B/D/E onto the
current PR#27-inclusive HEAD (re-run each focused stream from this base,
or hand-merge each conflict) with **PR#27's regression suite as the
gate** — every `b4_1_*` / B6 / G3 / G4 test must still pass after
integration. This is a focused, gated next step, not a rushed tail-end
merge.

## ACCEPT-AND-DOCUMENT (no code — fixing would weaken a decision)

- **B2-4** scoped-key project-path `:` confusion: a cheap `:`-reject
  breaks a legitimate macOS cwd containing `:`; the correct fix is a
  credential storage-format migration. Low exploitability (in-model
  same-uid + crafted cwd). Deferred to a storage-format change.
- **B1-3** L1-cache pre-seed: an HMAC is near-theater against an
  in-model same-uid attacker who can write the cache/rule table
  directly, and L0 runs before the cache. Accepted, documented.
- **B5-1 repo-settings:** the GitHub `homebrew-publish` environment +
  required-reviewers rule is a repo-settings/runbook action (out of
  code scope); note: environment protection rules require the release
  repo be public on a non-Enterprise plan.

## Net

PR #27 (1 CRIT + 8 HIGH) remains the shipped security baseline. Stream A
adds 4 verified residual hardening fixes on top with no regression.
B/D/E are complete-but-unintegrated pending a gated rebase; B2-4/B1-3
and the B5-1 repo-settings step are documented accepted risks. No
finding was silently dropped; nothing was force-merged at the risk of a
security regression.
