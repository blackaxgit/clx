# CLX Residual / Tracked-Condition Remediation Plan

**Date:** 2026-05-19
**Branch:** `chore/rgp-residual-hardening`
**HEAD:** `1d21d15` (PURPLE sign-off; PR #27 blocking fixes `60cf4d7`..`9fd7261` all in ancestry)
**Scope:** the 2 tracked PURPLE conditions + the accepted/Track residual register
(rgp-purple-signoff §5/§7, rgp-red-findings "Track/accepted").
**Method:** each item re-verified by reading the POST-PR#27 source at exact
file:line. No source modified by this plan. This plan seeds a multi-agent fix.

---

## 0. Re-verification of "already neutralized by PR #27" claims (do this first)

Before any new work, two RED items the register treats as "free / folded" were
re-confirmed against current source so streams below do not redo closed work:

- **B4-2 (`validator.trust_mode` project-settable) — CONFIRMED CLOSED by B4-1.**
  `config/project.rs:84-89` `NON_INERT_KEY_PATTERNS` now contains the bare
  subtree root `"validator"`; `is_non_inert` (`project.rs:177-181`) matches
  `path == pat || path.starts_with("{pat}.")`. So `validator.trust_mode` from an
  untrusted project config is dropped by `filter_value` (`:161-168`). No
  separate B4-2 fix is needed; do **not** reopen it.
- **B1-1/B1-2 fail-open carrier — CONFIRMED CLOSED.** `default_decision` is now
  inside the dropped `validator` subtree (untrusted project config cannot set
  it, B4-1) and is loudly WARNed when env-set (`config/mod.rs:1242-1245` +
  `security_env_overrides_active`). The *out-of-model carrier* is gone. The
  *in-model L0 normalization* half is still open (see Item I below) — but it is
  in-model and was always the lower-priority half.
- **R1-NEW-2 (`validator.layer1_timeout_ms:1`) — CONFIRMED CLOSED by B4-1**
  (same subtree drop). No action.

These confirmations cost ~0 and prevent two streams from colliding on
`project.rs`.

---

## Item-by-item analysis

Each item: (a) current root-cause file:line POST-PR#27; (b) minimal
remediation + design; (c) closing-test design; (d) honest disposition;
adversarial regression notes inline.

---

### B5-4-audit — wire `security_env_overrides_active()` into a clx-hook audit row

**(a) Root cause / current state (verified):**
`Config::security_env_overrides_active()` exists and is correct at
`crates/clx-core/src/config/mod.rs:1229-1254` (stateless re-read; 4 weakening
vars; precise — non-weakening values excluded). It is **never called outside
`#[cfg(test)]`** (grep: only `config/mod.rs:2583..2758` test sites). The hook
audit sink is `crates/clx-hook/src/audit.rs:9-38` `log_audit_entry`; the
`PreToolUse` entrypoint that loads `Config` is
`crates/clx-hook/src/hooks/pre_tool_use.rs:25` (`Config::load()`), and the
disabled-validator early return is `pre_tool_use.rs:67-70`. The silent-bypass
*blocker* is already closed (the `tracing::warn!` at `config/mod.rs:1242-1251`
neighbourhood is a grep-able forensic trail). What is missing is a **structured
audit-DB row**.

**(b) Remediation + design (minimal):**
- Add a new audit layer tag `"SECURITY-ENV"` emitted **once per process** at the
  top of `handle_pre_tool_use`, immediately after `let config = Config::load()`
  (`pre_tool_use.rs:25`), guarded by a `std::sync::Once` so it is not written on
  every command (the hook is spawned per-event, so "once per process" ≈ "once
  per hook invocation" — acceptable; a per-invocation row is in fact *more*
  forensically complete than once-per-daemon, and the hook is short-lived).
  Decision: emit it unconditionally per invocation but **only when
  `config.security_env_overrides_active()` is non-empty** (zero overhead on the
  normal hot path — empty Vec → no write).
- Reuse the existing `log_audit_entry(session_id, command="<env-override>",
  working_dir=&input.cwd, layer="SECURITY-ENV", AuditDecision::Prompted,
  None, Some(&joined_env_list))` signature — **no new audit schema**. The
  `reasoning` field carries the joined `KEY=value` list of active weakening
  vars. (Note: this `reasoning` write interacts with B6-3; see B6-3 disposition
  — the env names/values here are not secrets, but the redaction added in B6-3
  is harmless over them.)
- Do **not** change `config/mod.rs` (accessor is correct and owned by core; the
  wiring is hook-owned, matching the G4 cross-ownership boundary note).

**(c) Closing-test design:**
- New test in `crates/clx-hook/tests/memory_hooks_e2e.rs` or
  `pre_tool_use` `#[cfg(test)]`: set `CLX_VALIDATOR_ENABLED=false` (serial +
  isolated HOME + in-memory `Storage`), drive `handle_pre_tool_use` with a Bash
  envelope, then query the audit store for a row with `layer == "SECURITY-ENV"`
  whose `reasoning` contains `CLX_VALIDATOR_ENABLED`.
  **Must FAIL before** (no such row is ever written today) **and PASS after**.
- Negative test: with no weakening env var set, assert **no** `SECURITY-ENV`
  row is written (proves zero hot-path overhead / no false audit noise).

**(d) Disposition: FIX-NOW.**
Cheap, clearly correct, no behavioral risk (additive audit row only; cannot
weaken any constraint; cannot fail the hook — `log_audit_entry` already swallows
storage errors at `audit.rs:18,35`). This is exactly tracked condition #1 in
rgp-purple-signoff §7. Adversarial check: does an extra row leak anything? The
env *names* are public and the *values* are `false`/`allow`/`true` (no secret) —
no disclosure. Safe.

---

### B5-1-homebrew — manual-approval `environment:` gate before `update-homebrew`

**(a) Root cause / current state (verified):**
`.github/workflows/release.yml`. The supply-chain gate IS present and
fail-closed: `:74-78` `cargo audit` + `cargo deny check` run in the `build` job
before artifacts; `:148` `actions/attest-build-provenance@v1`. The residual:
`update-homebrew` (`:237-242`) has `needs: release` and `runs-on: ubuntu-latest`
with **no `environment:` key** — it auto-chains and `git push`es the formula
using `secrets.HOMEBREW_TAP_TOKEN` (`:249`) with zero human gate. SLSA
attestation gives *detectability*, not *prevention* of an auto-publish of a
poisoned build.

**(b) Remediation + design (minimal):**
- Add to the `update-homebrew` job (after `runs-on:`, before `needs:` is fine;
  conventionally near the top):
  ```yaml
      environment: homebrew-publish
  ```
- Create the GitHub Environment `homebrew-publish` with **Required reviewers**
  (repo admin) — this is a one-time GitHub repo-settings change (NOT in the
  YAML; document it in the plan and the tracked issue). The job will then pause
  for manual approval before any tap push.
- No change to `build`/`release` jobs (their gates are already closed).

**(c) Closing-test design:**
- Static assertion test (consistent with how B5-1/B5-2 were verified —
  "static workflow assertions" per signoff §3): a workflow-lint test (e.g. in
  the existing CI yaml-lint step or a small Rust/`ruby -ryaml` check) asserting
  the parsed `release.yml` has `jobs.update-homebrew.environment` set to a
  non-empty string. **Fails before** (key absent), **passes after**.
- The *human-gate-enforced* property cannot be unit-tested (it is a GitHub
  control-plane setting); the issue must record the manual repo-settings step
  as a checklist item with a screenshot/owner sign-off.

**(d) Disposition: FIX-NOW (YAML) + ACCEPT-AND-DOCUMENT (the repo-settings
half).**
The 1-line `environment:` addition is cheap and clearly correct. The
*effectiveness* depends on a GitHub Environment with required reviewers, which
is **not expressible in-repo** and needs a maintainer action — that half is
"document + track as a release-owner checklist item", not code. Adversarial
check: an `environment:` pointing at a non-existent environment is a no-op
(GitHub treats it as an unprotected environment) — so the closing test asserting
only "key present" is necessary-but-not-sufficient; the issue MUST carry the
repo-settings step or this is theater. Flag this honestly in the tracked issue.

---

### serde_yml RUSTSEC-2025-0068 — YAML parser migration

**(a) Root cause / current state (verified):**
`serde_yml 0.0.12` is a direct dep: `Cargo.toml:27`, `crates/clx-core/Cargo.toml:13`,
`crates/clx/Cargo.toml:18`. RUSTSEC-2025-0068 ("unsound and unmaintained")
is **enumerated** (not blanket-ignored) in `deny.toml:23`. Production use sites:
`config/project.rs:96,101,147-151` (the B4-1 inert-filter parse/serialize),
`config/mod.rs:1194` (`Config` load from `~/.clx/config.yaml`),
`error.rs:26` (`#[from] serde_yml::Error`). All other hits are `#[cfg(test)]`.

**(b) Remediation + design (FIX-CAREFUL):**
- Migrate to a maintained YAML crate. Candidate: `serde_yaml_ng` (maintained
  fork of dtolnay's `serde_yaml`, drop-in `serde_yaml` API) or `serde_norway`.
  Decision driver: minimal API churn. `serde_yml` was itself a `serde_yaml`
  fork, so the surface (`from_str`, `to_string`, `Value`, `Mapping`, `Error`) is
  near-identical.
- Required code changes are mechanical but must be exact:
  - `Cargo.toml` (workspace + 2 crate manifests): swap the dep.
  - `config/project.rs:96` `serde_yml::Value` → new crate `Value`; `:101`
    `to_string`; `:147-151` `filter_value` signature + `Mapping::new()`.
  - `config/mod.rs:1194` `from_str`.
  - `error.rs:26` `#[from] <newcrate>::Error` (the `From` impl + the public
    `Error` enum variant change is the one cross-cutting break — every
    `crate::Result` caller still compiles since the variant type is internal,
    but the `thiserror` `#[from]` must point at the new error type).
- **Behavioral invariant that MUST be preserved:** `filter_inert_only`
  (`project.rs:95-102`) returns `String::new()` on a parse error (fail-closed:
  empty project layer → global config wins). The new parser's error path must
  keep that exact semantics. Also `serde_yml::to_string` ordering / tag
  behavior must round-trip the `Config` struct (there are ~30 `from_str`/`to_string`
  round-trip tests in `config/mod.rs` — they are the safety net).

**(c) Closing-test design:**
- No new *security* test is needed (this is not an exploitable CVE — see
  disposition). The closing evidence is: (1) `cargo audit` no longer reports
  RUSTSEC-2025-0068 and the entry is **removed from `deny.toml:23`** (its
  presence post-migration would itself be a regression — add a grep test or CI
  assertion that `deny.toml` does not list RUSTSEC-2025-0068 once migrated);
  (2) the full existing `config` round-trip + `project.rs` inert-filter test
  suite passes unchanged (≈30 `serde_yml::from_str` round-trip tests +
  `filter_inert_only` fail-closed tests are the regression net — they must pass
  byte-identically on the new parser);
  (3) a targeted test asserting `filter_inert_only("{ : invalid yaml")` still
  returns `""` (fail-closed preserved across the parser swap).

**(d) Disposition: FIX-CAREFUL.**
Valuable (removes an unsound-crate advisory and the deny.toml exception) but
non-trivial: it is a cross-cutting dependency swap touching 3 manifests +
`error.rs` `#[from]` + 2 config files, with a ~30-test round-trip blast radius.
**It is NOT a release blocker** — honest rationale: the advisory is
unsound+unmaintained, *not* an exploitable CVE; the only attacker-reachable
parse path is the untrusted-project-config B4-1 surface, and (i) the inert
filter strips dangerous keys regardless of parser soundness, (ii) a parse panic
fails closed (`filter_inert_only` → `""` → global wins), (iii) the advisory is
enumerated (not blanket-ignored) so any *new* advisory still surfaces. Do it as
a standalone, well-tested PR — do **not** rush it into the residual-hardening
batch where a parser-behavior regression could mask a real fix. Adversarial
note: a careless swap to a crate with different `to_string` map-ordering or
different empty-input error behavior could silently change `filter_inert_only`'s
fail-closed contract — the targeted invalid-YAML test above is the guard.

---

### B6-3 — audit `reasoning` / `working_dir` persisted unredacted

**(a) Root cause / current state (verified):**
`crates/clx-hook/src/audit.rs`. `:23` redacts `command`
(`redact_secrets(command)` — good). `:31` `entry.working_dir =
Some(working_dir.to_string())` — **unredacted**. `:33` `entry.reasoning =
reasoning.map(...)` — **unredacted**. `reasoning` origin is L1 model output
(`policy/llm.rs` risk→reason) and the trust-mode/cache reasons (which are
static, safe). `working_dir` is `input.cwd` (an attacker/agent-influenced path
that can embed an inline secret or tenant path).

**(b) Remediation + design (minimal):**
- In `audit.rs`, change `:31` to
  `entry.working_dir = Some(redact_secrets(working_dir));`
  and `:33` to
  `entry.reasoning = reasoning.map(|r| redact_secrets(r));`.
- `redact_secrets` already includes the B6-2 Azure-host scrubber
  (`redaction.rs` `redact_azure_hosts` integrated into the entry point), so this
  one-line-each change also closes the tenant-host class in these fields for
  free.

**(c) Closing-test design:**
- Test in `clx-hook` audit `#[cfg(test)]` (in-memory `Storage`): call
  `log_audit_entry` with `working_dir` containing a synthetic
  `sk-` token and `reasoning` containing a synthetic `*.openai.azure.com`
  host; read the row back; assert neither field contains the raw secret/host and
  the redaction marker is present.
  **Fails before** (verbatim today) **/ passes after**.
- Non-regression test: a benign `working_dir=/Users/x/proj` and
  `reasoning="[network] curl to public api"` survive **unchanged** (proves no
  over-redaction of forensic value).

**(d) Disposition: FIX-NOW — but with an explicit forensic-value tradeoff
called out.**
The change is one line each and uses an already-trusted redactor.
**Adversarial concern (must be honest):** redacting `reasoning` *can* destroy
forensic value — `reasoning` is the L1 model's risk explanation and a security
analyst reviewing the audit log relies on it to understand *why* a command was
allowed/blocked. `redact_secrets` is **pattern-based** (API-key prefixes,
`key=`/`token=` kv, Bearer/Basic, Azure hosts) — it does **not** blanket-scrub
prose, so a normal reasoning string ("blocked: command matches rm -rf
blacklist") is untouched; only embedded credential-shaped tokens are masked.
Net: the forensic loss is bounded to exactly the substrings that are
secrets-by-pattern, which a forensic reviewer should not need in plaintext
anyway. Verdict: FIX-NOW is correct, and the non-regression test above is the
explicit guard that prose survives. (`working_dir` redaction has effectively
zero forensic downside — a path almost never legitimately contains a
key-shaped token.) This satisfies rgp-red-findings B6-3 Track and signoff §5.

---

### B6-4 — raw stdin debug log uses free-text redactor not `redact_json_value`

**(a) Root cause / current state (verified):**
`crates/clx-hook/src/router.rs:232` `debug!("Hook input: {}",
redact_secrets(&raw));`. `raw` is the full JSON envelope **as a string** at this
point (parse happens at `:234`). The structure-aware `redact_json_value`
(`redaction.rs:474-487`) exists and is used elsewhere
(`hooks/post_tool_use.rs:45,49`). Post-PR#27 `redact_secrets` *does* now carry
the B6-2 Azure host pattern, so the line is **partially improved** vs the RED
finding — the tenant-host class is now scrubbed even from the raw-string path.
The residual gap is only the non-host structured-secret class (e.g. a value
under a `password`/`token` JSON key that `redact_secrets`'s kv heuristic does
not catch because the surrounding bytes are JSON punctuation, not `key=value`).

**(b) Remediation + design (minimal):**
- Replace the line with a parse-then-redact:
  ```rust
  let redacted_dbg = serde_json::from_str::<serde_json::Value>(&raw)
      .map(|v| clx_core::redaction::redact_json_value(&v).to_string())
      .unwrap_or_else(|_| redact_secrets(&raw));
  debug!("Hook input: {}", redacted_dbg);
  ```
  i.e. if the envelope parses as JSON, walk it with the structure-aware
  redactor (which itself calls `redact_secrets` per string leaf, so it also
  gets the B6-2 host scrub); if it does **not** parse (malformed/oversize
  fragment), fall back to the existing free-text `redact_secrets` so a
  non-JSON blob is still scrubbed. This double-parses the envelope (it is
  re-parsed at `:234`) — acceptable at `debug!` level only (the log line is
  gated by the level filter; in the default non-debug build the `from_str` is
  inside the `debug!` arg and is **not** evaluated because `debug!` does not
  evaluate args when the level is disabled — confirm with the `tracing` macro
  semantics; if uncertain, gate behind `if tracing::enabled!(Level::DEBUG)`).

**(c) Closing-test design:**
- `router.rs` `#[cfg(test)]`: build an envelope JSON with a synthetic secret
  under a nested key that the free-text `redact_secrets` misses but
  `redact_json_value` catches; capture the `debug!` line via a `tracing`
  subscriber; assert the secret is absent. **Fails before / passes after.**
- Edge test: malformed (non-JSON) input still goes through the `redact_secrets`
  fallback and does not panic / does not leak an obvious `sk-` token.

**(d) Disposition: FIX-NOW (low risk, clearly correct).**
`debug!`-level only and already partially improved by B6-2, so the *blocking*
aspect was never present — but the parse-then-`redact_json_value` change is
small, the structure-aware redactor is already battle-tested
(`post_tool_use.rs`), and it closes the structured-secret class cleanly.
Adversarial note: the double-parse cost is the only downside and is
debug-gated; the `unwrap_or_else` fallback guarantees no *regression* for
non-JSON input (it degrades to exactly today's behavior).

---

### B5-3 — `CLX_ALLOW_AZURE_HOSTS` has no internal-IP recheck (asymmetry with Ollama)

**(a) Root cause / current state (verified):**
`crates/clx-core/src/llm/azure.rs:99-125` `validate_host`. The env-allowlist
branch at `:105-115` returns `Ok(())` on an **exact `host == h`** match with no
further check. Contrast the Ollama path
`crates/clx-core/src/llm/ollama.rs:205-226`: even with
`CLX_ALLOW_REMOTE_OLLAMA=true` it still calls `is_private_or_internal(host)`
(`ollama.rs:215`, defined `ollama.rs:133`) and rejects RFC1918 / link-local /
metadata / `.local|.internal|.lan|.home|.corp|.intranet`. `is_private_or_internal`
is a private `fn` in the `ollama` module (not exported).

**(b) Remediation + design (FIX-CAREFUL, with a deliberate-tradeoff knob):**
- Promote `is_private_or_internal` to a shared location:
  `crates/clx-core/src/llm/mod.rs` (or a small `llm/net.rs`), `pub(crate)`,
  re-exported so both `ollama.rs` and `azure.rs` use the single
  implementation (eliminates the asymmetry at the source — currently two
  SSRF policies, one enforced one not).
- In `azure.rs::validate_host`, after an exact env-allowlist match at `:111`,
  **before returning `Ok(())`**, run `is_private_or_internal(host)`; if true,
  reject **unless** a second explicit opt-in env
  `CLX_ALLOW_AZURE_INTERNAL_HOSTS=true` is set (mirroring the Ollama
  "remote override is still SSRF-checked" design, but with an escape hatch for
  the legitimate private-Azure case — see adversarial note).
- The suffix-allowlist branch (`:117-121`) needs no change: real Azure
  suffixes (`*.openai.azure.com` etc.) never resolve to a literal RFC1918 host
  string, so that path is unaffected.

**(c) Closing-test design:**
- Unit test on `validate_host` (env serial): `CLX_ALLOW_AZURE_HOSTS=169.254.169.254`
  → `validate_host` is `Err` (metadata endpoint blocked even though
  allowlisted). **Fails before** (currently `Ok`) **/ passes after.**
- Tests: `CLX_ALLOW_AZURE_HOSTS=10.0.0.5` → `Err`; same + 
  `CLX_ALLOW_AZURE_INTERNAL_HOSTS=true` → `Ok` (the deliberate escape hatch).
- Non-regression: `CLX_ALLOW_AZURE_HOSTS=127.0.0.1` with the escape hatch set
  still works (wiremock/emulator dev flow at `azure.rs:407` test must keep
  passing — that test sets `127.0.0.1`; it will now require the new opt-in or
  it regresses. **This is the key regression risk — see disposition.**)

**(d) Disposition: FIX-CAREFUL — real regression risk to a legitimate flow.**
**Adversarial concern (must be flagged):** an unconditional internal-IP recheck
**breaks two legitimate use cases**: (1) the in-tree wiremock test at
`azure.rs:404-464` sets `CLX_ALLOW_AZURE_HOSTS=127.0.0.1,localhost` — an
unconditional recheck makes that test fail; (2) a real customer running an
**Azure private endpoint / Private Link** (a genuinely private RFC1918 IP for
`*.openai.azure.com` reached over a VNet) is a *supported, legitimate*
configuration — blanket-blocking RFC1918 for Azure would break private-endpoint
Azure OpenAI, which is a common enterprise deployment. This is exactly why the
two-tier design (recheck **+** explicit `CLX_ALLOW_AZURE_INTERNAL_HOSTS`
second opt-in) is required, not a flat block. Even so this is in-model
(env is the documented injection surface, same class as B5-4) and the Azure
client only issues its own configured calls (no attacker-chosen path), so the
SSRF impact is bounded. Verdict: worth doing for defense-in-depth + symmetry
with Ollama, but **must** ship the escape-hatch knob and update the wiremock
test, hence FIX-CAREFUL not FIX-NOW. If the escape hatch is deemed too much
surface, the honest fallback is ACCEPT-AND-DOCUMENT (it is Track/in-model in
both RED and PURPLE registers).

---

### B1-10 — legacy mtime-only trust-token fallback

**(a) Root cause / current state (verified):**
`crates/clx-hook/src/hooks/pre_tool_use.rs:115-122`. When the trust token file
does **not** parse as a JSON `TrustToken`, the code falls back to
`std::fs::metadata(...).modified()...elapsed() < 3600` — i.e. any file at
`~/.clx/.trust_mode_token` whose mtime is < 1h old grants 1h global auto-allow
(audited as `TRUST`, `:132-140`). The *carrier* (B4-2 hostile-repo-set
`validator.trust_mode`) is now closed by B4-1 (re-verified in §0), materially
shortening the chain: the attacker can no longer pre-arm `trust_mode` from a
cloned repo.

**(b) Remediation + design (minimal):**
- Remove the `else` branch at `pre_tool_use.rs:115-122` entirely. The JSON
  token path (expiry + session binding, `:78-114`) is the only supported form
  and is already implemented and tested. A non-JSON token file → `trust_valid =
  false` → falls through to normal validation (`:145-147` already does the
  WARN + `remove_file`).
- Net code: replace the `else { mtime-fallback }` with `else { false }`.

**(c) Closing-test design:**
- `pre_tool_use` `#[cfg(test)]` (isolated HOME, in-memory storage,
  `trust_mode=true`): write a **non-JSON** `~/.clx/.trust_mode_token`
  (e.g. `"legacy"`) with a fresh mtime; drive a Bash command; assert the
  decision is **NOT** auto-allow-via-TRUST (it falls through to validation).
  **Fails before** (mtime fallback auto-allows) **/ passes after.**
- Non-regression: a valid JSON `TrustToken` (unexpired, matching session) still
  auto-allows (the supported path is untouched).

**(d) Disposition: FIX-NOW — but flag the back-compat break honestly.**
The change is a 6-line deletion and clearly correct (removes an
mtime-is-not-authentication primitive). **Adversarial / migration concern:** any
existing user who currently has a *legacy plain-text* trust token will silently
lose trust-mode on upgrade and fall back to normal validation. Honest
assessment: this is **acceptable and arguably desirable** — (i) the legacy
format predates the JSON token and the JSON path has been the documented one;
(ii) the fallback is a *security downgrade by design* (mtime ≠ auth); (iii) the
failure mode is fail-safe (more prompting, never more allowing); (iv) the user
re-establishes trust mode with one `clx trust` invocation which writes a proper
JSON token. The migration cost is one re-run of the trust command, and the
behavior change is strictly toward *more* validation. Document in CHANGELOG as a
security hardening with the one-line migration note. In-model for the touch
itself; this removes the cheap-harden the register explicitly flagged
(rgp-red-R1 R1-07 "Fix direction: remove the legacy mtime fallback entirely").

---

### B2-4 — scoped-key project-path `:` confusion

**(a) Root cause / current state (verified):**
`crates/clx-core/src/credentials.rs:621-626` `scoped_key` =
`format!("{PROJECT_PREFIX}{path}:{key}")` (`PROJECT_PREFIX="clx:project:"`,
`GLOBAL_PREFIX="clx:global:"`, `:47-50`). `validate_key` (`:580-618`) validates
**only `key`** (rejects `:`, `..`, non-`[A-Za-z0-9_.-]`, NUL, >255) — `path` is
**unvalidated**. `list_from_backend_scoped` (`:542-562`) strips
`clx:project:{path}:` / `clx:global:` over a flat keyspace. MCP `get`/`set`
pass `project` straight from a length-only-validated JSON arg
(`clx-mcp/src/tools/credentials.rs`). A `path` containing `clx:global:` makes a
project-scoped key textually de-scope into the global namespace during
prefix-strip.

**(b) Remediation + design (minimal, FIX-CAREFUL):**
- Add a `validate_project_path(path: &str)` helper in `credentials.rs` that
  rejects any `path` containing `:` (the scope separator) or NUL. Call it in
  `scoped_key` (return a `Result`, or validate at all four call sites
  `:322,379,433,482` which already call `validate_key`). Rejecting `:` in the
  project path closes the textual de-scope completely with no ambiguity.
- **Design caution:** `scoped_key` currently returns `String` and is called in
  five places; the project path is a *filesystem path* and on most systems will
  not contain `:` — but a macOS HFS path component *can* contain `:` (rare) and
  a crafted MCP `project` arg certainly can. Safer minimal design: do **not**
  reject (could break a legit `:`-containing cwd); instead **hash/encode** the
  path component: store scope as `clx:project:{hex(sha256(path))}:{key}` so the
  separator can never appear in the path slot. This is collision-safe and
  removes the confusion structurally without rejecting any real path.
  - Tradeoff: changing the scoped-key format is a **storage-format migration**
    — existing stored project credentials under the old
    `clx:project:{rawpath}:{key}` form become unreadable. Mitigation: on read
    miss, fall back to the legacy raw-path key (read-compat shim), and migrate
    on next write. This is the careful part.

**(c) Closing-test design:**
- Unit test mirroring RED `b2_4_project_path_colon_scope_confusion`: a project
  path `"/tmp/p:clx:global"` must **not** produce a scoped key whose tail
  equals the byte-identical global-form key. With the hash design, assert the
  scoped key contains only `[0-9a-f]` in the path slot. **Fails before / passes
  after.**
- Migration test: a credential written under the legacy format is still
  readable via the read-compat shim, then re-written in the new format.

**(d) Disposition: FIX-CAREFUL (or ACCEPT-AND-DOCUMENT).**
CVSS 3.7, high attack complexity (needs a crafted cwd/`project` arg whose
structure aligns with the prefixes, **and** same-uid store access for the
confusion to matter). The clean structural fix (hash the path slot) is correct
but introduces a credential **storage-format migration** with a read-compat
shim — non-trivial and risky to rush. The cheap fix (reject `:` in project
path) has a real **adversarial regression**: a legitimate cwd containing `:`
(uncommon but possible on macOS, and CLX runs on macOS per the env) would make
all project-scoped credential ops fail for that project. Honest verdict: this is
**Track/ACCEPT-AND-DOCUMENT for the residual batch** (high-AC, in-model,
bounded), with the hash-slot redesign filed as a separate tracked credential-
storage hardening if/when a format migration is otherwise scheduled. Do not
fold a storage-format migration into a security-residual sweep.

---

### B1-3 — L1-cache pre-seed (unauthenticated `{cwd}:{cmd}` cache key)

**(a) Root cause / current state (verified):**
`crates/clx-core/src/policy/cache.rs:156-158` `compute_cache_key` =
`format!("{working_dir}:{command}")` (no integrity token). Consumed at
`crates/clx-hook/src/hooks/pre_tool_use.rs:223-252`: the SQLite decision cache
is checked **after** the L0 whitelist/blacklist path (the L0 logic and its
`output_decision`/early returns are above line 215) and **before** L1. So a
same-uid pre-seed of the cache row pre-approves the **L1 verdict** for a chosen
`(cwd, command)`, but **cannot defeat an L0 hard deny** (L0 runs first;
`evaluate()` is blacklist-first). This exactly matches the RED bound.

**(b) Remediation + design (minimal):**
- Bind cache rows to a per-install integrity token: on first use, generate a
  random secret stored 0600 at `~/.clx/.cache_hmac_key`; store
  `HMAC(key, working_dir || 0x1F || command || decision)` alongside each row;
  on read, recompute and discard the row on mismatch (treat as cache miss → run
  L1). Decision should be part of the MAC so a same-uid attacker cannot flip an
  existing legit `deny` row to `allow`.
- Alternative (lower-effort, also acceptable per RED "Fix direction"): treat any
  cache hit as **advisory** — on a cache `allow` hit, still run L1 if L1 is
  reachable, and only use the cached verdict when L1 is unreachable. This
  removes the pre-seed's power without a new on-disk secret.

**(c) Closing-test design:**
- `policy`/`pre_tool_use` test: pre-write a forged cache row
  (`compute_cache_key` shape) with `decision="allow"` for an L0-unknown command
  via a tampered/raw `Storage` insert; drive `handle_pre_tool_use`; assert the
  forged row is **rejected** (HMAC mismatch) and L1 path is taken (or, advisory
  design: L1 still runs). **Fails before** (forged row honored) **/ passes
  after.**
- Non-regression: a legitimately-written cache row (written through the normal
  path that also writes the HMAC) is still honored — no extra L1 latency for the
  honest cache-hit case.

**(d) Disposition: ACCEPT-AND-DOCUMENT (in-model; same-uid). FIX optional.**
Honest rationale: this is **fully in-model** — it requires a same-uid write to
the CLX SQLite DB, which is the exact same-uid local-trust boundary the whole
threat model accepts; it **cannot defeat an L0 hard deny** (L0 runs first,
verified at `pre_tool_use.rs:215`-and-above); and it is bounded to the L1 tier
of L0-*unknown* commands. Adding an HMAC introduces a new on-disk secret and a
cache-invalidation surface (key rotation, multi-machine sync of `~/.clx`) for a
threat that is already inside the accepted model — that is arguably net-negative
complexity. The "advisory cache" variant is cheaper and has merit as
defense-in-depth, but it costs an L1 round-trip on every cache-allow hit
(latency regression for the dominant happy path). Recommend ACCEPT-AND-DOCUMENT
for the residual batch (matches PURPLE §5 "ACCEPTED, in-model"), with the
advisory-cache variant noted as an optional future hardening if cache integrity
is ever independently required. **Do not** add the HMAC purely to satisfy a
checklist — it is largely theater against an in-model same-uid attacker who, by
definition of the model, could also just write the rule table directly.

---

## Disposition summary

| Item | File(s) | Disposition | One-line rationale |
|---|---|---|---|
| **B5-4-audit** | `clx-hook/hooks/pre_tool_use.rs` (+`audit.rs` reuse) | **FIX-NOW** | Additive audit row, accessor already exists, zero risk |
| **B5-1-homebrew** | `.github/workflows/release.yml` + repo settings | **FIX-NOW** (yaml) + **ACCEPT-DOC** (settings) | 1-line `environment:`; effectiveness needs out-of-repo reviewer setting |
| **serde_yml** | 3×`Cargo.toml`, `config/{project,mod}.rs`, `error.rs` | **FIX-CAREFUL** | Unsound not exploitable; cross-cutting dep swap, 30-test blast radius |
| **B6-3** | `clx-hook/audit.rs` | **FIX-NOW** | 1 line each; pattern redactor preserves prose forensic value |
| **B6-4** | `clx-hook/router.rs` | **FIX-NOW** | debug-only, partially closed by B6-2; clean structure-aware swap |
| **B5-3** | `clx-core/llm/{azure.rs,ollama.rs,mod.rs}` | **FIX-CAREFUL** | Recheck breaks legit Azure Private Link + wiremock test; needs opt-in knob |
| **B1-10** | `clx-hook/hooks/pre_tool_use.rs` | **FIX-NOW** | 6-line deletion; fail-safe; legacy-token users re-`clx trust` (CHANGELOG) |
| **B2-4** | `clx-core/credentials.rs` (+mcp) | **ACCEPT-DOC** (FIX-CAREFUL if scheduled) | High-AC in-model; clean fix is a cred storage-format migration |
| **B1-3** | `clx-core/policy/cache.rs` + `pre_tool_use.rs` | **ACCEPT-DOC** | Fully in-model same-uid; cannot defeat L0; HMAC is near-theater here |

---

## Disjoint multi-agent stream grouping

Streams are partitioned so **no two streams write the same file**. Ordering
note: serde_yml (Stream E) and B6-3/B5-4-audit do not overlap files; B5-3
(Stream D) and B1-10/B5-4-audit (Stream A) are disjoint within `clx-hook` vs
`clx-core/llm`. `pre_tool_use.rs` is touched by **both** B5-4-audit and B1-10 —
these are deliberately put in the **same stream (A)** to avoid a collision.

### Stream A — clx-hook validator/audit hardening (owner: clx-hook)
- **Files owned (exclusive):** `crates/clx-hook/src/hooks/pre_tool_use.rs`,
  `crates/clx-hook/src/audit.rs`, `crates/clx-hook/src/router.rs`, their
  `#[cfg(test)]` + `crates/clx-hook/tests/*`.
- **Items:** B5-4-audit (FIX-NOW), B1-10 (FIX-NOW), B6-3 (FIX-NOW),
  B6-4 (FIX-NOW).
- Rationale: all four are clx-hook-local, all FIX-NOW, and three of them
  (`pre_tool_use.rs`, `audit.rs`, `router.rs`) are interdependent within the
  hook crate — single ownership prevents the `pre_tool_use.rs` double-touch.
- Read-only deps on `clx-core::redaction` / `Config::security_env_overrides_active`
  (no writes to core).

### Stream B — CI / supply-chain (owner: release/CI)
- **Files owned (exclusive):** `.github/workflows/release.yml`,
  `.github/workflows/ci.yml`, any new workflow-lint test.
- **Items:** B5-1-homebrew (FIX-NOW yaml + documented repo-settings).
- Fully disjoint from all Rust streams; can run in parallel with everything.

### Stream C — credentials scope hardening (owner: credentials) — CONDITIONAL
- **Files owned (exclusive):** `crates/clx-core/src/credentials.rs`,
  `crates/clx-mcp/src/tools/credentials.rs`.
- **Items:** B2-4 — **disposition is ACCEPT-AND-DOCUMENT for the batch**; this
  stream only activates if the orchestrator elects the FIX-CAREFUL hash-slot
  redesign (separate scheduled work, not the residual sweep). Default: this
  stream produces only the documented-accepted register entry, no code.

### Stream D — Azure SSRF symmetry (owner: llm) — FIX-CAREFUL
- **Files owned (exclusive):** `crates/clx-core/src/llm/azure.rs`,
  `crates/clx-core/src/llm/ollama.rs`, `crates/clx-core/src/llm/mod.rs`.
- **Items:** B5-3. Promote `is_private_or_internal` to shared, add Azure
  recheck + `CLX_ALLOW_AZURE_INTERNAL_HOSTS` opt-in, update the wiremock test.
- Disjoint from all other streams (own `llm/*` only). Must update the in-tree
  `azure.rs:404-464` test in the same stream (it owns that file).

### Stream E — serde_yml migration (owner: core/config) — FIX-CAREFUL, STANDALONE
- **Files owned (exclusive):** `Cargo.toml`, `crates/clx-core/Cargo.toml`,
  `crates/clx/Cargo.toml`, `crates/clx-core/src/config/project.rs`,
  `crates/clx-core/src/config/mod.rs`, `crates/clx-core/src/error.rs`,
  `deny.toml`.
- **Items:** serde_yml RUSTSEC-2025-0068 swap.
- **Must be its own PR, not merged into the residual sweep** (30-test
  round-trip blast radius; a parser-behavior regression could mask other
  fixes). It owns `config/mod.rs` and `error.rs` exclusively — note Stream A
  reads `Config::security_env_overrides_active` from `config/mod.rs` but does
  **not** write it, so no collision; still, land Stream E **after** Stream A
  is merged to keep the diff bisectable.

### Accept-and-document only (no stream / no code)
- **B1-3** (in-model, cannot defeat L0) and **B2-4** (high-AC, in-model) →
  recorded in the accepted-risk register with the rationales above. Owner
  sign-off, no implementation in this batch.

**Parallelism plan:** Streams A, B, D run fully in parallel (disjoint files,
all valuable). Stream E is serialized after A (bisectability, not a file
collision). Stream C is conditional/no-op by default. B1-3/B2-4 are register
entries only.

---

## Files of record (absolute)

- This plan: `/Users/blackax/Projects/clx/specs/2026-05-19-residual-plan.md`
- Verified root-cause sources:
  - `/Users/blackax/Projects/clx/crates/clx-core/src/config/mod.rs:1229-1254` (B5-4 accessor)
  - `/Users/blackax/Projects/clx/crates/clx-core/src/config/project.rs:84-89,177-181` (B4-1/B4-2 confirm closed)
  - `/Users/blackax/Projects/clx/crates/clx-hook/src/audit.rs:23,31,33` (B6-3)
  - `/Users/blackax/Projects/clx/crates/clx-hook/src/router.rs:232` (B6-4)
  - `/Users/blackax/Projects/clx/crates/clx-hook/src/hooks/pre_tool_use.rs:25,67-70,115-122,223-252` (B5-4-audit wiring point, B1-10, B1-3)
  - `/Users/blackax/Projects/clx/crates/clx-core/src/llm/azure.rs:99-125,404-464` (B5-3 + wiremock test)
  - `/Users/blackax/Projects/clx/crates/clx-core/src/llm/ollama.rs:133,205-226` (B5-3 reference impl)
  - `/Users/blackax/Projects/clx/crates/clx-core/src/credentials.rs:580-626` (B2-4)
  - `/Users/blackax/Projects/clx/crates/clx-core/src/policy/cache.rs:156-158` (B1-3)
  - `/Users/blackax/Projects/clx/crates/clx-core/src/policy/matching.rs:55-85` (B1-1/B1-2 L0-norm still open, in-model)
  - `/Users/blackax/Projects/clx/.github/workflows/release.yml:74-78,237-242` (B5-1)
  - `/Users/blackax/Projects/clx/Cargo.toml:27`, `crates/clx-core/Cargo.toml:13`, `crates/clx/Cargo.toml:18`, `deny.toml:23` (serde_yml)
