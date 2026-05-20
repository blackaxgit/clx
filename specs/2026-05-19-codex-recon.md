# 2026-05-19 — Codex Independent-Audit Recon (Adversarial)

**Scope:** fresh, read-only reconnaissance of CLX HEAD on
`chore/rgp-residual-hardening` (3 ahead of `origin/main` after the
v0.8.1 + PR#27 + PR#26 + PR#29 baseline) to enumerate the highest-yield
targets for an INDEPENDENT Codex review. Treats every prior artifact
(`rgp-recon.md`, `rgp-red-findings.md`, `rgp-purple-signoff.md`,
`residual-status.md`, `residual-impl.md`, `coverage-campaign-v2.md S7`)
as a hypothesis, NOT as evidence — what those documents say "closed"
is exactly what an independent pass should probe hardest.

Posture: name every place the prior team's claim is non-obvious,
glue-code-bearing, or supported by a self-test rather than an
adversarial-style cross-check. Skip places where the closure is
mechanical (e.g., `Cargo.toml` license string).

---

## Top targets — ranked by expected yield per Codex hour

### T1 — Audit chain is not actually chained (B5-4 / Stream A) — HIGH yield

**File:** `crates/clx-hook/src/audit_chain.rs:1-298`,
`crates/clx-hook/src/hooks/pre_tool_use.rs:37-76`

**Observed code:** `build_record` is invoked with hard-coded
`seq=1` and `GENESIS_HASH` on every hook invocation
(`pre_tool_use.rs:47`). `clx-hook` is a short-lived per-event process;
no chain head is read from disk before this call, no head is persisted
after it. There is NO `chain_state.json`, no `audit_chain_head` SQLite
column, no file I/O in `audit_chain.rs` (it is a pure-function module).

**Independent-reviewer question:** in what operational sense is this a
"hash chain"? Each invocation produces `SHA256(canonical_record ||
zeros)`. Tampering with a single event in the audit DB or log
aggregator is undetectable across the timeline because there is no
linkage between record N and record N+1 from a SEPARATE process. The
`warn!` head-hash anchor (`pre_tool_use.rs:50-55`) is the only
inter-process artefact, and it is a one-record fingerprint, not a
chain.

**What would falsify the prior claim:** show that the spec/PURPLE
sign-off described B5-4 as a *chain* (it does — `audit_chain.rs:3-21`
explicitly says "Each record contains [...] `prev_hash`" and "altering
or deleting any record breaks all subsequent hashes"). A reasonable
adversary deleting one row from `audit_logs` (or one line from the
external log sink) cannot be detected by re-running `verify_chain`
unless someone persists `entry_hash` from the prior process and
threads it into the next process's `prev_hash`. Today that thread is
absent. The construct is **per-event tamper-resistance** (Merkle of
size 1), not a chain.

**Severity if correct:** the property advertised in the source
comments and `rgp-purple-signoff` row 6 is not satisfied. Re-classify
as a forensic anchor (which is fine), not as the documented chain.

**Cross-process race:** N/A — no shared mutable state. But that very
absence is the problem.

**Fail-mode test:** none (no chain-corruption recovery path exists,
because there is no on-disk chain).

---

### T2 — `Connection`-class Azure errors leak the tenant host (B6-1/B6-2 incomplete) — HIGH yield

**Files:** `crates/clx-core/src/llm/azure.rs:280-310`,
`crates/clx-core/src/llm/mod.rs:31-51`

**Observed code:** post-fix, the 401/404/429/5xx body path is gated by
`build_error_summary` (azure.rs:38, redact-then-truncate). BUT the
transport-error path (azure.rs:280-286 for chat, 297-310 for embed)
wraps `reqwest::Error::to_string()` straight into
`LlmError::Connection(...)` with **no `redact_secrets` call**.
`reqwest::Error` Display embeds the full request URL, which includes
the user's tenant host (e.g. `https://acme-prod.openai.azure.com/...`).

The same gap applies to `azure.rs:82` (`format!("invalid endpoint URL:
{e}")`) and `azure.rs:88` (`http client init: {e}`) — these surface
via `LlmError::Connection(String)` which derives Display via
`thiserror`'s `#[error("connection failed: {0}")]` (mod.rs:33). That
string then reaches:
- `crates/clx/src/commands/health.rs:110` — wrapped in
  `redact_secrets(&e.to_string())` correctly here.
- `crates/clx-core/src/policy/llm.rs:166` — wrapped in
  `redact_secrets(&e.to_string())` correctly here.
- `crates/clx-core/src/llm/fallback.rs:78-82, 99-103` — only emits
  `kind_str()`, never `to_string()`. Safe.

**Independent-reviewer question:** are there any sites — outside
`health.rs` and `policy/llm.rs` — that render an `LlmError` via
`Display`/`Debug` without `redact_secrets`? Probe every `?` and every
`e.to_string()` reachable from the Azure transport errors. The
`Debug`-derived form is particularly risky: `tracing::error!("{e:?}")`
gives the un-redacted form.

**What would falsify the prior team's claim that "B6-2 closes the
tenant-host class on every Display/log sink reachable from Azure":**
construct a wiremock test where the connection ABORTS mid-flight
(reset peer) and grep the `LlmError::Connection(...)` string for the
tenant host. Confirmed transport-error paths do not go through
`build_error_summary` so the inner reqwest message is verbatim.

**Severity:** HIGH residual on the same class B6-2 was meant to close;
caught only by the two known call-site wrappers, brittle to any future
call site.

---

### T3 — File-loaded ALLOW rules bypass the overbroad-allow gate (B1-4/B3-2 gap) — HIGH yield

**File:** `crates/clx-core/src/policy/rules.rs:202-234,237-241`

**Observed code:** `load_learned_rules` (line 244+) DOES gate with
`is_overbroad_allow_pattern` (line 259-268). `load_rules_from_file`
(line 202-234) DOES NOT. `load_default_rules` calls
`load_rules_from_file` against `~/.clx/rules/default.yaml`
(`paths.rs:54-58`). The file path is under `$HOME` and writable by the
local same-uid attacker, which the threat model accepts as in-scope
for some attacks but not others.

**Independent-reviewer question:** is the explicit-config-file path
considered "trusted user intent" because the user wrote the file
themselves? If yes, document it. If no, the overbroad-allow gate
should also apply at line 216-219 where `config.whitelist` patterns
become whitelist rules.

A linked concern: the MCP `add` path (`clx-mcp/src/tools/rules.rs:67`)
DOES gate. So there is an inconsistency: API-added ALLOW patterns are
gated, file-added ALLOW patterns are not.

**What would falsify the prior claim that "B1-4 closes overbroad allow
at both boundaries":** write `Bash(*)` into `~/.clx/rules/default.yaml`,
trace the load, observe it becomes an active L0 ALLOW rule, then
issue any Bash command and watch it hard-allow at L0 before L1.

**Severity:** depends on threat model. If file edits to
`~/.clx/rules/default.yaml` are deemed equivalent to user consent (a
defensible call), document that explicitly and add a `warn!` on overbroad
patterns at load time. If not, the gate is missing.

**Adversarial pattern set to also test against `is_overbroad_allow_pattern`:**
- `Bash(:*)` (only `:` + `*` → after `:`→space normalization, all
  whitespace+`*` → IS flagged, good)
- `Bash(::*)` (same logic, IS flagged)
- `Tool(*)` (unwraps to `*`, IS flagged)
- `Bash(\u{3000}*)` (full-width space) — `c.is_whitespace()` does
  recognize this, so IS flagged
- `**Bash**(*)` — the unwrap only triggers on `pattern.ends_with(')')`
  with a `(` somewhere; `**Bash**(*)` ends with `)` and contains `(`,
  so unwraps to `*` → IS flagged. Good.
- `Bash( * )` — leading/trailing spaces unwrap to ` * ` → all
  whitespace+`*` → IS flagged.
- `Bash(\t*\t)` — same.
- `**` — IS flagged.
- `***` — IS flagged.
- `Bash(*)x` — does NOT end with `)`, falls through unwrap path,
  becomes `Bash(*)x` → contains `B`, `a`, `s`, `h`, `x` literals → NOT
  flagged. Probably fine because the L0 matcher won't match anything
  useful with a trailing `x` outside the parens, but worth confirming.
- `Bash(*)*` — same; trailing `*` outside parens, NOT flagged. Likely
  benign because the L0 matcher parses `Bash(*)` then ignores trailing
  characters? Codex should re-check.
- `*(*)` — ends with `)`, unwraps to `*` → IS flagged.

**Codex prompt:** verify the matcher's behaviour on `Bash(*)x`,
`Bash(*)*`, and the `convert_learned_pattern` wrap (`matching.rs:34-42`)
when fed a bare `*`.

---

### T4 — Auto-summary snapshot path has no secret redaction (downstream of B6-3) — HIGH yield

**Files:** `crates/clx-hook/src/hooks/stop_auto_summary.rs:124-147`,
`crates/clx-core/src/storage/snapshot.rs:15-50`,
`crates/clx-core/src/recall/mod.rs:189-191,222,235`

**Observed code:** the Stop hook samples raw transcript turns
(`stop_auto_summary.rs:117-122`), passes them to `build_summary` which
invokes the LLM, then persists `summary` verbatim into a `Snapshot` row
(line 145, 147). There is no `redact_secrets` call on the LLM-produced
summary, and `Snapshot.summary` is read back via `recall/mod.rs:222`
where the only sanitiser is `sanitize_recall_text`, which only escapes
`<` and `>`. Secrets that the user pasted into Claude and that the
summarizer copied verbatim are then **emitted into future LLM context
blocks** as plaintext.

**Independent-reviewer question:** B6-3 wired `redact_secrets` into
`audit.rs::log_audit_entry` (audit.rs:23, 36, 38) — was the same wire
done on the snapshot/summary path? Grep shows no `redact_secrets` use
inside `clx-hook/src/hooks/stop_auto_summary.rs`,
`clx-core/src/storage/snapshot.rs`, or `clx-core/src/recall/mod.rs`.

**What would falsify the prior team's claim that "B6-3 closes the
attacker-influenced-text class":** craft a transcript turn containing
`api_key = sk-LIVELONGTOKEN12345`, run the auto-summary, inspect
`snapshots.summary` in `clx.db`. Then issue a `clx_recall` and observe
the secret echoed into the `<historical-context>` block.

**Severity:** HIGH residual on the same redaction class B6-3 closed
on the audit-log path. The transcript surface is larger and the
secret-disclosure window is longer (snapshots persist across sessions;
audit rows are pruned).

---

### T5 — Inert-key filter is YAML-naive (B4-1 partial closure) — MEDIUM-HIGH yield

**File:** `crates/clx-core/src/config/project.rs:84-89, 147-181`

**Observed code:** `filter_value` only matches keys via
`k.as_str()` and silently DROPS non-string keys (line 152-155). A
hostile project YAML using:
- numeric keys (`!!int` or bare integer):
  `1: { auto_whitelist_threshold: 1 }` — `k.as_str()` returns `None`,
  the entry is dropped, NO logged warning. Safe.
- **YAML merge keys (`<<`)**:
  ```yaml
  validator-anchor: &v
    layer1_enabled: false
    default_decision: allow
  validator:
    <<: *v
  ```
  Here the **anchor's contents** are merged into `validator:` by
  `serde_yml`'s merge-key handler BEFORE `filter_value` walks the
  tree. Question: does `serde_yml::from_str::<serde_yml::Value>(...)`
  resolve `<<: *v` at parse time, or preserve the merge marker for the
  caller? If at parse time, `filter_value` sees the resolved
  `validator: { layer1_enabled: false, default_decision: allow }` and
  correctly drops everything under `validator.`. If preserved, the
  filter never traverses into the merged keys.
- **Aliases / deeply-nested aliases** under a non-filtered key:
  ```yaml
  validator-config: &vc
    layer1_enabled: false
  auto_recall: *vc   # this is `auto_recall: { layer1_enabled: false }`
  ```
  This puts `layer1_enabled: false` under `auto_recall.*`, which is
  NOT in `NON_INERT_KEY_PATTERNS`. `auto_recall.layer1_enabled` does
  not exist in the schema, so `serde_yml::from_str::<Config>` would
  ignore it. Safe.
- **Dotted keys** (literal `.` in key): `"validator.layer1_enabled":
  false` as a string key. `k.as_str() == Some("validator.layer1_enabled")`,
  `next_path = "validator.layer1_enabled"` (because `path` is empty
  and the join inserts a `.` only when nested), so the check
  `path == "validator"` fails BUT `path.starts_with("validator.")` is
  the actual condition (project.rs:180):
  ```rust
  path == *pat || path.starts_with(&format!("{pat}."))
  ```
  Here `path = "validator.layer1_enabled"`, `pat = "validator"`,
  `"validator.layer1_enabled".starts_with("validator.")` is TRUE.
  So the dotted-key bypass IS caught. Good.
- **BOM in YAML**: `serde_yml` handles BOMs at the front; uncertain
  about embedded ones. Probably benign.
- **Mixed scalars** (`validator: !!bool false`): the tag means the key
  is `validator`, value is a bool. `filter_value` matches the
  `Mapping` arm only for mapping VALUES, so a non-mapping value under
  `validator:` falls through to `other => other.clone()` (line 173)
  and is RETURNED VERBATIM. Question: does a top-level
  `validator: false` (bool, not map) get serialized back into the YAML
  string by `serde_yml::to_string(&filtered)` and then deserialized
  into `validator.enabled = false`? Probably YES because
  `ValidatorConfig::enabled` defaults from `false`, but
  `serde_yml::from_str::<Config>` would fail to deserialize `bool` into
  a struct. Re-check: a hostile config
  `validator: false` likely fails parse; if so, fall-back is empty
  string (project.rs:98). Safe.
- **Sequence key**: `[a, b]: true` — `k.as_str()` is None, dropped.
  Safe.

**Independent-reviewer question:** the prior team's regression tests
(`b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key`)
only exercise the **plain map under `validator:`** form. Codex should
add evidence tests for:
1. Merge-key (`<<: *anchor`) form.
2. Anchor → alias under a `validator-shaped` key.
3. Tagged scalar (`validator: !!set { ... }`).
4. Nested aliases two layers deep.

**What would falsify "B4-1 closes B4-1":** any of the above resulting
in `validator.layer1_enabled = false` taking effect at runtime under
an untrusted config.

**Severity:** MEDIUM-HIGH if any of (1)-(4) is exploitable; LOW if
serde_yml resolves merges at parse time AND drops unknown keys.

---

### T6 — `redact_azure_hosts` Pass-2 boundary set is incomplete — MEDIUM yield

**File:** `crates/clx-core/src/redaction.rs:99-140`

**Observed code:** Pass-2 tokenizes on ` \t\n\r"',}{[]()`. NOT on:
- `:` (colon-terminated host: `tenant.openai.azure.com:443` —
  `audit.rs` test at line 144-160 ACKNOWLEDGES this gap)
- `;` (semicolon after error string)
- `<>` (XML/HTML-shaped envelopes — relevant since recall context is
  XML-shaped)
- `\\` (literal backslash from JSON escape)
- `=` (key=value form, `host=tenant.openai.azure.com&port=...`)
- `?` (query separator — only triggers in Pass-1 url path, not Pass-2)
- Trailing punctuation like `tenant.openai.azure.com,` is consumed by
  the `,` boundary so the comma stays in the redacted output. OK.

**Independent-reviewer question:** what is the threat envelope? If
Azure server-side messages can embed `host:port` or `host;
deployment=...`, the colon/semicolon gap leaks. The B6-3
audit-test self-documents this gap as "low-residual". Codex should
verify it stays low-residual by enumerating real Azure error-body
shapes.

**Falsification:** craft a synthetic error body containing
`tenant.openai.azure.com:8443` and pass it through `redact_secrets`;
observe the host fragment survives.

**Severity:** LOW-MEDIUM, contingent on real Azure shape.

---

### T7 — Supply chain: `serde_yml` unsoundness + ignore list — MEDIUM yield

**File:** `deny.toml:13-26`, `Cargo.lock` (serde_yml 0.0.12),
`crates/clx-core/src/config/project.rs:96`,
`crates/clx-core/src/config/mod.rs:1194`

**Observed code:** `deny.toml` lists 5 ignored advisories. The
RUSTSEC-2025-0068 (serde_yml unsound + unmaintained) ignore is
labelled "tracked migration" but never executed. `serde_yml::from_str`
is the entry point for the **untrusted project config parse**
(`project.rs:96`) — this is **the** path that processes attacker-
influenced YAML. The unsoundness vector matters here.

**Independent-reviewer question:** look up RUSTSEC-2025-0068. The
advisory describes an unsound type confusion via crafted YAML that
permits memory unsafety in `serde_yml`'s tagged-value parsing.
`filter_inert_only` parses **untrusted YAML** through this exact API
before any security check. A crafted project YAML could in principle
exploit `serde_yml` to corrupt memory inside `clx-core` BEFORE the
inert filter ever runs. The inert filter is then operating on
already-tainted process state.

**What would falsify "ignore list is minimal-justified":** if
RUSTSEC-2025-0068 is exploitable through untrusted YAML (and it is —
that is the definition of "unsound" for a parser library), the ignore
is NOT justified for a binary that parses untrusted YAML. The Stream E
migration to `serde_yaml_ng` (residual-status.md:41) is the real fix
and was deferred. Codex should call out the gap between the deny.toml
comment ("compensating controls today") and the actual control: the
inert-filter runs AFTER `serde_yml::from_str`, so it is not a
compensating control against parse-time memory unsafety.

**Other deny.toml ignores:**
- `RUSTSEC-2024-0388` derivative (proc-macro, parse-time only) — low.
- `RUSTSEC-2024-0384` instant — only triggers on Windows; OK.
- `RUSTSEC-2025-0119` number_prefix (via indicatif, only used in CLI
  progress bars) — low.
- `RUSTSEC-2024-0436` paste (proc-macro, parse-time only) — low.

**Workflow permissions:** `id-token: write` and `attestations: write`
on `release.yml:30-32` are scoped to the `Release` workflow only (tag
push). `contents: write` is broader but standard. The `update-homebrew`
job inherits these — should NOT be a problem because that job uses a
different repo (`blackaxgit/homebrew-clx`) via `HOMEBREW_TAP_TOKEN`,
not the OIDC token. **No `environment:` gate on `update-homebrew`** —
the B5-1 residual is real (confirmed at `release.yml:243`).

**Severity:** HIGH for the serde_yml ignore (untrusted-parser memory
unsafety). MEDIUM for the homebrew auto-publish (no manual approval).

---

### T8 — Trust-token mtime fallback removal — completeness check — LOW yield

**Files:** `crates/clx-hook/src/hooks/pre_tool_use.rs:125-201, 714-770`

**Observed code:** the JSON-token path is preserved (line 129); the
non-JSON arm is hard-coded `false` (line 174); the `if trust_valid`
arm (line 180) is therefore unreachable for non-JSON tokens. The
unreachable branch still LOGS and ALLOWS — if an attacker can get
`trust_valid = true` through a different path (e.g., a future JSON
parse-leniency bug), it short-circuits to allow.

**Independent-reviewer question:** is there any `#[cfg(test)]` or
debug-only override that re-enables the legacy path? Grep across all
crates for "mtime" trust:
- `crates/clx-core/tests/validation_behavior.rs:868-880` — describes
  legacy mtime window as documented accepted risk; the test
  `v_r9_legacy_trust_token_mtime_window_is_3600s_pinned` is a
  documentation pin, not an exploit gate.
- `crates/clx-hook/tests/validation_e2e.rs:338-403` — asserts the
  post-removal behaviour.
- No `#[cfg(test)]` override of `trust_valid` was found.

**What would falsify "B1-10 closed":** find any path where a fresh
plaintext token grants trust. None located in this pass.

**Severity:** LOW. The fix appears complete. The dead-code branch at
180-196 should be deleted for clarity but is currently unreachable.

---

### T9 — Accept-and-document items: challenge each — VARIABLE yield

**B2-4 — scoped-key project-path `:` confusion:**
- Disposition: "deferred to a storage-format change". The
  exploitability requires (a) same-uid in-model and (b) the agent
  crafting a cwd containing `:`. Same-uid in-model is the standing
  threat model boundary; if accepted, this is consistent. Independent
  question: can the agent INFLUENCE the cwd at hook spawn time without
  same-uid code execution? `cwd` enters via the hook JSON envelope
  from stdin (`router.rs`). The envelope source is Claude Code's hook
  pipe, which the threat model treats as trusted-because-spawned-by-CC.
  Claude Code itself sets `cwd` from the project root — agent cannot
  override directly. **Accept seems sound.**

**B1-3 — L1-cache pre-seed HMAC:**
- Disposition: "HMAC is near-theater against same-uid attacker who can
  write the cache/rule table directly, AND L0 runs before the cache".
- Independent challenge: is L0 truly always-before? Trace
  `pre_tool_use.rs:223-274` (L0 evaluate) vs 277-305 (cache lookup):
  cache lookup runs only IF L0 returned `Ask`. So a same-uid attacker
  cannot pre-seed an Allow for a command L0 would Deny (L0 hits first).
  They COULD pre-seed an Allow for a command L0 returns Ask on, but
  same-uid can already directly invoke commands without going through
  Claude. **Accept seems sound.**

**B5-1 repo-settings (homebrew approval gate):**
- Disposition: "repo-settings/runbook action, out of code scope".
- Independent challenge: the absence of `environment:` on
  `update-homebrew` (release.yml:243) is in-code, and adding it IS in
  scope. Disposition wording is a dodge. Either (a) add the
  `environment:` line and document the repo-side rule, or (b) accept
  that an attacker controlling `HOMEBREW_TAP_TOKEN` (via the same
  `release.yml`) can publish to the tap without manual review on every
  tagged release. Codex should NOT accept the disposition as written.

**9 `#[ignore]`-gated keychain tests:**
- These exist because of `#[serial]` + macOS keychain prompt
  interaction. The risk is that they hide a real keychain regression
  behind `#[ignore]`. Codex should confirm the ignored tests still
  build (`cargo test --no-run`) and are CI-runnable behind an explicit
  job, not silently skipped forever.

**Stream B/D/E follow-ons:**
- Stream B (B5-1 CI gate): same as above; not deferred, just unmerged.
- Stream D (B5-3 Azure SSRF post-allowlist internal-IP reblock):
  current code allows ANY `.openai.azure.com` host suffix
  (`azure.rs:77, 117-121`). A DNS rebinding attack against
  `attacker-prod.openai.azure.com` resolving to 169.254.x.x or
  127.0.0.1 is NOT blocked by string-allowlist alone. The Stream D
  worktree's reblock + opt-in escape is the right pattern. **This is a
  real open finding; rebase priority HIGH.**
- Stream E (serde_yml → serde_yaml_ng): see T7.

---

### T10 — Multi-agent rationalisation traces — VARIABLE yield

Areas where the multi-agent flow may have closed-by-rationalisation:

1. **PURPLE sign-off row 7 (B1-1/B1-2):** disposition is "mitigated by
   the B4-1/B5-4 pair, in-model standalone is acceptable". This is
   genuinely a partial close — the L0 normalization gap (the original
   RED fix-direction) is NOT fixed; only the *fail-open carrier* is
   removed. The wording "acceptable" hides that the matcher still has
   L0-evasion forms reaching Ask. Codex should re-derive: enumerate
   the L0-evasion forms (e.g. `Bash(eval "rm -rf /")`, `Bash($'echo
   foo')`, `Bash(rm$'\\\\x20'-rf /tmp/x)`) and confirm L1 catches each.
   If L1 does not catch one of these AND `default_decision = ask`,
   then in-model the agent gets a prompt — fine. If `default_decision`
   is somehow `allow` (which B4-1 prevents from untrusted config but a
   trusted/global config can still set), the evasion silently passes.
   So the "documented in-model residual" depends on the user not
   setting `default_decision: allow` in their global config.

2. **PURPLE sign-off row 8 (B3-1 mask):** the `[REDACTED:<bracket>]`
   form gives "≤~4 bits" leakage. The 4-bit number is a hand-wave —
   how many distinct buckets are there? `mask_credential_value`
   returns one of 5 brackets. log2(5) ≈ 2.3 bits, not 4. The 4-bit
   number probably comes from a different counting; Codex should
   recompute and challenge the disposition's math.

3. **Stream A residual disclosure:** the residual-status.md:19-21
   notes the colon-terminated Azure host gap. This is an honest
   disclosure but the disposition ("low-residual; B6-2 is the primary
   control") begs the question: B6-2 IS `redact_azure_hosts`, which IS
   the function that has the colon gap. The "compensating control" is
   the same control with a hole. Codex should challenge: name a
   DIFFERENT control that compensates, or close the hole.

4. **PURPLE sign-off section 4 toolchain tails:** "1718 passed, 9
   skipped". The 9 skipped are the `#[ignore]`-gated keychain tests
   (T9). The sign-off does NOT call this out by name. Codex should
   ask: what are the 9? Are any of them the SAME tests the keychain
   prompt-fix landed against?

---

## Independent-audit yield ranking (Codex prompt priority)

| Rank | Target | File:line | Effort | Yield if hit |
|---|---|---|---|---|
| 1 | T1 audit-chain semantics | `audit_chain.rs:1-298`, `pre_tool_use.rs:47` | LOW | HIGH (spec re-classify) |
| 2 | T2 Azure transport-error host leak | `llm/azure.rs:280-310` | LOW | HIGH (real leak path) |
| 3 | T4 snapshot-summary redaction gap | `hooks/stop_auto_summary.rs:145`, `storage/snapshot.rs` | LOW | HIGH (PII surface) |
| 4 | T5 YAML merge-key / anchor edge cases | `config/project.rs:147-181` | MEDIUM | HIGH if any form sneaks through |
| 5 | T3 file-rules overbroad-allow gap | `policy/rules.rs:216-219` | LOW | MEDIUM (disclosure: gate inconsistency) |
| 6 | T7 serde_yml unsound vs untrusted YAML | `deny.toml`, `project.rs:96` | MEDIUM | HIGH (memory unsafety class) |
| 7 | T9 Stream D Azure SSRF rebinding | `azure.rs:77,117-121` | MEDIUM | HIGH (network-class) |
| 8 | T6 redact_azure_hosts boundary set | `redaction.rs:99-140` | LOW | LOW-MED |
| 9 | T10-3 colon-gap "compensating control" | `redaction.rs:99-140`, `audit.rs:144-160` | LOW | LOW (already disclosed) |
| 10 | T10-1 L0-evasion + global default_decision | `policy/matching.rs`, `config/mod.rs` | MEDIUM | MEDIUM (in-model residual depth) |
| 11 | T9-B5-1 homebrew gate (dodge) | `release.yml:243` | LOW | LOW (already known) |
| 12 | T8 trust-token completeness | `pre_tool_use.rs:125-201` | LOW | LOW (clean) |

---

## Codex prompt seed (ready to paste)

Use the following framing in the Codex review prompt:

> CLX HEAD on `chore/rgp-residual-hardening`. Five claimed-closed
> findings (B4-1 CRIT, B6-1, B6-2, B1-4, B5-4) have non-obvious
> closure paths. Treat the PURPLE sign-off
> (`specs/2026-05-19-rgp-purple-signoff.md`) as a hypothesis only.
> For each of the 12 targets in `specs/2026-05-19-codex-recon.md`,
> independently re-derive the closure (or non-closure) at the
> cited file:line; do NOT trust the self-tests. Output: for each
> target, one of {confirms-closed, partial-closed, falsified} with a
> file:line citation and (if falsified) a minimal repro sketch.

---

## Doc-vs-code drift call-outs (T-DRIFT)

1. **`audit_chain.rs:3-21`** comments say "altering or deleting any
   record breaks all subsequent hashes". Per T1, there are no
   *subsequent* hashes across invocations. Comment is misleading.

2. **`residual-status.md:13`** says "B5-4: SHA-256 hash-chained
   `validator_disabled` audit event ... wired via
   `Config::security_env_overrides_active`". Per T1, the "chain" is
   length-1.

3. **`rgp-purple-signoff.md:50`** says "B5-4 ... silent-bypass prong
   fully closed (WARN is a forensic trail); dedicated audit-row is a
   tracked pre-1.0 follow-on". The audit-row IS now wired
   (`pre_tool_use.rs:66-74`). The doc is stale on this point — the
   row exists, but it's a per-invocation row, not a chain.

4. **`deny.toml:13-17`** comment says "inert-filter + hash-trust gate
   are the compensating controls today" for `RUSTSEC-2025-0068`. Per
   T7, the inert filter runs AFTER `serde_yml::from_str`, so it does
   not compensate against parse-time memory unsafety. The
   compensating-control claim is incorrect.

5. **`CHANGELOG.md` v0.8.1 entry** — not read in this pass, but worth
   cross-checking that the B5-4 entry does not repeat the "chain"
   wording.

---

## Out-of-scope (not probed in this pass)

- Memory backend / embeddings model correctness (covered by S7 of
  `coverage-campaign-v2`).
- TUI dashboard pixel-snapshot pipeline (not security-relevant).
- Provider-fallback cooldown timing (not security-relevant).
- MCP server protocol conformance (covered by `mcp_protocol_e2e.rs`).
- The 9 `#[ignore]`-gated keychain tests' specific identities —
  needs a separate `cargo nextest list --ignored` pass.

---

## Recon-author confidence notes

Findings T1, T2, T4 are **mechanical** (grep+read): the gap exists in
the source as written. Findings T3, T5, T6 require Codex to confirm
behaviour against a real `serde_yml` parse or matcher run. Findings
T7, T9-D are dependent on advisory text and threat-model framing.
Findings T10-1, T10-2 are framing challenges, not new exploits.

No prior-team self-test was treated as evidence in this recon.
