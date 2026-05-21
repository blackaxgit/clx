# CLX 0.8.0 Pre-Release Spec — 01: Validation Pipeline

Authoritative QA reference for the command validation / security guard.
Branch `feat/0.8.0-memory-skills-coverage`, HEAD `1b8515a`.
Every behavioral claim cites `file:line` from the real code. This describes
ACTUAL behavior, not aspirational behavior.

---

## 1. Overview

The validation pipeline gates every command Claude Code attempts to run. It is
invoked from the `PreToolUse` hook. Entry point:

- Router dispatch: `crates/clx-hook/src/router.rs:180` (`"PreToolUse" => handle_pre_tool_use(input).await`).
- Handler: `crates/clx-hook/src/hooks/pre_tool_use.rs:20` (`handle_pre_tool_use`).

Flow for a Bash or MCP command-tool invocation
(`crates/clx-hook/src/hooks/pre_tool_use.rs:20-501`):

1. Load config (`pre_tool_use.rs:24`, `Config::load().unwrap_or_default()`).
2. Route by tool name to extract the raw command (`pre_tool_use.rs:28-53`).
3. Empty command -> allow (`pre_tool_use.rs:55-58`).
4. `validator.enabled == false` -> allow, full bypass (`pre_tool_use.rs:66-69`).
5. Trust mode -> token check -> auto-allow + audit (`pre_tool_use.rs:72-147`).
6. Resolve symlinks in command paths (TOCTOU mitigation) (`pre_tool_use.rs:150-151`).
7. Compute `is_read_only` flag (`pre_tool_use.rs:154`).
8. Build `PolicyEngine`, load learned rules from DB (`pre_tool_use.rs:157-164`).
9. **L0** deterministic rules: `evaluate("Bash", command)` (`pre_tool_use.rs:169`).
   - Allow -> audit `L0`/Allowed, output allow (`pre_tool_use.rs:172-185`).
   - Deny -> audit `L0`/Blocked, output deny (`pre_tool_use.rs:186-199`).
   - Ask -> if read-only, audit `L0-READ`/Allowed, output allow (`pre_tool_use.rs:200-216`); else continue.
10. **Decision cache** lookup (`pre_tool_use.rs:223-251`).
11. **L1** disabled -> audit `L0`/Prompted, output ask (`pre_tool_use.rs:254-272`).
12. Create LLM client; failure -> `default_decision` fallback (`pre_tool_use.rs:275-307`).
13. LLM health-cache gate; unavailable -> `default_decision` fallback (`pre_tool_use.rs:310-352`).
14. **L1** `evaluate_with_llm` (`pre_tool_use.rs:356-366`).
15. `Ask("LLM unavailable")` (generation failure) -> `default_decision` fallback (`pre_tool_use.rs:371-395`).
16. Map L1 decision -> output + cache write (`pre_tool_use.rs:400-498`).

Every terminal branch writes an audit row (`crates/clx-hook/src/audit.rs:9`)
and emits exactly one `PreToolUse` JSON decision
(`crates/clx-hook/src/output.rs:10-35`). Learned-rule promotion is driven from
the **PostToolUse** path, not here
(`crates/clx-hook/src/hooks/post_tool_use.rs:113-119`,
`crates/clx-hook/src/learning.rs:131`).

L1 (LLM) **never hard-denies**. Only the L0 blacklist can `deny`. L1 maps
risk 1-3 -> allow, 4-10 -> ask
(`crates/clx-core/src/policy/llm.rs:551-564`).

---

## 2. Feature Inventory

Config struct: `ValidatorConfig`, `crates/clx-core/src/config/mod.rs:577-629`.
Defaults applied at `config/mod.rs:937-948`. Default fns at `config/mod.rs:779-801`.
Env override parsing at `config/mod.rs:1240-1320`.

| Capability | Config key | Env var | Default | Defining file:line |
|---|---|---|---|---|
| Master enable/bypass | `validator.enabled` | `CLX_VALIDATOR_ENABLED` | `true` | `config/mod.rs:580-581`, `:779`; bypass `pre_tool_use.rs:66-69` |
| L0 deterministic enable | `validator.layer0_enabled` | `CLX_VALIDATOR_LAYER0_ENABLED` | `true` | `config/mod.rs:583-589`; gate around the L0 evaluate in `pre_tool_use.rs`. Disabling skips `PolicyEngine::evaluate` and treats the L0 verdict as `Ask` (falls through to L1, or the forced-`ask` posture if L1 is also off). Security-weakening override: WARN + audit-chain fingerprint emitted at hook start. |
| L1 LLM enable | `validator.layer1_enabled` | `CLX_VALIDATOR_LAYER1_ENABLED` | `true` | `config/mod.rs:591-593`; gate `pre_tool_use.rs:254-272` |
| L1 timeout (ms) | `validator.layer1_timeout_ms` | `CLX_VALIDATOR_LAYER1_TIMEOUT_MS` | `30000` | `config/mod.rs:588-589`, `:783-785` |
| Inconclusive fallback | `validator.default_decision` | `CLX_VALIDATOR_DEFAULT_DECISION` | `DefaultDecision::default()` | `config/mod.rs:592-593`; use `pre_tool_use.rs:286,332,375` |
| Trust mode (auto-allow all) | `validator.trust_mode` | none (config-file only) | `false` | `config/mod.rs:598-599`, `:941`; logic `pre_tool_use.rs:72-147`; env explicitly unsupported `config/mod.rs:1266` |
| Auto-allow read-only | `validator.auto_allow_reads` | `CLX_VALIDATOR_AUTO_ALLOW_READS` | `true` | `config/mod.rs:603-604`; use `pre_tool_use.rs:154` |
| SQLite decision cache | `validator.cache_enabled` | `CLX_VALIDATOR_CACHE_ENABLED` | `true` | `config/mod.rs:607-608`; use `pre_tool_use.rs:223` |
| Allow-decision TTL (s) | `validator.cache_allow_ttl_secs` | `CLX_VALIDATOR_CACHE_ALLOW_TTL` | `3600` | `config/mod.rs:611-612`, `:787-789` |
| Ask-decision TTL (s) | `validator.cache_ask_ttl_secs` | `CLX_VALIDATOR_CACHE_ASK_TTL` | `900` | `config/mod.rs:615-616`, `:791-793` |
| Prompt sensitivity | `validator.prompt_sensitivity` | `CLX_VALIDATOR_PROMPT_SENSITIVITY` | `Standard` | `config/mod.rs:619-620`, `:946`; map `policy/llm.rs:462-468` |
| Trust-mode max duration (s) | `validator.trust_mode_max_duration` | `CLX_VALIDATOR_TRUST_MODE_MAX_DURATION` | `86400` | `config/mod.rs:623-624`, `:795-797` |
| Trust-mode default duration (s) | `validator.trust_mode_default_duration` | `CLX_VALIDATOR_TRUST_MODE_DEFAULT_DURATION` | `3600` | `config/mod.rs:627-628`, `:799-801` |
| Learned-rule master enable | `user_learning.enabled` | `CLX_USER_LEARNING_ENABLED` | `true` | `config/mod.rs:687-688` |
| Auto-whitelist threshold | `user_learning.auto_whitelist_threshold` | `CLX_USER_LEARNING_AUTO_WHITELIST_THRESHOLD` | `3` | `config/mod.rs:691-692`, `:837-839` |
| Auto-blacklist threshold | `user_learning.auto_blacklist_threshold` | `CLX_USER_LEARNING_AUTO_BLACKLIST_THRESHOLD` | `2` | `config/mod.rs:695-696`, `:841-843` |
| MCP command extraction | `mcp_tools.enabled`, `mcp_tools.command_tools`, `mcp_tools.default_decision` | `CLX_MCP_TOOLS_ENABLED`, `CLX_MCP_TOOLS_DEFAULT_DECISION` | enabled `true` | route `pre_tool_use.rs:37-48`; `policy/mcp.rs:30-46` |
| Config-trust (file-hash) | `~/.clx/trusted_configs.json` | none | empty list | `crates/clx-core/src/config/trust.rs:1-251` |

Notes:

- `DefaultDecision` derives `Default`; the inconclusive fallback default is
  whatever `#[derive(Default)]` selects on the enum
  (`config/mod.rs:592` uses `#[serde(default)]`, no explicit fn). QA should
  read `clx config show` or the enum definition to confirm the live default
  rather than assume `ask`. See RISKS R1.
- `RateLimiter::new(30)` caps L1 calls (`policy/mod.rs:80,93`).

---

## 3. Behavior Spec Per Capability

Format: **Given** config / **When** command / **Then** decision + audit + cache.

### 3.1 `validator.enabled`

- **Given** `validator.enabled = true` (default). **When** any non-empty Bash
  command. **Then** full pipeline runs (L0 -> cache -> L1).
- **Given** `validator.enabled = false`. **When** any command. **Then**
  immediate `allow`, no audit row, no cache, no L0/L1
  (`pre_tool_use.rs:66-69`). The hook still emits the allow JSON with
  `RULES_REMINDER` additionalContext.
  - Edge: empty command short-circuits to `allow` at `pre_tool_use.rs:55-58`
    BEFORE the `enabled` check, also without an audit row.
  - Edge: non-Bash non-MCP tools (Read/Write/Edit) auto-allow at
    `pre_tool_use.rs:49-53` with no audit, regardless of `enabled`.

### 3.2 L0 Deterministic Rules

Engine: `crates/clx-core/src/policy/mod.rs:132-163`. Order: blacklist first
(deny wins), then whitelist (allow), else `Ask`. Built-in rules:
`crates/clx-core/src/policy/rules.rs:19-197` (48 whitelist patterns,
~50 blacklist patterns; counts are data-driven, verify with the unit test).

- **Hard-blocked (deny)**: matches a blacklist pattern, e.g.
  `rm -rf /*`, `rm -rf ~/*`, `chmod 777 *`, `curl ...| bash`,
  `wget ...| sh`, `sudo rm*`, `dd if=/dev/zero*`, fork bombs,
  `nc -e*`, `docker run --privileged*`, `pip install --index-url*`,
  backtick substitution `` Bash(*`*) ``, `eval *`, `exec *`,
  `source *`, `python*-c*import*os*` (`rules.rs:90-185`).
  Decision `Deny{reason}` -> audit layer `L0`, decision `blocked`,
  reasoning = rule description (`pre_tool_use.rs:186-199`).
- **Hard-allowed (allow)**: matches a whitelist pattern, e.g.
  `ls:*`, `cat:*`, `git:status*`, `git:log*`, `npm:test*`,
  `cargo:build*`, `pytest:*`, `whoami`, `env` (`rules.rs:21-81`).
  -> audit `L0`/`allowed`, output allow (`pre_tool_use.rs:172-185`).
- **Escalated (ask)**: no blacklist and no whitelist match
  (`policy/mod.rs:160-162`). If `is_read_only` true -> auto-allow as
  `L0-READ`/`allowed`, reasoning "Read-only command auto-allowed"
  (`pre_tool_use.rs:200-216`). Else fall to cache/L1.
- Blacklist precedence over whitelist is proven by
  `test_engine_blacklist_priority` (`policy/tests.rs:169`).
- Learned rules are merged into the same whitelist/blacklist vectors before
  L0 evaluation (`pre_tool_use.rs:160-164`, `policy/rules.rs:244-269`).
  A learned `Deny` rule therefore hard-blocks at L0; a learned `Allow`
  rule hard-allows. Learned rules carry no special precedence: built-in and
  learned rules are checked in insertion order, blacklist before whitelist
  (`policy/mod.rs:133-157`). Built-ins are loaded first
  (`policy/mod.rs:82`), learned rules appended after
  (`pre_tool_use.rs:160-164`).

### 3.3 L1 LLM Validation

Invoked only when L0 returns Ask, command is not read-only, and the cache
missed (`pre_tool_use.rs:217-366`). Implementation
`crates/clx-core/src/policy/llm.rs:74-176`.

- **Given** `layer1_enabled = false`. **When** L0 Ask. **Then** audit layer
  `L0`, decision `prompted`, reasoning `"L1-DISABLED (with v0.9.0
  dual-emit alias 'L1 disabled' retained for one minor version)"`;
  output `ask` with reason "Command requires review" (`pre_tool_use.rs:254-272`). Note the
  ask is NOT cached in this branch.
- **Given** LLM client construction fails. **Then** `default_decision`
  fallback; audit layer `L1`, decision mapped from `default_decision`
  (Allow->allowed, Deny->blocked, Ask->prompted), reasoning
  "Ollama client error: ... default_decision: ..." (`pre_tool_use.rs:281-307`).
- **Given** LLM provider unavailable (health cache Unavailable, or
  `is_available()` false). **Then** same `default_decision` fallback, audit
  `L1`, reasoning "Ollama unavailable ..." (`pre_tool_use.rs:310-352`).
  Health is read from a file cache first to avoid a network probe per hook
  (`pre_tool_use.rs:310-325`).
- **Given** the generation call itself fails (returns
  `Ask{reason == "LLM unavailable"}` from `evaluate_with_llm`).
  **Then** health cache set false, `default_decision` fallback, audit `L1`,
  reasoning "LLM generation failed ..." (`pre_tool_use.rs:371-395`,
  source of the sentinel `policy/llm.rs:161-166`).
- **Given** a parsed LLM response. **Then** risk mapping
  (`policy/llm.rs:551-564`):
  - 1-3 -> `Allow` -> audit `L1`/`allowed` risk_score 1; cache `allow`
    with `cache_allow_ttl_secs` (`pre_tool_use.rs:400-426`).
  - 4-10 -> `Ask{[category] reasoning}`. If read-only ->
    `L1-READ`/`allowed` risk 5, cached as `allow`/`cache_allow_ttl_secs`
    (`pre_tool_use.rs:441-470`); else `L1`/`prompted` risk 5, cached as
    `ask`/`cache_ask_ttl_secs` (`pre_tool_use.rs:471-496`).
  - The `Deny` arm at `pre_tool_use.rs:427-439` exists but L1 never
    produces `Deny` (`policy/llm.rs:558-563`); dead in practice. See R2.
- **Prompt-injection defenses in L1**:
  - Command and working_dir JSON-escaped before template substitution
    (`policy/llm.rs:104-118`).
  - LLM reasoning scanned for injection markers; if suspicious -> `Ask`
    "Suspicious LLM response detected" (`policy/llm.rs:131-136`,
    `is_suspicious_llm_response` `:495-528`).
  - Response parse failure -> `Ask` "LLM response parsing failed"
    (`policy/llm.rs:150-158`). This is distinct from the "LLM unavailable"
    sentinel and does NOT trigger the `default_decision` fallback; it surfaces
    as a plain ask. See R3.
  - Rate limit exceeded (30 calls/window) -> `Ask` "Rate limit exceeded"
    (`policy/llm.rs:84-90`).
- **Timeout**: `layer1_timeout_ms` (default 30000) is the LLM client request
  timeout, not enforced by a wrapper in `handle_pre_tool_use`. On timeout the
  generate call returns Err, surfacing as the "LLM unavailable" sentinel ->
  `default_decision` fallback. See R4.

### 3.4 `default_decision`

Applied ONLY on L1 inconclusive paths: client error, provider unavailable,
generation failure (`pre_tool_use.rs:286,332,375`). Mapping to audit decision
at `pre_tool_use.rs:293-297, 339-343, 382-386`. It does NOT apply when
`layer1_enabled = false` (that path hardcodes `ask`,
`pre_tool_use.rs:265-271`) nor on parse-failure / suspicious-response asks.

### 3.5 `auto_allow_reads`

`is_read_only = config.validator.auto_allow_reads && is_read_only_command(cmd)`
(`pre_tool_use.rs:154`). Read-only detection:
`crates/clx-core/src/policy/read_only.rs:15-209`.

- Read-only first-words include `cat ls head tail grep rg find` (without
  `-exec/-delete`), `git status|log|diff|show|branch|...`, version checks
  (`node --version`), `echo`/`printf` without `>` (`read_only.rs:106-208`).
- NEVER read-only: contains backtick, `$(` command substitution,
  `<(`/`>(` process substitution; composite commands only read-only if
  ALL parts are (`read_only.rs:23-67`).
- Effect: a read-only command that L0 escalates is auto-allowed at L0
  (`L0-READ`), and even an L1 `ask` for a read-only command is auto-allowed
  (`L1-READ`) and cached as allow (`pre_tool_use.rs:200-216, 441-470`).

### 3.6 Decision Cache

Storage: `crates/clx-core/src/storage/validation_cache.rs`. Key:
`format!("{working_dir}:{command}")` (`policy/cache.rs:156-158`), full
string (no hashing, no collisions).

- **Lookup** before L1 only, gated by `cache_enabled`
  (`pre_tool_use.rs:223-251`). SQL filters `expires_at > datetime('now')`
  (`validation_cache.rs:26-30`), so expired rows are a miss.
- **Hit** -> audit `L1-CACHE` with mapped decision and stored risk/reason,
  output cached decision (`pre_tool_use.rs:231-249`).
- **Write**: allow -> `cache_allow_ttl_secs` (3600); ask ->
  `cache_ask_ttl_secs` (900); read-only auto-allow -> allow TTL
  (`pre_tool_use.rs:414-425, 459-470, 483-494`). `INSERT OR REPLACE`
  upserts (`validation_cache.rs:53-66`).
- **Deny is never cached by the pre-hook**: no L1 deny path writes cache
  (storage can store deny but the caller never calls it for deny;
  `validation_cache.rs:206-223` documents this).
- **Invalidation**: TTL expiry only; probabilistic cleanup ~5% of hook
  invocations (`pre_tool_use.rs:226-229, 503-508`,
  `validation_cache.rs:77-86`). No content-change invalidation; identical
  command+cwd reuses the cached verdict until TTL.
- The in-memory `ValidationCache` (`policy/cache.rs`) is intentionally
  passed `None` from the hook (`pre_tool_use.rs:363`) because hook
  processes are short-lived; only SQLite caching is cross-process.

### 3.7 Learned Rules (auto-whitelist / blacklist)

Accumulation happens in **PostToolUse**, not pre
(`post_tool_use.rs:113-119` -> `learning.rs:131`).

- A command that was executed (tool_response present) calls
  `track_user_decision(..., approved=true)` (`post_tool_use.rs:114-118`).
  There is no explicit denial signal wired here, so `denial_count`
  growth via this path is limited. See R5.
- Pattern generalization: `extract_command_pattern`
  (`learning.rs:228-260`) e.g. `cargo build` -> `Bash(cargo:build*)`.
- **Auto-whitelist**: when `confirmation_count >= auto_whitelist_threshold`
  (default 3) the rule becomes `RuleType::Allow`, UNLESS the base command
  is in `NEVER_AUTO_WHITELIST` (`rm dd chmod kill mount systemctl ...`,
  `learning.rs:13-35`) or the pattern is structurally dangerous
  (`is_pattern_too_broad`: pipes, `&&`, redirection, `$()`, backticks,
  shell-exec words, `learning.rs:68-128`) (`learning.rs:152-168`).
- **Auto-blacklist**: when `denial_count >= auto_blacklist_threshold`
  (default 2) the rule becomes `RuleType::Deny`, UNLESS the command is in
  `NEVER_AUTO_BLACKLIST` (`cargo npm git python cat ls ...`,
  `learning.rs:46-50`) or the deny-rule cap (50,
  `MAX_AUTO_BLACKLIST_ENTRIES`) is reached (`learning.rs:170-200`).
- Storage upserts via `ON CONFLICT(pattern) DO UPDATE`
  (`storage/rules.rs:16-46`), so no duplicate rules
  (proven `learning.rs:390-414`).
- **Precedence vs L0/L1**: a promoted learned rule is loaded into the L0
  engine on the next invocation (`pre_tool_use.rs:160-164`) and is
  evaluated identically to built-in rules. A learned `Deny` short-circuits
  at L0 before cache and L1; a learned `Allow` short-circuits at L0 before
  L1. Project scoping: rules with NULL project_path are global, others
  match the cwd (`storage/rules.rs:67-84`).

### 3.8 Prompt Sensitivity

`sensitivity_to_prompt` (`policy/llm.rs:462-468`): High -> `PROMPT_HIGH`,
Standard|Custom -> `PROMPT_STANDARD`, Low -> `PROMPT_LOW`.

- Resolution is 3-tier (`policy/llm.rs:386-423`):
  1. `<cwd>/.clx/prompts/validator.txt`
  2. `~/.clx/prompts/validator.txt`
  3. built-in preset by sensitivity.
- Custom is NOT a separate file by itself; it falls back to STANDARD's
  built-in text unless a file override exists (`policy/llm.rs:465`).
  See R6.
- High preset is stricter ("STRICT", "When in doubt, score higher",
  interactive ssh = caution 5 vs 4 in built-in)
  (`policy/prompts/validator-high.txt`). Low preset is more permissive
  ("Trust standard dev tools").
- File-based prompts must pass `validate_prompt_template`
  (`policy/llm.rs:241-384`): <=50KB, must contain `{{command}}` and
  `{{working_dir}}` and "json", and must NOT contain bypass patterns
  ("ignore previous", "always allow", "never deny", hardcoded
  `"risk_score": 0`, etc.) with Unicode homoglyph normalization
  (`policy/llm.rs:187-227`). Unsafe (world-writable) or invalid files are
  skipped and the next tier is used (`policy/llm.rs:427-459`).

### 3.9 Trust Mode (PR #15 auto-allow)

`validator.trust_mode` is a config-file-only flag (env explicitly
unsupported, `config/mod.rs:1266`). When true, the hook reads
`~/.clx/.trust_mode_token` (`pre_tool_use.rs:72-147`):

- JSON `TrustToken` valid if `expires_at` in the future AND
  (token has no session_id OR session_id == input session)
  (`pre_tool_use.rs:77-95`). Valid -> audit layer `TRUST`,
  decision `allowed`, reasoning "Trust mode (Ns remaining)", output allow
  (`pre_tool_use.rs:100-110`). Commands are still audited.
- Legacy plain-text token: valid if file mtime < 3600s
  (`pre_tool_use.rs:114-121, 126-142`).
- Expired/invalid token -> warn, delete token file, fall through to normal
  validation (`pre_tool_use.rs:144-146`).
- Token created by `clx trust on [--duration] [--session]`
  (`crates/clx/src/commands/trust.rs:128-169`); duration clamped to
  `[300, trust_mode_max_duration]`, default `trust_mode_default_duration`.

### 3.10 Config-Trust (file-hash) Interaction

`crates/clx-core/src/config/trust.rs`. This is independent of command
validation: it gates whether non-inert keys in a per-project
`.clx/config.yaml` are honored. Trust is keyed by `sha256(file_contents)`
(`trust.rs:248-251`), stored in `~/.clx/trusted_configs.json` mode 0600,
per-machine, never propagated by git (`trust.rs:6-21`). Any byte edit
invalidates trust; load falls back to inert-key filtering
(`trust.rs:13-16`). Malformed/old-version trustlist fails loud
(`trust.rs:105-128`). Relevance to validation: an untrusted project config
cannot weaken `validator.*` because non-inert keys are filtered before they
reach `ValidatorConfig`. The PR-15 trust token and config-trust are
explicitly separate concerns (`trust.rs:19-21`).

### 3.11 Audit Log

Pre-hook writes via `log_audit_entry`
(`crates/clx-hook/src/audit.rs:9-38`). Per decision the row contains:
`session_id`, `timestamp` (rfc3339), `command` (REDACTED), `working_dir`,
`layer` (`L0`/`L0-READ`/`L1`/`L1-CACHE`/`L1-READ`/`TRUST`/`PostToolUse`),
`decision` (`allowed`/`blocked`/`prompted`,
`crates/clx-core/src/types.rs:575-588`), `risk_score`, `reasoning`,
`user_decision` (null from pre-hook). FK guard: `create_audit_log` does
`INSERT OR IGNORE` into `sessions` so synthetic session IDs do not trip the
`audit_log -> sessions` FK (`crates/clx-core/src/storage/audit.rs:19-45`).

**Redaction guarantee**: the command string is passed through
`redact_secrets` before persistence in BOTH paths — pre-hook
(`audit.rs:22-23`) and post-hook (`post_tool_use.rs:126-138`). Redaction
covers key prefixes `sk- pk- ghp_ gho_ xoxb- xoxp-` and
`key=/token=/password=/secret=` style assignments
(`crates/clx-core/src/redaction.rs:20-70`). Guarantee: a raw secret
matching a known pattern is never written verbatim to `audit_log.command`.
Secrets that do not match a known pattern are NOT guaranteed redacted
(prefix/keyword heuristic, no regex). See R7.

---

## 4. Edge / Failure Matrix

| Scenario | Expected behavior | Cite |
|---|---|---|
| Empty command string | `allow`, no audit, no cache (before `enabled` check) | `pre_tool_use.rs:55-58` |
| Non-Bash non-MCP tool (Read/Write) | `allow`, no audit | `pre_tool_use.rs:49-53` |
| MCP tool, not in command_tools registry | output `mcp_tools.default_decision`, no audit | `pre_tool_use.rs:42-47` |
| MCP command tool, command field missing | extracted as `""` -> empty -> `allow` | `policy/mcp.rs:37-42`, `pre_tool_use.rs:55-58` |
| MCP, `mcp_tools.enabled=false` | falls to non-MCP branch -> `allow` | `pre_tool_use.rs:37,49-53` |
| Very long command | no length cap in hook; passed to L0 glob (ReDoS-safe matcher, `policy/tests.rs:113`) then JSON-escaped for L1 | `policy/llm.rs:104-118` |
| Secrets in command | redacted before audit write (both paths) | `audit.rs:22-23`, `post_tool_use.rs:126-138` |
| L1 provider down | `default_decision` fallback, audit `L1` | `pre_tool_use.rs:327-352` |
| L1 generation failure | `default_decision` fallback, health set false | `pre_tool_use.rs:371-395` |
| L1 parse failure | plain `ask` "LLM response parsing failed" (NOT default_decision) | `policy/llm.rs:150-158`; R3 |
| L1 suspicious response | `ask` "Suspicious LLM response detected" | `policy/llm.rs:131-136` |
| Cache corrupt / open fails | `Storage::open_default()` err -> cache skipped, proceeds to L1 | `pre_tool_use.rs:225` |
| Audit DB open fails | `log_audit_entry` returns early, decision still emitted | `audit.rs:18-20` |
| Config missing | `Config::load().unwrap_or_default()` -> documented defaults | `pre_tool_use.rs:24` |
| Config malformed | same `unwrap_or_default()` swallow; no user error in hook | `pre_tool_use.rs:24`; R8 |
| Concurrent hook processes | each opens its own SQLite conn; `INSERT OR REPLACE` cache + FK-guarded audit are idempotent; no in-proc shared state | `validation_cache.rs:53-66`, `storage/audit.rs:19-45` |
| Trust token expired | warn, delete token, fall through to validation | `pre_tool_use.rs:144-146` |
| Trust token session mismatch | treated invalid -> fall through | `pre_tool_use.rs:83-95,112-113` |

---

## 5. Verification Steps

Prereqs: built `clx-hook` binary wired as the Claude Code hook, an `~/.clx`
dir, optional running Ollama. Inspect results three ways:
(a) `clx dashboard` Audit tab, (b) raw SQL on the audit DB
(`sqlite3 ~/.clx/clx.db "SELECT timestamp,layer,decision,risk_score,command FROM audit_log ORDER BY timestamp DESC LIMIT 20;"`),
(c) hook logs (`~/.clx/clx.log`, level via `CLX_LOGGING_LEVEL=debug`).

### 5.1 Master bypass

```yaml
# ~/.clx/config.yaml
validator:
  enabled: false
```
Action: in Claude Code run `rm -rf /tmp/whatever`. Expected: command allowed,
NO new `audit_log` row, no cache entry. Re-enable
(`enabled: true`) and repeat -> a `blocked` `L0` row appears.

### 5.2 L0 hard block

Config default. Action: run `rm -rf /`. Expected: decision `deny`, dashboard
Audit shows layer `L0`, decision `blocked`, reasoning "Recursive deletion
from root". SQL: `SELECT layer,decision FROM audit_log WHERE command LIKE 'rm -rf /%'`.

### 5.3 L0 hard allow + read-only

Action: run `git status`. Expected: `allow`, layer `L0`, decision `allowed`.
Action: run `cat /etc/hosts` (unknown to whitelist? it is `cat:*` whitelisted)
-> `L0` allowed. Action: run an unknown read-only like
`tldr tar` -> layer `L0-READ`, decision `allowed`, reasoning
"Read-only command auto-allowed".

### 5.4 L1 disabled

```yaml
validator: { layer1_enabled: false }
```
Action: run an unknown non-read-only command e.g. `mycustomtool --apply`.
Expected: `ask` "Command requires review", audit layer `L0`,
decision `prompted`, reasoning `"L1-DISABLED (with v0.9.0 dual-emit
alias 'L1 disabled' retained for one minor version)"`. Confirm NO cache
row written.

### 5.5 L1 provider down -> default_decision

Stop Ollama. Set:
```yaml
validator: { layer1_enabled: true, default_decision: deny }
```
Action: run unknown command `frobnicate --x`. Expected: decision `deny`,
audit layer `L1`, reasoning contains "Ollama unavailable" or
"LLM unavailable". Repeat with `default_decision: allow` -> `allow`.

### 5.6 Decision cache

Start Ollama. Action: run a novel ambiguous command twice (e.g.
`somebin --do-thing`). First run: audit layer `L1`. Second run within TTL:
audit layer `L1-CACHE`, same decision. SQL:
`SELECT cache_key,decision,expires_at FROM validation_cache;` shows the row.
Set `cache_ask_ttl_secs: 5`, wait 6s, rerun -> `L1` again (miss).

### 5.7 Trust mode

```yaml
validator: { trust_mode: true }
```
Run `clx trust on --duration 10m`. Action: run `rm -rf /tmp/x`
(would normally L0-deny). Expected: `allow`, audit layer `TRUST`, decision
`allowed`, reasoning "Trust mode (...s remaining)". Run `clx trust off`
or wait for expiry -> normal L0 deny resumes (token deleted,
`pre_tool_use.rs:144-146`).

### 5.8 Config-trust

In a project create `.clx/config.yaml` with a non-inert key. Without trust,
load uses inert filter. `clx config-trust add .clx/config.yaml`, verify
`~/.clx/trusted_configs.json` exists mode 0600. Edit one byte of the file ->
trust auto-invalidated on next load (`trust.rs:13-16`). Confirm validator
config is unaffected by an untrusted project file.

### 5.9 Learned auto-whitelist

```yaml
user_learning: { enabled: true, auto_whitelist_threshold: 3 }
```
Action: run `somebuildtool ci` 3 times, confirming each. After the 3rd,
`sqlite3 ~/.clx/clx.db "SELECT pattern,rule_type,confirmation_count FROM learned_rules;"`
shows `Bash(somebuildtool:ci*)` `rule_type=allow` `confirmation_count>=3`.
Next run is allowed at L0 without prompt. Verify `rm` style commands are NOT
promoted (NEVER_AUTO_WHITELIST).

### 5.10 Automated tests

```
cargo test -p clx-core --lib policy          # L0 engine, glob, blacklist priority
cargo test -p clx-core --lib policy::llm     # sensitivity, prompt loading, validation
cargo test -p clx-core --lib validation_cache
cargo test -p clx-core --lib audit
cargo test -p clx-core config::trust         # file-hash trustlist
cargo test -p clx-hook learning              # T15-1..T15-5 thresholds
cargo test -p clx-hook router                # PreToolUse dispatch
cargo test -p clx-core --lib policy::mcp     # MCP command extraction
```
Key named tests: `test_engine_blacklist_priority` (`policy/tests.rs:169`),
`test_below_whitelist_threshold_no_rule_upgrade` (`learning.rs:273`),
`test_auto_whitelist_at_threshold` (`learning.rs:300`),
`test_auto_blacklist_at_threshold` (`learning.rs:328`),
`test_cache_expired_returns_none` (`validation_cache.rs:138`),
`compute_file_hash_changes_on_edit` (`config/trust.rs:272`),
`test_missing_command_field_returns_empty` (`policy/mcp.rs:142`).

---

## 6. Known Limitations / Out of Scope for 0.8.0

- L1 never hard-denies; a "dangerous" LLM verdict only asks
  (`policy/llm.rs:558-563`). Hard blocks require an L0 blacklist or learned
  deny rule.
- No content-aware cache invalidation; verdicts persist until TTL even if
  rules change (`pre_tool_use.rs:223-251`).
- `layer1_timeout_ms` is the client request timeout, not a wrapper-enforced
  deadline in the hook.
- Redaction is heuristic (prefix/keyword), not exhaustive; novel secret
  formats may pass through (`redaction.rs:20-70`).
- Denial signal for learned auto-blacklist is not wired from the
  PostToolUse path (only approvals are tracked there); auto-blacklist
  primarily exercised via tests/other callers.

---

## RISKS / SUSPECTED GAPS

- **R1** `default_decision` has no explicit default fn; relies on
  `DefaultDecision`'s derived `Default`. QA must confirm the live value via
  `clx config show`; spec/docs should not assume `ask`
  (`config/mod.rs:592-593`).
- **R2** Dead `Deny` arm for L1 at `pre_tool_use.rs:427-439`:
  `risk_score_to_decision` never returns `Deny` (`policy/llm.rs:558-563`),
  so this branch and its `deny` audit/cache code are unreachable. Either
  intended documentation gap or a sign L1 hard-deny was removed without
  cleanup.
- **R3** L1 parse-failure and suspicious-response produce a plain `ask`
  ("LLM response parsing failed" / "Suspicious LLM response detected") that
  is NOT routed through `default_decision` (`policy/llm.rs:131-158`). A site
  configured `default_decision: deny` will still only `ask` on a malformed
  LLM reply — a weaker-than-expected fallback. Flag for product decision.
- **R4** No explicit timeout wrapper around `evaluate_with_llm` in
  `handle_pre_tool_use`; a hung provider relies entirely on the LLM client's
  internal timeout. If that timeout is large, the hook (and Claude Code)
  blocks. Verify `layer1_timeout_ms` actually reaches the client
  (`pre_tool_use.rs:356-366`).
- **R5** Learned-rule denial accumulation: `track_user_decision` is only
  called with `approved=true` from PostToolUse when a command executed
  (`post_tool_use.rs:114-118`). There is no pre/post wiring that increments
  `denial_count` on a user rejection, so the documented auto-blacklist
  threshold is not reachable through normal hook flow. Confirm whether
  another caller feeds denials.
- **R6** `PromptSensitivity::Custom` silently maps to STANDARD built-in
  text unless a file override exists (`policy/llm.rs:465`). Users selecting
  "custom" without providing `.clx/prompts/validator.txt` get standard
  behavior with no warning.
- **R7** Redaction is pattern-limited; secrets without a known prefix or
  `key=` shape are stored verbatim in `audit_log.command`
  (`redaction.rs:20-70`). The "redaction guarantee" is conditional.
- **R8** Malformed `~/.clx/config.yaml` is swallowed by
  `unwrap_or_default()` in the hook (`pre_tool_use.rs:24`), silently
  reverting to defaults (including potentially weaker validation) with no
  user-visible error in the PreToolUse path.
- **R9** Trust-mode legacy plain-text token accepts any file with mtime
  < 3600s regardless of content (`pre_tool_use.rs:114-121`); a stale or
  attacker-touched legacy token grants blanket auto-allow for up to an hour.
  Verify whether legacy tokens can still be created in 0.8.0.
