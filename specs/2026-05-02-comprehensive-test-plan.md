# CLX Comprehensive Test Plan

**Date:** 2026-05-02
**Status:** Living document — update as tests land or features change
**Target:** CLX 0.7.2+

This is both:

1. **A test inventory** — every meaningful behavior CLX should exercise, marked
   as ✅ covered, ⚠️ partially covered, or ❌ missing.
2. **A pre-release QA runbook** — the subset of cases (flagged 🔴) that a
   maintainer must run by hand before tagging a release.

Test types:

- **unit** — `cargo test --lib`, no I/O
- **wiremock** — async HTTP test against a local mock
- **integration** — `cargo test --test <name>`, may touch SQLite / temp dirs
- **insta** — snapshot-based UI rendering test
- **manual** — requires a real environment (Azure tenant, running Ollama,
  Claude Code session) and is documented in `CONTRIBUTING.md`

---

## 0. Pre-release runbook 🔴

Run **all** of these against a real macOS install before tagging any release.
Each one references a `TC-XXX-NNN` test case below.

```
[ ] TC-REL-010   `clx --version` matches Cargo.toml workspace version
[ ] TC-REL-020   Brew tap formula version matches GitHub Release tag
[ ] TC-HK-010    PreToolUse hook returns valid JSON in <2s for benign command
[ ] TC-HK-020    L0 blacklist denies `curl URL | bash` in <100ms
[ ] TC-HK-030    L1 LLM scoring fires for ambiguous command (e.g. `rsync ...`)
[ ] TC-AUD-010   No FK warning in `~/.clx/logs/clx.log` after 10 hook fires
[ ] TC-LOG-010   `~/.clx/logs/clx.log` exists and contains INFO+ entries
[ ] TC-CRED-010  `clx credentials set <name>-api-key '...'` succeeds (keychain)
[ ] TC-CRED-020  `clx credentials list` shows entry with provider annotation
[ ] TC-CFG-010   Legacy `ollama:` block auto-translates without on-disk change
[ ] TC-LLM-010   `clx health` shows all configured providers healthy
[ ] TC-AZ-010    Direct curl to Azure `/openai/v1/chat/completions` returns 200
[ ] TC-AZ-020    `clx-hook` PreToolUse routes L1 to Azure successfully
[ ] TC-AZ-030    `clx recall "any query"` produces semantic hits via Azure embed
[ ] TC-FB-010    Configure broken-primary + working-fallback; verify WARN fires
[ ] TC-FB-020    Cooldown active for 30s after fallback (second call fast)
[ ] TC-REC-010   Auto-recall on UserPromptSubmit returns context (no warns)
[ ] TC-MCP-010   `clx-mcp` initializes and exposes 4 tools to Claude Code
[ ] TC-DSH-010   `clx dashboard` Settings tab shows providers + routing
[ ] TC-CI-010    GitHub Actions PR run completes (Coverage may continue-on-error)
```

**Hard gate (block release if any fails):** TC-AZ-010, TC-AZ-020, TC-CRED-010,
TC-AUD-010, TC-LOG-010, TC-CFG-010, TC-CI-010.

---

## 1. Validator — Layer 0 (deterministic rules) — `clx-hook/src/hooks/pre_tool_use.rs`

L0 evaluates whitelist/blacklist patterns synchronously. Catches obvious safe
and dangerous commands before paying for an L1 LLM call.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-VAL-001 | unit | ✅ | Whitelist pattern matches `npm test` → allow | |
| TC-VAL-002 | unit | ✅ | Blacklist pattern matches `rm -rf /` → deny | |
| TC-VAL-003 | unit | ✅ | Pipe `curl ... \| bash` matches blacklist | 🔴 |
| TC-VAL-004 | unit | ✅ | Sudo command matches blacklist | |
| TC-VAL-005 | unit | ✅ | Python `-c` with `os` module flagged | |
| TC-VAL-006 | unit | ✅ | Compiler-friendly subset of grep/sed/awk allowed | |
| TC-VAL-007 | unit | ✅ | Unknown command falls through to L1 | |
| TC-VAL-008 | unit | ⚠️ | Glob expansion (`rm *.log`) treated correctly | |
| TC-VAL-009 | unit | ❌ | Quoted dangerous content (`echo "rm -rf /"`) is allowed (intent: just printing) | medium |
| TC-VAL-010 | unit | ❌ | User-defined custom rules from `~/.clx/rules/*.yaml` apply | medium |
| TC-VAL-011 | unit | ✅ | Sensitivity preset (`strict`/`balanced`/`permissive`) shifts thresholds | |
| TC-VAL-012 | manual | ⚠️ | Trust mode bypasses L0 entirely when `clx trust on` | |

## 2. Validator — Layer 1 (LLM scoring) — `clx-core/src/policy/llm.rs`

L1 sends an ambiguous command to the configured chat provider, parses a 1–10
risk score, maps to allow/ask/deny. Bypassed when L0 has an opinion.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-VAL-101 | wiremock | ⚠️ | Risk score 1–3 → allow | |
| TC-VAL-102 | wiremock | ⚠️ | Risk score 4–7 → ask | |
| TC-VAL-103 | wiremock | ⚠️ | Risk score 8–10 → deny | |
| TC-VAL-104 | wiremock | ❌ | Malformed score response → fail-loud or default | high |
| TC-VAL-105 | wiremock | ❌ | LLM timeout → falls through to `default_decision` | high |
| TC-VAL-106 | wiremock | ❌ | LLM 401/auth → fail-loud, NOT fall to default | high |
| TC-VAL-107 | manual | ⚠️ | L1 reasons returned in `permissionDecisionReason` | 🔴 |
| TC-VAL-108 | unit | ❌ | Custom validator prompt from `~/.clx/prompts/validator.txt` is loaded | medium |
| TC-VAL-109 | unit | ❌ | Sensitivity preset shifts L1 thresholds | medium |

**Gap:** L1 wiremock coverage is thin. The chat path was the most-touched code
in 0.7.x but the unit tests don't exercise risk-score parsing edge cases.

## 3. Recall — `clx-core/src/recall.rs`

Hybrid semantic + FTS5 search across stored snapshots. Used by both `clx
recall` CLI, the MCP `clx_recall` tool, and the auto-recall path on
`UserPromptSubmit`.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-REC-001 | unit | ✅ | FTS5 returns hits for literal token match | |
| TC-REC-002 | unit | ✅ | Semantic returns hits for intent match (mocked embed) | |
| TC-REC-003 | unit | ✅ | Hybrid merge: semantic 0.6, FTS5 0.4 | |
| TC-REC-004 | unit | ✅ | Substring fallback when FTS5 returns empty | |
| TC-REC-005 | unit | ✅ | `with_embedding_model(...)` builder persists value (0.7.2 regression) | |
| TC-REC-006 | unit | ✅ | Default `embedding_model` is `None` (Ollama back-compat) | |
| TC-REC-007 | unit | ✅ | `check_model_mismatch` returns `Some(stored, configured)` on differ | |
| TC-REC-008 | unit | ✅ | Pre-migration sentinel ignored in mismatch check | |
| TC-REC-009 | manual | ⚠️ | Auto-recall on UserPromptSubmit produces context against Azure | 🔴 |
| TC-REC-010 | manual | ⚠️ | Recall mismatch error printed when embedding provider switched without rebuild | |
| TC-REC-011 | unit | ❌ | Empty embedding store falls through to FTS5 cleanly | medium |
| TC-REC-012 | unit | ❌ | Hybrid merge dedupes by `snapshot_id`, keeps higher score | medium |
| TC-REC-013 | unit | ❌ | `min_prompt_len` skips short prompts | low |

## 4. Embedding storage — `clx-core/src/embeddings.rs`

`sqlite-vec`-backed vector storage. 1024-d default, configurable via
`embedding_dim`. Tracks `embedding_model` per row (added 0.7.0).

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-EMB-001 | unit | ✅ | `store_embedding` writes vector and reads back exactly | |
| TC-EMB-002 | unit | ✅ | `find_similar` returns nearest by cosine distance | |
| TC-EMB-003 | unit | ✅ | `store_with_model` records `<provider>:<model>` ident | |
| TC-EMB-004 | unit | ✅ | `current_model` returns most-recent ident, ignores sentinel | |
| TC-EMB-005 | unit | ✅ | Dimension mismatch detected on `open_with_dimension` | |
| TC-EMB-006 | unit | ❌ | Vector serialization round-trips correctly across schema versions | low |
| TC-EMB-007 | unit | ❌ | `iter_snapshots_for_rebuild` yields non-empty rows in id order | low |

## 5. Configuration — `clx-core/src/config/mod.rs` + `project.rs`

Layered loader (figment): defaults → global → per-project → env vars.
Per-project file at `<repo>/.clx/config.yaml` with inert-keys allowlist.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-CFG-001 | unit | ✅ | Legacy `ollama:` block translates to `providers.ollama-local` + routing | 🔴 |
| TC-CFG-002 | unit | ✅ | New schema with `providers:` + `llm:` parses cleanly | |
| TC-CFG-003 | unit | ✅ | Both legacy + new present → new wins, legacy ignored with WARN | |
| TC-CFG-004 | unit | ✅ | `translate_legacy_in_place` is idempotent | |
| TC-CFG-005 | unit | ✅ | `capability_route(Chat)` returns chat route, `Embeddings` returns embeddings | |
| TC-CFG-006 | unit | ✅ | Missing `llm:` section → `ConfigError::MissingLlmRouting` | |
| TC-CFG-007 | unit | ✅ | Unknown provider name → `ConfigError::UnknownProvider` | |
| TC-CFG-008 | unit | ✅ | `fallback` field round-trips through serialization | |
| TC-CFG-009 | unit | ✅ | `fallback: None` omitted in YAML output | |
| TC-CFG-010 | unit | ✅ | Project config path discovery via env var (`CLX_CONFIG_PROJECT`) | 🔴 |
| TC-CFG-011 | unit | ✅ | `CLX_CONFIG_PROJECT=none` disables project config | |
| TC-CFG-012 | unit | ⚠️ | Walk-up from CWD finds nearest `.clx/config.yaml` stopping at `$HOME` | |
| TC-CFG-013 | unit | ✅ | Inert allowlist drops `providers.*` keys with WARN | |
| TC-CFG-014 | unit | ✅ | Inert allowlist drops `logging.file` | |
| TC-CFG-015 | unit | ✅ | Inert allowlist drops `validator.enabled` | |
| TC-CFG-016 | unit | ✅ | Inert allowlist preserves `llm.chat.fallback` | |
| TC-CFG-017 | unit | ❌ | Env var `CLX_LLM_CHAT_PROVIDER=X` overrides project + global | high |
| TC-CFG-018 | unit | ❌ | Env var `CLX_LLM_CHAT_MODEL=X` overrides project + global | medium |
| TC-CFG-019 | unit | ❌ | Default config when no file exists is local-first Ollama | medium |
| TC-CFG-020 | unit | ❌ | Invalid YAML in project file is ignored, global wins (no panic) | medium |

## 6. LLM backends — trait + factory — `clx-core/src/llm/`

Provider-neutral `LlmBackend` trait. Two impls (Ollama, Azure). Static
dispatch via `LlmClient` enum.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-LLM-001 | unit | ✅ | `LlmError::is_transient` → true for Connection/Timeout/RateLimit/5xx/408 | |
| TC-LLM-002 | unit | ✅ | `LlmError::is_transient` → false for Auth/DeploymentNotFound/ContentFilter/4xx | |
| TC-LLM-003 | unit | ✅ | `LlmError::kind_str` returns one-word category | |
| TC-LLM-004 | unit | ❌ | `LlmClient` enum dispatches to correct backend | low |
| TC-LLM-005 | manual | ✅ | `clx health` lists all providers from config | 🔴 |
| TC-LLM-006 | unit | ❌ | `Config::create_llm_client` builds Ollama client when route → ollama | medium |
| TC-LLM-007 | unit | ❌ | `Config::create_llm_client` builds Azure client when route → azure | medium |
| TC-LLM-008 | unit | ❌ | Factory wraps in `LlmClient::Fallback` when `route.fallback.is_some()` | high |

## 7. Ollama backend — `clx-core/src/llm/ollama.rs`

Native `/api/generate`, `/api/embed`, `/api/tags` endpoints. Localhost-only by
default (SSRF guard).

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-OLL-001 | wiremock | ✅ | `generate` happy path returns text | |
| TC-OLL-002 | wiremock | ✅ | `embed` happy path returns 1024-d vector | |
| TC-OLL-003 | wiremock | ✅ | `is_available` GET `/api/tags` 200 → true | |
| TC-OLL-004 | wiremock | ✅ | `is_available` 5xx → false | |
| TC-OLL-005 | wiremock | ✅ | `list_models` returns model names | |
| TC-OLL-006 | unit | ✅ | `embed` with `model: None` falls back to `OllamaConfig.embedding_model` | |
| TC-OLL-007 | unit | ✅ | Localhost host accepted | |
| TC-OLL-008 | unit | ✅ | IPv6 loopback accepted | |
| TC-OLL-009 | unit | ✅ | Remote IP rejected unless `CLX_ALLOW_REMOTE_OLLAMA=true` | |
| TC-OLL-010 | unit | ✅ | Private IPs (10/8, 172.16/12, 192.168/16) blocked | |
| TC-OLL-011 | unit | ✅ | `.local`/`.internal`/`.lan` hostnames blocked | |
| TC-OLL-012 | wiremock | ✅ | Retry-with-backoff on transient (timeout/5xx) | |
| TC-OLL-013 | wiremock | ✅ | No retry on 4xx | |
| TC-OLL-014 | wiremock | ❌ | Concurrent request semaphore caps in-flight at 5 | low |

## 8. Azure OpenAI backend — `clx-core/src/llm/azure.rs`

Hand-rolled `reqwest` client. v1 OpenAI-compatible path. Host allowlist
(`*.openai.azure.com`, `*.azure-api.net`).

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-AZ-001 | wiremock | ✅ | `chat_happy_path` POST `/openai/v1/chat/completions` 200 | |
| TC-AZ-002 | wiremock | ✅ | `embed_happy_path` POST `/openai/v1/embeddings` returns 1024-d | |
| TC-AZ-003 | wiremock | ✅ | `auth_401` → `LlmError::Auth` | |
| TC-AZ-004 | wiremock | ✅ | `deployment_not_found_404` → `LlmError::DeploymentNotFound` | |
| TC-AZ-005 | wiremock | ✅ | `rate_limit_with_retry_after` → `LlmError::RateLimit { retry_after: Some }` | |
| TC-AZ-006 | wiremock | ✅ | `content_filter_400` → `LlmError::ContentFilter` | |
| TC-AZ-007 | wiremock | ✅ | `server_500` → `LlmError::Server` | |
| TC-AZ-008 | wiremock | ✅ | `is_available_2xx` GET `/openai/v1/models` → true | |
| TC-AZ-009 | wiremock | ✅ | `is_available_5xx` → false | |
| TC-AZ-010 | wiremock | ✅ | Host outside allowlist rejected at constructor | 🔴 |
| TC-AZ-011 | manual | ✅ | Direct curl to real tenant `/openai/v1/models` returns 200 | 🔴 |
| TC-AZ-012 | manual | ✅ | Direct curl to real tenant `/openai/v1/chat/completions` returns 200 | 🔴 |
| TC-AZ-013 | wiremock | ❌ | Dated URL shape (`api_version` set) → `/openai/deployments/.../?api-version=...` | high |
| TC-AZ-014 | wiremock | ❌ | `x-request-id` captured from response header | medium |
| TC-AZ-015 | unit | ❌ | `dimensions: 1024` parameter sent in embed request | medium |
| TC-AZ-016 | manual | ✅ | `clx-hook` PreToolUse with Azure chat returns valid risk score | 🔴 |
| TC-AZ-017 | manual | ✅ | `clx recall` with Azure embeddings returns semantic hits | 🔴 |

## 9. Provider fallback — `clx-core/src/llm/fallback.rs`

Primary→secondary failover with 30s in-process cooldown.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-FB-001 | wiremock | ✅ | Primary 503 → fallback called → fallback's response returned | |
| TC-FB-002 | wiremock | ✅ | Primary 401 → fallback NOT called → 401 propagated | |
| TC-FB-003 | wiremock | ✅ | After fallback fires, second call within 30s skips primary | |
| TC-FB-004 | unit | ❌ | After cooldown expires, primary is retried first | high |
| TC-FB-005 | unit | ❌ | `is_available` returns true if EITHER backend healthy | medium |
| TC-FB-006 | unit | ❌ | `fallback_model` overrides caller's model when delegating | high |
| TC-FB-007 | wiremock | ❌ | Fallback applies to embeddings path, not just chat | high |
| TC-FB-008 | manual | ✅ | Real-tenant: broken-primary + working-fallback → WARN fires, request succeeds | 🔴 |

## 10. Credentials / secrets — `clx-core/src/credentials.rs` + `config/mod.rs`

OS keychain-backed. Validator restricts keys to `[A-Za-z0-9_.-]`. Resolver
checks env → keychain → file.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-CRED-001 | unit | ✅ | `store` writes, `get` reads back | |
| TC-CRED-002 | unit | ✅ | `delete` removes entry | |
| TC-CRED-003 | unit | ✅ | `list` returns known keys | |
| TC-CRED-004 | unit | ✅ | Validator rejects keys with colons (the 0.6.0 bug) | |
| TC-CRED-005 | unit | ✅ | Validator rejects empty / null-byte / >255-char keys | |
| TC-CRED-006 | unit | ✅ | Validator rejects path-traversal patterns | |
| TC-CRED-007 | unit | ✅ | Hyphen-format `<provider>-api-key` key passes validator (0.6.1 regression) | 🔴 |
| TC-CRED-008 | unit | ⚠️ | Test gracefully handles macOS GHA headless keychain (skips with notice) | |
| TC-CRED-009 | unit | ❌ | `resolve_azure_credential` env var path returns wrapped `SecretString` | high |
| TC-CRED-010 | unit | ❌ | `resolve_azure_credential` falls back env → keychain → file | high |
| TC-CRED-011 | unit | ❌ | `SecretString` `Debug` impl prints `[REDACTED]` | high |
| TC-CRED-012 | unit | ❌ | File credential rejected if mode != 0600 (Unix only) | medium |
| TC-CRED-013 | manual | ✅ | `clx credentials set <provider>-api-key '...'` succeeds via keychain | 🔴 |
| TC-CRED-014 | manual | ✅ | `clx credentials list` shows annotation `(azure_openai)` for provider keys | 🔴 |
| TC-CRED-015 | unit | ✅ | Redaction: GitHub token regex masks `ghp_*` | |
| TC-CRED-016 | unit | ✅ | Redaction: Slack token regex masks `xoxb-*` | |
| TC-CRED-017 | unit | ✅ | Redaction: generic `sk-*` masked | |

## 11. Audit log — `clx-core/src/storage/audit.rs`

Per-decision row in `audit_log` table. FK to `sessions(id)`. Auto-creates
session row if missing (0.7.1 fix).

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-AUD-001 | unit | ✅ | `create_audit_log` inserts row | |
| TC-AUD-002 | unit | ❌ | `create_audit_log` with synthetic session_id → session row auto-created (0.7.1) | high |
| TC-AUD-003 | unit | ❌ | Auto-created session has `source='audit-placeholder'`, `status='active'` | medium |
| TC-AUD-004 | unit | ✅ | `get_audit_log_by_session` returns rows in DESC timestamp order | |
| TC-AUD-005 | unit | ✅ | `get_recent_audit_log` respects limit | |
| TC-AUD-006 | unit | ✅ | `count_audit_by_decision` groups correctly | |
| TC-AUD-007 | unit | ✅ | `cleanup_old_audit_logs` deletes rows older than N days | |
| TC-AUD-008 | unit | ❌ | Command field is redacted before insert (0.6.x feature) | high |
| TC-AUD-009 | manual | ✅ | After 10 hook fires with synthetic session IDs, no FK warnings in log | 🔴 |

## 12. Migrations — `clx-core/src/storage/migration.rs`

Versioned schema. Each `migrate_to_vN` runs once on a fresh DB.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-MIG-001 | unit | ✅ | Fresh DB ends at SCHEMA_VERSION (currently 5) | |
| TC-MIG-002 | unit | ✅ | Re-running migrations on existing DB is idempotent | |
| TC-MIG-003 | unit | ✅ | FTS5 table created at v3 | |
| TC-MIG-004 | unit | ✅ | `embedding_model` column added at v5 | |
| TC-MIG-005 | unit | ❌ | Pre-v5 row's `embedding_model` defaults to `<unknown-pre-migration>` | high |
| TC-MIG-006 | unit | ❌ | column_exists guard rejects unsafe table names | high |

## 13. Hooks — `clx-hook/src/hooks/`

Seven hook handlers. JSON in stdin → JSON out stdout. ERROR-only stderr to
avoid Claude Code treating as failure.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-HK-001 | integration | ✅ | PreToolUse with allow command returns valid `permissionDecision: allow` JSON | 🔴 |
| TC-HK-002 | integration | ✅ | PreToolUse with deny command returns `permissionDecision: deny` + reason | 🔴 |
| TC-HK-003 | integration | ✅ | PreToolUse with ambiguous command returns `permissionDecision: ask` + LLM reason | 🔴 |
| TC-HK-004 | integration | ✅ | Malformed input returns `ask` with parse-error reason | |
| TC-HK-005 | integration | ✅ | Missing `cwd` field handled (0.7.0 confusion) | |
| TC-HK-006 | integration | ❌ | Input >1MB rejected with `block` decision | high |
| TC-HK-007 | integration | ⚠️ | PostToolUse logs event + adjusts learning rules | |
| TC-HK-008 | integration | ⚠️ | PreCompact creates snapshot before context compression | |
| TC-HK-009 | integration | ⚠️ | SessionStart creates session row + loads previous summary | |
| TC-HK-010 | integration | ⚠️ | SessionEnd updates session status + creates final snapshot | |
| TC-HK-011 | integration | ⚠️ | UserPromptSubmit injects auto-recall context (when configured) | 🔴 |
| TC-HK-012 | integration | ⚠️ | SubagentStart injects specialist rules | |
| TC-HK-013 | manual | ❌ | Stale session detection marks abandoned sessions after N hours | medium |
| TC-HK-014 | unit | ❌ | Health-cache 60s TTL prevents redundant `is_available` probes | medium |

## 14. MCP server — `clx-mcp/src/`

Exposes `clx_recall`, `clx_remember`, `clx_checkpoint`, `clx_rules` to Claude
Code via MCP protocol.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-MCP-001 | integration | ✅ | Server initializes with config-derived providers | |
| TC-MCP-002 | integration | ✅ | `clx_recall` returns hybrid hits as JSON | |
| TC-MCP-003 | integration | ✅ | `clx_remember` stores text + embedding | |
| TC-MCP-004 | integration | ⚠️ | `clx_checkpoint` creates snapshot on demand | |
| TC-MCP-005 | integration | ⚠️ | `clx_rules` returns current ruleset | |
| TC-MCP-006 | unit | ✅ | `mask_credential_value` redacts middle of value | |
| TC-MCP-007 | manual | ⚠️ | MCP tools work end-to-end in a Claude Code session | 🔴 |
| TC-MCP-008 | unit | ❌ | `clx_recall` passes `embed_model` to `RecallEngine.with_embedding_model()` (0.7.2) | high |
| TC-MCP-009 | unit | ❌ | Input validation: oversize query string rejected | medium |

## 15. CLI commands — `crates/clx/src/commands/`

User-facing surface. ~38 integration tests covering happy paths.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-CLI-001 | integration | ✅ | `clx --version` exits 0 + matches Cargo.toml | 🔴 |
| TC-CLI-002 | integration | ✅ | `clx --help` exits 0 with usage text | |
| TC-CLI-003 | integration | ✅ | `clx health` exits 0 or 1, never panics | 🔴 |
| TC-CLI-004 | integration | ✅ | `clx health --json` returns valid JSON | |
| TC-CLI-005 | integration | ✅ | `clx config` with no args prints current config | |
| TC-CLI-006 | integration | ✅ | `clx config edit` opens `$EDITOR` | |
| TC-CLI-007 | integration | ✅ | `clx config reset --json` exits 0 | |
| TC-CLI-008 | integration | ❌ | `clx config migrate` rewrites legacy block, creates `.bak` | high |
| TC-CLI-009 | integration | ❌ | `clx config migrate` is no-op when already on new schema | medium |
| TC-CLI-010 | integration | ✅ | `clx credentials set/get/list/delete` round-trip | |
| TC-CLI-011 | integration | ✅ | `clx recall` with no args → exit nonzero | |
| TC-CLI-012 | integration | ✅ | `clx recall <query>` with empty DB exits 0 | |
| TC-CLI-013 | integration | ✅ | `clx recall --json` returns valid JSON | |
| TC-CLI-014 | integration | ✅ | `clx rules allow/deny/list/reset` round-trip | |
| TC-CLI-015 | integration | ✅ | `clx trust on/off/status` round-trip | |
| TC-CLI-016 | integration | ✅ | `clx trust on --duration <Xm>` exits 0 | |
| TC-CLI-017 | integration | ✅ | `clx install` is idempotent | |
| TC-CLI-018 | integration | ✅ | `clx uninstall` removes binaries | |
| TC-CLI-019 | integration | ✅ | `clx uninstall --purge` removes `~/.clx` | |
| TC-CLI-020 | integration | ✅ | `clx completions bash/zsh` produces output | |
| TC-CLI-021 | integration | ✅ | `clx embeddings status` exits 0 | |
| TC-CLI-022 | integration | ⚠️ | `clx embeddings rebuild` re-embeds via configured provider | |
| TC-CLI-023 | integration | ❌ | `clx embeddings rebuild` refuses when provider unavailable | high |
| TC-CLI-024 | integration | ❌ | `clx embed-backfill --dry-run` exits 0, lists candidates | medium |

## 16. Dashboard — `crates/clx/src/dashboard/`

Terminal UI built with `ratatui` + `crossterm`. Insta snapshots lock layout.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-DSH-001 | insta | ✅ | Sessions tab renders empty state | |
| TC-DSH-002 | insta | ✅ | Settings tab renders with config loaded | |
| TC-DSH-003 | insta | ✅ | Settings tab renders without config (fallback message) | |
| TC-DSH-004 | unit | ⚠️ | Settings tab shows per-provider routing block (0.7.0) | 🔴 |
| TC-DSH-005 | unit | ❌ | Credential source displayed without secret value | high |
| TC-DSH-006 | manual | ✅ | `clx dashboard` opens, key bindings work | 🔴 |
| TC-DSH-007 | unit | ❌ | Detail-view drill-down keyboard nav (Enter / Esc) | medium |

## 17. Logging — `clx-hook/src/main.rs` + tracing config

Two writers: stderr (ERROR-only) and file (WARN+). File path supports `~`
expansion (0.7.1 fix wired the file sink, the expansion existed earlier).

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-LOG-001 | unit | ✅ | `Config::expand_tilde` handles `~/foo` | |
| TC-LOG-002 | unit | ✅ | `Config::expand_tilde` leaves absolute paths alone | |
| TC-LOG-003 | unit | ✅ | `log_file_path()` returns expanded `PathBuf` | |
| TC-LOG-004 | manual | ✅ | After hook fire, `~/.clx/logs/clx.log` exists with INFO+ entries | 🔴 |
| TC-LOG-005 | manual | ✅ | Stderr remains ERROR-only (Claude Code unaffected) | |
| TC-LOG-006 | unit | ❌ | Log file rotation (`max_size_mb`, `max_files`) honored | medium |
| TC-LOG-007 | unit | ❌ | `MutexFile` adapter handles concurrent writes correctly | low |

## 18. Plugin (`plugin/`) — Claude Code plugin

Skills-only plugin. Validator script + `using-clx` skill.

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-PLG-001 | manual | ✅ | `./plugin/scripts/validate.sh` exits 0 on valid plugin | 🔴 |
| TC-PLG-002 | manual | ✅ | Validator catches missing `plugin.json` | |
| TC-PLG-003 | manual | ✅ | Validator catches frontmatter without required trigger keywords | |
| TC-PLG-004 | manual | ✅ | Validator handles YAML folded scalars (line-wrapped triggers) | |
| TC-PLG-005 | manual | ❌ | `using-clx` skill loads when Claude sees CLX-relevant prompts | high |
| TC-PLG-006 | manual | ❌ | Plugin version equals CLX workspace version on every release | high |

## 19. CI/CD — `.github/workflows/ci.yml` + `release.yml`

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-CI-001 | manual | ✅ | `cargo fmt --all -- --check` runs in CI on every push | |
| TC-CI-002 | manual | ✅ | `cargo clippy ... -D warnings` runs in CI (`::pedantic` gate) | |
| TC-CI-003 | manual | ✅ | `cargo test --workspace` runs on macOS + Linux | |
| TC-CI-004 | manual | ✅ | `cargo build --release --workspace` runs on macOS + Linux | |
| TC-CI-005 | manual | ✅ | `cargo audit` runs and tolerates known unmaintained-dep warnings | |
| TC-CI-006 | manual | ✅ | Coverage job has `timeout-minutes: 30` and `continue-on-error` (PR #22 fix) | 🔴 |
| TC-CI-007 | manual | ✅ | `cargo insta test --workspace --check` blocks unreviewed snapshots | |
| TC-CI-008 | manual | ❌ | Coverage gate (>=70% line) when not skipped | medium |
| TC-CI-009 | manual | ✅ | Auto-Tag workflow creates `vX.Y.Z` tag on workspace version bump | 🔴 |
| TC-CI-010 | manual | ✅ | Release workflow builds + publishes macOS tarballs | 🔴 |

## 20. Release — versioning + Homebrew

| ID | Type | Status | Description | 🔴 |
|---|---|---|---|---|
| TC-REL-001 | manual | ✅ | Workspace `Cargo.toml` version cascades to all 4 crates | 🔴 |
| TC-REL-002 | manual | ✅ | `CHANGELOG.md` has entry for the new version | |
| TC-REL-003 | manual | ✅ | Plugin `plugin.json` version matches workspace version | |
| TC-REL-004 | manual | ✅ | `homebrew-clx` tap formula updated post-release | 🔴 |
| TC-REL-005 | manual | ✅ | `brew upgrade clx` lands new binary on user's PATH | 🔴 |
| TC-REL-006 | manual | ❌ | Old `~/.clx/bin/clx` symlinks (if any) updated to new brew install | medium |

---

## Bug-history regression appendix

Every bug we've shipped (or almost shipped) gets a regression test ID. Cross-
reference with the inventory above.

| Bug | Shipped in | Caught in | Regression test |
|---|---|---|---|
| Keychain key colon-vs-hyphen contract mismatch | 0.6.0 | 0.6.1 | TC-CRED-007 |
| Audit log FK fail on synthetic session_id | 0.6.0 → 0.7.0 | 0.7.1 | TC-AUD-002 |
| File logging never wired up | 0.6.x → 0.7.0 | 0.7.1 | TC-LOG-004 |
| Auto-recall passes `None` model to embed (Azure breaks) | 0.7.0 → 0.7.1 | 0.7.2 | TC-REC-005, TC-MCP-008 |
| `embed_happy_path` env-var race (test hygiene) | 0.7.0 | 0.7.0 | `serial_test` annotations on TC-AZ-001..009 |
| Coverage CI hung 6h on macOS keychain | 0.7.0 | 0.7.0 | CI workflow timeout (TC-CI-006) + TC-CRED-008 |
| Workflow injection-protection hook false positive | n/a | n/a | (workflow change) |
| `~` not expanded in `logging.file` | 0.6.x → 0.7.0 | 0.7.1 | TC-LOG-001..003 |

---

## Coverage-by-area summary

| Area | ✅ existing | ⚠️ partial | ❌ missing | 🔴 runbook gates |
|---|---|---|---|---|
| Validator L0 | 8 | 1 | 3 | 1 |
| Validator L1 | 0 | 4 | 5 | 1 |
| Recall | 8 | 1 | 3 | 1 |
| Embeddings | 5 | 0 | 2 | 0 |
| Config | 16 | 1 | 4 | 2 |
| LLM trait/factory | 4 | 0 | 4 | 1 |
| Ollama backend | 13 | 0 | 1 | 0 |
| Azure backend | 11 | 0 | 4 | 4 |
| Fallback | 3 | 0 | 5 | 1 |
| Credentials | 12 | 1 | 5 | 2 |
| Audit log | 5 | 0 | 4 | 1 |
| Migrations | 4 | 0 | 2 | 0 |
| Hooks | 5 | 6 | 3 | 4 |
| MCP server | 5 | 2 | 3 | 1 |
| CLI | 21 | 1 | 3 | 2 |
| Dashboard | 3 | 1 | 3 | 1 |
| Logging | 3 | 0 | 2 | 1 |
| Plugin | 4 | 0 | 2 | 1 |
| CI/CD | 7 | 0 | 1 | 3 |
| Release | 5 | 0 | 1 | 3 |
| **Totals** | **142** | **17** | **60** | **30** |

**Top priorities to fill (high-severity gaps):**

1. TC-VAL-104..106 — L1 wiremock tests for malformed/timeout/auth failures.
   Heart of the validator, currently no negative-path coverage.
2. TC-FB-004 / TC-FB-006 / TC-FB-007 — fallback cooldown expiry, model
   override, embeddings-path fallback. Touches every LLM call.
3. TC-CRED-009..011 — `resolve_azure_credential` resolution-order tests +
   `SecretString` redaction. Security-sensitive.
4. TC-AUD-002 / TC-AUD-008 — synthetic session_id auto-create + command
   redaction. Production data integrity.
5. TC-CFG-017 / TC-LLM-008 — env-var override precedence, factory wraps in
   `LlmClient::Fallback`. Touches every config load.

---

## How to use this document

- **Adding a feature:** add new `TC-XXX-NNN` entries in the relevant section.
- **Fixing a bug:** add a `TC-XXX-NNN` entry with a description of the regression
  scenario; cross-reference in the bug-history appendix.
- **Before tagging a release:** run every 🔴 entry by hand. The `## 0.
  Pre-release runbook` section at the top is the copy-pasteable checklist.
- **Updating an existing test:** the inventory should match what `cargo test
  --list` reports. Drift = stale doc.

This document is a living artifact, not a contract. The format is more
important than the precise numbers — we want one place to see "what does CLX
do, and how do we know it does that."
