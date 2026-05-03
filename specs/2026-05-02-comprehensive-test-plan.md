# CLX Comprehensive Test Plan — v2

**Date:** 2026-05-02
**Status:** Living document
**Target:** CLX 0.7.2+
**Baseline (measured 2026-05-02 via `cargo llvm-cov --all-features --workspace`):**
- **Region: 70.83%** · **Function: 82.13%** · **Line: 72.37%**

This is both:

1. **A test inventory** — every meaningful behavior CLX should exercise, marked
   ✅ covered, ⚠️ partial, ❌ missing.
2. **A pre-release QA runbook** — the subset (flagged 🔴 hard / 🟡 sweep) a
   maintainer runs by hand before tagging a release.
3. **A coverage roadmap** — what to write next, in what order, to land at the
   defensible target.

## Coverage target — the honest number

The naïve "95% workspace" goal that originally motivated this revision is
**test theater for a TUI + external-process codebase**. Mature Rust projects
(`tokio`, `serde`, `clap`, `sqlx`, `rust-analyzer`) all sit at 70–85% and
substitute Loom (concurrency) + Miri (UB) + `cargo-mutants` (assertion
strength) for the line-coverage chase.

**Adopted target:**

| Scope | Region | Line | Mutation score |
|---|---|---|---|
| Workspace-wide | **85%** | **85%** | n/a |
| `clx-core/src/storage/migration*` | **95%** | **95%** | **80%** |
| `clx-core/src/llm/{azure,ollama,fallback}.rs` | **95%** | **95%** | **80%** |
| `clx-core/src/policy/llm.rs` (L1 validator) | **95%** | **95%** | **80%** |
| `clx-hook/src/main.rs` parser path | **95%** | **95%** | n/a |

Untestable categories (TUI event loop, real keychain in CI, panic recovery)
get `#[cfg_attr(coverage_nightly, coverage(off))]` with a one-line rationale,
counted *out* of the denominator.

CI gate ramps in two-week stages: **70 → 80 → 85** with `continue-on-error`
removed at the 85 step. Mutation testing job (non-blocking) lands day one so
the score is visible before it's enforced.

Test types in this document:

- **unit** — `cargo test --lib`, no I/O
- **db-unit** — in-memory SQLite, no filesystem (NEW; previously conflated with unit)
- **wiremock** — async HTTP test against a local mock
- **integration** — `tests/`, may touch SQLite + temp dirs
- **insta** — snapshot-based UI rendering test
- **property** — `proptest` 1.x strategy + invariant
- **mutation** — `cargo-mutants` v27, scored, not enumerated per-test
- **fuzz** — `cargo-fuzz` or `bolero` target with a corpus
- **loom** — concurrency model (shared-state primitives only)
- **manual** — requires real environment; lives in `CONTRIBUTING.md`

---

## 0. Pre-release runbook

### Tier 0 — Hard gates 🔴 (must pass to tag a release)

```
[ ] TC-REL-010   `clx --version` matches Cargo.toml workspace version
[ ] TC-CI-010    GitHub Actions PR run completes (Coverage may continue-on-error)
[ ] TC-CFG-010   Legacy `ollama:` block auto-translates without on-disk change
[ ] TC-AZ-010    Direct curl to Azure `/openai/v1/chat/completions` returns 200
[ ] TC-CRED-010  `clx credentials set <name>-api-key '...'` succeeds (keychain)
[ ] TC-AUD-010   No FK warning in `~/.clx/logs/clx.log` after 10 hook fires
[ ] TC-LOG-010   `~/.clx/logs/clx.log` exists and contains INFO+ entries after run
```

### Tier 1 — Regression sweep 🟡 (run before any minor or major bump)

```
[ ] TC-REL-020   Brew tap formula version matches GitHub Release tag
[ ] TC-HK-010    PreToolUse hook returns valid JSON in <2s for benign command
[ ] TC-HK-020    L0 blacklist denies `curl URL | bash` in <100ms
[ ] TC-HK-030    L1 LLM scoring fires for ambiguous command (e.g. `rsync ...`)
[ ] TC-AZ-020    `clx-hook` PreToolUse routes L1 to Azure successfully
[ ] TC-AZ-030    `clx recall "any query"` produces semantic hits via Azure embed
[ ] TC-FB-010    Configure broken-primary + working-fallback; verify WARN fires
[ ] TC-FB-020    Cooldown active for 30s after fallback (second call fast)
[ ] TC-REC-010   Auto-recall on UserPromptSubmit returns context (no warns)
[ ] TC-MCP-010   `clx-mcp` initializes and exposes 4 tools to Claude Code
[ ] TC-DSH-010   `clx dashboard` Settings tab shows providers + routing
[ ] TC-CRED-020  `clx credentials list` shows entry with provider annotation
[ ] TC-LLM-010   `clx health` shows all configured providers healthy
```

### Tier 2 — Always-forgotten items 🟠 (run on major bumps and when in doubt)

```
[ ] TC-INST-001  Fresh-machine install (no existing ~/.clx) — first-run UX
[ ] TC-INST-002  Upgrade-in-place from previous minor with populated DB
[ ] TC-INST-003  `clx uninstall --purge` then reinstall — no stale keychain
[ ] TC-INST-004  `cargo install --path .` works (different feature set than brew)
[ ] TC-RES-001   Hook fire under `claude --resume` with stale session_id
[ ] TC-LRG-001   Large prompt (>100KB) on UserPromptSubmit — auto-recall under pressure
[ ] TC-NET-001   Fully-offline behavior: `clx health`, hook PreToolUse with no network
```

---

## 1. Validator — Layer 0 (deterministic rules)

`clx-hook/src/hooks/pre_tool_use.rs` + `clx-core/src/policy/`. Synchronous
allow/deny patterns; catches obvious cases before paying for L1.

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-VAL-001 | unit | ✅ | Whitelist `npm test` → allow | |
| TC-VAL-002 | unit | ✅ | Blacklist `rm -rf /` → deny | |
| TC-VAL-003 | unit | ✅ | `curl ... \| bash` matches blacklist | 🟡 |
| TC-VAL-004 | unit | ✅ | Sudo command matches blacklist | |
| TC-VAL-005 | unit | ✅ | Python `-c` with `os` module flagged | |
| TC-VAL-006 | unit | ✅ | grep/sed/awk allowed | |
| TC-VAL-007 | unit | ✅ | Unknown command → L1 | |
| TC-VAL-008 | unit | ⚠️ | Glob `rm *.log` denied with reason citing glob expansion (rewrite) | |
| TC-VAL-009 | unit | ❌ | Quoted `echo "rm -rf /"` → allow (just printing) | |
| TC-VAL-010 | unit | ❌ | Custom rules from `~/.clx/rules/*.yaml` apply | |
| TC-VAL-011 | unit | ✅ | Sensitivity preset shifts thresholds | |
| TC-VAL-012 | manual | ⚠️ | Trust mode bypasses L0 entirely | |
| TC-VAL-PROP-001 | property | ❌ | Adding a known-bad token never weakens to allow (monotonicity) | |

## 2. Validator — Layer 1 (LLM scoring)

`clx-core/src/policy/llm.rs`. **Heart of the product, currently zero negative-path
coverage.** Highest test-debt area in the codebase.

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-VAL-101 | wiremock | ⚠️ | Risk score 1–3 → allow (rewrite: assert reason text) | |
| TC-VAL-102 | wiremock | ⚠️ | Risk score 4–7 → ask (rewrite: assert reason text) | |
| TC-VAL-103 | wiremock | ⚠️ | Risk score 8–10 → deny (rewrite: assert reason text) | |
| TC-VAL-104 | wiremock | ❌ | Malformed score response → Ask + parse-fail message | 🟡 |
| TC-VAL-105 | wiremock | ❌ | LLM timeout → falls through to `default_decision` | 🟡 |
| TC-VAL-106 | wiremock | ❌ | LLM 401 → fail-loud (NOT silently allowed) | 🟡 |
| TC-VAL-107 | manual | ⚠️ | L1 reason returned in `permissionDecisionReason` | 🟡 |
| TC-VAL-108 | unit | ❌ | Custom validator prompt loaded from global path | |
| TC-VAL-109 | unit | ❌ | Sensitivity preset shifts L1 thresholds | |
| TC-VAL-PROP-002 | property | ❌ | `parse_llm_response` never panics on arbitrary input | |
| TC-VAL-MUT-001 | mutation | ❌ | `cargo-mutants` on `policy/llm.rs`, target 80% kill rate | |

## 3. Recall

`clx-core/src/recall.rs`. Hybrid semantic + FTS5.

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-REC-001 | unit | ✅ | FTS5 hits for literal token | |
| TC-REC-002 | unit | ✅ | Semantic hits for intent (mocked embed) | |
| TC-REC-003 | unit | ✅ | Hybrid merge: 0.6 / 0.4 weights | |
| TC-REC-004 | unit | ✅ | Substring fallback when FTS5 empty | |
| TC-REC-005 | unit | ✅ | `with_embedding_model` builder persists value (0.7.2 regression) | |
| TC-REC-006 | unit | ✅ | Default model is `None` (Ollama back-compat) | |
| TC-REC-007 | unit | ✅ | `check_model_mismatch` reports stored vs configured | |
| TC-REC-008 | unit | ✅ | Pre-migration sentinel ignored | |
| TC-REC-009 | manual | ⚠️ | Auto-recall on UserPromptSubmit produces context against Azure | 🟡 |
| TC-REC-010 | manual | ⚠️ | Mismatch error printed when provider switched without rebuild | |
| TC-REC-011 | db-unit | ❌ | Empty embedding store → FTS5 path, no panic | |
| TC-REC-012 | unit | ❌ | Hybrid merge dedupes by `snapshot_id`, keeps higher score | |
| TC-REC-013 | unit | ❌ | `min_prompt_len` skips short prompts | |

## 4. Embedding storage — `clx-core/src/embeddings.rs`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-EMB-001 | db-unit | ✅ | `store_embedding` round-trips | |
| TC-EMB-002 | db-unit | ✅ | `find_similar` returns nearest by cosine | |
| TC-EMB-003 | db-unit | ✅ | `store_with_model` records ident | |
| TC-EMB-004 | db-unit | ✅ | `current_model` ignores sentinel | |
| TC-EMB-005 | db-unit | ✅ | Dimension mismatch detected | |
| TC-EMB-006 | db-unit | ❌ | Vector round-trips across schema versions | |
| TC-EMB-007 | db-unit | ❌ | `iter_snapshots_for_rebuild` ascending id order | |
| TC-EMB-008 | db-unit | ❌ | NULL/oversized vector rejected with error | |
| TC-EMB-009 | db-unit | ❌ | Batch insert atomicity on partial failure | |
| TC-EMB-010 | loom | ❌ | Concurrent writers do not corrupt index | |

## 5. Snapshots & sessions storage — `clx-core/src/storage/{snapshots,sessions}.rs` (NEW SECTION)

Critical FK target for audit_log + recall. **Previously omitted from the plan.**

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-SNAP-001 | db-unit | ❌ | `create_snapshot` writes session_id, summary, key_facts, todos | |
| TC-SNAP-002 | db-unit | ❌ | `get_snapshots_for_session` ordered DESC by created_at | |
| TC-SNAP-003 | db-unit | ❌ | Snapshot deduplication on identical content | |
| TC-SNAP-004 | db-unit | ❌ | `cleanup_old_snapshots` retention policy | |
| TC-SNAP-005 | db-unit | ❌ | FK integrity: snapshot insert auto-creates session row | |
| TC-SES-001 | db-unit | ✅ | `create_session` writes row | |
| TC-SES-002 | db-unit | ❌ | Stale session detection marks as abandoned after N hours | |
| TC-SES-003 | db-unit | ❌ | Concurrent session updates serialize correctly | |

## 6. Configuration — `clx-core/src/config/`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-CFG-001 | unit | ✅ | Legacy `ollama:` block translates to providers + routing | 🔴 |
| TC-CFG-002 | unit | ✅ | New schema parses cleanly | |
| TC-CFG-003 | unit | ✅ | Both legacy + new → new wins, legacy WARN | |
| TC-CFG-004 | unit | ✅ | `translate_legacy_in_place` idempotent | |
| TC-CFG-005 | unit | ✅ | `capability_route(Chat/Embeddings)` returns correct route | |
| TC-CFG-006 | unit | ✅ | Missing `llm:` → `MissingLlmRouting` | |
| TC-CFG-007 | unit | ✅ | Unknown provider → `UnknownProvider` | |
| TC-CFG-008 | unit | ✅ | `fallback` field round-trips | |
| TC-CFG-009 | unit | ✅ | `fallback: None` omitted in YAML output | |
| TC-CFG-010 | unit | ✅ | `CLX_CONFIG_PROJECT` env var path | 🔴 |
| TC-CFG-011 | unit | ✅ | `CLX_CONFIG_PROJECT=none` disables project | |
| TC-CFG-012 | unit | ⚠️ | Walk-up from CWD finds nearest `.clx/config.yaml` | |
| TC-CFG-013 | unit | ✅ | Inert allowlist drops `providers.*` with WARN | |
| TC-CFG-014 | unit | ✅ | Inert allowlist drops `logging.file` | |
| TC-CFG-015 | unit | ✅ | Inert allowlist drops `validator.enabled` | |
| TC-CFG-016 | unit | ✅ | Inert allowlist preserves `llm.chat.fallback` | |
| TC-CFG-017 | unit | ❌ | `CLX_LLM_CHAT_PROVIDER=X` overrides project + global | |
| TC-CFG-018 | unit | ❌ | `CLX_LLM_CHAT_MODEL=X` overrides project + global | |
| TC-CFG-019 | unit | ❌ | Default config (no file) is local-first Ollama | |
| TC-CFG-020 | unit | ❌ | Invalid project YAML ignored, global wins (no panic) | |
| TC-CFG-PROP-001 | property | ❌ | `parse(serialize(x)) == x` for any valid Config | |

## 7. LLM trait + factory — `clx-core/src/llm/`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-LLM-001 | unit | ✅ | `LlmError::is_transient` true for transient | |
| TC-LLM-002 | unit | ✅ | `LlmError::is_transient` false for terminal | |
| TC-LLM-003 | unit | ✅ | `LlmError::kind_str` one-word category | |
| TC-LLM-004 | unit | ❌ | `LlmClient` enum dispatches correctly | |
| TC-LLM-005 | manual | ✅ | `clx health` lists configured providers | 🟡 |
| TC-LLM-006 | unit | ❌ | Factory builds Ollama client for ollama route | |
| TC-LLM-007 | unit | ❌ | Factory builds Azure client for azure route | |
| TC-LLM-008 | unit | ❌ | Factory wraps in `LlmClient::Fallback` when route has fallback | |

## 8. Ollama backend

13/14 covered. (See v1 for full list.) Notable gap: TC-OLL-014 concurrent
semaphore — leave as `loom` follow-up.

## 9. Azure OpenAI backend — `clx-core/src/llm/azure.rs`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-AZ-001..012 | wiremock + manual | ✅ | (see v1) | 🔴/🟡 |
| TC-AZ-013 | unit | ❌ | Dated URL shape: `chat_url`/`embeddings_url` with `api_version` | |
| TC-AZ-014 | wiremock | ❌ | `x-request-id` captured from response header | |
| TC-AZ-015 | wiremock | ❌ | `dimensions: 1024` sent in embed request body | |
| TC-AZ-MUT-001 | mutation | ❌ | `cargo-mutants` on `azure.rs`, target 80% kill | |

## 10. Provider fallback — `clx-core/src/llm/fallback.rs`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-FB-001 | wiremock | ✅ | Primary 503 → fallback fires | |
| TC-FB-002 | wiremock | ✅ | Primary 401 → fallback NOT called | |
| TC-FB-003 | wiremock | ✅ | Cooldown skips primary within 30s | |
| TC-FB-004 | unit | ❌ | After cooldown expires, primary retried first (use `tokio::time::pause/advance`) | |
| TC-FB-005 | wiremock | ❌ | `is_available` true if EITHER backend healthy | |
| TC-FB-006 | wiremock | ❌ | `fallback_model` overrides caller's model when delegating | |
| TC-FB-007 | wiremock | ❌ | Fallback applies to embeddings path (not just chat) | |
| TC-FB-008 | manual | ✅ | Real-tenant: broken-primary, fallback fires | 🟡 |
| TC-FB-MUT-001 | mutation | ❌ | `cargo-mutants` on `fallback.rs`, target 80% kill | |
| TC-FB-LOOM-001 | loom | ❌ | Cooldown atomic ordering under concurrent fallback events | |

## 11. Credentials + secrets — `clx-core/src/credentials.rs` + `config/mod.rs`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-CRED-001 | unit | ✅ | `store/get/delete` round-trip | |
| TC-CRED-002..006 | unit | ✅ | (see v1 for full list) | |
| TC-CRED-007 | unit | ✅ | Hyphen-format key passes validator (0.6.1 regression) | 🟡 |
| TC-CRED-008 | unit | ✅ | Test gracefully handles macOS GHA headless keychain | |
| TC-CRED-009 | unit | ❌ | `resolve_azure_credential` env var path returns `SecretString` | |
| TC-CRED-010 | unit | ❌ | Resolution order: env → keychain → file | 🔴 |
| TC-CRED-011 | unit | ❌ | `SecretString::Debug` prints `[REDACTED]` | |
| TC-CRED-012 | unit | ❌ | File credential rejected if mode != 0600 (Unix) | |
| TC-CRED-013 | manual | ✅ | `clx credentials set ...` succeeds | 🔴 |
| TC-CRED-014 | manual | ✅ | `list` shows provider annotation | 🟡 |
| TC-CRED-015..017 | unit | ✅ | Redaction (GitHub/Slack/sk-* tokens) | |
| TC-CRED-PROP-001 | property | ❌ | Any validator-passing key round-trips through `store/get/delete` | |
| TC-CRED-PROP-002 | property | ❌ | Redacted output never contains the original secret as substring | |

## 12. Audit log — `clx-core/src/storage/audit.rs`

**Honesty fix:** TC-AUD-002 was listed as ❌ but referenced as the regression
test for the 0.7.1 FK fix. It must be implemented before the next release.

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-AUD-001 | db-unit | ✅ | `create_audit_log` inserts row | |
| TC-AUD-002 | db-unit | ❌ | **Synthetic session_id auto-creates session row (0.7.1 regression — currently uncovered)** | |
| TC-AUD-003 | db-unit | ❌ | Auto-created session has `source='audit-placeholder'`, `status='active'` | |
| TC-AUD-004 | db-unit | ✅ | `get_audit_log_by_session` DESC order | |
| TC-AUD-005 | db-unit | ✅ | `get_recent_audit_log` respects limit | |
| TC-AUD-006 | db-unit | ✅ | `count_audit_by_decision` groups | |
| TC-AUD-007 | db-unit | ✅ | `cleanup_old_audit_logs` deletes > N days | |
| TC-AUD-008 | db-unit | ❌ | **Command field redacted before insert (data-integrity property)** | |
| TC-AUD-009 | manual | ✅ | After 10 hook fires, no FK warns | 🔴 |

## 13. Migrations — `clx-core/src/storage/migration.rs` (HIGH-PRIORITY MODULE: 95% target)

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-MIG-001 | db-unit | ✅ | Fresh DB ends at SCHEMA_VERSION (5) | |
| TC-MIG-002 | db-unit | ✅ | Re-running migrations idempotent | |
| TC-MIG-003 | db-unit | ✅ | FTS5 table at v3 | |
| TC-MIG-004 | db-unit | ✅ | `embedding_model` column at v5 | |
| TC-MIG-005 | db-unit | ❌ | Pre-v5 row's `embedding_model` defaults to sentinel | |
| TC-MIG-006 | db-unit | ❌ | `column_exists` rejects unsafe table names (SQL-injection guard) | |
| TC-MIG-007 | db-unit | ❌ | Per-migration up behavior: schema diff matches expectation | |
| TC-MIG-008 | db-unit | ❌ | Corrupt-DB recovery / partial-migration rollback | |
| TC-MIG-MUT-001 | mutation | ❌ | `cargo-mutants` on `migration.rs`, target 80% kill | |

## 14. Hooks — `clx-hook/src/hooks/`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-HK-001 | integration | ⚠️ | PreToolUse allow command — rewrite: assert reason + audit row written | 🔴 |
| TC-HK-002 | integration | ⚠️ | PreToolUse deny command — rewrite: assert reason | 🔴 |
| TC-HK-003 | integration | ⚠️ | PreToolUse ambiguous — rewrite: assert LLM-authored reason | 🔴 |
| TC-HK-004 | integration | ✅ | Malformed input → ask + parse-error reason | |
| TC-HK-005 | integration | ✅ | Missing `cwd` field handled | |
| TC-HK-006 | integration | ❌ | Input >1MB → block decision | |
| TC-HK-007..012 | integration | ⚠️ | (see v1 for PostToolUse, PreCompact, SessionStart, etc.) | |
| TC-HK-013 | manual | ❌ | Stale session detection (refactor first: inject clock) | |
| TC-HK-014 | unit | ❌ | Health-cache 60s TTL prevents redundant probes | |
| TC-HK-CONTRACT-001..007 | integration | ❌ | **Pin Claude Code hook JSON envelope per event with frozen schema fixture** | |
| TC-HK-FUZZ-001 | fuzz | ❌ | Hook input parser doesn't panic on arbitrary JSON | |

## 15. MCP server — `clx-mcp/src/`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-MCP-001..006 | integration | ✅/⚠️ | (see v1) | |
| TC-MCP-007 | manual | ⚠️ | Tools work end-to-end in real Claude Code session | 🟡 |
| TC-MCP-008 | unit | ❌ | **`clx_recall` passes `embed_model` to `RecallEngine.with_embedding_model()` (0.7.2 regression — currently uncovered)** | |
| TC-MCP-009 | unit | ❌ | Oversize query rejected | |

## 16. CLI commands — `crates/clx/src/commands/`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-CLI-001..007 | integration | ✅ | (see v1) | 🔴/🟡 |
| TC-CLI-008 | integration | ❌ | `clx config migrate` rewrites legacy + creates `.bak` | |
| TC-CLI-009 | integration | ❌ | `migrate` no-op when already on new schema | |
| TC-CLI-010..021 | integration | ✅ | (see v1) | |
| TC-CLI-022 | integration | ⚠️ | `embeddings rebuild` re-embeds via configured provider | |
| TC-CLI-023 | integration | ❌ | `embeddings rebuild` refuses when provider unavailable | |
| TC-CLI-024 | integration | ❌ | `embed-backfill --dry-run` lists candidates | |
| Several CLI entries (003, 011..013, 015..017) | rewrite | weak | Rewrite to assert side effects, not just exit codes | |

## 17. Dashboard — `crates/clx/src/dashboard/` (REFACTOR-FIRST)

**Coverage data (measured 2026-05-02):**

- `dashboard/ui/detail.rs`: **8.33% line, 7.57% region** — dominates the
  workspace coverage gap (1294/1400 regions uncovered).
- `dashboard/settings/render.rs`: **16.96% line, 16.07% region**.
- `dashboard/ui/audit.rs`: 57.75% line.

**Refactor before testing:**

1. Extract a pure `update(state, event) -> state` reducer from the event loop.
   Snapshot tests target the state, not the rendered terminal.
2. Mark the `crossterm` event poll + `ratatui` `run()` shell
   `#[cfg_attr(coverage_nightly, coverage(off))]` with rationale
   "TTY-driven event loop, untestable in CI."

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-DSH-001..003 | insta | ✅ | Sessions/Settings empty + loaded states | |
| TC-DSH-004 | insta | ❌ | (Promote from unit) Settings tab snapshot with provider routing | 🟡 |
| TC-DSH-005 | unit | ❌ | Credential source rendered without secret value (security property) | |
| TC-DSH-006 | manual | ✅ | `clx dashboard` opens, key bindings work | 🟡 |
| TC-DSH-007 | unit | ❌ | Detail-view keyboard nav (Enter/Esc) on extracted reducer | |
| TC-DSH-REFACTOR-001 | (refactor) | ❌ | Extract `update()` reducer; mark event loop `coverage(off)` | |

## 18. Logging — `clx-hook/src/main.rs` + tracing config

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-LOG-001..003 | unit | ✅ | `expand_tilde` handles `~/`/`~`/abs paths | |
| TC-LOG-004 | manual | ✅ | After hook fire, log file populated | 🔴 |
| TC-LOG-005 | integration | ⚠️ | Stderr remains ERROR-only (capture stderr in test) | |
| TC-LOG-006 | unit | ❌ | Log file rotation (`max_size_mb`, `max_files`) | |
| TC-LOG-007 | loom | ❌ | `MutexFile` concurrent writes correctness | |
| TC-LOG-008 | integration | ❌ | Tracing spans propagate `session_id` + `request_id` end-to-end | |

## 19. Trust mode — `crates/clx/src/commands/trust.rs` (NEW SECTION)

Previously absent from the plan. State machine + L0 bypass + token expiry.

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-TRUST-001 | integration | ❌ | `clx trust on --duration 5m` writes token, status reflects | |
| TC-TRUST-002 | integration | ❌ | Expired token forces validator back on (refactor first: inject clock) | |
| TC-TRUST-003 | integration | ❌ | `clx trust off` deletes token immediately | |
| TC-TRUST-004 | unit | ❌ | Token JSON shape matches `TrustToken` struct | |
| TC-TRUST-005 | integration | ❌ | L0 bypass when trust active and command in scope | |

## 20. Rules engine — `crates/clx/src/commands/rules.rs` (NEW SECTION)

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-RULES-001 | integration | ⚠️ | `rules allow/deny/list/reset` round-trip (rewrite: assert L0 sees the rule) | |
| TC-RULES-002 | integration | ❌ | Rule precedence: project > global > builtin | |
| TC-RULES-003 | integration | ❌ | Conflicting allow + deny — deny wins | |
| TC-RULES-004 | integration | ❌ | Rules persist across CLI invocations | |
| TC-RULES-005 | integration | ❌ | Rules YAML round-trips after edit | |

## 21. Plugin (`plugin/`) — Claude Code plugin

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-PLG-001..004 | manual | ✅ | Validator script behavior | 🔴 |
| TC-PLG-005 | manual | ❌ | `using-clx` skill loads on CLX-relevant prompts (Claude session needed) | |
| TC-PLG-006 | unit | ❌ | Plugin version equals workspace version (`include_str!` + `env!("CARGO_PKG_VERSION")`) | |

## 22. CI/CD — `.github/workflows/`

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-CI-001..007 | manual | ✅ | (see v1) | |
| TC-CI-008 | manual | ❌ | Coverage gate ≥85% (after `continue-on-error` removed) | |
| TC-CI-009..010 | manual | ✅ | Auto-Tag + Release workflows | 🔴 |
| TC-CI-MUT-001 | manual | ❌ | Nightly mutation-testing job (non-blocking) | |

## 23. Release — versioning + Homebrew

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-REL-001..005 | manual | ✅ | (see v1) | 🔴 |
| TC-REL-006 | manual | ❌ | Old `~/.clx/bin/clx` symlinks updated post-brew (re-symlink check) | |

## 24. Security — cross-cutting (NEW SECTION)

| ID | Type | Status | Description | 🔴/🟡 |
|---|---|---|---|---|
| TC-SEC-001 | unit | ❌ | Prompt-injection: `{{command}}` placeholder doesn't double-substitute | |
| TC-SEC-002 | wiremock | ❌ | SSRF guard: `CLX_ALLOW_REMOTE_OLLAMA=true` still blocks non-allowlisted hosts | |
| TC-SEC-003 | property | ❌ | API keys never appear in any tracing output (capture + assert) | |
| TC-SEC-004 | property | ❌ | API keys never appear in audit log command field | |

---

## Bug-history regression appendix

Every shipped bug → its regression test ID. **Honesty fix:** entries below
marked ❌ existed as documentation lies in v1 (claimed regression but no test).

| Bug | Shipped | Caught | Regression test | Status |
|---|---|---|---|---|
| Keychain key colon-vs-hyphen | 0.6.0 | 0.6.1 | TC-CRED-007 | ✅ |
| Audit log FK on synthetic session_id | 0.6.0 → 0.7.0 | 0.7.1 | TC-AUD-002 | ❌ **gap** |
| File logging never wired up | 0.6.x → 0.7.0 | 0.7.1 | TC-LOG-004 | ✅ manual |
| Auto-recall passes `None` model (Azure breaks) | 0.7.0 → 0.7.1 | 0.7.2 | TC-REC-005 | ✅ |
| Auto-recall in MCP path same bug | 0.7.0 → 0.7.1 | 0.7.2 | TC-MCP-008 | ❌ **gap** |
| Test env-var race (`embed_happy_path`) | 0.7.0 | 0.7.0 | `serial_test` annotations on TC-AZ-001..009 | ✅ |
| Coverage CI hung 6h on macOS keychain | 0.7.0 | 0.7.0 | CI workflow timeout (TC-CI-006) + TC-CRED-008 | ✅ |
| `~` not expanded in `logging.file` | 0.6.x → 0.7.0 | 0.7.1 | TC-LOG-001..003 | ✅ |

**TC-AUD-002 and TC-MCP-008 are the highest-priority gaps to land.**

Likely-to-recur bug categories not enumerated in v1:

- YAML parser version bumps (`figment` + `serde_yml`) — add a canary fixture suite
- `sqlite-vec` extension loading on different macOS/Linux glibc combos
- Tokio runtime nesting (`block_on` inside async) — easy to reintroduce in CLI
  commands; no lint or test gate
- Reqwest connection-pool exhaustion under sustained hook fires
- Claude Code hook JSON envelope drift — see `TC-HK-CONTRACT-001..007`

---

## Coverage-by-area summary (post-v2)

Counts **after** adding new sections (Snapshots/Sessions, Trust, Rules,
Security) and the property/mutation/fuzz/loom rows:

| Area | ✅ existing | ⚠️ partial | ❌ missing | 🔴 hard | 🟡 sweep |
|---|---|---|---|---|---|
| L0 Validator | 8 | 1 | 4 | | 1 |
| L1 Validator | 0 | 4 | 7 | | 1 |
| Recall | 8 | 1 | 4 | | 1 |
| Embeddings | 5 | 0 | 5 | | |
| Snapshots/sessions | 1 | 0 | 7 | | |
| Config | 16 | 1 | 5 | | |
| LLM trait/factory | 4 | 0 | 4 | | 1 |
| Ollama | 13 | 0 | 1 | | |
| Azure | 11 | 0 | 4 | 4 | |
| Fallback | 3 | 0 | 7 | | 1 |
| Credentials | 12 | 1 | 7 | 1 | 2 |
| Audit | 5 | 0 | 4 | | 1 |
| Migrations | 4 | 0 | 5 | | |
| Hooks | 5 | 4 | 11 | 3 | |
| MCP | 5 | 2 | 3 | | 1 |
| CLI | 21 | 1 | 4 | | |
| Dashboard | 3 | 1 | 4 | | 1 |
| Logging | 3 | 1 | 3 | 1 | |
| Trust | 0 | 0 | 5 | | |
| Rules | 0 | 1 | 4 | | |
| Plugin | 4 | 0 | 2 | | |
| CI/CD | 7 | 0 | 2 | | |
| Release | 5 | 0 | 1 | | |
| Security | 0 | 0 | 4 | | |
| **Totals** | **143** | **17** | **107** | **9** | **9** |

(v1 had 60 missing; v2 has 107 because we added entire feature areas the
plan was missing and broke out property/mutation/fuzz/loom entries.)

---

## Top 15 sequencing — write these first to move 72.37% → 85%

Ranked by `coverage_payoff / effort`. Numbered IDs land tests; `REFACTOR-001`
unlocks an entire section.

1. **TC-CRED-011** — `SecretString` Debug = `[REDACTED]`. ~10 LoC. Security invariant.
2. **TC-MIG-006** — `column_exists` SQL-injection guard. ~15 LoC.
3. **TC-MCP-009** — Oversize query validation. ~15 LoC.
4. **TC-AUD-003** — Auto-created session has correct fields. ~15 LoC.
5. **TC-AZ-013** — Dated URL shape. ~25 LoC, no mocks.
6. **TC-AUD-002** — Synthetic session FK auto-create. ~30 LoC. Closes documentation lie.
7. **TC-AUD-008** — Command redaction before audit insert. ~30 LoC. Privacy property.
8. **TC-VAL-104..106** — L1 wiremock negative paths (parse fail / timeout / auth). ~120 LoC. Heart of the product.
9. **TC-CRED-009..010** — `resolve_azure_credential` env + ordering. ~100 LoC. Security-sensitive.
10. **TC-FB-004 / TC-FB-007** — Cooldown expiry + embeddings fallback. ~90 LoC.
11. **TC-LLM-006..008** — Factory builds correct backend per route + wraps in Fallback. ~95 LoC.
12. **TC-CFG-017..020** — Env override + invalid YAML resilience. ~95 LoC.
13. **TC-MCP-008** — `clx_recall` passes embed_model. ~70 LoC. Closes documentation lie.
14. **TC-CLI-008/009/023** — `clx config migrate` + `embeddings rebuild` refusal. ~150 LoC.
15. **TC-DSH-REFACTOR-001** — Extract dashboard reducer + `coverage(off)` shells. **Multi-day refactor; unlocks ~25 percentage points in workspace line coverage.**

Add in parallel (non-blocking, separate CI job):

- **TC-VAL-MUT-001 / TC-AZ-MUT-001 / TC-FB-MUT-001 / TC-MIG-MUT-001** — `cargo-mutants` on hot modules; target 80% kill rate.
- **TC-VAL-PROP-001 / TC-VAL-PROP-002 / TC-CFG-PROP-001 / TC-CRED-PROP-001..002 / TC-SEC-003..004** — `proptest` 1.x suites for monotonicity, round-trips, redaction.
- **TC-HK-FUZZ-001** — `cargo-fuzz` target on hook JSON parser.
- **TC-FB-LOOM-001 / TC-EMB-010 / TC-LOG-007** — `loom` models for racy primitives.

---

## Refactor-first tasks (unlock testability)

| Task | Impact |
|---|---|
| Extract dashboard `update(state, event) -> state` reducer | Unlocks TC-DSH-005/007 + ~25 pp line coverage |
| Inject `Clock` into `pre_tool_use` for trust-token expiry | Unlocks TC-TRUST-002 + TC-HK-013 |
| Trait-abstract `KeyringBackend` for in-memory testing | Unlocks TC-CRED-008 to be enforced (not skip-on-CI) |
| Extract `clx-hook/src/main.rs` `handle_event(reader, writer, deps)` from `main()` | Unlocks contract tests TC-HK-CONTRACT-001..007 |
| Inject `FsRoot` abstraction for `clx install/uninstall` | Unlocks TC-INST-001..003 as integration tests |

---

## CI rollout plan

Two-week stages, removing `continue-on-error` only at the final step:

| Week | Threshold | Status |
|---|---|---|
| 0 | continue-on-error | current |
| 0 (parallel) | mutation testing job, non-blocking | adopt `cargo-mutants` v27 |
| 2 | gate ≥75% line | after Top-15 sequencing items #1-#7 land |
| 4 | gate ≥80% line | after items #8-#13 land |
| 6 | gate ≥85% line, remove continue-on-error | after refactor + items #14-#15 |
| ongoing | mutation score ≥80% on hot modules | non-blocking warn → blocking on next minor |

---

## How to use this document

- **Adding a feature:** add new `TC-XXX-NNN` entries in the relevant section.
- **Fixing a bug:** add a `TC-XXX-NNN` entry; cross-reference in the bug-history appendix.
- **Before tagging a release:** Tier 0 hard gates always; Tier 1 sweep on minor/major; Tier 2 always-forgotten on major.
- **Picking up new test work:** start at the Top-15 sequencing list, write the smallest coverage_payoff/effort wins first.
- **Extending the plan itself:** if you find a category not covered, add a section. The format is more important than the precise IDs.

This document is a living artifact. Drift between it and `cargo test --list`
output is the canary.
