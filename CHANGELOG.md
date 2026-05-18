# Changelog

All notable changes to CLX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.8.0] - 2026-05-17

The "memory and quality" release. Five user-visible outcomes plus an
engineering coverage push, hardened by a two-round comprehensive review
and a Red/Green/Purple security pass. All work landed on
`feat/0.8.0-memory-skills-coverage`.

### Added

- **Recall accuracy pipeline (Phase 5).** `RecallEngine::query` now runs
  parallel embedding + FTS5 candidate generation, fuses via Reciprocal
  Rank Fusion (RRF) with `k = 60` (Cormack et al. 2009), reranks the top
  candidates through `bge-reranker-v2-m3` (fastembed-rs 5.x) with a 250 ms
  graceful timeout, then applies multiplicative time-decay (30-day default
  half-life) and a p70 percentile gate. New config keys on
  `AutoRecallConfig`: `rrf_enabled`, `rrf_k`, `time_decay_half_life_days`,
  `percentile_gate`, `reranker_enabled`, `reranker_timeout_ms`. All
  default-on. Backward compat: set `rrf_enabled: false` to reproduce the
  0.7.x linear hybrid merge.
- **`clx model` CLI (Phase 5b).** New `clx model fetch [--background] [--force]`,
  `clx model status`, and `clx model list` subcommands manage the
  `~/.clx/models/bge-reranker-v2-m3/` cache. First-run UX: the
  `UserPromptSubmit` hook spawns `clx model fetch --background` exactly
  once per process via `std::sync::Once` when the model is missing, emits
  one WARN to logs, and falls back to RRF-only ordering until the
  `.ready` sentinel appears.
- **Model-discoverable skills (Phase 1).** Plugin layout migrated to the
  2026 `.claude-plugin/` schema. Six narrow named skills replace the old
  monolithic `using-clx`: `clx-recall`, `clx-remember`, `clx-checkpoint`,
  `clx-rules`, `clx-resume`, `clx-doctor`. Frontmatter validator
  (`plugin/scripts/validate.sh`) checks 2026 schema (name length,
  description length, kebab-case, parent-dir match, bidirectional
  manifest/disk orphans) with `--strict` mode enforcing the "Use when"
  trigger-bleed guard. Migration script `plugin/scripts/migrate.sh` for
  existing users.
- **Pinned recent sessions (Phase 6).** Opt-in
  `auto_recall.pin_recent_sessions.{enabled,count,max_chars_each}` config
  injects the last-N session summaries into every `UserPromptSubmit`
  recall, with current-session self-pin guard via SQL exclude. Backed by
  new `Storage::recent_session_summaries(n, exclude_session_id)`.
- **`tool_events` aggregator (Phase 4).** New schema-v6 `tool_events`
  table records mutator tool invocations (`Edit`, `Write`, `MultiEdit`,
  `NotebookEdit`, mutator `Bash`) with 60-second windowed dedup per
  `(session_id, tool_name, target)`. Aggregator runs from `PostToolUse`
  hook after the existing `events` append. New `retention.tool_events_days`
  config key (default 30; `0` disables trimming). `clx maintenance trim`
  command runs the retention window.
- **Auto-summarize mode (Phase 10).** Opt-in
  `memory.auto_summarize.{enabled,every_n_turns,summarizer_capability,max_summary_chars,skip_when_idle}`
  config. New `Stop` hook handler reads the rolling N-turn transcript,
  calls the configured chat LLM via the existing
  `Config::create_llm_client` factory, and writes the result as a snapshot
  with new `SnapshotTrigger::AutoSummary` variant. Deterministic template
  summarizer (no LLM) is the fallback when the chat capability is
  unavailable. `skip_when_idle` guards against firing on a no-op session
  by checking `tool_events` count since the last `AutoSummary`.
- **`clx config-trust` file-hash trustlist (Phase 7, §3.11).** Per-machine
  per-user trustlist at `~/.clx/trusted_configs.json` (0600 mode) lets
  power users bypass the inert-key filter for project configs by
  registering the SHA-256 hash of `<repo>/.clx/config.yaml`. New
  subcommands: `clx config-trust add <path> [-y]`, `clx config-trust list`,
  `clx config-trust remove <hash|prefix>`. Trust does NOT propagate via
  git. Any byte edit to the file invalidates trust automatically.
  Parallel to and independent from the existing PR #15 trust-mode
  auto-allow.
- **Contract tests for hook envelopes (Phase 2).** 7 sanitized JSON
  fixtures under `crates/clx-hook/tests/fixtures/hook_envelopes/` cover
  `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SubagentStart`,
  `Stop`, `SessionStart`, `PreCompact`. `insta` snapshot assertions drive
  the new `handle_event` router and detect schema drift in both
  directions (Claude Code spec changes and our emit changes).
- **`handle_event` library router (Phase 2).** New `clx-hook` lib target
  exposes `router::handle_event<R: Read, W: Write>(reader, writer, deps)
  -> ExitCode`. Binary `main()` slimmed from 196 LoC to 126 LoC,
  delegates to the library. Hook integration tests now drive
  `handle_event` end-to-end with in-memory readers and writers, no
  subprocess spawn.
- **Dashboard reducer (Phase 3).** Pure
  `update(state: AppState, event: DashboardEvent) -> (AppState, Vec<DashboardCmd>)`
  reducer drives the entire event loop. `AppState` (data) is cleanly
  separated from `AppRuntime` (terminal, mutexes, timers). All
  `DashboardEvent` variants (`Key`, `Resize`, `Tick`, `Quit`) flow
  through the reducer with deterministic state transitions; side effects
  are explicit `DashboardCmd` intents executed by the runtime.
- **Coverage push (Phase 8).** 17 deterministic `ratatui::TestBackend` +
  `insta` snapshots cover `dashboard/ui/detail.rs` (9 snapshots: each
  detail tab in both empty and populated states) and
  `dashboard/settings/render.rs` (8 snapshots: each settings tab,
  edit-mode popup, confirm-reset, reload-confirm, exit-guard).
  Workspace `[workspace.metadata.cargo-llvm-cov]` configures
  `ignore-filename-regex` to exclude scaffolded reducer files and
  shell-only `main.rs` paths from the denominator.
- **Mutation testing CI (Phase 11).** `mutants.toml` v27 schema
  whitelists seven hot modules (`recall::mod`, `recall::rrf`,
  `recall::decay`, `llm::fallback`, `storage::migration`,
  `policy::mcp`, `redaction`). Two new GitHub Actions workflows:
  `mutants.yml` (weekly Monday 06:00 UTC baseline + tracking-issue
  comment when survivors > 24) and `mutants-pr.yml` (PR-diff
  check-only, warn-only in 0.8.0). `docs/mutation-testing.md` documents
  the 80% kill-rate target rationale and additive-not-substitutional
  relationship to coverage.
- **RAGAS-style synthetic bench (Phase 9).** 30 hand-curated synthetic
  `(query, expected_snapshot_ids)` pairs at
  `tests/fixtures/recall_golden.yaml` (six categories: recall, skills,
  config, hook, trust, migration; 5 pairs each). Generator script
  `scripts/generate_golden_set.py` is deterministic (`random.seed(0xCAFE)`)
  and runs a forbidden-token scan before write to ensure no user content
  or PHI leaks. New `criterion` bench `benches/recall_accuracy.rs`
  reports `context_precision@10` and `context_recall@10` mean/p50/p95
  across both `rrf_enabled` configurations.

### Changed

- `RecallQueryConfig` now derives `Default`. All call sites (clx-mcp,
  clx-hook subagent, internal tests) use `..Default::default()` for
  forward-compat field additions.
- `Config::load` now applies a per-project trust gate before the inert
  filter via the new `apply_project_layer`. Untrusted configs see the
  pre-existing `filter_inert_only` behavior, unchanged.
- `Storage` schema version bumped from 5 to 7. Schema-v6 adds the
  `tool_events` table plus two supporting indexes; schema-v7 adds a
  UNIQUE INDEX on `(session_id, tool_name, IFNULL(target,''), window_end_unix/60)`
  enabling atomic `INSERT ... ON CONFLICT DO UPDATE` upserts so parallel
  hook processes cannot race-insert duplicate aggregation rows.
- `fastembed` dev/runtime dep bumped 4 -> 5 (ort 2.0 stable, away from
  rc.9; v5 `TextRerank::rerank` now takes `&mut self` so the cached
  model is held in a `Mutex<Option<TextRerank>>` under the existing
  `Arc` wrapper).
- `criterion` dev dep bumped 0.5 -> 0.8.
- `redact_secrets` is unchanged for string inputs; the new
  `redact_json_value(&serde_json::Value) -> Value` walks objects/arrays
  recursively and redacts values under 20 sensitive key patterns
  (`api_key`, `password`, `secret`, `token`, `authorization`,
  `credential`, `bearer`, ...) case-insensitive. `PostToolUse` now
  routes `tool_input` and `tool_response` through this richer path
  before persisting to the events table.
- `clx model fetch` now verifies the cached model directory contains
  non-zero `tokenizer.json`, `special_tokens_map.json`, `config.json`,
  and `model.onnx` (at root or `onnx/` subdir) before writing the
  `.ready` sentinel, and acquires `.fetch.lock` BEFORE any
  `--force`-driven `remove_dir_all`. fastembed-rs continues to verify
  per-blob LFS SHA-256 during download; our gate catches partial /
  poisoned caches.
- `FastembedReranker::score` lazy-loads the ONNX session inside the
  same `tokio::task::spawn_blocking` as the rerank call, so the outer
  `tokio::time::timeout` budget governs cold loads instead of being
  bypassed by a synchronous `ensure_loaded()`.
- `stop_auto_summary` re-reads the last `AutoSummary` snapshot
  timestamp immediately before its own write; if another handler
  landed a summary inside the active window, the duplicate write is
  skipped.
- Plugin manifest (`plugin/.claude-plugin/plugin.json`) drops the
  non-spec `mcp_servers: {}` field (the 2026 schema uses a separate
  `.mcp.json` file at plugin root) and adds the optional `author` /
  `license` fields per the official Claude Code plugin reference. All
  six `SKILL.md` frontmatters drop the non-spec `version:` field; the
  Claude Code 2026 skill spec only defines `description` as
  recommended and several functional optional keys. Skill versioning
  now lives exclusively in `plugin.json`.

### Fixed

- **Repeated macOS keychain password prompt, eliminated at the root.**
  CLX no longer uses the macOS keychain by default. A parallel
  Codex + research investigation established definitively that no
  macOS keychain API can serve an unsigned / adhoc-signed binary
  prompt-free: the legacy keychain re-prompts on every read because
  its "Always Allow" ACL binds to a code signature that an
  adhoc-signed binary does not stably have, and the iOS-style
  data-protection keychain outright rejects unsigned binaries with
  `errSecMissingEntitlement (-34018)`. Therefore the keychain cannot
  be the default secret store for a tool distributed without an Apple
  Developer ID. CLX now follows the 2026 dev-CLI consensus
  (`gh`, `aws`, `stripe`, `doppler`, `cargo`): a local file backend by
  default, keychain opt-in.
  - New `CredentialBackend` trait under `CredentialStore`; scoping,
    validation, indexing, and the session cache are unchanged above it.
  - New default `AgeFileBackend`: secrets stored in
    `~/.clx/credentials.age` (mode 0600), encrypted with `age`
    (age-encryption.org v1, X25519 + ChaCha20-Poly1305) under a random
    identity at `~/.clx/cred.key` (mode 0600); `~/.clx` is 0700. Writes
    are atomic (temp file + rename). Encrypted at rest specifically to
    defeat the realistic CLX exposure path (dotfile sync, backups,
    log/support bundles); a same-uid attacker remains out of scope, as
    it is for the keychain.
  - `KeyringBackend` retains the previous keychain code and is selected
    only when the user explicitly sets `credentials.backend: keychain`
    (or `CLX_CREDENTIALS_BACKEND=keychain`). Default is `file`.
  - Credential resolution is now env (`api_key_env`) then the selected
    backend then `api_key_file`; under the default backend the keychain
    code path is never reached. Every credential-construction callsite
    (`resolve_azure_credential`, the MCP server, the `clx credentials`
    and `clx keychain-trust` commands) was repointed through a single
    config-aware constructor so nothing silently falls through to the
    keychain. A regression test asserts zero keychain calls under the
    default backend.
  - Fixed a latent `SecAccessCreate(NULL)` defect in the opt-in
    keychain path: `NULL` means "trust only the calling app" (the
    opposite of the intended permissive access); it now passes an
    empty trusted-application list, and the misleading comments were
    corrected. The opt-in keychain remains best-effort for adhoc
    binaries by macOS design.
  - New `clx credentials migrate <key>`: explicit, one-time move of a
    secret that exists only in the legacy keychain into the file
    backend. This is the single place a keychain prompt may still
    occur, and only when the user runs it deliberately and the secret
    is not already available from env / `api_key_file` / the file
    backend. Automatic paths never read the keychain.
  - Net result: a fresh user with default config sees zero macOS
    keychain prompts for the entire Claude Code session, with no code
    signing, no manual `security` command, and no temporary toggle.

  Superseded earlier in this release cycle (kept for historical
  context): an interim session-scoped credential cache
  (`CredentialStore::new_cached`, `secrecy::SecretString`, zeroized on
  drop, owned by `McpServer`) and a `clx keychain-trust` repair command
  that relaxed the legacy keychain ACL with a single documented
  `security set-generic-password-partition-list` call. Both still exist
  and are correct for the opt-in keychain backend, but are no longer on
  the default path. The original interim note read:
- **(interim, now superseded by the file backend above)** The `clx-mcp`
  server re-read `com.clx.credentials` from the OS keychain on every
  credential-bearing tool invocation (e.g. each `clx_credentials`
  call), so macOS prompted far more often than necessary.
  `CredentialStore` gained an opt-in session-scoped cache
  (`CredentialStore::new_cached`) holding values as
  `secrecy::SecretString` (zeroized on drop, redacting `Debug`); the
  cache is owned by the `McpServer` and lives exactly as long as the
  server process (not a global static). The first read for a given
  scoped key hits the keychain; subsequent reads (including negative
  results and both legs of a fallback lookup) are served from memory.
  Concurrent first access converges to a single keychain read.
  Non-MCP callers (CLI, hook) keep the previous uncached semantics.
  Note: a complete fix also requires the Homebrew binary to be signed
  with an Apple Developer ID so the keychain "Always Allow" ACL
  persists across launches; that lives in the Homebrew formula
  (separate repo), not this codebase. Mid-session credential rotation
  is reflected only after an MCP server restart (standard
  cached-credential tradeoff); in-session `store`/`delete` invalidate
  the affected entry.

### Security (Red/Green/Purple Team review)

Three findings from the Purple Team synthesis were fixed before tag:

- **F10 audit-log secret leak (HIGH)**: `PostToolUse` was writing the
  raw extracted Bash/MCP command to `audit_log.command` without
  redaction; the `pre_tool_use` path correctly wraps via
  `log_audit_entry`. Fix: `post_tool_use.rs` now redacts the command
  through `redact_secrets` before `AuditLogEntry::new`.
- **F4 recall context XML injection (HIGH)**: stored snapshot
  summaries and key_facts were injected verbatim into the
  `<historical-context>` block, letting a malicious `clx_remember`
  payload close the wrapper and inject system-style instructions. Fix:
  `format_recall_context` now escapes `<` and `>` in summary and
  key_facts via `sanitize_recall_text`. Regression test
  `test_format_context_escapes_xml_in_summary`.
- **F1 free-text redaction gaps (MEDIUM)**: `redact_secrets` missed
  `api_key = sk_test_...` (whitespace around `=`/`:`), lowercase
  `bearer`, and `Authorization: Basic ...`. Fix: added section 3
  (case-insensitive `bearer ` / `basic ` scheme prefix) above a new
  section 2b (whitespace-tolerant keyword scan). Four regression tests.

### Security (remaining Purple Team findings, also fixed in 0.8.0)

The five findings the Purple Team had classified as 0.8.1-deferrable
were pulled forward into 0.8.0 since the release had not yet shipped:

- **F3** Stop auto-summary write race (TOCTOU): new
  `Storage::create_snapshot_if_no_recent_auto_summary` performs the
  freshness guard and the `INSERT` as a single
  `INSERT ... SELECT ... WHERE NOT EXISTS` inside a `BEGIN IMMEDIATE`
  transaction. Concurrent Stop handlers now produce exactly one
  AutoSummary snapshot. No schema migration required.
- **F5** Auto-summarize prompt content injection: `build_prompt` wraps
  the turns block in a per-call random nonce fence
  (`BEGIN_TURNS_<nonce>` / `END_TURNS_<nonce>`) and neutralizes forged
  role headers and fence/section literals in each turn's content. This
  is the 2026-standard structural-delimitation + neutralization defense
  (escaping is unreliable for LLMs). Anti-forgery nonce is std-only
  (`SystemTime` + atomic counter, SplitMix64 avalanche), no new dep.
- **F7** Hook envelope provenance: `clx-hook` now classifies
  invocation provenance from the `CLAUDE_PROJECT_DIR` /
  `CLAUDE_PLUGIN_ROOT` env vars Claude Code sets for plugin hooks
  (verified against the 2026 official hooks docs). Operates fail-safe
  (WARN + continue on `Unverified`, never a hard block) because a false
  positive that disables all hooks is worse than the residual same-uid
  risk already in the threat model. Pure decision function is unit
  tested; the env read sits at the `main.rs` orchestration edge so the
  contract tests (which drive `handle_event` directly) are unaffected.
- **F8** Transcript path hardening: a new `safe_transcript_path`
  canonicalizes the envelope-supplied path (resolving symlinks and
  `..`) and enforces `MAX_TRANSCRIPT_BYTES = 64 MiB` before opening, on
  all three read sites (`last_n_turns`, `count_transcript_tokens`,
  `process_transcript`). A filesystem allowlist was deliberately not
  added because relocated-config users and the test suite legitimately
  point at arbitrary paths; canonicalize + size-cap bounds the read
  scope without that fragility.
- **F9** Reranker model integrity: `clx model fetch` now writes a
  content-pinned sentinel (`clx-model-sentinel v1` with
  `sha256:`/`size:`/`path:` lines) covering both `model.onnx` and the
  large external `model.onnx.data` weights blob. `ready_at` re-verifies
  the digest, gated to at most once per process via `OnceLock` with a
  cheap size short-circuit so the recall hot path is not penalized.
  Trust-on-first-verified-fetch then verify-on-every-use (SSH
  known_hosts / pip-hash-pinning model). Legacy opaque sentinels from
  pre-F9 dev builds are treated as not-ready so the model is re-fetched
  and re-pinned. Residual risk (a same-uid attacker who rewrites both
  the file and the sentinel) is inherent to any local scheme without an
  external root of trust and is documented in code.
- **Recall pipeline layering refactor.** The Domain layer in
  `crates/clx-core/src/recall/` no longer imports `Storage`,
  `LlmClient`, or `EmbeddingStore` directly. Two new ports live in
  `recall/ports.rs`: `SnapshotRepo` (sync, snapshot reads) and
  `QueryEmbedder` (async, query embedding). `RecallEngine` (now in
  `recall/engine.rs`) depends only on the trait references; the
  concrete `Storage` impl lives in the new
  `crates/clx-core/src/storage/recall_repo.rs::StorageSnapshotRepo`
  and the `LlmClient + EmbeddingStore + Option<model>` adapter lives
  in `recall/adapters.rs::LlmQueryEmbedder`. Existing call sites
  (`clx-hook::subagent::do_recall`, `clx-mcp::tools::recall`,
  recall_accuracy bench) wire the adapters at construction time. The
  public builder API (`with_reranker`, `with_embedding_model`,
  `with_model_ident`) is preserved. Layering proof: production
  Domain modules import zero infrastructure types.

### Decisions (resolved with user, 2026-05-16)

1. `reranker_enabled = true` by default in 0.8.0 (ships with
   `clx model fetch` background prefetch + per-query 250 ms graceful
   degradation to RRF-only)
2. `retention.tool_events_days = 30` by default, configurable per
   deployment
3. Auto-summarize mode IS in 0.8.0, opt-in (default off)
4. Coverage CI gate stays warn-only in 0.8.0 (hard-fail flip planned for
   0.8.1)
5. Golden set is synthetic-only in 0.8.0 (user-derived layer deferred to
   0.8.1)

### Notes

- Plugin migration is a manual one-shot via `plugin/scripts/migrate.sh`;
  the old `plugin/skills/` path will be removed in 0.9.0
- `bge-reranker-v2-m3` is a 568 MB download (one-time, lazy); set
  `auto_recall.reranker_enabled: false` to opt out
- Existing per-project configs continue to apply only the inert-key
  allowlist until `clx config-trust add <path>` registers their hash

## [0.7.2] - 2026-05-02

### Fixed
- Auto-recall (`UserPromptSubmit` hook) silently produced no semantic
  context when embeddings were routed to Azure OpenAI. The recall path
  called `embed(query, None)`; Azure rejects `None` with
  `DeploymentNotFound` (only Ollama tolerated it via its own
  baked-in default). `RecallEngine` now accepts an explicit embedding
  model via `with_embedding_model(...)`, and both production callers
  (`clx-hook` auto-recall and `clx-mcp` `clx_recall` tool) pass the
  configured `llm.embeddings.model`. FTS5 fallback was working all
  along, but the headline semantic-recall feature was dark on
  Azure-routed embeddings until this fix.

## [0.7.1] - 2026-05-02

### Fixed
- Audit log foreign-key constraint failure on every L0-decided hook call.
  `Storage::create_audit_log` now ensures the referenced session row exists
  via `INSERT OR IGNORE` before the audit insert. Synthetic / fast-path /
  fabricated session IDs no longer trip the FK.
- File logging was never wired up — `logging.file: ~/.clx/logs/clx.log` in
  the config was silently ignored. `clx-hook` now opens the configured log
  path (with `~` expansion already implemented in `Config::log_file_path`)
  and writes WARN+ events there. stderr remains ERROR-only so Claude Code's
  hook stderr-handling is unaffected.

## [0.7.0] - 2026-04-30

### Added
- Automatic primary→secondary LLM provider fallback. New `fallback:` field on
  each capability route in `llm.chat` / `llm.embeddings`. When the primary
  fails with a transient error (Connection, Timeout, RateLimit, 5xx, 408),
  the configured fallback runs automatically. The fallback's `model` field
  overrides the caller's model name (providers don't share model identifiers).
- 30-second in-process cooldown after a fallback event — primary is skipped
  during the cooldown window so sustained outages don't pay the latency
  penalty of always retrying the primary first.
- Per-project config override at `<repo>/.clx/config.yaml`, discovered by
  walking from CWD up to `$HOME`. Env-var escape: `CLX_CONFIG_PROJECT=/path`
  or `CLX_CONFIG_PROJECT=none` to disable.
- Layered config loading via `figment`: built-in defaults → global →
  project → `CLX_*` env vars → CLI flags (lowest to highest precedence).
- Inert-keys allowlist for project configs: only routing-related keys
  (provider, model, fallback, validator thresholds, auto_recall, etc.)
  take effect from a project file. Security-sensitive keys
  (`providers.*`, `logging.file`, `validator.enabled`) are silently
  dropped with a single `WARN` per dropped key.
- New `LlmClient::Fallback(FallbackClient)` enum variant. Single insertion
  point at the factory; zero production call sites changed.

### Changed
- `is_transient` is now a method on `LlmError` (was a private free function
  in `azure.rs`). Backends and the new fallback wrapper share one predicate.
- `Config::load` now goes through `figment` instead of direct
  `serde_yml::from_str`. Existing single-file configs continue to work
  unchanged.

### Deferred to v0.7.x
- `clx trust <repo>` UX command for promoting non-inert project keys past
  the allowlist (mise-style trust gating).
- Multi-fallback chains (`fallback: [a, b, c]`).
- Cross-process cooldown persistence.

## [0.6.1] - 2026-04-30

### Fixed
- Azure provider keychain credential resolution: 0.6.0 looked up the entry as
  `<provider>:api-key`, but `CredentialStore` rejects colons in user keys, so
  the entry was unwriteable through `clx credentials set`. 0.6.1 uses
  `<provider>-api-key` (hyphen). Users who configured Azure via env var
  (`AZURE_OPENAI_API_KEY`) are unaffected. Users who tried the keychain path
  on 0.6.0 should retry with:
  `clx credentials set <provider-name>-api-key '<your-key>'`
- Error message when no credentials are available now prints the exact
  `clx credentials set …` command to run as a fix.

## [0.6.0] - 2026-04-30

### Added
- Azure OpenAI as an opt-in remote LLM backend alongside the existing local
  Ollama client, behind a unified `LlmBackend` trait
- New config schema with `providers:` and `llm:` sections supporting
  per-capability routing (chat and embeddings can route to different providers
  independently)
- Hand-rolled Azure client targeting the v1 OpenAI-compatible API
  (`/openai/v1/chat/completions`, `/openai/v1/embeddings`, `/openai/v1/models`),
  with optional dated-URL escape hatch via `api_version`
- Layered API-key resolution (env var → existing `CredentialStore` keychain
  → 0600 file), wrapped in `secrecy::SecretString` end-to-end
- Embedding-model identity tracking (`embedding_model` column on snapshots);
  recall refuses on mismatch with a clear `clx embeddings rebuild` instruction
- Provider-aware `clx embeddings rebuild` that refuses to run when the
  configured provider is unavailable
- Per-provider `clx health` with routing summary
- `clx config migrate` to rewrite legacy `ollama:` config to the new schema
- `clx credentials list` annotates entries that match a configured provider
- Dashboard Settings tab shows per-provider routing and credential source
  (never the secret value)
- Manual Azure smoke-test checklist in `CONTRIBUTING.md`

### Changed
- `OllamaClient` moved behind `LlmBackend` trait; static dispatch via
  `LlmClient` enum (no `dyn Trait` heap allocation in hot paths)
- `ollama_health` module renamed to `llm_health`; cache keyed by provider name
- Existing `ollama:` config block silently auto-translates to the new schema
  in memory on load — on-disk file is never modified without `clx config
  migrate`. Roll-back to a pre-0.6 CLX remains safe.

### Fixed
- Bump `rustls-webpki` 0.103.10 → 0.103.13 to address RUSTSEC-2026-0098,
  RUSTSEC-2026-0099, and RUSTSEC-2026-0104 (transitive dep via reqwest)

### Security
- New host allowlist guard for Azure provider endpoints (`*.openai.azure.com`,
  `*.azure-api.net`); override via `CLX_ALLOW_AZURE_HOSTS` env var only.
  Symmetric to the existing localhost SSRF guard for Ollama.
- Credentials never accepted as CLI arg (would leak to `ps`); never logged or
  displayed in `Debug`/`Display` impls.

## [0.5.0] - 2026-03-27

### Added
- Dashboard session detail drill-down: press Enter on any session to see
  full-screen detail with 4 sub-tabs (Info, Commands, Audit, Snapshots)
- Info tab: session metadata, token/command/risk statistics
- Commands tab: scrollable audit entries with decision reasoning detail pane
- Audit tab: event timeline with tool use input/output details
- Snapshots tab: snapshot list with expandable summary, key facts, and TODOs

## [0.4.0] - 2026-03-27

### Added
- `clx trust on/off/status` command for managing auto-allow mode with
  configurable duration (5m-24h), session scoping, and JSON token metadata
- `clx install` now auto-installs Ollama via Homebrew, starts the server,
  and pulls required models automatically
- `clx health` command: runs 9 concurrent system validators and reports
  status in colored table or JSON (`--json`)
- Config fields: `trust_mode_max_duration`, `trust_mode_default_duration`

### Fixed
- Flaky hook integration tests eliminated with isolated temp directories
