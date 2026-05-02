# Changelog

All notable changes to CLX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
