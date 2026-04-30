# Azure OpenAI Backend — Design Spec

**Date:** 2026-04-16
**Status:** Draft, pending user review
**Target version:** ships in the next minor CLX release after the current 0.5.x line (TBD; version pinned at implementation time)

## 1. Goal & Scope

### Goal

Add Azure OpenAI as an additional, opt-in LLM backend for CLX, behind a clean
provider trait shared with the existing Ollama client. Users keep the local-first
default; users who want a remote managed LLM configure Azure and route chat,
embeddings, or both to it without forking the codebase.

The plugin is a backend addition. It does not replace Ollama, does not change
the local-first install story, and does not change the `clx_*` MCP tool surface.

### In scope (v1)

- `LlmBackend` trait in `crates/clx-core/src/llm.rs` exposing the three methods
  the production code path actually uses today (`generate`, `embed`,
  `is_available`).
- Two concrete implementations behind that trait:
  - `OllamaBackend` — the existing Ollama client, refactored to implement the
    trait. Continues to use Ollama's native `/api/generate`, `/api/embed`,
    `/api/tags` endpoints (not Ollama's experimental OpenAI-compat layer).
  - `AzureOpenAIBackend` — new, hand-rolled `reqwest` + `serde` client (~200 LoC
    estimate), targeting Azure's v1 OpenAI-compatible path
    (`/openai/v1/chat/completions`, `/openai/v1/embeddings`,
    `/openai/v1/models`).
- New config schema with `providers:` and `llm:` sections. Per-capability
  routing — chat and embeddings can route to different providers in the same
  install. Single config file at `~/.clx/config.yaml`. Legacy `ollama:` block
  silently auto-translated on load.
- API-key authentication for Azure, sourced via a layered resolver
  (env var → OS keychain → file). Wrapped in `secrecy::SecretString`
  end-to-end. Never accepted as a CLI arg.
- New CLI commands for credential management modeled on `gh auth`:
  `clx auth login | status | logout | token`.
- New CLI command `clx config migrate` to rewrite the legacy `ollama:` block
  into the new schema on demand.
- Embedding-model identity tracking: a new `embedding_model` column on the
  snapshots table; recall refuses on mismatch and prints
  `clx embeddings rebuild` as the fix.
- Test coverage with `wiremock` mirroring the existing `ollama.rs` pattern.

### Out of scope (v1, deferred to v2 or later)

- Microsoft Entra ID / device-code flow / managed identity. (`azure_identity`
  crate, token cache, refresh.)
- Streaming responses (SSE). CLX's call sites are short prompts; non-streaming
  is enough.
- Azure Responses API (`/openai/responses`). Chat Completions only.
- Per-project config files / layered config. Env var overrides cover the
  ad-hoc case.
- Automatic provider fallback on failure. Failures are loud; fallback must
  be explicit in user config (which v1 does not yet support).
- OpenAI public API as a third backend. Trivial to add later — same wire
  format, different `BaseUrl` and `AuthScheme`.

## 2. Architecture

### 2.1 Trait

A new module `crates/clx-core/src/llm.rs`:

```rust
#[trait_variant::make(LlmBackend: Send)]
pub trait LocalLlmBackend {
    async fn generate(&self, prompt: &str, model: Option<&str>)
        -> Result<String, LlmError>;
    async fn embed(&self, text: &str, model: Option<&str>)
        -> Result<Vec<f32>, LlmError>;
    async fn is_available(&self) -> bool;
}
```

- Native `async fn` in trait (Rust 1.75+); no `#[async_trait]`, no
  `Pin<Box<dyn Future>>` allocation.
- `#[trait_variant::make(...: Send)]` provides a `Send`-bounded variant for
  Tokio multi-threaded executors.
- Static dispatch via an enum, not `dyn LlmBackend`:

```rust
pub enum LlmClient {
    Ollama(OllamaBackend),
    Azure(AzureOpenAIBackend),
}

impl LlmClient {
    pub async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        match self {
            Self::Ollama(b) => b.generate(prompt, model).await,
            Self::Azure(b)  => b.generate(prompt, model).await,
        }
    }
    // analogous embed, is_available
}
```

Rationale: two backends, no plugin loading, no need for object safety.
Static dispatch is simpler, faster, and avoids `Box::pin` futures in hot
paths.

### 2.2 Error type

A unified `LlmError` replaces `OllamaError` in callsites. Variants:

| Variant                       | Source                                      |
| ----------------------------- | ------------------------------------------- |
| `Connection(String)`          | network unreachable, DNS failure            |
| `Timeout`                     | request exceeded `timeout_ms`               |
| `Auth(String)`                | 401 / 403 — bad or revoked credentials      |
| `RateLimit { retry_after: Option<Duration> }` | 429 with `Retry-After`        |
| `DeploymentNotFound(String)`  | 404 — wrong model/deployment name           |
| `ContentFilter(String)`       | Azure `content_filter_results` rejection    |
| `Server { status: u16, body: String }` | 5xx                                |
| `InvalidResponse(String)`     | malformed JSON, missing required fields     |
| `Serialization(serde_json::Error)` | encode failure                         |

`OllamaError` becomes a subset that maps into `LlmError` via `From`.

### 2.3 Factory & wiring

A factory in `config.rs`:

```rust
pub fn create_llm_client(config: &Config, capability: Capability)
    -> Result<LlmClient, ConfigError>;
```

`Capability` is `Chat` or `Embeddings`. The factory looks up the routing in
`config.llm.<capability>`, finds the named provider in `config.providers`,
and constructs the backend with credentials resolved from the layered
secret resolver (§5).

All ~8 callsites in the workspace (Agent 3's map) replace
`OllamaClient::new(config.ollama)` with
`config.create_llm_client(Capability::Chat)` or `Capability::Embeddings`
as appropriate.

### 2.4 Module layout

```
crates/clx-core/src/
├── llm.rs              # NEW: trait, LlmClient enum, LlmError, factory glue
├── llm/
│   ├── ollama.rs       # MOVED from src/ollama.rs; refactored to impl LlmBackend
│   ├── azure.rs        # NEW: AzureOpenAIBackend
│   └── retry.rs        # NEW: extracted from ollama.rs's retry_with_backoff
├── llm_health.rs       # RENAMED from ollama_health.rs; provider-agnostic cache
└── secrets.rs          # NEW: layered resolver, SecretString wrapper
```

Old `src/ollama.rs` and `src/ollama_health.rs` paths disappear; the existing
content is moved, not rewritten. All public symbols re-exported from
`llm.rs` so external `use clx_core::ollama::OllamaClient` callers continue
to compile during the migration via deprecation shims.

## 3. Wire Format (Azure)

### 3.1 Chat completions

```
POST https://<resource>.openai.azure.com/openai/v1/chat/completions
Headers:
  api-key: <secret>
  Content-Type: application/json
Body:
  {
    "model": "<deployment-name>",
    "messages": [{ "role": "user", "content": "<prompt>" }],
    "max_completion_tokens": <configurable, default 2048>
  }
```

Response: standard OpenAI shape. CLX reads
`choices[0].message.content`, ignores everything else for v1.

### 3.2 Embeddings

```
POST https://<resource>.openai.azure.com/openai/v1/embeddings
Headers: api-key, Content-Type as above.
Body:
  {
    "model": "<embedding-deployment>",
    "input": "<text>",
    "dimensions": 1024
  }
```

`dimensions: 1024` uses Matryoshka-style truncation (supported on
`text-embedding-3-large` and `text-embedding-3-small`). This preserves the
existing sqlite-vec schema width (1024-d) so no schema migration is
required for the storage table itself. Vectors are still in a different
vector space than Ollama's (§6).

### 3.3 Health probe

```
GET https://<resource>.openai.azure.com/openai/v1/models
Headers: api-key
```

Returns the deployment list visible to the API key. CLX treats any 2xx as
"available." Result cached for 60s in the existing health cache (renamed
to `llm_health.rs`, keyed by provider name).

### 3.4 Escape hatch — dated URL shape

If the user sets `providers.<name>.api_version` to a non-empty string (e.g.
`"2024-10-21"`), the backend switches to the dated path:

```
POST https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<version>
```

Default is unset — the v1 path is used.

### 3.5 Host validation

`AzureOpenAIBackend` enforces that `endpoint`'s host matches one of:

- `*.openai.azure.com` (the canonical Azure OpenAI domain)
- `*.azure-api.net` (API Management front for some enterprise setups)
- whatever is set in `CLX_ALLOW_AZURE_HOSTS=` (comma-separated allowlist) for
  emulators and dev tenants

Constructor returns `LlmError::Connection("host not in azure allowlist")`
otherwise. Symmetric with the localhost guard in `OllamaBackend`.

## 4. Config Schema

### 4.1 New shape (single `~/.clx/config.yaml`)

```yaml
providers:
  ollama-local:
    kind: ollama
    host: http://127.0.0.1:11434
    timeout_ms: 60000
  azure-prod:
    kind: azure_openai
    endpoint: https://<your-resource>.openai.azure.com
    api_key_env: AZURE_OPENAI_API_KEY    # name of env var to read; never inlined
    # api_version: "2024-10-21"           # optional; default unset = v1 path
    timeout_ms: 30000

llm:
  chat:
    provider: azure-prod
    model: gpt-5.4-mini                   # = Azure deployment name
  embeddings:
    provider: ollama-local
    model: qwen3-embedding:0.6b
```

`providers.<name>.kind` discriminates the union; unknown kinds are a
deserialize error.

`api_key_env` always names an env var. The actual key value never appears
in the config file. If the env var is unset at runtime, the resolver
falls back to keychain (§5).

### 4.2 Env var overrides

For ad-hoc per-invocation switching:

| Env var                          | Overrides                                |
| -------------------------------- | ---------------------------------------- |
| `CLX_LLM_CHAT_PROVIDER=<name>`   | `llm.chat.provider`                      |
| `CLX_LLM_CHAT_MODEL=<name>`      | `llm.chat.model`                         |
| `CLX_LLM_EMBEDDINGS_PROVIDER=...`| `llm.embeddings.provider`                |
| `CLX_LLM_EMBEDDINGS_MODEL=...`   | `llm.embeddings.model`                   |
| `AZURE_OPENAI_API_KEY=<secret>`  | resolved via secret resolver (§5)        |

Precedence highest-to-lowest: env var → config file → built-in default.

### 4.3 Legacy auto-translate

When `~/.clx/config.yaml` contains the legacy `ollama:` block and no
`providers:` / `llm:` sections, CLX synthesizes in memory:

```yaml
providers:
  ollama-local:
    kind: ollama
    host: <ollama.host>
    timeout_ms: <ollama.timeout_ms>
llm:
  chat:       { provider: ollama-local, model: <ollama.model> }
  embeddings: { provider: ollama-local, model: <ollama.embedding_model> }
```

The on-disk file is **never** touched by this translation. Roll-back to a
prior CLX version continues to work because the legacy keys are still
present.

`clx config migrate` writes the synthesized config back to disk, leaves a
backup at `~/.clx/config.yaml.bak`, and prints a one-line confirmation.

If both legacy and new sections are present, the new sections win and the
legacy block is ignored (with a `WARN` log line on first load).

## 5. Authentication & Secrets

### 5.1 Resolution order

For each provider needing credentials:

1. **Environment variable** named in `providers.<name>.api_key_env`. Highest
   precedence.
2. **OS keychain entry** under service `clx`, account
   `<provider-name>:api-key`, accessed via the `keyring` crate v3.
3. **Config-file fallback** — only if `providers.<name>.api_key_file:
   <path>` is set (path must be mode 0600). On read, CLX warns:
   `WARN: api key for '<name>' loaded from plaintext file; consider 'clx auth login'`.
4. **None** — return `LlmError::Auth("no credentials for provider <name>")`.

### 5.2 In-memory hygiene

- All credentials wrap in `secrecy::SecretString`.
- `Debug` and `Display` impls on any struct holding a `SecretString` print
  `[REDACTED]`.
- `zeroize` (transitively from `secrecy`) wipes memory on drop.
- The HTTP layer extracts the raw value via `.expose_secret()` only at the
  point of building the request header. Nowhere else.

### 5.3 CLI commands

```
clx auth login    --provider <name>   # interactive rpassword prompt; writes to keychain
clx auth status                       # lists providers, source tier per provider, fingerprint (last 4 chars only)
clx auth logout   --provider <name>   # deletes keychain entry
clx auth token    --provider <name>   # prints to stdout ONLY when stdout is not a TTY
```

`clx auth token` follows `gh auth token`'s safety pattern: if stdout is a
TTY, exit non-zero with `refusing to print token to terminal; pipe to a
file or command instead`.

The key is **never** acceptable as a CLI argument. There is no
`--api-key=<value>` flag — that would leak into `ps`, shell history, and
process accounting.

### 5.4 Keychain backend per OS

- macOS: Keychain Services via `keyring`'s default backend.
- Linux: Secret Service via D-Bus. On headless / no-D-Bus systems CLX
  prints a clear diagnostic and falls through to env var. Never silently
  falls through to plaintext file.
- Windows: not supported by CLX overall today; keyring code paths compile
  in case future cross-platform work picks them up.

## 6. Embedding Migration

A new `embedding_model TEXT NOT NULL` column on the snapshots table records
which model produced each stored vector. Default value for the migration
that adds the column: `'<unknown-pre-migration>'` for pre-existing rows.

On startup, the recall engine compares
`config.llm.embeddings.{provider, model}` against the most recent
`embedding_model` value in the snapshots table. If they differ:

- `clx_recall` and CLI `clx recall` return:
  ```
  embedding model changed
    stored: <old-provider>:<old-model>
    config: <new-provider>:<new-model>
  vectors are not comparable across providers/models.
  run 'clx embeddings rebuild' to re-embed all snapshots.
  ```
- Auto-recall in `additionalContext` injection silently degrades to FTS5-only
  (no semantic search) until rebuilt. A one-line `WARN` is logged once per
  session.

`clx embeddings rebuild` is extended:

- Reads the configured embedding provider/model.
- Iterates all snapshots, re-embeds via the configured backend, writes back
  to `snapshot_embeddings`.
- Updates `snapshots.embedding_model` to the new identifier.
- Shows a progress bar for long runs (existing UI primitive).
- Refuses to run if the configured provider is unavailable
  (`is_available() == false`); prints a clear "fix the provider first" error.

`clx embeddings status` reports the current `embedding_model` and dimension
of stored vectors vs. configured.

## 7. Failure Model

### 7.1 Retries

A new `crates/clx-core/src/llm/retry.rs` module extracts the existing
`retry_with_backoff` helper from `ollama.rs`. Both backends use it.

- Retry on: `408`, `429`, `500`, `502`, `503`, `504`, connect errors, timeout.
- Never retry: `400`, `401`, `403`, `404`, `422` (errors that won't get
  better on retry).
- Honor `Retry-After` header on 429/503; clamp to `min(Retry-After,
  computed_backoff_max)`.
- Exponential backoff with jitter: base 250ms, factor 2.0, cap 10s, max
  attempts 4 (1 initial + 3 retries).
- Existing `OllamaConfig` fields `max_retries`, `retry_delay_ms`,
  `retry_backoff` move to a per-provider `retry: { ... }` block; defaults
  preserved.

### 7.2 No automatic cross-provider fallback

If `llm.chat.provider` fails, CLX surfaces the failure. It does **not**
silently retry against `llm.embeddings.provider` or any other provider.
A risk-assessment CLI that silently degrades produces wrong-but-confident
answers; the cure is worse than the disease.

Explicit user-configurable fallback is deferred to v2 if requested.

### 7.3 Telemetry capture

On every Azure response, CLX captures and logs (at `INFO` level):

- `x-request-id` — append to all error messages so support cases are
  traceable.
- `x-ratelimit-remaining-requests`, `x-ratelimit-remaining-tokens` — log
  every 10th call to avoid spam, and on every `429`. Not displayed in
  `clx dashboard` for v1; can be added later.

These headers are absent on Ollama responses; the code path tolerates
their absence.

### 7.4 Content filter

Azure may return a 200 response with `content_filter_results` indicating a
soft block, or a 400 with `code: "content_filter"`. Both map to
`LlmError::ContentFilter(<filter-category>)`. The error surfaces with the
exact category (`hate`, `self-harm`, `sexual`, `violence`,
`jailbreak`, etc.) so the user can decide whether to rephrase.

CLX does **not** disable, downgrade, or retry around content filters. They
are working as intended; bypassing them silently would be wrong.

## 8. Defaults & Backward Compatibility

### 8.1 Fresh install

A brand-new install with no `~/.clx/config.yaml` writes the local-first
default:

```yaml
providers:
  ollama-local:
    kind: ollama
    host: http://127.0.0.1:11434
llm:
  chat:       { provider: ollama-local, model: qwen3:1.7b }
  embeddings: { provider: ollama-local, model: qwen3-embedding:0.6b }
```

Azure is opt-in: the user adds a `providers.azure-prod` block, runs
`clx auth login --provider azure-prod`, and edits the `llm:` block to
route there.

### 8.2 Upgrade

Existing install with the legacy `ollama:` block: §4.3 auto-translation
applies. No on-disk change. Existing behavior preserved bit-for-bit; the
`is_available` health check, retry semantics, embedding storage, and
recall results are unchanged.

### 8.3 Roll-back

Because `clx config migrate` is opt-in and otherwise the on-disk config is
untouched, downgrading CLX to a pre-Azure version always works against
the same `~/.clx/config.yaml`.

## 9. Testing

### 9.1 Unit / wiremock

`AzureOpenAIBackend` mirrors `ollama.rs`'s wiremock pattern. Required
coverage:

- `generate()` happy path (200 with valid JSON).
- `generate()` with explicit deployment override.
- `embed()` happy path with `dimensions=1024` round-trip.
- 401 → `LlmError::Auth`.
- 404 → `LlmError::DeploymentNotFound`.
- 429 with `Retry-After: 2` → retried once, succeeds, returns OK.
- 429 with `Retry-After` exceeding max attempts → `LlmError::RateLimit`.
- 500 → retried then surfaced as `LlmError::Server`.
- Content-filter 400 → `LlmError::ContentFilter("hate")`.
- Host outside the Azure allowlist → constructor returns
  `LlmError::Connection`.
- `is_available()` 200 → `true`; non-2xx → `false`.

### 9.2 Refactor coverage

After the trait extraction, every existing Ollama test in
`ollama.rs` continues to pass — the implementation is the same, the public
API just moved behind the trait. Net new code is the trait, the enum, and
the Azure backend; existing code is structurally rearranged, not
rewritten.

### 9.3 No real-Azure CI

CI does not hit a real Azure tenant. Reasons: secrets in CI, cost,
flakiness, region availability of `gpt-5.4-mini`. Real-tenant validation
is a manual smoke test run by the author before each release, documented
in `CONTRIBUTING.md`:

1. Set `AZURE_OPENAI_API_KEY` and an Azure-routed config.
2. `clx health` — passes.
3. `clx recall "anything"` — works against the configured embedding
   provider.
4. Trigger a `pre_tool_use` validation on a non-trivial command — risk
   score returned by Azure backend.
5. Check `clx auth status` shows the Azure provider with the right
   fingerprint and source tier.

### 9.4 Integration / hook tests

The existing `clx-hook/tests/integration.rs` cases for "Ollama
unavailable" run unchanged; equivalent cases parameterize over the
provider so the same scenarios cover Azure-unavailable.

## 10. Observability & Diagnostics

- `clx health` — extended to probe each configured provider in the
  `providers:` map and show one row per provider: name, kind, endpoint,
  health, last `x-request-id` if any.
- `clx dashboard` Settings tab — extended to display the current
  `llm.chat.provider`/`llm.embeddings.provider` and credential source
  tier per provider, never the secret value.
- Logs include `x-request-id` on every Azure error.
- `clx auth status` shows fingerprint (last 4 chars) only.

## 11. Risks & Open Questions

### Risks

1. **Azure tenant disables local auth.** Some Microsoft tenants set
   `disableLocalAuth=true`, blocking API-key auth entirely. Users in
   those tenants cannot use the v1 plugin. Mitigation: clearly
   documented in `clx auth login --provider azure` error output;
   Entra ID flow is the v2 fix.
2. **Embedding-model identity drift.** If a user changes
   `llm.embeddings.model` without rebuilding, recall degrades to
   FTS5-only silently for auto-recall (with a `WARN`). Risk: users miss
   the warning and assume search is broken. Mitigation: `clx health`
   surfaces "embeddings: model mismatch — run rebuild" as a red row.
3. **Preview API drift.** If a user sets `api_version` to a preview
   value (escape hatch) and Microsoft force-upgrades it, requests start
   failing. Mitigation: docs explicitly call out that the escape hatch
   is for current-state debugging, not long-term pinning.
4. **Cost surprise on Azure.** Embedding all snapshots when migrating
   from Ollama to Azure embeddings can cost real money on large
   histories. Mitigation: `clx embeddings rebuild` shows estimated token
   count and prompts for confirmation when the configured provider is
   Azure. (Implementation detail; estimation is sum of snapshot lengths
   ÷ ~4 chars/token.)
5. **Keychain availability on headless Linux.** No D-Bus =
   keyring failure. Mitigation: clear diagnostic, fall through to env
   var, never to plaintext file.

### Open questions (decide during implementation, not blocking the spec)

- **a.** Whether `clx auth login` writes to keychain by default or asks
  the user explicitly. Default: write to keychain, with a one-line
  confirmation message that says where it went.
- **b.** Exact format of the `embedding_model` identifier string —
  `<provider>:<model>` (`azure-prod:text-embedding-3-large`) is the
  current proposal, finalize during implementation.
- **c.** Whether `clx config migrate` is interactive (asks before
  writing) or non-interactive (writes immediately, prints summary).
  Default: non-interactive, user already opted in by running the command.

## 12. Versioning & Release

- New CLX minor version bump (e.g. 0.5.x → 0.6.0) when this lands.
  Because the config schema gains new sections and the legacy block is
  auto-translated rather than rejected, this is **not** a breaking
  change for users — but the new feature surface justifies a minor bump.
- The CLX Claude Code plugin (`plugin/`) ships unchanged in this release
  except for its `plugin.json` version field bumping in lockstep with
  CLX, per the existing rule in `CONTRIBUTING.md`.
- The `using-clx` skill in the plugin gains a paragraph mentioning the
  Azure backend exists and that `clx_recall` / `clx_remember` /
  `clx_checkpoint` work the same regardless of which provider the user
  has configured. No new MCP tools.

## 13. Implementation Order (informational, plan owns this)

The `writing-plans` step that follows this spec will decompose the work.
For sanity-checking the spec is shaped right, the rough order is:

1. Extract `LlmBackend` trait + `LlmError` + `LlmClient` enum.
2. Move `OllamaClient` behind the trait; all existing tests pass unchanged.
3. Rename `ollama_health.rs` → `llm_health.rs`; key cache by provider name.
4. Add `secrets.rs` with the layered resolver and `SecretString` wrapper.
5. Add `AzureOpenAIBackend` + its wiremock test suite.
6. Add the new config schema; legacy auto-translate.
7. Add `clx auth login | status | logout | token` commands.
8. Add `clx config migrate`.
9. Add embedding-model identity column + migration check + extended
   `clx embeddings rebuild`.
10. Extend `clx health` and `clx dashboard` for per-provider visibility.
11. Update `CONTRIBUTING.md` with the manual Azure smoke test checklist.
12. Update `using-clx` skill with the one-paragraph addition.

Each step lands as its own commit / sub-PR. Existing CI's coverage gate
(70% line coverage) is enforced per-step.
