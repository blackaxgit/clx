# Azure OpenAI Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Azure OpenAI as an opt-in remote LLM backend in CLX, behind a unified `LlmBackend` trait shared with the existing Ollama client. Per-capability routing, layered-secret resolution, no breaking changes for current installs.

**Architecture:** Extract a provider-neutral `LlmBackend` trait in `clx-core/src/llm.rs`. Refactor the existing Ollama client to implement it; introduce a new hand-rolled `reqwest`-based `AzureOpenAIBackend`. Static dispatch via an `LlmClient` enum (no `dyn Trait`). Single `~/.clx/config.yaml` gains `providers:` and `llm:` sections; legacy `ollama:` block silently auto-translates on load. API-key auth via `secrecy::SecretString` resolved from env → OS keychain → file (0600 with warning).

**Tech Stack:** Rust 1.85+ (workspace), Tokio async, `reqwest` HTTP, `serde` JSON, `wiremock` tests, `secrecy` + `zeroize` for in-memory hygiene, `keyring` v3 for OS keychain, `trait_variant` for `Send`-bounded async traits, `rpassword` for terminal prompts.

**Spec:** `specs/2026-04-16-azure-openai-backend-design.md`

---

## File Structure

| Path                                                  | Status         | Responsibility                                                                |
| ----------------------------------------------------- | -------------- | ----------------------------------------------------------------------------- |
| `crates/clx-core/Cargo.toml`                          | modify         | Add `trait_variant`, `secrecy`, `keyring`, `rpassword` deps.                  |
| `crates/clx-core/src/llm.rs`                          | **new**        | `LlmBackend` trait, `LlmError`, `LlmClient` enum, factory.                    |
| `crates/clx-core/src/llm/mod.rs`                      | **new**        | Re-exports for the `llm` submodule tree.                                      |
| `crates/clx-core/src/llm/ollama.rs`                   | **moved**      | From `src/ollama.rs`; refactored to `impl LlmBackend`.                        |
| `crates/clx-core/src/llm/azure.rs`                    | **new**        | `AzureOpenAIBackend`, host allowlist, retry-aware HTTP.                       |
| `crates/clx-core/src/llm/retry.rs`                    | **new**        | Extracted from `ollama.rs`'s `retry_with_backoff`. Shared by both backends.   |
| `crates/clx-core/src/llm_health.rs`                   | **renamed**    | From `ollama_health.rs`. Cache keyed by provider name.                        |
| `crates/clx-core/src/secrets.rs`                      | **new**        | Layered resolver, `SecretString` wrapper, keyring access.                     |
| `crates/clx-core/src/config.rs`                       | modify         | New `providers:` + `llm:` schema, legacy auto-translate, factory.             |
| `crates/clx-core/src/error.rs`                        | modify         | `LlmError` aggregated into `crate::Error`.                                    |
| `crates/clx-core/src/recall.rs`                       | modify         | Replace `&OllamaClient` param with `&LlmClient` (chat path) and (embed path). |
| `crates/clx-core/src/policy/llm.rs`                   | modify         | Replace `&OllamaClient` with `&LlmClient`.                                    |
| `crates/clx-core/src/embeddings.rs`                   | modify         | Track `embedding_model` per row.                                              |
| `crates/clx-core/migrations/<n>_embedding_model.sql`  | **new**        | Add `embedding_model TEXT NOT NULL DEFAULT '<unknown-pre-migration>'`.         |
| `crates/clx-hook/src/embedding.rs`                    | modify         | Use `LlmClient` factory, write `embedding_model` value.                       |
| `crates/clx-hook/src/hooks/pre_tool_use.rs`           | modify         | Use `LlmClient` factory.                                                      |
| `crates/clx-hook/src/hooks/subagent.rs`               | modify         | Use `LlmClient` factory.                                                      |
| `crates/clx-hook/src/transcript.rs`                   | modify         | Use `LlmClient` factory.                                                      |
| `crates/clx-mcp/src/server.rs`                        | modify         | Use `LlmClient` factory.                                                      |
| `crates/clx-mcp/src/tools/recall.rs`                  | modify         | Use `LlmClient` factory.                                                      |
| `crates/clx/src/commands/recall.rs`                   | modify         | Use `LlmClient` factory.                                                      |
| `crates/clx/src/commands/embeddings.rs`               | modify         | Use `LlmClient` factory; provider-aware rebuild; mismatch detection.          |
| `crates/clx/src/commands/health.rs`                   | modify         | Probe each configured provider; one row per provider.                         |
| `crates/clx/src/commands/auth.rs`                     | **new**        | `clx auth login | status | logout | token` subcommands.                       |
| `crates/clx/src/commands/config.rs`                   | **new** or modify | `clx config migrate` subcommand.                                           |
| `crates/clx/src/main.rs`                              | modify         | Register new `auth` and `config` subcommands.                                 |
| `crates/clx/src/dashboard/settings/`                  | modify         | Show per-provider routing and credential source tier.                         |
| `CONTRIBUTING.md`                                     | modify         | Add Azure manual smoke test checklist.                                        |
| `plugin/skills/using-clx/SKILL.md`                    | modify         | Add one paragraph noting Azure backend exists, MCP tools are unchanged.       |
| `crates/clx-core/tests/integration.rs`                | modify         | Parameterize "provider unavailable" tests over both backends.                 |

---

## Task 1: Add new Cargo dependencies

**Files:**
- Modify: `crates/clx-core/Cargo.toml`
- Modify: `crates/clx/Cargo.toml`

- [ ] **Step 1: Read current `crates/clx-core/Cargo.toml` to find the `[dependencies]` section**

Run: `grep -n "^\[dependencies\]" crates/clx-core/Cargo.toml`
Expected: line number printed.

- [ ] **Step 2: Add deps to `crates/clx-core/Cargo.toml` under `[dependencies]`**

Add these lines (preserve alphabetical order if the file uses one; otherwise append):

```toml
keyring = { version = "3", default-features = false, features = ["apple-native", "linux-native-sync-persistent"] }
secrecy = { version = "0.10", features = ["serde"] }
trait-variant = "0.1"
```

- [ ] **Step 3: Add deps to `crates/clx/Cargo.toml`**

```toml
rpassword = "7"
```

(Only the CLI binary needs `rpassword`; the core lib does not.)

- [ ] **Step 4: Verify the workspace builds**

Run: `cargo build --workspace`
Expected: clean build, no warnings on the new deps. If `keyring` v3 features differ on your platform, adjust the feature flags to match your `cargo build` output exactly.

- [ ] **Step 5: Commit**

```bash
git add crates/clx-core/Cargo.toml crates/clx/Cargo.toml Cargo.lock
git commit -m "build(deps): add keyring, secrecy, trait-variant, rpassword"
```

---

## Task 2: Define `LlmBackend` trait, `LlmError`, and `LlmClient` enum

**Files:**
- Create: `crates/clx-core/src/llm.rs`
- Create: `crates/clx-core/src/llm/mod.rs`
- Modify: `crates/clx-core/src/lib.rs` — add `pub mod llm;`

- [ ] **Step 1: Create `crates/clx-core/src/llm/mod.rs`**

```rust
//! LLM backend abstractions and concrete implementations.

mod ollama;
mod azure;
mod retry;

pub use ollama::OllamaBackend;
pub use azure::AzureOpenAIBackend;
pub use retry::with_backoff;
```

(`ollama.rs` and `azure.rs` are added in Tasks 3 and 7 respectively. This module file references them up front so we have one place to look; the inner files start as stubs and grow.)

- [ ] **Step 2: Create `crates/clx-core/src/llm/ollama.rs` and `crates/clx-core/src/llm/azure.rs` and `crates/clx-core/src/llm/retry.rs` as empty stubs**

```rust
// crates/clx-core/src/llm/ollama.rs
pub struct OllamaBackend;
```

```rust
// crates/clx-core/src/llm/azure.rs
pub struct AzureOpenAIBackend;
```

```rust
// crates/clx-core/src/llm/retry.rs
// Retry helper extracted in Task 3.
```

- [ ] **Step 3: Create `crates/clx-core/src/llm.rs` with the trait, error, and enum**

```rust
//! Provider-neutral LLM client surface.

use std::time::Duration;
use thiserror::Error;

/// All operations the production code path performs against an LLM provider.
///
/// Only three methods because that's what `clx-hook`, `clx-mcp`, `clx-core::recall`,
/// and `clx-core::policy::llm` actually call. `list_models` from the legacy
/// Ollama client was unused outside tests and is intentionally not part of the
/// trait.
#[trait_variant::make(LlmBackend: Send)]
pub trait LocalLlmBackend {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError>;
    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError>;
    async fn is_available(&self) -> bool;
}

/// Provider-neutral error type. Concrete backends map their wire-level errors
/// into these variants.
#[derive(Debug, Error)]
pub enum LlmError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("request timed out")]
    Timeout,
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("rate limited (retry_after: {retry_after:?})")]
    RateLimit { retry_after: Option<Duration> },
    #[error("deployment or model not found: {0}")]
    DeploymentNotFound(String),
    #[error("content filter triggered: {0}")]
    ContentFilter(String),
    #[error("server error {status}: {body}")]
    Server { status: u16, body: String },
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Static-dispatch wrapper that owns one of the concrete backend types and
/// forwards trait calls. Avoids `Box<dyn LlmBackend>` and the heap allocation
/// it forces on every async call.
pub enum LlmClient {
    Ollama(crate::llm::OllamaBackend),
    Azure(crate::llm::AzureOpenAIBackend),
}

impl LlmClient {
    pub async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        match self {
            Self::Ollama(b) => b.generate(prompt, model).await,
            Self::Azure(b) => b.generate(prompt, model).await,
        }
    }

    pub async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        match self {
            Self::Ollama(b) => b.embed(text, model).await,
            Self::Azure(b) => b.embed(text, model).await,
        }
    }

    pub async fn is_available(&self) -> bool {
        match self {
            Self::Ollama(b) => b.is_available().await,
            Self::Azure(b) => b.is_available().await,
        }
    }
}
```

(The `impl LlmBackend for OllamaBackend` and `impl LlmBackend for AzureOpenAIBackend` blocks live in the next tasks; for now the stubs in step 2 prevent the compiler errors from `LlmClient`'s match arms — they will fail to typecheck until Task 3 lands the Ollama impl, which is fine: `cargo check` after this step is allowed to fail with "method `generate` not found on `OllamaBackend`". Step 4 confirms.)

- [ ] **Step 4: Add `pub mod llm;` to `crates/clx-core/src/lib.rs`**

```rust
// add near other `pub mod` lines
pub mod llm;
```

- [ ] **Step 5: Run `cargo check -p clx-core` — expect failure**

Run: `cargo check -p clx-core`
Expected: errors of the form `no method named 'generate' found for struct 'OllamaBackend'`. This is the "red" state — Task 3 makes it pass.

- [ ] **Step 6: Commit (compile-broken state is intentional, parked by next task)**

```bash
git add crates/clx-core/src/llm.rs crates/clx-core/src/llm/ crates/clx-core/src/lib.rs
git commit -m "feat(llm): add LlmBackend trait, LlmError, LlmClient enum (stubs)"
```

---

## Task 3: Refactor existing `OllamaClient` to implement `LlmBackend`

**Files:**
- Move/rewrite: `crates/clx-core/src/ollama.rs` → `crates/clx-core/src/llm/ollama.rs`
- Move/rewrite: relevant retry helper → `crates/clx-core/src/llm/retry.rs`
- Modify: `crates/clx-core/src/lib.rs` to remove the old `pub mod ollama;` line

The behavior of the Ollama client must not change — same endpoints, same retry semantics, same SSRF guard, same error variants (now mapped via `From<OllamaError> for LlmError`). Existing tests in `ollama.rs` move with the file and continue to pass.

- [ ] **Step 1: Read the existing `crates/clx-core/src/ollama.rs`**

Run: `wc -l crates/clx-core/src/ollama.rs`
Expected: ~840 lines.

- [ ] **Step 2: Move the file**

```bash
git mv crates/clx-core/src/ollama.rs crates/clx-core/src/llm/ollama.rs
```

- [ ] **Step 3: Extract the `retry_with_backoff` function into `crates/clx-core/src/llm/retry.rs`**

Find the helper in `crates/clx-core/src/llm/ollama.rs` (it's a local `async fn retry_with_backoff<...>`). Cut it out, paste into `retry.rs`, and rename to `with_backoff`. Make it `pub`. Remove any `OllamaError`-specific fields from the signature; parameterize over a generic `Err` that the caller maps. Concrete signature:

```rust
//! Generic retry-with-backoff for transient HTTP failures.
//! Used by every LLM backend so retry semantics are identical.

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub backoff_factor: f64,
    pub max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(250),
            backoff_factor: 2.0,
            max_delay: Duration::from_secs(10),
        }
    }
}

pub async fn with_backoff<T, E, F, Fut>(
    cfg: RetryConfig,
    mut op: F,
    is_transient: impl Fn(&E) -> bool,
    retry_after: impl Fn(&E) -> Option<Duration>,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut delay = cfg.base_delay;
    let mut attempt = 0u32;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < cfg.max_retries && is_transient(&e) => {
                let wait = retry_after(&e).unwrap_or(delay).min(cfg.max_delay);
                tokio::time::sleep(wait).await;
                delay = (delay.mul_f64(cfg.backoff_factor)).min(cfg.max_delay);
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}
```

Then, in `crates/clx-core/src/llm/ollama.rs`, replace the previous in-line retry calls with `crate::llm::retry::with_backoff(...)`. The existing `OllamaError::is_retryable` predicate becomes the `is_transient` closure.

- [ ] **Step 4: Add the `LlmBackend` impl for `OllamaClient` (renamed `OllamaBackend`)**

At the top of `crates/clx-core/src/llm/ollama.rs`, change the type name from `OllamaClient` to `OllamaBackend` (rename via search/replace within the file). Keep `pub use crate::llm::OllamaBackend as OllamaClient;` re-export at the bottom of the file as a deprecation shim — old `use clx_core::ollama::OllamaClient` callsites continue to compile during Task 4.

Append:

```rust
use crate::llm::{LlmError, LocalLlmBackend};

impl From<OllamaError> for LlmError {
    fn from(e: OllamaError) -> Self {
        match e {
            OllamaError::ConnectionFailed(s) => LlmError::Connection(s),
            OllamaError::Timeout => LlmError::Timeout,
            OllamaError::HttpError { status, body } if status == 401 || status == 403 => {
                LlmError::Auth(body)
            }
            OllamaError::HttpError { status, body } if status == 429 => {
                LlmError::RateLimit { retry_after: None }
            }
            OllamaError::HttpError { status, body } if status == 404 => {
                LlmError::DeploymentNotFound(body)
            }
            OllamaError::HttpError { status, body } => LlmError::Server { status, body },
            OllamaError::InvalidResponse(s) => LlmError::InvalidResponse(s),
            OllamaError::ModelNotFound(s) => LlmError::DeploymentNotFound(s),
            OllamaError::ServerError(s) => LlmError::Server { status: 500, body: s },
            OllamaError::SerializationError(e) => LlmError::Serialization(e),
        }
    }
}

impl LocalLlmBackend for OllamaBackend {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        // Existing implementation already returns Result<String, OllamaError>.
        // Map at the boundary.
        self.generate_inner(prompt, model).await.map_err(LlmError::from)
    }
    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        self.embed_inner(text, model).await.map_err(LlmError::from)
    }
    async fn is_available(&self) -> bool {
        self.is_available_inner().await
    }
}
```

Rename the existing `pub async fn generate` / `embed` / `is_available` methods on `OllamaBackend` to `pub(crate) async fn generate_inner` / etc. (still returning `Result<_, OllamaError>` internally) so the trait impl can wrap them. This keeps the existing in-file unit tests working unchanged.

- [ ] **Step 5: Run `cargo check -p clx-core`**

Run: `cargo check -p clx-core`
Expected: clean. If errors mention `OllamaError` not having a variant you matched on, add the missing arm to the `From` impl.

- [ ] **Step 6: Run the moved Ollama unit tests**

Run: `cargo test -p clx-core --lib llm::ollama`
Expected: all the tests that were previously in `ollama.rs` continue to pass.

- [ ] **Step 7: Commit**

```bash
git add crates/clx-core/src/llm/ crates/clx-core/src/lib.rs
git commit -m "refactor(llm): move OllamaClient behind LlmBackend trait"
```

---

## Task 4: Replace `OllamaClient::new(...)` callsites with `LlmClient` factory

**Files (all modify):**
- `crates/clx-core/src/recall.rs:732` (test code)
- `crates/clx-core/src/recall.rs:123` (semantic embed)
- `crates/clx-core/src/policy/llm.rs:121`
- `crates/clx-hook/src/embedding.rs:12`
- `crates/clx-hook/src/embedding.rs:30`
- `crates/clx-hook/src/hooks/pre_tool_use.rs:276,318`
- `crates/clx-hook/src/hooks/subagent.rs:99`
- `crates/clx-hook/src/transcript.rs:138`
- `crates/clx-mcp/src/server.rs:76`
- `crates/clx-mcp/src/tools/recall.rs`
- `crates/clx/src/commands/recall.rs:36`
- `crates/clx/src/commands/embeddings.rs:166,281`

The factory does not yet exist; for this task, each callsite gets a temporary helper:

```rust
fn build_legacy_client(cfg: &OllamaConfig) -> Result<LlmClient, LlmError> {
    Ok(LlmClient::Ollama(OllamaBackend::new(cfg.clone())?))
}
```

Task 11 replaces that helper with the real `Config::create_llm_client(Capability)` factory.

- [ ] **Step 1: Add the temporary helper to `crates/clx-core/src/llm.rs`**

```rust
use crate::config::OllamaConfig;

impl LlmClient {
    /// TEMPORARY: Task 4 uses this until Task 11 wires the real config-driven
    /// factory. Constructs an Ollama-only client from the legacy config block.
    pub fn from_legacy_ollama(cfg: &OllamaConfig) -> Result<Self, LlmError> {
        let backend = crate::llm::OllamaBackend::new(cfg.clone())
            .map_err(LlmError::from)?;
        Ok(Self::Ollama(backend))
    }
}
```

- [ ] **Step 2: Update each callsite, one file at a time**

Pattern for replacement:

```rust
// before
let client = OllamaClient::new(config.ollama.clone())?;
let summary = client.generate(&prompt, None).await?;

// after
let client = LlmClient::from_legacy_ollama(&config.ollama)?;
let summary = client.generate(&prompt, None).await?;
```

Update each of the files listed above. For `recall.rs:123` and `embeddings.rs`, the new shape is the same — `LlmClient::embed(text, None)` returns `Result<Vec<f32>, LlmError>` instead of `Result<Vec<f32>, OllamaError>`. The recall engine and embeddings command propagate the error via `?` and existing `From<OllamaError> for crate::Error` carries it through.

For `policy/llm.rs:121`, the `OllamaClient` field on `PolicyEngine` becomes `LlmClient`. Ripple updates touch the constructor and any test code that builds a `PolicyEngine`.

- [ ] **Step 3: Run the full test suite**

Run: `cargo test --workspace`
Expected: all tests pass. Any failure is almost certainly a missed callsite or a struct field type that needs updating.

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "refactor(llm): switch all Ollama callsites to LlmClient::from_legacy_ollama"
```

---

## Task 5: Rename `ollama_health.rs` → `llm_health.rs`, key cache by provider name

**Files:**
- Move: `crates/clx-core/src/ollama_health.rs` → `crates/clx-core/src/llm_health.rs`
- Modify: `crates/clx-core/src/lib.rs`
- Modify: every file that `use clx_core::ollama_health::...`

Today's cache file uses a single global cache file (`~/.clx/cache/ollama_health.json`). The new shape uses per-provider cache files (`~/.clx/cache/health/<provider-name>.json`) so Ollama and Azure don't fight over the same key.

- [ ] **Step 1: Move the file**

```bash
git mv crates/clx-core/src/ollama_health.rs crates/clx-core/src/llm_health.rs
```

- [ ] **Step 2: Rewrite the cache key**

Inside `llm_health.rs`, change the cache-file path computation from a constant `"ollama_health.json"` to a function:

```rust
pub fn health_cache_path(provider_name: &str) -> std::path::PathBuf {
    crate::paths::cache_dir().join("health").join(format!("{provider_name}.json"))
}
```

Update every call to read/write the cache to take a `provider_name: &str` argument.

- [ ] **Step 3: Update `lib.rs`**

```rust
// remove
pub mod ollama_health;
// add
pub mod llm_health;
```

Add a deprecation shim: `pub use llm_health as ollama_health;` so external callers don't break in the same commit.

- [ ] **Step 4: Update callsites**

Use grep to find every `use clx_core::ollama_health::` — typical sites are in `clx-hook/src/hooks/pre_tool_use.rs` and possibly `clx/src/commands/health.rs`. Each call now passes `"ollama-local"` (or whatever the configured provider name is) as the cache key.

- [ ] **Step 5: Run tests**

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add -u
git commit -m "refactor(llm): rename ollama_health to llm_health, key cache by provider"
```

---

## Task 6: Add `secrets.rs` with layered resolver and `SecretString` wrapper

**Files:**
- Create: `crates/clx-core/src/secrets.rs`
- Modify: `crates/clx-core/src/lib.rs` — `pub mod secrets;`
- Test: in-file unit tests + `tests/integration.rs` if needed.

- [ ] **Step 1: Write `crates/clx-core/src/secrets.rs`**

```rust
//! Layered credential resolver.
//!
//! Resolution order (highest precedence first):
//!   1. Environment variable named in the provider config.
//!   2. OS keychain entry under service "clx", account "<provider>:api-key".
//!   3. Plaintext config file at the configured path (mode must be 0600).
//!
//! All credentials are wrapped in `secrecy::SecretString` end-to-end. Debug
//! and Display impls on holding structs print "[REDACTED]". `.expose_secret()`
//! is called only at the HTTP boundary.

use secrecy::SecretString;
use std::path::Path;
use thiserror::Error;

const KEYRING_SERVICE: &str = "clx";

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("no credentials available for provider '{0}' (checked env, keychain, file)")]
    NotFound(String),
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("file mode for {path} is {mode:o}; refuse to read (must be 0600)")]
    InsecureFileMode { path: String, mode: u32 },
    #[error("io error reading {path}: {source}")]
    Io { path: String, #[source] source: std::io::Error },
}

#[derive(Debug, Clone)]
pub struct CredentialSpec {
    pub provider_name: String,
    pub env_var: Option<String>,
    pub file_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    Env,
    Keychain,
    File,
}

pub struct ResolvedCredential {
    pub value: SecretString,
    pub source: CredentialSource,
}

pub fn resolve(spec: &CredentialSpec) -> Result<ResolvedCredential, SecretError> {
    // 1. Env var
    if let Some(name) = spec.env_var.as_deref() {
        if let Ok(v) = std::env::var(name) {
            if !v.is_empty() {
                return Ok(ResolvedCredential {
                    value: SecretString::new(v.into()),
                    source: CredentialSource::Env,
                });
            }
        }
    }

    // 2. Keychain
    let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("{}:api-key", spec.provider_name))
        .map_err(|e| SecretError::Keychain(e.to_string()))?;
    match entry.get_password() {
        Ok(v) => return Ok(ResolvedCredential {
            value: SecretString::new(v.into()),
            source: CredentialSource::Keychain,
        }),
        Err(keyring::Error::NoEntry) => { /* fall through */ }
        Err(e) => {
            // Headless Linux without D-Bus, etc. — log and fall through.
            tracing::warn!(provider = %spec.provider_name, error = %e, "keychain unavailable");
        }
    }

    // 3. File
    if let Some(path) = spec.file_path.as_deref() {
        return read_file_credential(path);
    }

    Err(SecretError::NotFound(spec.provider_name.clone()))
}

#[cfg(unix)]
fn read_file_credential(path: &Path) -> Result<ResolvedCredential, SecretError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|source| SecretError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(SecretError::InsecureFileMode {
            path: path.display().to_string(),
            mode,
        });
    }
    let value = std::fs::read_to_string(path).map_err(|source| SecretError::Io {
        path: path.display().to_string(),
        source,
    })?;
    tracing::warn!(path = %path.display(), "api key loaded from plaintext file; consider 'clx auth login'");
    Ok(ResolvedCredential {
        value: SecretString::new(value.trim().to_string().into()),
        source: CredentialSource::File,
    })
}

#[cfg(not(unix))]
fn read_file_credential(_path: &Path) -> Result<ResolvedCredential, SecretError> {
    Err(SecretError::Keychain("file credential not supported on this OS".into()))
}

pub fn store_in_keychain(provider_name: &str, secret: &SecretString) -> Result<(), SecretError> {
    use secrecy::ExposeSecret;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("{}:api-key", provider_name))
        .map_err(|e| SecretError::Keychain(e.to_string()))?;
    entry.set_password(secret.expose_secret())
        .map_err(|e| SecretError::Keychain(e.to_string()))
}

pub fn delete_from_keychain(provider_name: &str) -> Result<(), SecretError> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("{}:api-key", provider_name))
        .map_err(|e| SecretError::Keychain(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(SecretError::Keychain(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_from_env() {
        std::env::set_var("CLX_TEST_KEY", "secret-from-env");
        let spec = CredentialSpec {
            provider_name: "test".into(),
            env_var: Some("CLX_TEST_KEY".into()),
            file_path: None,
        };
        let r = resolve(&spec).unwrap();
        assert_eq!(r.source, CredentialSource::Env);
        std::env::remove_var("CLX_TEST_KEY");
    }

    #[test]
    fn missing_everywhere_returns_not_found() {
        let spec = CredentialSpec {
            provider_name: "definitely-does-not-exist-clx-test".into(),
            env_var: Some("CLX_DEFINITELY_UNSET_VAR_XYZ".into()),
            file_path: None,
        };
        match resolve(&spec) {
            Err(SecretError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    #[cfg(unix)]
    fn rejects_insecure_file_mode() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"insecure-key\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let spec = CredentialSpec {
            provider_name: "test".into(),
            env_var: None,
            file_path: Some(path),
        };
        match resolve(&spec) {
            Err(SecretError::InsecureFileMode { mode, .. }) => assert_eq!(mode, 0o644),
            other => panic!("expected InsecureFileMode, got {:?}", other),
        }
    }
}
```

(`tempfile` is a dev-dependency already used elsewhere in the workspace; if not, add to `[dev-dependencies]` of `clx-core`.)

- [ ] **Step 2: Add `pub mod secrets;` to `crates/clx-core/src/lib.rs`**

- [ ] **Step 3: Run the new tests**

Run: `cargo test -p clx-core --lib secrets`
Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/clx-core/src/secrets.rs crates/clx-core/src/lib.rs crates/clx-core/Cargo.toml
git commit -m "feat(secrets): add layered credential resolver with keychain support"
```

---

## Task 7: Implement `AzureOpenAIBackend` — happy path + wiremock test

**Files:**
- Modify: `crates/clx-core/src/llm/azure.rs` (replace stub)
- Modify: `crates/clx-core/Cargo.toml` (already has `reqwest`, `serde_json`, `wiremock` dev-dep)

The Azure backend is hand-rolled `reqwest`. It speaks the OpenAI v1 path on Azure (`/openai/v1/chat/completions`, `/openai/v1/embeddings`, `/openai/v1/models`), uses the `api-key` header, and supports an optional `api_version` escape hatch for the dated URL shape.

- [ ] **Step 1: Define the config struct in `crates/clx-core/src/config.rs`**

(Full schema lands in Task 10; for this task add the minimum needed.)

```rust
// crates/clx-core/src/config.rs - append
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureOpenAIConfig {
    pub endpoint: String,
    pub api_key_env: Option<String>,
    pub api_key_file: Option<std::path::PathBuf>,
    #[serde(default)]
    pub api_version: Option<String>,
    #[serde(default = "default_azure_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub retry: crate::llm::retry::RetryConfig,
}

fn default_azure_timeout() -> u64 { 30_000 }
```

(`RetryConfig` already implements `Deserialize` if you derived it; if not, add `#[derive(Deserialize, Serialize, Debug, Clone, Copy)]` to it in `retry.rs`.)

- [ ] **Step 2: Write `crates/clx-core/src/llm/azure.rs`**

```rust
//! Azure OpenAI backend (hand-rolled reqwest client).
//!
//! Targets the v1 OpenAI-compatible path by default. If the user sets
//! `api_version` in the provider config, switches to the dated URL shape
//! (`/openai/deployments/<deployment>/...?api-version=<v>`).

use crate::config::AzureOpenAIConfig;
use crate::llm::retry::{with_backoff, RetryConfig};
use crate::llm::{LlmError, LocalLlmBackend};
use crate::secrets::{CredentialSpec, ResolvedCredential};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct AzureOpenAIBackend {
    endpoint: Url,
    api_key: SecretString,
    api_version: Option<String>,
    timeout: Duration,
    retry: RetryConfig,
    http: reqwest::Client,
}

const ALLOWED_HOST_SUFFIXES: &[&str] = &[
    ".openai.azure.com",
    ".azure-api.net",
];

impl AzureOpenAIBackend {
    pub fn new(cfg: &AzureOpenAIConfig, api_key: SecretString) -> Result<Self, LlmError> {
        let endpoint = Url::parse(&cfg.endpoint)
            .map_err(|e| LlmError::Connection(format!("invalid endpoint URL: {e}")))?;
        Self::validate_host(&endpoint)?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()
            .map_err(|e| LlmError::Connection(format!("http client init: {e}")))?;

        Ok(Self {
            endpoint,
            api_key,
            api_version: cfg.api_version.clone().filter(|s| !s.is_empty()),
            timeout: Duration::from_millis(cfg.timeout_ms),
            retry: cfg.retry,
            http,
        })
    }

    fn validate_host(url: &Url) -> Result<(), LlmError> {
        let host = url.host_str().ok_or_else(|| {
            LlmError::Connection("endpoint URL has no host".into())
        })?;

        // Allow override for dev tenants / emulators.
        if let Ok(allowlist) = std::env::var("CLX_ALLOW_AZURE_HOSTS") {
            for h in allowlist.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if host == h { return Ok(()); }
            }
        }

        for suffix in ALLOWED_HOST_SUFFIXES {
            if host.ends_with(suffix) { return Ok(()); }
        }
        Err(LlmError::Connection(format!(
            "host '{host}' not in azure allowlist (set CLX_ALLOW_AZURE_HOSTS to override)"
        )))
    }

    fn chat_url(&self, deployment: &str) -> Url {
        match &self.api_version {
            Some(v) => {
                let mut u = self.endpoint.clone();
                u.set_path(&format!("/openai/deployments/{deployment}/chat/completions"));
                u.query_pairs_mut().clear().append_pair("api-version", v);
                u
            }
            None => {
                let mut u = self.endpoint.clone();
                u.set_path("/openai/v1/chat/completions");
                u
            }
        }
    }

    fn embeddings_url(&self, deployment: &str) -> Url {
        match &self.api_version {
            Some(v) => {
                let mut u = self.endpoint.clone();
                u.set_path(&format!("/openai/deployments/{deployment}/embeddings"));
                u.query_pairs_mut().clear().append_pair("api-version", v);
                u
            }
            None => {
                let mut u = self.endpoint.clone();
                u.set_path("/openai/v1/embeddings");
                u
            }
        }
    }

    fn models_url(&self) -> Url {
        let mut u = self.endpoint.clone();
        match &self.api_version {
            Some(v) => {
                u.set_path("/openai/models");
                u.query_pairs_mut().clear().append_pair("api-version", v);
            }
            None => u.set_path("/openai/v1/models"),
        }
        u
    }
}

// Wire types --------------------------------------------------------------

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
}

#[derive(Serialize)]
struct ChatMessage<'a> { role: &'a str, content: &'a str }

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
    #[serde(default)]
    content_filter_results: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ChatChoiceMessage { content: String }

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<u32>,
}

#[derive(Deserialize)]
struct EmbedResponse {
    data: Vec<EmbedDatum>,
}

#[derive(Deserialize)]
struct EmbedDatum { embedding: Vec<f32> }

// Trait impl --------------------------------------------------------------

impl LocalLlmBackend for AzureOpenAIBackend {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        let deployment = model.ok_or_else(|| {
            LlmError::DeploymentNotFound("no model/deployment specified for chat".into())
        })?;
        let url = self.chat_url(deployment);
        let body = ChatRequest {
            model: deployment,
            messages: vec![ChatMessage { role: "user", content: prompt }],
            max_completion_tokens: Some(2048),
        };
        let req_id = post_with_retry(self, &url, &body, self.retry).await?;
        // post_with_retry returns the parsed ChatResponse — see helper below.
        // (For brevity in this plan, the helper is fully shown in Step 3.)
        unimplemented!("see Step 3 for the post_with_retry helper that returns ChatResponse")
    }

    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        let deployment = model.ok_or_else(|| {
            LlmError::DeploymentNotFound("no model/deployment specified for embeddings".into())
        })?;
        let url = self.embeddings_url(deployment);
        let body = EmbedRequest { model: deployment, input: text, dimensions: Some(1024) };
        // analogous helper invocation; see Step 3.
        unimplemented!("see Step 3 for embed_with_retry helper")
    }

    async fn is_available(&self) -> bool {
        let url = self.models_url();
        let resp = self.http.get(url)
            .header("api-key", self.api_key.expose_secret())
            .send().await;
        matches!(resp, Ok(r) if r.status().is_success())
    }
}
```

- [ ] **Step 3: Implement the typed helper functions for chat and embed (replaces the `unimplemented!()` lines)**

Inside `azure.rs` add:

```rust
async fn post_chat(
    backend: &AzureOpenAIBackend,
    url: &Url,
    body: &ChatRequest<'_>,
) -> Result<ChatResponse, LlmError> {
    let resp = backend.http.post(url.clone())
        .header("api-key", backend.api_key.expose_secret())
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| {
            if e.is_timeout() { LlmError::Timeout }
            else { LlmError::Connection(e.to_string()) }
        })?;
    map_response(resp).await
}

async fn post_embed(
    backend: &AzureOpenAIBackend,
    url: &Url,
    body: &EmbedRequest<'_>,
) -> Result<EmbedResponse, LlmError> {
    let resp = backend.http.post(url.clone())
        .header("api-key", backend.api_key.expose_secret())
        .header("Content-Type", "application/json")
        .json(body)
        .send().await
        .map_err(|e| {
            if e.is_timeout() { LlmError::Timeout }
            else { LlmError::Connection(e.to_string()) }
        })?;
    map_response(resp).await
}

async fn map_response<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T, LlmError> {
    let status = resp.status();
    let request_id = resp.headers().get("x-request-id").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if status.is_success() {
        let txt = resp.text().await.map_err(|e| LlmError::InvalidResponse(e.to_string()))?;
        serde_json::from_str(&txt).map_err(LlmError::Serialization)
    } else {
        let retry_after = resp.headers().get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs);
        let body = resp.text().await.unwrap_or_default();
        let body_with_id = if request_id.is_empty() { body.clone() } else {
            format!("{body} (x-request-id: {request_id})")
        };
        match status.as_u16() {
            401 | 403 => Err(LlmError::Auth(body_with_id)),
            404 => Err(LlmError::DeploymentNotFound(body_with_id)),
            408 => Err(LlmError::Timeout),
            429 => Err(LlmError::RateLimit { retry_after }),
            400 if body.contains("content_filter") => {
                Err(LlmError::ContentFilter(body_with_id))
            }
            s if (500..=599).contains(&s) => {
                Err(LlmError::Server { status: s, body: body_with_id })
            }
            s => Err(LlmError::Server { status: s, body: body_with_id }),
        }
    }
}
```

Now replace the `unimplemented!()` markers in the trait impl with:

```rust
async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
    let deployment = model.ok_or_else(|| {
        LlmError::DeploymentNotFound("no model/deployment specified for chat".into())
    })?;
    let url = self.chat_url(deployment);
    let body = ChatRequest {
        model: deployment,
        messages: vec![ChatMessage { role: "user", content: prompt }],
        max_completion_tokens: Some(2048),
    };
    let resp = with_backoff(
        self.retry,
        || post_chat(self, &url, &body),
        |e| matches!(e, LlmError::Timeout | LlmError::RateLimit { .. } |
                       LlmError::Server { status, .. } if (500..=599).contains(status) ||
                                                          *status == 408),
        |e| if let LlmError::RateLimit { retry_after } = e { *retry_after } else { None },
    ).await?;
    resp.choices.into_iter().next()
        .map(|c| c.message.content)
        .ok_or_else(|| LlmError::InvalidResponse("no choices returned".into()))
}

async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
    let deployment = model.ok_or_else(|| {
        LlmError::DeploymentNotFound("no model/deployment specified for embeddings".into())
    })?;
    let url = self.embeddings_url(deployment);
    let body = EmbedRequest { model: deployment, input: text, dimensions: Some(1024) };
    let resp = with_backoff(
        self.retry,
        || post_embed(self, &url, &body),
        |e| matches!(e, LlmError::Timeout | LlmError::RateLimit { .. } |
                       LlmError::Server { status, .. } if (500..=599).contains(status) ||
                                                          *status == 408),
        |e| if let LlmError::RateLimit { retry_after } = e { *retry_after } else { None },
    ).await?;
    resp.data.into_iter().next()
        .map(|d| d.embedding)
        .ok_or_else(|| LlmError::InvalidResponse("no embeddings returned".into()))
}
```

- [ ] **Step 4: Add wiremock test for the chat happy path**

Append to `azure.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

    fn cfg(endpoint: String) -> AzureOpenAIConfig {
        AzureOpenAIConfig {
            endpoint,
            api_key_env: None,
            api_key_file: None,
            api_version: None,
            timeout_ms: 5_000,
            retry: RetryConfig { max_retries: 0, ..Default::default() },
        }
    }

    fn allow_local_for_tests() {
        std::env::set_var("CLX_ALLOW_AZURE_HOSTS", "127.0.0.1,localhost");
    }

    #[tokio::test]
    async fn chat_happy_path() {
        allow_local_for_tests();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .and(matchers::header("api-key", "test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "hello back" } }]
            })))
            .mount(&mock).await;
        let backend = AzureOpenAIBackend::new(
            &cfg(mock.uri()),
            SecretString::new("test-key".to_string().into()),
        ).unwrap();
        let out = backend.generate("hello", Some("gpt-5.4-mini")).await.unwrap();
        assert_eq!(out, "hello back");
    }

    #[tokio::test]
    async fn embed_happy_path() {
        allow_local_for_tests();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{ "embedding": vec![0.1f32; 1024] }]
            })))
            .mount(&mock).await;
        let backend = AzureOpenAIBackend::new(
            &cfg(mock.uri()),
            SecretString::new("test-key".to_string().into()),
        ).unwrap();
        let v = backend.embed("text", Some("text-embedding-3-large")).await.unwrap();
        assert_eq!(v.len(), 1024);
    }

    #[tokio::test]
    async fn host_outside_allowlist_rejected() {
        std::env::remove_var("CLX_ALLOW_AZURE_HOSTS");
        let r = AzureOpenAIBackend::new(
            &cfg("https://evil.example.com".into()),
            SecretString::new("k".to_string().into()),
        );
        assert!(matches!(r, Err(LlmError::Connection(_))));
    }
}
```

- [ ] **Step 5: Run the new tests**

Run: `cargo test -p clx-core --lib llm::azure`
Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/clx-core/src/llm/azure.rs crates/clx-core/src/config.rs
git commit -m "feat(llm): implement AzureOpenAIBackend with chat, embed, health"
```

---

## Task 8: Add Azure error-mapping tests (auth, rate limit, deployment not found, content filter, server)

**Files:**
- Modify: `crates/clx-core/src/llm/azure.rs` (append tests)

- [ ] **Step 1: Append the error-case tests**

```rust
#[tokio::test]
async fn auth_401_maps_to_auth_error() {
    allow_local_for_tests();
    let mock = MockServer::start().await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&mock).await;
    let backend = AzureOpenAIBackend::new(
        &cfg(mock.uri()),
        SecretString::new("bad-key".to_string().into()),
    ).unwrap();
    let r = backend.generate("hi", Some("gpt-5.4-mini")).await;
    assert!(matches!(r, Err(LlmError::Auth(_))));
}

#[tokio::test]
async fn deployment_not_found_404() {
    allow_local_for_tests();
    let mock = MockServer::start().await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(404).set_body_string("deployment not found"))
        .mount(&mock).await;
    let backend = AzureOpenAIBackend::new(
        &cfg(mock.uri()),
        SecretString::new("k".to_string().into()),
    ).unwrap();
    let r = backend.generate("hi", Some("does-not-exist")).await;
    assert!(matches!(r, Err(LlmError::DeploymentNotFound(_))));
}

#[tokio::test]
async fn rate_limit_with_retry_after() {
    allow_local_for_tests();
    let mock = MockServer::start().await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(429)
            .insert_header("retry-after", "2")
            .set_body_string("too many"))
        .mount(&mock).await;
    let mut c = cfg(mock.uri());
    c.retry.max_retries = 0; // surface 429 immediately
    let backend = AzureOpenAIBackend::new(&c, SecretString::new("k".to_string().into())).unwrap();
    let r = backend.generate("hi", Some("gpt-5.4-mini")).await;
    match r {
        Err(LlmError::RateLimit { retry_after }) => {
            assert_eq!(retry_after, Some(Duration::from_secs(2)));
        }
        other => panic!("expected RateLimit, got {:?}", other),
    }
}

#[tokio::test]
async fn content_filter_400() {
    allow_local_for_tests();
    let mock = MockServer::start().await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            r#"{"error":{"code":"content_filter","message":"hate detected"}}"#))
        .mount(&mock).await;
    let backend = AzureOpenAIBackend::new(
        &cfg(mock.uri()),
        SecretString::new("k".to_string().into()),
    ).unwrap();
    let r = backend.generate("hi", Some("gpt-5.4-mini")).await;
    assert!(matches!(r, Err(LlmError::ContentFilter(_))));
}

#[tokio::test]
async fn server_500_after_retries_surfaced() {
    allow_local_for_tests();
    let mock = MockServer::start().await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
        .mount(&mock).await;
    let mut c = cfg(mock.uri());
    c.retry.max_retries = 1;
    let backend = AzureOpenAIBackend::new(&c, SecretString::new("k".to_string().into())).unwrap();
    let r = backend.generate("hi", Some("gpt-5.4-mini")).await;
    assert!(matches!(r, Err(LlmError::Server { status: 500, .. })));
}

#[tokio::test]
async fn is_available_returns_true_on_2xx() {
    allow_local_for_tests();
    let mock = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/openai/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data":[]})))
        .mount(&mock).await;
    let backend = AzureOpenAIBackend::new(
        &cfg(mock.uri()),
        SecretString::new("k".to_string().into()),
    ).unwrap();
    assert!(backend.is_available().await);
}

#[tokio::test]
async fn is_available_returns_false_on_5xx() {
    allow_local_for_tests();
    let mock = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/openai/v1/models"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock).await;
    let backend = AzureOpenAIBackend::new(
        &cfg(mock.uri()),
        SecretString::new("k".to_string().into()),
    ).unwrap();
    assert!(!backend.is_available().await);
}
```

- [ ] **Step 2: Run the new tests**

Run: `cargo test -p clx-core --lib llm::azure`
Expected: 10 tests pass total (3 from Task 7 + 7 added here).

- [ ] **Step 3: Commit**

```bash
git add crates/clx-core/src/llm/azure.rs
git commit -m "test(llm): cover Azure backend error paths and health probe"
```

---

## Task 9: Extend config schema with `providers:` and `llm:` sections + legacy auto-translate

**Files:**
- Modify: `crates/clx-core/src/config.rs`

- [ ] **Step 1: Add the new schema types**

Append to `config.rs`:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderConfig {
    Ollama(OllamaConfig),
    AzureOpenai(AzureOpenAIConfig),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LlmRouting {
    pub chat: CapabilityRoute,
    pub embeddings: CapabilityRoute,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CapabilityRoute {
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability { Chat, Embeddings }
```

Add fields to the top-level `Config` struct:

```rust
pub struct Config {
    // existing fields ...

    #[serde(default)]
    pub providers: std::collections::BTreeMap<String, ProviderConfig>,

    #[serde(default)]
    pub llm: Option<LlmRouting>,

    // legacy block — keep for auto-translate, may be None on new installs
    #[serde(default)]
    pub ollama: Option<OllamaConfig>,
}
```

(If `ollama` is currently `pub ollama: OllamaConfig` (non-optional), changing it to `Option<OllamaConfig>` is part of the auto-translate work. Update every place it's read.)

- [ ] **Step 2: Implement `load_with_translation`**

```rust
impl Config {
    /// Load config from the canonical path. If the loaded YAML has a legacy
    /// `ollama:` block but no `providers:`/`llm:` sections, synthesize them
    /// in memory. The on-disk file is NEVER touched.
    pub fn load_with_translation(path: &std::path::Path) -> Result<Self, ConfigError> {
        let mut cfg: Self = serde_yaml::from_str(&std::fs::read_to_string(path)?)?;
        cfg.translate_legacy_in_place();
        Ok(cfg)
    }

    fn translate_legacy_in_place(&mut self) {
        let has_new = !self.providers.is_empty() || self.llm.is_some();
        let has_old = self.ollama.is_some();

        if has_new && has_old {
            tracing::warn!(
                "config has both legacy 'ollama:' block and new 'providers:'/'llm:' sections; \
                 new sections win, legacy block ignored"
            );
            return;
        }
        if has_new || !has_old {
            return;
        }

        let legacy = self.ollama.clone().expect("has_old guard");
        self.providers.insert(
            "ollama-local".into(),
            ProviderConfig::Ollama(legacy.clone()),
        );
        self.llm = Some(LlmRouting {
            chat: CapabilityRoute {
                provider: "ollama-local".into(),
                model: legacy.model.clone(),
            },
            embeddings: CapabilityRoute {
                provider: "ollama-local".into(),
                model: legacy.embedding_model.clone(),
            },
        });
    }
}
```

- [ ] **Step 3: Implement `Config::create_llm_client(Capability)` factory**

```rust
impl Config {
    pub fn create_llm_client(&self, capability: Capability) -> Result<crate::llm::LlmClient, ConfigError> {
        let llm = self.llm.as_ref().ok_or(ConfigError::MissingLlmRouting)?;
        let route = match capability {
            Capability::Chat => &llm.chat,
            Capability::Embeddings => &llm.embeddings,
        };
        let provider = self.providers.get(&route.provider)
            .ok_or_else(|| ConfigError::UnknownProvider(route.provider.clone()))?;
        match provider {
            ProviderConfig::Ollama(c) => {
                let backend = crate::llm::OllamaBackend::new(c.clone())
                    .map_err(|e| ConfigError::ProviderInit(e.to_string()))?;
                Ok(crate::llm::LlmClient::Ollama(backend))
            }
            ProviderConfig::AzureOpenai(c) => {
                let spec = crate::secrets::CredentialSpec {
                    provider_name: route.provider.clone(),
                    env_var: c.api_key_env.clone(),
                    file_path: c.api_key_file.clone(),
                };
                let cred = crate::secrets::resolve(&spec)
                    .map_err(|e| ConfigError::ProviderInit(e.to_string()))?;
                let backend = crate::llm::AzureOpenAIBackend::new(c, cred.value)
                    .map_err(|e| ConfigError::ProviderInit(e.to_string()))?;
                Ok(crate::llm::LlmClient::Azure(backend))
            }
        }
    }

    pub fn capability_route(&self, capability: Capability) -> Result<&CapabilityRoute, ConfigError> {
        let llm = self.llm.as_ref().ok_or(ConfigError::MissingLlmRouting)?;
        Ok(match capability {
            Capability::Chat => &llm.chat,
            Capability::Embeddings => &llm.embeddings,
        })
    }
}
```

Add error variants to `ConfigError`:

```rust
#[error("config has no `llm:` routing section and no legacy `ollama:` block")]
MissingLlmRouting,
#[error("unknown provider: '{0}'")]
UnknownProvider(String),
#[error("provider init failed: {0}")]
ProviderInit(String),
```

- [ ] **Step 4: Add env-var override layer**

After `load_with_translation`, apply env-var overrides:

```rust
fn apply_env_overrides(&mut self) {
    if let Some(llm) = self.llm.as_mut() {
        if let Ok(v) = std::env::var("CLX_LLM_CHAT_PROVIDER") {
            llm.chat.provider = v;
        }
        if let Ok(v) = std::env::var("CLX_LLM_CHAT_MODEL") {
            llm.chat.model = v;
        }
        if let Ok(v) = std::env::var("CLX_LLM_EMBEDDINGS_PROVIDER") {
            llm.embeddings.provider = v;
        }
        if let Ok(v) = std::env::var("CLX_LLM_EMBEDDINGS_MODEL") {
            llm.embeddings.model = v;
        }
    }
}
```

Call it from `load_with_translation` after `translate_legacy_in_place`.

- [ ] **Step 5: Add unit tests**

```rust
#[test]
fn legacy_ollama_block_translated() {
    let yaml = r#"
ollama:
  host: "http://127.0.0.1:11434"
  model: "qwen3:1.7b"
  embedding_model: "qwen3-embedding:0.6b"
  embedding_dim: 1024
  timeout_ms: 60000
  max_retries: 3
  retry_delay_ms: 100
  retry_backoff: 2.0
"#;
    let mut cfg: Config = serde_yaml::from_str(yaml).unwrap();
    cfg.translate_legacy_in_place();
    assert!(cfg.providers.contains_key("ollama-local"));
    let llm = cfg.llm.as_ref().unwrap();
    assert_eq!(llm.chat.provider, "ollama-local");
    assert_eq!(llm.chat.model, "qwen3:1.7b");
    assert_eq!(llm.embeddings.model, "qwen3-embedding:0.6b");
}

#[test]
fn new_schema_passes_through() {
    let yaml = r#"
providers:
  azure-prod:
    kind: azure_openai
    endpoint: "https://x.openai.azure.com"
    api_key_env: "AZURE_OPENAI_API_KEY"
    timeout_ms: 30000
llm:
  chat: { provider: "azure-prod", model: "gpt-5.4-mini" }
  embeddings: { provider: "azure-prod", model: "text-embedding-3-large" }
"#;
    let cfg: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.providers.len(), 1);
    assert_eq!(cfg.llm.as_ref().unwrap().chat.model, "gpt-5.4-mini");
}

#[test]
fn env_override_replaces_chat_provider() {
    std::env::set_var("CLX_LLM_CHAT_PROVIDER", "azure-prod");
    let yaml = r#"
providers:
  ollama-local: { kind: ollama, host: "http://127.0.0.1:11434", model: "x", embedding_model: "y", embedding_dim: 1024, timeout_ms: 1000, max_retries: 0, retry_delay_ms: 0, retry_backoff: 1.0 }
  azure-prod: { kind: azure_openai, endpoint: "https://x.openai.azure.com", api_key_env: "X", timeout_ms: 1000 }
llm:
  chat: { provider: "ollama-local", model: "x" }
  embeddings: { provider: "ollama-local", model: "y" }
"#;
    let mut cfg: Config = serde_yaml::from_str(yaml).unwrap();
    cfg.apply_env_overrides();
    assert_eq!(cfg.llm.as_ref().unwrap().chat.provider, "azure-prod");
    std::env::remove_var("CLX_LLM_CHAT_PROVIDER");
}
```

- [ ] **Step 6: Run config tests**

Run: `cargo test -p clx-core --lib config`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add crates/clx-core/src/config.rs
git commit -m "feat(config): add providers/llm schema with legacy auto-translate"
```

---

## Task 10: Replace `LlmClient::from_legacy_ollama` callsites with the real factory

**Files:** same set as Task 4 (~10 files).

The temporary helper from Task 4 is now obsolete. Each callsite that needs chat goes through `cfg.create_llm_client(Capability::Chat)`; each that needs embeddings goes through `Capability::Embeddings`.

- [ ] **Step 1: Remove `LlmClient::from_legacy_ollama` from `crates/clx-core/src/llm.rs`**

Delete the function. The Task 4 callsites will fail to compile until updated below.

- [ ] **Step 2: Update each callsite**

Pattern:

```rust
// before (post-Task 4)
let client = LlmClient::from_legacy_ollama(&config.ollama.clone().unwrap_or_default())?;

// after
let client = config.create_llm_client(Capability::Chat)?;       // for generate()
// or
let client = config.create_llm_client(Capability::Embeddings)?; // for embed()
```

Capability assignment by file:

| File                                            | Capability                |
| ----------------------------------------------- | ------------------------- |
| `clx-core/src/recall.rs:123`                    | `Embeddings`              |
| `clx-core/src/recall.rs:732` (test)             | `Embeddings`              |
| `clx-core/src/policy/llm.rs:121`                | `Chat`                    |
| `clx-hook/src/embedding.rs:12,30`               | `Embeddings`              |
| `clx-hook/src/hooks/pre_tool_use.rs:276,318`    | `Chat`                    |
| `clx-hook/src/hooks/subagent.rs:99`             | `Chat`                    |
| `clx-hook/src/transcript.rs:138`                | `Chat`                    |
| `clx-mcp/src/server.rs:76`                      | `Embeddings` (recall path)|
| `clx-mcp/src/tools/recall.rs`                   | `Embeddings`              |
| `clx/src/commands/recall.rs:36`                 | `Embeddings`              |
| `clx/src/commands/embeddings.rs:166,281`        | `Embeddings`              |

- [ ] **Step 3: Run the full test suite**

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "refactor(llm): wire all callsites through Config::create_llm_client"
```

---

## Task 11: Implement `clx auth` subcommands

**Files:**
- Create: `crates/clx/src/commands/auth.rs`
- Modify: `crates/clx/src/main.rs`

- [ ] **Step 1: Write `crates/clx/src/commands/auth.rs`**

```rust
use clap::Subcommand;
use clx_core::secrets::{
    delete_from_keychain, resolve, store_in_keychain, CredentialSource, CredentialSpec,
};
use secrecy::{ExposeSecret, SecretString};
use std::io::IsTerminal;

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Prompt for an API key and store it in the OS keychain.
    Login { #[arg(long)] provider: String },
    /// Show configured providers and the source tier of each credential.
    Status,
    /// Delete a provider's credential from the keychain.
    Logout { #[arg(long)] provider: String },
    /// Print the API key for a provider to stdout (only when stdout is not a TTY).
    Token { #[arg(long)] provider: String },
}

pub fn run(cmd: AuthCommand, cfg: &clx_core::config::Config) -> anyhow::Result<()> {
    match cmd {
        AuthCommand::Login { provider } => login(&provider, cfg),
        AuthCommand::Status => status(cfg),
        AuthCommand::Logout { provider } => logout(&provider),
        AuthCommand::Token { provider } => token(&provider, cfg),
    }
}

fn login(provider: &str, cfg: &clx_core::config::Config) -> anyhow::Result<()> {
    if !cfg.providers.contains_key(provider) {
        anyhow::bail!("provider '{provider}' not in config; add it first");
    }
    eprint!("API key for '{provider}': ");
    let key = rpassword::read_password()?;
    if key.is_empty() {
        anyhow::bail!("empty key; aborting");
    }
    store_in_keychain(provider, &SecretString::new(key.into()))?;
    println!("saved to OS keychain (service: clx, account: {provider}:api-key)");
    Ok(())
}

fn status(cfg: &clx_core::config::Config) -> anyhow::Result<()> {
    println!("provider             source     fingerprint");
    println!("-------------------- ---------- ------------");
    for (name, p) in &cfg.providers {
        let (env_var, file_path) = match p {
            clx_core::config::ProviderConfig::AzureOpenai(c) => (c.api_key_env.clone(), c.api_key_file.clone()),
            clx_core::config::ProviderConfig::Ollama(_) => (None, None),
        };
        let spec = CredentialSpec {
            provider_name: name.clone(),
            env_var,
            file_path,
        };
        let (source, fingerprint) = match resolve(&spec) {
            Ok(c) => {
                let s = c.value.expose_secret();
                let fp = if s.len() >= 4 { format!("…{}", &s[s.len()-4..]) } else { "(short)".into() };
                (format!("{:?}", c.source), fp)
            }
            Err(_) => ("none".into(), "—".into()),
        };
        println!("{name:<20} {source:<10} {fingerprint}");
    }
    Ok(())
}

fn logout(provider: &str) -> anyhow::Result<()> {
    delete_from_keychain(provider)?;
    println!("removed keychain entry for '{provider}'");
    Ok(())
}

fn token(provider: &str, cfg: &clx_core::config::Config) -> anyhow::Result<()> {
    if std::io::stdout().is_terminal() {
        anyhow::bail!("refusing to print token to terminal; pipe to a file or command instead");
    }
    let p = cfg.providers.get(provider)
        .ok_or_else(|| anyhow::anyhow!("provider '{provider}' not in config"))?;
    let (env_var, file_path) = match p {
        clx_core::config::ProviderConfig::AzureOpenai(c) => (c.api_key_env.clone(), c.api_key_file.clone()),
        clx_core::config::ProviderConfig::Ollama(_) => anyhow::bail!("provider '{provider}' has no credential (Ollama)"),
    };
    let cred = resolve(&CredentialSpec {
        provider_name: provider.to_string(),
        env_var,
        file_path,
    })?;
    print!("{}", cred.value.expose_secret());
    Ok(())
}
```

- [ ] **Step 2: Register the subcommand in `main.rs`**

Find the `Cli`/`Commands` enum in `crates/clx/src/main.rs`. Add:

```rust
/// Manage provider credentials.
Auth {
    #[command(subcommand)]
    cmd: crate::commands::auth::AuthCommand,
},
```

In the `match` block:

```rust
Commands::Auth { cmd } => crate::commands::auth::run(cmd, &config)?,
```

Also add `mod auth;` to `crates/clx/src/commands/mod.rs`.

- [ ] **Step 3: Smoke-test login/logout locally with a fake provider**

Run:
```bash
cargo run --bin clx -- auth login --provider does-not-exist
```
Expected: error "provider 'does-not-exist' not in config; add it first".

If you have an `azure-prod` block in your local config:
```bash
cargo run --bin clx -- auth login --provider azure-prod
# enter a fake key like 'aaaaaaaa1234'
cargo run --bin clx -- auth status
# should show 'Keychain' source and fingerprint '…1234'
cargo run --bin clx -- auth logout --provider azure-prod
```

- [ ] **Step 4: Commit**

```bash
git add crates/clx/src/commands/auth.rs crates/clx/src/main.rs crates/clx/src/commands/mod.rs
git commit -m "feat(clx): add 'clx auth login|status|logout|token' subcommands"
```

---

## Task 12: Implement `clx config migrate`

**Files:**
- Create or modify: `crates/clx/src/commands/config.rs`
- Modify: `crates/clx/src/main.rs`

- [ ] **Step 1: Add the `migrate` action**

```rust
use clap::Subcommand;
use clx_core::config::Config;

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Rewrite ~/.clx/config.yaml into the new providers/llm schema.
    Migrate,
    // other existing config subcommands stay where they are
}

pub fn run(cmd: ConfigCommand) -> anyhow::Result<()> {
    match cmd {
        ConfigCommand::Migrate => migrate(),
    }
}

fn migrate() -> anyhow::Result<()> {
    let path = clx_core::paths::config_path();
    let original = std::fs::read_to_string(&path)?;
    let mut cfg: Config = serde_yaml::from_str(&original)?;

    if !cfg.providers.is_empty() || cfg.llm.is_some() {
        anyhow::bail!("config already uses the new schema; nothing to migrate");
    }

    if cfg.ollama.is_none() {
        anyhow::bail!("config has neither legacy 'ollama:' block nor new sections; nothing to migrate");
    }

    cfg.translate_legacy_in_place();
    // Drop the legacy block on disk so the file matches the new shape.
    cfg.ollama = None;

    let backup = path.with_extension("yaml.bak");
    std::fs::write(&backup, &original)?;

    let new_yaml = serde_yaml::to_string(&cfg)?;
    std::fs::write(&path, new_yaml)?;
    println!("migrated config; backup at {}", backup.display());
    Ok(())
}
```

- [ ] **Step 2: Register in `main.rs`**

```rust
Config { #[command(subcommand)] cmd: crate::commands::config::ConfigCommand },
```

```rust
Commands::Config { cmd } => crate::commands::config::run(cmd)?,
```

(If `clx config` already exists with an existing subcommand structure, integrate `Migrate` as a new variant of the existing subcommand enum.)

- [ ] **Step 3: Smoke test**

Manually craft a temp config with the legacy block and run `clx config migrate` against it; confirm `.bak` is written and the new file parses.

- [ ] **Step 4: Commit**

```bash
git add crates/clx/src/commands/config.rs crates/clx/src/main.rs
git commit -m "feat(clx): add 'clx config migrate' to rewrite legacy config"
```

---

## Task 13: Add `embedding_model` column to snapshots and recall mismatch detection

**Files:**
- Create: `crates/clx-core/migrations/<next-number>_embedding_model.sql`
- Modify: `crates/clx-core/src/embeddings.rs`
- Modify: `crates/clx-core/src/recall.rs`

- [ ] **Step 1: Find the migrations directory and pick the next number**

Run: `ls crates/clx-core/migrations 2>/dev/null || ls crates/clx-core/src/storage/migrations 2>/dev/null`
Expected: a list of `NNN_*.sql` files. Pick `NNN+1` for the new file.

- [ ] **Step 2: Write the migration**

```sql
-- migrations/<n>_embedding_model.sql
ALTER TABLE snapshots
  ADD COLUMN embedding_model TEXT NOT NULL DEFAULT '<unknown-pre-migration>';
```

- [ ] **Step 3: Update the embedding-write path**

In `crates/clx-hook/src/embedding.rs`, when storing a fresh embedding, also write the model identifier:

```rust
let route = config.capability_route(clx_core::config::Capability::Embeddings)?;
let model_ident = format!("{}:{}", route.provider, route.model);
embedding_store.store_with_model(snapshot_id, &embedding, &model_ident)?;
```

Add `store_with_model` to `EmbeddingStore` in `crates/clx-core/src/embeddings.rs`:

```rust
pub fn store_with_model(&self, snapshot_id: i64, vector: &[f32], model_ident: &str)
    -> Result<(), EmbeddingsError>
{
    self.store_embedding(snapshot_id, vector)?;
    self.db.execute(
        "UPDATE snapshots SET embedding_model = ?2 WHERE id = ?1",
        rusqlite::params![snapshot_id, model_ident],
    )?;
    Ok(())
}

pub fn current_model(&self) -> Result<Option<String>, EmbeddingsError> {
    let v = self.db.query_row(
        "SELECT embedding_model FROM snapshots ORDER BY id DESC LIMIT 1",
        [], |r| r.get::<_, String>(0)).optional()?;
    Ok(v)
}
```

- [ ] **Step 4: Add mismatch detection in `recall.rs`**

In `RecallEngine::semantic_search` (or the equivalent entry point), at the top:

```rust
let stored = self.embeddings.current_model()?;
let route = self.config.capability_route(Capability::Embeddings)?;
let configured = format!("{}:{}", route.provider, route.model);
if let Some(stored) = stored {
    if stored != configured && stored != "<unknown-pre-migration>" {
        return Err(RecallError::EmbeddingModelMismatch {
            stored,
            configured,
        });
    }
}
```

Add to `RecallError`:

```rust
#[error("embedding model changed (stored: {stored}, configured: {configured}); run 'clx embeddings rebuild'")]
EmbeddingModelMismatch { stored: String, configured: String },
```

For auto-recall (in `clx-hook` or wherever `additionalContext` is built), wrap the recall call: on `EmbeddingModelMismatch`, log a one-line warning and fall through to FTS5-only.

- [ ] **Step 5: Add tests**

```rust
#[test]
fn current_model_returns_none_on_empty_db() {
    let store = EmbeddingStore::new_in_memory(1024).unwrap();
    assert_eq!(store.current_model().unwrap(), None);
}

#[test]
fn store_with_model_persists_identifier() {
    let store = EmbeddingStore::new_in_memory(1024).unwrap();
    // create a snapshot row first via test helper
    let snap_id = test_insert_snapshot(&store);
    store.store_with_model(snap_id, &vec![0.1; 1024], "ollama-local:qwen3-embedding:0.6b").unwrap();
    assert_eq!(store.current_model().unwrap().as_deref(), Some("ollama-local:qwen3-embedding:0.6b"));
}
```

(`new_in_memory` and `test_insert_snapshot` may need to be added if they don't exist; existing embeddings tests should already have similar helpers.)

- [ ] **Step 6: Run tests**

Run: `cargo test -p clx-core --lib embeddings`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add crates/clx-core/migrations/ crates/clx-core/src/embeddings.rs crates/clx-core/src/recall.rs crates/clx-hook/src/embedding.rs
git commit -m "feat(embeddings): track model identity per vector; detect mismatch on recall"
```

---

## Task 14: Extend `clx embeddings rebuild` for provider-aware re-embed

**Files:**
- Modify: `crates/clx/src/commands/embeddings.rs`

- [ ] **Step 1: Update the rebuild command**

```rust
pub async fn rebuild(cfg: &Config) -> anyhow::Result<()> {
    let route = cfg.capability_route(Capability::Embeddings)?;
    let model_ident = format!("{}:{}", route.provider, route.model);
    let client = cfg.create_llm_client(Capability::Embeddings)?;

    if !client.is_available().await {
        anyhow::bail!(
            "embedding provider '{}' is unavailable; fix that before running rebuild",
            route.provider
        );
    }

    let store = EmbeddingStore::open(&clx_core::paths::database_path(), cfg.embedding_dim())?;
    let snapshots = store.list_all_snapshots()?;
    let total = snapshots.len();
    println!("rebuilding {total} snapshot embeddings via {model_ident}…");

    let pb = indicatif::ProgressBar::new(total as u64);
    for (i, snap) in snapshots.iter().enumerate() {
        let v = client.embed(&snap.summary, Some(&route.model)).await?;
        store.store_with_model(snap.id, &v, &model_ident)?;
        pb.set_position((i + 1) as u64);
    }
    pb.finish_with_message("done");
    Ok(())
}
```

(`indicatif` is likely already a CLI dep; if not, add to `crates/clx/Cargo.toml`.)

- [ ] **Step 2: Run a small end-to-end check**

Run: `cargo run --bin clx -- embeddings rebuild` against a local dev DB with a couple of snapshots. Confirm progress shows and `embedding_model` column is updated.

- [ ] **Step 3: Commit**

```bash
git add crates/clx/src/commands/embeddings.rs
git commit -m "feat(embeddings): rebuild routes through configured provider; tag vectors"
```

---

## Task 15: Extend `clx health` to probe each configured provider

**Files:**
- Modify: `crates/clx/src/commands/health.rs`

- [ ] **Step 1: Replace the single Ollama probe with a per-provider loop**

```rust
pub async fn run(cfg: &Config, json: bool) -> anyhow::Result<()> {
    let mut rows = Vec::new();
    for (name, prov) in &cfg.providers {
        let client = cfg.create_llm_client_by_name(name)?;
        let ok = client.is_available().await;
        rows.push(HealthRow {
            provider: name.clone(),
            kind: kind_label(prov),
            endpoint: endpoint_label(prov),
            healthy: ok,
        });
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        print_table(&rows);
    }
    Ok(())
}
```

Add `Config::create_llm_client_by_name(&str)` to `clx-core/src/config.rs` if it doesn't exist — same body as `create_llm_client` but takes the provider name directly instead of routing through a capability. This is health-specific and shouldn't go through the routing layer.

- [ ] **Step 2: Manual verification**

Run: `cargo run --bin clx -- health`
Expected: one row per provider configured in `~/.clx/config.yaml`, with green or red health.

- [ ] **Step 3: Commit**

```bash
git add crates/clx/src/commands/health.rs crates/clx-core/src/config.rs
git commit -m "feat(clx): clx health probes every configured provider"
```

---

## Task 16: Update dashboard Settings tab to show provider routing

**Files:**
- Modify: `crates/clx/src/dashboard/settings/render.rs` (or whatever file owns the Settings tab — find via `grep -r "Ollama" crates/clx/src/dashboard/`)

- [ ] **Step 1: Find the file that renders the Ollama config row**

Run: `grep -rn "ollama" crates/clx/src/dashboard/ | head -20`

- [ ] **Step 2: Replace the single-provider section with a per-provider section**

Show, for each entry in `cfg.providers`:

- name, kind, endpoint
- credential source (Env / Keychain / File / None) via `secrets::resolve`'s `source` field — never the secret value
- last 4 chars of the key as fingerprint, or `—` if no credential

Show, for the `llm:` section:

- chat → `<provider> / <model>`
- embeddings → `<provider> / <model>`

- [ ] **Step 3: Manual verification**

Run: `cargo run --bin clx -- dashboard` and tab to the Settings view.

- [ ] **Step 4: Commit**

```bash
git add crates/clx/src/dashboard/settings/
git commit -m "feat(dashboard): show provider routing and credential source per provider"
```

---

## Task 17: Update `CONTRIBUTING.md` with the manual Azure smoke test

**Files:**
- Modify: `CONTRIBUTING.md`

- [ ] **Step 1: Append a section**

```markdown
## Azure OpenAI smoke test

Run before tagging any release that includes Azure backend changes. Requires a real Azure OpenAI tenant.

1. `export AZURE_OPENAI_API_KEY=...`
2. Configure `~/.clx/config.yaml` with an `azure-prod` provider and route `llm.chat` and/or `llm.embeddings` to it.
3. `clx health` — every configured provider must be healthy.
4. `clx auth status` — `azure-prod` must show source `Env` (or `Keychain` if you used `clx auth login`).
5. Trigger a `pre_tool_use` validation by issuing a non-trivial command in a Claude Code session — the L1 risk score must be returned without errors. Check logs for `x-request-id` capture.
6. Run `clx recall "anything"` — must return either results or an empty set, not an error. If `llm.embeddings.provider` is Azure, this exercises the embeddings path.
7. If switching from Ollama to Azure embeddings: run `clx embeddings rebuild` first; verify the progress bar completes and post-rebuild recall works.
```

- [ ] **Step 2: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs(contributing): add Azure OpenAI manual smoke test checklist"
```

---

## Task 18: Update `using-clx` skill with one paragraph about Azure

**Files:**
- Modify: `plugin/skills/using-clx/SKILL.md` (Note: this file currently has only the frontmatter + stub body; the body sections from the parked plugin work were not merged. Append a single paragraph to the body that survives that work.)

- [ ] **Step 1: Append the paragraph after the existing `# Using CLX` heading**

```markdown
## Backend choice

CLX supports two LLM backends: a local Ollama server (default) and Azure OpenAI (opt-in). Which backend serves which capability is configured per-install in `~/.clx/config.yaml` under the `providers:` and `llm:` sections. The MCP tools (`clx_recall`, `clx_remember`, `clx_checkpoint`, `clx_rules`) work the same regardless of which backend is configured — the choice is invisible at the tool level. If a recall returns "embedding model changed", the user has switched embedding providers and must run `clx embeddings rebuild`.
```

- [ ] **Step 2: Run the plugin validator**

Run: `./plugin/scripts/validate.sh`
Expected: `OK: ...` (the frontmatter description is unchanged so trigger keywords still pass).

- [ ] **Step 3: Commit**

```bash
git add plugin/skills/using-clx/SKILL.md
git commit -m "docs(plugin): mention Azure backend in using-clx skill"
```

---

## Task 19: Final integration pass

**Files:** verification only.

- [ ] **Step 1: Full test suite**

Run: `cargo test --workspace`
Expected: every test green. Coverage gate (70% line) holds.

- [ ] **Step 2: Lint**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Format**

Run: `cargo fmt --all -- --check`
Expected: clean. If not, run `cargo fmt --all` and commit.

- [ ] **Step 4: Build release**

Run: `cargo build --release --workspace`
Expected: clean release build.

- [ ] **Step 5: `git log --oneline` review**

Run: `git log --oneline -25`
Expected: the chain `build(deps)` → `feat(llm)` (trait stubs) → `refactor(llm)` (Ollama behind trait) → `refactor(llm)` (callsites via legacy helper) → `refactor(llm)` (rename health) → `feat(secrets)` → `feat(llm)` (Azure backend) → `test(llm)` (Azure error paths) → `feat(config)` → `refactor(llm)` (factory wiring) → `feat(clx)` (auth commands) → `feat(clx)` (config migrate) → `feat(embeddings)` (model identity) → `feat(embeddings)` (rebuild) → `feat(clx)` (health) → `feat(dashboard)` → `docs(contributing)` → `docs(plugin)`. Every commit follows `<type>(<scope>): <subject>`.

- [ ] **Step 6: Manual Azure smoke test**

Run the checklist from Task 17 against the actual user tenant.

If everything green, the implementation is done. No final commit needed.

---

## Post-Plan Notes

- **No CLX version bump in this plan.** The release commit that bumps `Cargo.toml` and `plugin/plugin.json` in lockstep is a separate, non-coding task that happens when the user is ready to ship.
- **Out-of-scope items remain out of scope.** Entra ID, streaming, Responses API, layered config files, automatic provider fallback, and OpenAI public API support are all deferred per the spec's §1 scope statement.
- **Parked plugin work** (Tasks #1–#11 from the previous plugin plan) is unaffected by this plan. After Azure work merges, returning to Task #16 ("fix Task 2 YAML wrap bug") is straightforward.
