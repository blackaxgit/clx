# Provider Fallback + Per-Project Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ship CLX 0.7.0 with automatic primary→secondary LLM provider fallback (per-capability, with cooldown) plus a per-project config override mechanism (`<repo>/.clx/config.yaml` walk-up, figment-layered).

**Architecture:** New `LlmClient::Fallback` enum variant containing a `FallbackClient { primary: Box<LlmClient>, fallback: Box<LlmClient>, cooldown: Mutex<Option<Instant>> }` that itself implements the trait. Factory wraps when `CapabilityRoute.fallback.is_some()`. Config loader switches to `figment` for layered global+project+env merging with an inert-keys allowlist filter applied to the project layer.

**Tech Stack:** Rust 1.85+ (workspace), `figment` v0.10+ (new dep), `serde_yml` (existing), `tracing` (existing), `wiremock` (existing dev-dep), `tokio::sync::Mutex` for the cooldown cell.

**Spec:** `specs/2026-04-30-provider-fallback-design.md`

---

## File Structure

| Path                                        | Status   | Responsibility                                                          |
| ------------------------------------------- | -------- | ----------------------------------------------------------------------- |
| `Cargo.toml`                                | modify   | Add `figment` to `[workspace.dependencies]`.                            |
| `crates/clx-core/Cargo.toml`                | modify   | `figment.workspace = true`.                                             |
| `crates/clx-core/src/llm/mod.rs`            | modify   | Add `LlmClient::Fallback`, `FallbackClient`, `LlmError::is_transient`.  |
| `crates/clx-core/src/llm/azure.rs`          | modify   | Replace local `is_transient` with `LlmError::is_transient`.             |
| `crates/clx-core/src/llm/fallback.rs`       | **new**  | `FallbackClient` impl, cooldown, policy.                                |
| `crates/clx-core/src/config.rs`             | modify   | `CapabilityRoute.fallback` field, factory wraps, layered loader.        |
| `crates/clx-core/src/config/project.rs`     | **new**  | Walk-up discovery + inert-keys allowlist filter.                        |
| `Cargo.toml` (root)                         | modify   | Bump workspace version 0.6.1 → 0.7.0.                                   |
| `CHANGELOG.md`                              | modify   | New `[0.7.0]` section.                                                  |
| `CONTRIBUTING.md`                           | modify   | Add fallback smoke step.                                                |
| `plugin/skills/using-clx/SKILL.md`          | modify   | Add fallback paragraph.                                                 |

---

## Task 1: Add `figment` workspace dependency

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/clx-core/Cargo.toml`

- [ ] **Step 1: Add to workspace deps**

In `Cargo.toml` `[workspace.dependencies]` add:
```toml
figment = { version = "0.10", features = ["yaml", "env"] }
```

- [ ] **Step 2: Reference from clx-core**

In `crates/clx-core/Cargo.toml` `[dependencies]`:
```toml
figment.workspace = true
```

- [ ] **Step 3: Verify build**

```bash
cargo build --workspace
```
Expected: clean, `figment` downloads.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock crates/clx-core/Cargo.toml
git commit -m "build(deps): add figment for layered config loading"
```

---

## Task 2: Promote `is_transient` to `LlmError::is_transient`

**Files:**
- Modify: `crates/clx-core/src/llm/mod.rs`
- Modify: `crates/clx-core/src/llm/azure.rs`

- [ ] **Step 1: Add the method on `LlmError`**

In `crates/clx-core/src/llm/mod.rs` near the `LlmError` enum:

```rust
impl LlmError {
    /// Returns true if a fallback or retry might recover.
    /// Identical predicate used by both backends and the fallback wrapper.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            LlmError::Timeout | LlmError::Connection(_) | LlmError::RateLimit { .. }
        ) || matches!(
            self,
            LlmError::Server { status, .. } if (500..=599).contains(status) || *status == 408
        )
    }

    /// One-word category string for log fields.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            LlmError::Connection(_) => "connection",
            LlmError::Timeout => "timeout",
            LlmError::Auth(_) => "auth",
            LlmError::RateLimit { .. } => "rate_limit",
            LlmError::DeploymentNotFound(_) => "deployment_not_found",
            LlmError::ContentFilter(_) => "content_filter",
            LlmError::Server { .. } => "server",
            LlmError::InvalidResponse(_) => "invalid_response",
            LlmError::Serialization(_) => "serialization",
        }
    }
}
```

- [ ] **Step 2: Replace the local `is_transient` in `azure.rs`**

Find the existing free function in `crates/clx-core/src/llm/azure.rs` (around line 166):
```rust
fn is_transient(e: &LlmError) -> bool { ... }
```
Delete it. Update the call sites (look for `is_transient` callers in the same file — they're passed to `with_backoff`) to use `LlmError::is_transient`:
```rust
// before
with_backoff(self.retry, || ..., is_transient, retry_after_for).await
// after
with_backoff(self.retry, || ..., LlmError::is_transient, retry_after_for).await
```

The `retry_after_for` free function stays (it's unique to rate-limit handling).

- [ ] **Step 3: Build + test**

```bash
cargo build -p clx-core
cargo test -p clx-core --lib llm
```
Expected: clean. All existing Azure tests still pass.

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "refactor(llm): move is_transient to LlmError method, add kind_str"
```

---

## Task 3: Add `fallback` field to `CapabilityRoute`

**Files:**
- Modify: `crates/clx-core/src/config.rs`

- [ ] **Step 1: Locate the existing `CapabilityRoute` struct**

```bash
grep -n "pub struct CapabilityRoute" crates/clx-core/src/config.rs
```
Expected: line ~806.

- [ ] **Step 2: Add the recursive `fallback` field**

```rust
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CapabilityRoute {
    pub provider: String,
    pub model: String,

    /// Optional secondary provider used when the primary fails with a
    /// transient error. `Box` to allow recursion (each fallback can itself
    /// have a fallback, though v0.7.0 doesn't surface the chain UX).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Box<CapabilityRoute>>,
}
```

- [ ] **Step 3: Add a round-trip test**

In the `schema_tests` mod at the bottom of `config.rs`:

```rust
#[test]
fn fallback_field_round_trips() {
    let yaml = r#"
provider: azure-prod
model: gpt-5.4-mini
fallback:
  provider: ollama-local
  model: qwen3:1.7b
"#;
    let route: CapabilityRoute = serde_yml::from_str(yaml).unwrap();
    assert_eq!(route.provider, "azure-prod");
    let fb = route.fallback.as_deref().expect("fallback present");
    assert_eq!(fb.provider, "ollama-local");
    assert_eq!(fb.model, "qwen3:1.7b");
    assert!(fb.fallback.is_none());

    // Round-trip
    let yaml2 = serde_yml::to_string(&route).unwrap();
    let route2: CapabilityRoute = serde_yml::from_str(&yaml2).unwrap();
    assert_eq!(route, route2);
}

#[test]
fn fallback_field_omitted_in_serialization_when_none() {
    let route = CapabilityRoute {
        provider: "p".into(),
        model: "m".into(),
        fallback: None,
    };
    let yaml = serde_yml::to_string(&route).unwrap();
    assert!(!yaml.contains("fallback"), "skip_serializing_if not respected: {yaml}");
}
```

- [ ] **Step 4: Build + test**

```bash
cargo test -p clx-core --lib config::schema_tests::fallback_field
```
Expected: 2/2 pass.

- [ ] **Step 5: Commit**

```bash
git add -u
git commit -m "feat(config): add optional fallback field to CapabilityRoute"
```

---

## Task 4: Implement `FallbackClient` with cooldown

**Files:**
- Create: `crates/clx-core/src/llm/fallback.rs`
- Modify: `crates/clx-core/src/llm/mod.rs`

- [ ] **Step 1: Create `crates/clx-core/src/llm/fallback.rs`**

```rust
//! Primary→secondary LLM provider fallback wrapper.
//!
//! Wraps two `LlmClient` instances. On a transient error from the primary,
//! falls back to the secondary. After a fallback event, a short in-process
//! cooldown skips the primary entirely so a sustained outage does not pay
//! the latency penalty of always hitting the dead primary first.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::llm::{LlmClient, LlmError, LocalLlmBackend};

/// Sticky-fallback duration after a primary failure.
const COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct FallbackClient {
    primary: Box<LlmClient>,
    fallback: Box<LlmClient>,
    /// `Some(t)` means primary failed at instant `t`; skip primary until
    /// `t.elapsed() >= COOLDOWN`.
    last_primary_failure: Mutex<Option<Instant>>,
}

impl FallbackClient {
    pub fn new(primary: LlmClient, fallback: LlmClient) -> Self {
        Self {
            primary: Box::new(primary),
            fallback: Box::new(fallback),
            last_primary_failure: Mutex::new(None),
        }
    }

    fn use_fallback_directly(&self) -> bool {
        match *self.last_primary_failure.lock().expect("poisoned cooldown lock") {
            Some(t) => t.elapsed() < COOLDOWN,
            None => false,
        }
    }

    fn record_primary_failure(&self) {
        *self.last_primary_failure.lock().expect("poisoned cooldown lock") = Some(Instant::now());
    }

    /// Test-only accessor — exposes whether cooldown is currently active.
    #[cfg(test)]
    pub(crate) fn cooldown_active(&self) -> bool {
        self.use_fallback_directly()
    }
}

impl LocalLlmBackend for FallbackClient {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        if self.use_fallback_directly() {
            return self.fallback.generate(prompt, model).await;
        }
        match self.primary.generate(prompt, model).await {
            Ok(v) => Ok(v),
            Err(e) if e.is_transient() => {
                tracing::warn!(
                    op = "generate",
                    error.kind = %e.kind_str(),
                    "primary failed; falling back"
                );
                self.record_primary_failure();
                self.fallback.generate(prompt, model).await
            }
            Err(e) => Err(e),
        }
    }

    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        if self.use_fallback_directly() {
            return self.fallback.embed(text, model).await;
        }
        match self.primary.embed(text, model).await {
            Ok(v) => Ok(v),
            Err(e) if e.is_transient() => {
                tracing::warn!(
                    op = "embed",
                    error.kind = %e.kind_str(),
                    "primary failed; falling back"
                );
                self.record_primary_failure();
                self.fallback.embed(text, model).await
            }
            Err(e) => Err(e),
        }
    }

    async fn is_available(&self) -> bool {
        // Either backend healthy means "fallback path is alive."
        self.primary.is_available().await || self.fallback.is_available().await
    }
}
```

- [ ] **Step 2: Add the variant + dispatcher in `mod.rs`**

In `crates/clx-core/src/llm/mod.rs`:

```rust
pub mod fallback;
pub use fallback::FallbackClient;

pub enum LlmClient {
    Ollama(OllamaBackend),
    Azure(AzureOpenAIBackend),
    Fallback(FallbackClient),  // NEW
}

impl LlmClient {
    pub async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        match self {
            Self::Ollama(b) => b.generate(prompt, model).await,
            Self::Azure(b) => b.generate(prompt, model).await,
            Self::Fallback(b) => b.generate(prompt, model).await,
        }
    }

    pub async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        match self {
            Self::Ollama(b) => b.embed(text, model).await,
            Self::Azure(b) => b.embed(text, model).await,
            Self::Fallback(b) => b.embed(text, model).await,
        }
    }

    pub async fn is_available(&self) -> bool {
        match self {
            Self::Ollama(b) => b.is_available().await,
            Self::Azure(b) => b.is_available().await,
            Self::Fallback(b) => b.is_available().await,
        }
    }
}
```

- [ ] **Step 3: Implement `Debug` for `LlmClient` if missing**

Required because `FallbackClient`'s `Debug` derive uses `Box<LlmClient>` which needs `Debug`. Either add `#[derive(Debug)]` to `LlmClient` (will require it on inner types) or implement manually. Easiest:

```rust
impl std::fmt::Debug for LlmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ollama(_) => f.write_str("LlmClient::Ollama(..)"),
            Self::Azure(_) => f.write_str("LlmClient::Azure(..)"),
            Self::Fallback(_) => f.write_str("LlmClient::Fallback(..)"),
        }
    }
}
```

- [ ] **Step 4: Build**

```bash
cargo build -p clx-core
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add -u
git commit -m "feat(llm): add FallbackClient with cooldown and LlmClient::Fallback variant"
```

---

## Task 5: Wire factory + add fallback wiremock tests

**Files:**
- Modify: `crates/clx-core/src/config.rs`
- Modify: `crates/clx-core/src/llm/fallback.rs` (append `#[cfg(test)] mod tests`)

- [ ] **Step 1: Update factory in `config.rs`**

Find `Config::create_llm_client` (around line 1327). Modify the body so that after the primary is built, it checks for `route.fallback` and wraps:

```rust
pub fn create_llm_client(
    &self,
    capability: Capability,
) -> Result<crate::llm::LlmClient, LlmConfigError> {
    let route = self.capability_route(capability)?;
    let primary = self.build_client_for_provider(&route.provider)?;
    if let Some(fb) = route.fallback.as_deref() {
        let fallback = self.build_client_for_provider(&fb.provider)?;
        let wrapper = crate::llm::FallbackClient::new(primary, fallback);
        return Ok(crate::llm::LlmClient::Fallback(wrapper));
    }
    Ok(primary)
}
```

The fallback's *model* lives in `fb.model` and is passed at call time via the existing `route.model` plumbing — but the `FallbackClient` itself doesn't carry models, the trait methods take `Option<&str>`. The route's `model` is what callers pass. The fallback `model` would currently be ignored. **This is intentional for v0.7.0**: the fallback uses the same model name the caller passed (e.g. if chat passes `gpt-5.4-mini`, the Ollama fallback also gets `gpt-5.4-mini`, which it'll fail on). Document this.

(If the user wants per-fallback model substitution, that's a v0.7.x: requires the FallbackClient to remember `fallback_model: Option<String>` and override the caller's model when delegating. Out of v0.7.0 scope.)

**Update the doc comment on `CapabilityRoute.fallback`** (in Task 3's struct) to note: "the `model` field on a fallback route is currently *unused at call time*; the caller's model name is passed through. Per-fallback model substitution is planned for a follow-up."

Actually — reconsider. If primary is Azure with model `gpt-5.4-mini` and fallback is Ollama, Ollama doesn't have `gpt-5.4-mini`. Pass-through breaks. Better to honor `fallback.model`:

```rust
impl FallbackClient {
    pub fn new(primary: LlmClient, fallback: LlmClient, fallback_model: Option<String>) -> Self {
        ...
        fallback_model,
    }
}
```

And in `generate`:
```rust
let fb_model = self.fallback_model.as_deref().or(model);
self.fallback.generate(prompt, fb_model).await
```

Update Task 4's struct to include `fallback_model: Option<String>`. The factory passes `Some(fb.model.clone())`.

- [ ] **Step 2: Update `FallbackClient::new` signature + struct**

Modify `fallback.rs`:

```rust
#[derive(Debug)]
pub struct FallbackClient {
    primary: Box<LlmClient>,
    fallback: Box<LlmClient>,
    /// If set, overrides the caller's `model` arg when delegating to the
    /// fallback. Necessary because providers don't share model names
    /// (e.g. `gpt-5.4-mini` only exists on Azure).
    fallback_model: Option<String>,
    last_primary_failure: Mutex<Option<Instant>>,
}

impl FallbackClient {
    pub fn new(primary: LlmClient, fallback: LlmClient, fallback_model: Option<String>) -> Self {
        Self {
            primary: Box::new(primary),
            fallback: Box::new(fallback),
            fallback_model,
            last_primary_failure: Mutex::new(None),
        }
    }
    
    fn fb_model<'a>(&'a self, caller: Option<&'a str>) -> Option<&'a str> {
        self.fallback_model.as_deref().or(caller)
    }
}
```

Update each `self.fallback.generate(prompt, model)` to `self.fallback.generate(prompt, self.fb_model(model))` (and same for `embed`).

Update factory in step 1:
```rust
let wrapper = crate::llm::FallbackClient::new(primary, fallback, Some(fb.model.clone()));
```

- [ ] **Step 3: Add wiremock tests in `fallback.rs`**

Append to `fallback.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AzureOpenAIConfig;
    use crate::llm::{AzureOpenAIBackend, LlmClient};
    use crate::llm::retry::RetryConfig;
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

    fn allow_local() {
        // SAFETY: test-only env var manipulation
        unsafe { std::env::set_var("CLX_ALLOW_AZURE_HOSTS", "127.0.0.1,localhost"); }
    }

    fn azure(uri: String) -> LlmClient {
        let backend = AzureOpenAIBackend::new(
            &cfg(uri),
            SecretString::new("k".to_string().into()),
        ).unwrap();
        LlmClient::Azure(backend)
    }

    #[tokio::test]
    async fn fallback_on_primary_503_succeeds() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503).set_body_string("overloaded"))
            .expect(1)
            .mount(&primary_mock).await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "from fallback" } }]
            })))
            .expect(1)
            .mount(&fallback_mock).await;

        let fc = FallbackClient::new(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            Some("fallback-model".into()),
        );

        let out = fc.generate("hi", Some("primary-model")).await.unwrap();
        assert_eq!(out, "from fallback");
    }

    #[tokio::test]
    async fn fallback_not_used_on_terminal_error() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&primary_mock).await;

        // Fallback should NOT be called on 401.
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("should not fire"))
            .expect(0)
            .mount(&fallback_mock).await;

        let fc = FallbackClient::new(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            None,
        );

        let r = fc.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::Auth(_))));
    }

    #[tokio::test]
    async fn cooldown_skips_primary_after_failure() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        // Primary fails once.
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)  // hit exactly once
            .mount(&primary_mock).await;

        // Fallback succeeds twice (once on initial fall-through, once on cooled-down retry).
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "ok" } }]
            })))
            .expect(2)
            .mount(&fallback_mock).await;

        let fc = FallbackClient::new(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            None,
        );

        let _ = fc.generate("hi", Some("m")).await.unwrap();
        assert!(fc.cooldown_active(), "cooldown should be active after primary failure");

        // Second call: primary should NOT be re-attempted.
        let out = fc.generate("hi again", Some("m")).await.unwrap();
        assert_eq!(out, "ok");
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p clx-core --lib llm::fallback
```
Expected: 3/3 pass.

- [ ] **Step 5: Build + workspace tests**

```bash
cargo build --workspace
cargo test --workspace
```
Expected: green.

- [ ] **Step 6: Commit**

```bash
git add -u
git commit -m "feat(llm): factory wires LlmClient::Fallback when route.fallback is set"
```

---

## Task 6: Migrate `Config::load` to figment + per-project layer

**Files:**
- Create: `crates/clx-core/src/config/project.rs`
- Modify: `crates/clx-core/src/config.rs` (refactor `Config::load`)

- [ ] **Step 1: Create `project.rs` with walk-up + allowlist**

```rust
// crates/clx-core/src/config/project.rs
//! Per-project config discovery and inert-keys allowlist filter.

use std::path::PathBuf;

/// Discover the project config path, if any.
///
/// Order:
///   1. `CLX_CONFIG_PROJECT` env var (empty/`none`/`off` disables).
///   2. Walk up from CWD looking for `.clx/config.yaml`, stopping at `$HOME`.
pub fn project_config_path() -> Option<PathBuf> {
    if let Ok(s) = std::env::var("CLX_CONFIG_PROJECT") {
        return match s.as_str() {
            "" | "none" | "off" => None,
            path => Some(PathBuf::from(path)),
        };
    }
    let mut dir = std::env::current_dir().ok()?;
    let home = dirs::home_dir()?;
    loop {
        let candidate = dir.join(".clx").join("config.yaml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir == home || !dir.pop() {
            return None;
        }
    }
}

/// Keys NOT allowed from a project config (security gate). Project files
/// are inert by default; honoring these keys would let a hostile repo
/// redirect credentials, log paths, or HTTP endpoints.
const NON_INERT_KEY_PATTERNS: &[&str] = &[
    "providers.",  // nested: any providers.*.endpoint, .host, .api_key_*
    "logging.file",
    "validator.enabled",
];

/// Strip non-inert keys from a parsed project YAML before merging.
/// Logs one WARN per dropped key. Returns the filtered YAML string.
pub fn filter_inert_only(raw_yaml: &str) -> String {
    let value: serde_yml::Value = match serde_yml::from_str(raw_yaml) {
        Ok(v) => v,
        Err(_) => return String::new(), // invalid YAML — global wins
    };
    let filtered = filter_value(&value, "");
    serde_yml::to_string(&filtered).unwrap_or_default()
}

fn filter_value(v: &serde_yml::Value, path: &str) -> serde_yml::Value {
    use serde_yml::Value;
    match v {
        Value::Mapping(m) => {
            let mut out = serde_yml::Mapping::new();
            for (k, vv) in m {
                let Some(key) = k.as_str() else { continue };
                let next_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                if is_non_inert(&next_path) {
                    tracing::warn!(
                        key = %next_path,
                        "project config key is not inert; ignored. \
                         (clx trust will allow these in v0.7.x.)"
                    );
                    continue;
                }
                out.insert(k.clone(), filter_value(vv, &next_path));
            }
            Value::Mapping(out)
        }
        other => other.clone(),
    }
}

fn is_non_inert(path: &str) -> bool {
    NON_INERT_KEY_PATTERNS
        .iter()
        .any(|pat| path == *pat || path.starts_with(pat))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_endpoint_under_providers() {
        let raw = r#"
providers:
  azure-prod:
    endpoint: https://evil.example.com
    api_key_env: STOLEN
llm:
  chat:
    provider: azure-prod
    model: gpt-5.4-mini
"#;
        let out = filter_inert_only(raw);
        assert!(!out.contains("evil.example.com"));
        assert!(!out.contains("STOLEN"));
        assert!(out.contains("gpt-5.4-mini"));
    }

    #[test]
    fn drops_logging_file() {
        let raw = "logging:\n  file: /tmp/exfil.log\n  level: debug\n";
        let out = filter_inert_only(raw);
        assert!(!out.contains("exfil"));
        assert!(out.contains("level"));
    }

    #[test]
    fn keeps_inert_routing() {
        let raw = r#"
llm:
  chat:
    provider: ollama-local
    model: qwen3:1.7b
    fallback:
      provider: ollama-local
      model: qwen3:1.7b
"#;
        let out = filter_inert_only(raw);
        assert!(out.contains("ollama-local"));
        assert!(out.contains("fallback"));
    }
}
```

- [ ] **Step 2: Refactor `Config::load` to layered figment**

In `crates/clx-core/src/config.rs`, find the existing `Config::load()` function (it currently does `serde_yml::from_str(read_to_string(...))`). Replace with:

```rust
impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        use figment::providers::{Env, Format, Yaml};
        use figment::Figment;

        let global_path = Self::config_file_path()?;

        let mut fig = Figment::new();

        // Layer 1: built-in defaults from Config::default()
        fig = fig.merge(figment::providers::Serialized::defaults(Self::default()));

        // Layer 2: global ~/.clx/config.yaml (if exists)
        if global_path.is_file() {
            fig = fig.merge(Yaml::file(&global_path));
        }

        // Layer 3: project .clx/config.yaml (filtered through inert allowlist)
        if let Some(proj) = crate::config::project::project_config_path() {
            if let Ok(raw) = std::fs::read_to_string(&proj) {
                let filtered = crate::config::project::filter_inert_only(&raw);
                if !filtered.is_empty() {
                    fig = fig.merge(Yaml::string(&filtered));
                }
            }
        }

        // Layer 4: env vars (figment honors CLX_FOO_BAR → foo.bar)
        fig = fig.merge(Env::prefixed("CLX_"));

        let mut cfg: Config = fig.extract().map_err(|e| {
            ConfigError::ParseError(format!("figment merge failed: {e}"))
        })?;

        // Preserve existing migration steps:
        cfg.translate_legacy_in_place();
        cfg.apply_env_overrides();

        Ok(cfg)
    }
}
```

If `Config::default()` doesn't exist, derive it (`#[derive(Default)]` on `Config`). If a field doesn't have a sensible default, write a manual `Default` impl.

If `figment::providers::Yaml::string` isn't the actual API name, check `figment` docs and adjust — the goal is "merge a YAML literal as the project layer". Worst case fall through to writing the filtered YAML to a temp file.

- [ ] **Step 3: Declare the new module**

In `config.rs` near the top, add:
```rust
mod project;
```

- [ ] **Step 4: Build + test**

```bash
cargo build --workspace
cargo test -p clx-core --lib config::project
cargo test --workspace
```
Expected: clean. New project tests pass; no regression on existing config tests.

- [ ] **Step 5: Commit**

```bash
git add -u
git commit -m "feat(config): figment-layered loader with per-project override and inert-keys allowlist"
```

---

## Task 7: Add layered-config integration tests

**Files:**
- Modify: `crates/clx-core/src/config.rs` (`schema_tests` module)

- [ ] **Step 1: Add tests using temp dirs**

Append to `schema_tests`:

```rust
#[test]
fn project_config_overrides_chat_provider() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join(".clx");
    std::fs::create_dir_all(&project).unwrap();
    let path = project.join("config.yaml");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, r#"
llm:
  chat:
    provider: ollama-local
    model: qwen3:1.7b
"#).unwrap();

    // SAFETY: test-only env var manipulation
    unsafe {
        std::env::set_var("CLX_CONFIG_PROJECT", path.to_str().unwrap());
    }
    let cfg = Config::load().expect("load layered");
    assert_eq!(cfg.llm.as_ref().unwrap().chat.provider, "ollama-local");
    unsafe { std::env::remove_var("CLX_CONFIG_PROJECT"); }
}

#[test]
fn project_config_drops_endpoint_with_warn() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("project.yaml");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, r#"
providers:
  azure-prod:
    endpoint: https://evil.example.com
"#).unwrap();

    unsafe {
        std::env::set_var("CLX_CONFIG_PROJECT", path.to_str().unwrap());
    }
    let cfg = Config::load().expect("load layered");
    // Endpoint must NOT have been overridden.
    if let Some(ProviderConfig::AzureOpenai(c)) = cfg.providers.get("azure-prod") {
        assert!(!c.endpoint.contains("evil"), "endpoint not filtered: {}", c.endpoint);
    }
    unsafe { std::env::remove_var("CLX_CONFIG_PROJECT"); }
}
```

- [ ] **Step 2: Run new tests**

```bash
cargo test -p clx-core --lib config::schema_tests::project_
```
Expected: 2/2 pass.

- [ ] **Step 3: Run full suite**

```bash
cargo test --workspace
```
Expected: green.

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "test(config): integration tests for layered project override"
```

---

## Task 8: Bump version + CHANGELOG

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Bump version**

In `Cargo.toml` `[workspace.package]`:
```toml
version = "0.7.0"
```

- [ ] **Step 2: Add CHANGELOG entry**

Insert before the existing `[0.6.1]` entry:

```markdown
## [0.7.0] - 2026-04-30

### Added
- Automatic primary→secondary LLM provider fallback. New `fallback:` field
  on each capability route in `llm.chat.fallback` / `llm.embeddings.fallback`.
  When the primary fails with a transient error (Connection, Timeout,
  RateLimit, 5xx, 408), the configured fallback runs automatically.
- 30-second in-process cooldown after a fallback event — primary is skipped
  during the cooldown window so sustained outages don't pay the latency
  penalty of always retrying the primary first.
- Per-project config override at `<repo>/.clx/config.yaml`, discovered by
  walking from CWD up to `$HOME`. Env-var escape hatch:
  `CLX_CONFIG_PROJECT=/path` or `CLX_CONFIG_PROJECT=none`.
- Layered config loading via `figment`: built-in defaults → global →
  project → `CLX_*` env vars → CLI flags (lowest to highest precedence).
- Inert-keys allowlist for project configs: only routing-related keys
  (provider, model, fallback) take effect from a project file.
  Security-sensitive keys (`providers.*.endpoint`, `*.api_key_*`,
  `logging.file`, `validator.enabled`) are silently dropped with a single
  `WARN` per key.

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
```

- [ ] **Step 3: Run all gates**

```bash
cargo build --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo fmt --all -- --check
```
All clean.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore: bump version to 0.7.0"
```

---

## Task 9: Update CONTRIBUTING + skill

**Files:**
- Modify: `CONTRIBUTING.md`
- Modify: `plugin/skills/using-clx/SKILL.md`

- [ ] **Step 1: Append fallback section to `CONTRIBUTING.md`** (after the existing Azure smoke section):

```markdown
### Fallback smoke test

If the release includes provider-fallback changes, validate the fallback path:

1. Configure `llm.chat.fallback` to point at `ollama-local` with a real model.
2. Temporarily set `llm.chat.model` to a non-existent Azure deployment
   (e.g., `gpt-5.4-mini-doesnotexist`).
3. Trigger the L1 validator (issue a non-trivial command in Claude Code).
4. The risk score must come from the fallback (Ollama). The log must contain
   one `WARN llm.fallback ... primary failed; falling back`.
5. Issue a second validation immediately. The primary must NOT be re-tried
   (cooldown active). Ollama serves both.
6. Wait 31 seconds, repeat. Primary is re-tried (cooldown expired).
```

- [ ] **Step 2: Append fallback paragraph to `using-clx` SKILL.md**:

```markdown
## Provider fallback

CLX 0.7.0+ supports automatic primary→secondary LLM provider fallback per
capability. When `llm.chat.fallback` is configured and the primary fails
with a transient error (timeout, 5xx, rate limit), CLX automatically calls
the fallback provider. After a fallback event, a 30-second cooldown skips
the primary so sustained outages don't add latency. The MCP tools (`clx_recall`,
`clx_remember`, `clx_checkpoint`, `clx_rules`) work the same regardless of
whether the active call hit the primary or the fallback. If a recall returns
inconsistent results across calls, the embedding provider may have flapped
between primary and fallback — disable fallback on the embeddings route or
run `clx embeddings rebuild` after the outage.
```

- [ ] **Step 3: Verify plugin validator still passes**

```bash
./plugin/scripts/validate.sh
```
Expected: `OK: ...`.

- [ ] **Step 4: Commit**

```bash
git add CONTRIBUTING.md plugin/skills/using-clx/SKILL.md
git commit -m "docs: fallback smoke checklist + using-clx skill paragraph"
```

---

## Task 10: Final integration pass

**Files:** verification only.

- [ ] **Step 1: Lint + format + test + audit**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo audit
cargo build --release --workspace
```
All clean.

- [ ] **Step 2: Push + open PR**

```bash
git push -u origin feat/provider-fallback
gh pr create -B main -H feat/provider-fallback \
  --title "feat: provider fallback + per-project config (0.7.0)" \
  --body "<see summary in CHANGELOG and spec>"
```

- [ ] **Step 3: After PR merges + Auto-Tag fires + Release workflow completes**

```bash
brew update && brew upgrade clx
clx --version    # 0.7.0
```

- [ ] **Step 4: Real-tenant smoke**

Run the new fallback smoke test from `CONTRIBUTING.md` against your Azure
tenant. Confirm fallback fires, cooldown holds, recovery works.

---

## Post-Plan Notes

- **No new MCP tools** — fallback is invisible at the MCP surface.
- **Embedding fallback default-off via documentation** — the spec recommends
  not enabling fallback on the embeddings route to keep the
  `embedding_model` column in `snapshots` consistent. CHANGELOG and
  `using-clx` skill mention this.
- **`clx trust` is the natural follow-up** for v0.7.x — promote non-inert
  project keys past the allowlist after explicit user consent.
