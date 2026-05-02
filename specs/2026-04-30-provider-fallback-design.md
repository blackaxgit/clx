# Provider Fallback + Per-Project Config Override — Design Spec

**Date:** 2026-04-30
**Status:** Draft, pending user review
**Target version:** 0.7.0 (additive, opt-in)

## 1. Goal & Scope

### Goal

Add automatic primary-to-secondary LLM provider failover, configurable at three
tiers: main-only, main + fallback at the global level, and per-project override
of either of the above. Reverses the 0.6.x design's explicit "no automatic
fallback" decision based on user feedback that `default_decision: allow`-style
silent degradation under Azure outage is unsafe for a risk-scoring CLI.

### In scope (v0.7.0)

- New `fallback: Option<CapabilityRoute>` field on `CapabilityRoute` in the
  config schema. Each capability (`chat`, `embeddings`) can independently
  define a fallback or omit one.
- New `LlmClient::Fallback { primary: Box<LlmClient>, fallback: Box<LlmClient> }`
  variant that itself implements `LlmBackend`. Single insertion point at the
  factory; **no production call site changes**.
- Error classification reuses the existing `is_transient` helper — fall back
  on `Connection`, `Timeout`, `RateLimit`, 5xx, 408; fail fast on `Auth`,
  `DeploymentNotFound`, `ContentFilter`, other 4xx.
- In-process cooldown: after a fallback event, the next ~30s of calls go
  straight to the fallback without retrying the primary first. Skips sustained
  latency penalty during ongoing outages without `failsafe`-crate complexity.
- Per-project config file at `<repo>/.clx/config.yaml`, discovered by walking
  up from CWD to `$HOME`. Env-var escape: `CLX_CONFIG_PROJECT=/path` or
  `CLX_CONFIG_PROJECT=none`.
- Layered config loading via the `figment` crate (replaces ad-hoc
  `serde_yml::from_str`). Schema types stay on `serde_yml`-compatible derives.
- Deep-merge for scalars; full-replace for list-typed fields (`providers:`,
  `fallback:` blocks).
- Precedence (low → high): built-in defaults → `~/.clx/config.yaml` →
  `<project>/.clx/config.yaml` → `CLX_*` env vars → CLI flags.
- Project-config security allowlist: only **inert** keys (`provider`, `model`,
  `chat`/`embeddings` routes, threshold scalars) take effect from a project
  file. **Non-inert** keys (`endpoint:`, `api_key_env:`, `api_key_file:`,
  `host:`) are silently dropped with a single `WARN` log when present. Keeps
  `cd` into a hostile repo from redirecting credentials or HTTP.

### Out of scope (v0.7.x deferred)

- The `clx trust <repo>` UX command + `~/.clx/trusted.json` storage. The v0.7.0
  shape silently ignores risky keys; trust gating is a follow-up.
- Multi-fallback chains (`fallback: [a, b, c]`). v0.7.0 ships a single
  fallback per capability; chain support is a metadata-only schema extension
  if demand emerges.
- Cross-process cooldown persistence (`~/.cache/clx/fallback-state.json`).
  v0.7.0 cooldown is per-CLI-invocation only.
- Hedging (firing both primary and fallback in parallel, taking whichever wins
  first). Doubles Azure spend; rejected.
- Circuit-breaker statistics across calls (failure rate, sliding windows).
  v0.7.0 has only "did the most recent primary call fail."
- Migration of `pre-0.6.x` legacy configs that hit the new `figment` loader.
  The 0.6.x auto-translate path is preserved unchanged.

## 2. Architecture

### 2.1 Enum variant + generic helper

Add a new variant to `crates/clx-core/src/llm/mod.rs`:

```rust
pub enum LlmClient {
    Ollama(OllamaBackend),
    Azure(AzureOpenAIBackend),
    Fallback(FallbackClient),
}

#[derive(Debug)]
pub struct FallbackClient {
    pub primary: Box<LlmClient>,
    pub fallback: Box<LlmClient>,
    cooldown: std::sync::Mutex<Option<std::time::Instant>>,
}
```

`Box<LlmClient>` lets us nest if a future schema ever wants chains. `Mutex`
over `AtomicCell<Option<Instant>>` because `Instant` isn't `Pod` and the
contention is negligible (one CLI process, max one update per call).

The dispatcher methods on `LlmClient` extend their match arms by one case;
that case calls `FallbackClient::generate`/`embed`/`is_available`, which
implement the actual fallback policy.

### 2.2 `is_transient` becomes a method on `LlmError`

Today's `is_transient` lives as a free function in `azure.rs`. Move it to
`impl LlmError` (or a `pub(crate)` free function in `llm/mod.rs`) so both
backends and `FallbackClient` use the identical predicate:

```rust
impl LlmError {
    /// Returns true if a fallback or retry might recover.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            LlmError::Timeout
                | LlmError::Connection(_)
                | LlmError::RateLimit { .. }
        ) || matches!(
            self,
            LlmError::Server { status, .. } if (500..=599).contains(status) || *status == 408
        )
    }
}
```

### 2.3 `FallbackClient` policy

```rust
impl FallbackClient {
    const COOLDOWN: Duration = Duration::from_secs(30);

    fn use_fallback_directly(&self) -> bool {
        if let Some(t) = *self.cooldown.lock().unwrap() {
            return t.elapsed() < Self::COOLDOWN;
        }
        false
    }

    fn record_primary_failure(&self) {
        *self.cooldown.lock().unwrap() = Some(std::time::Instant::now());
    }

    pub async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        if self.use_fallback_directly() {
            return self.fallback.generate(prompt, model).await;
        }
        match self.primary.generate(prompt, model).await {
            Ok(v) => Ok(v),
            Err(e) if e.is_transient() => {
                tracing::warn!(
                    primary = %describe(&self.primary),
                    fallback = %describe(&self.fallback),
                    error.kind = %e.kind_str(),
                    "primary failed; falling back"
                );
                self.record_primary_failure();
                self.fallback.generate(prompt, model).await
            }
            Err(e) => Err(e),
        }
    }
    // analogous embed, is_available
}
```

`is_available` returns `primary.is_available() || fallback.is_available()` —
either backend healthy means "fallback path is alive."

### 2.4 Factory wiring

`Config::create_llm_client(Capability)` (in `config.rs`) gains:

```rust
let primary = self.build_client_for_provider(&route.provider)?;
if let Some(fb) = route.fallback.as_ref() {
    let fallback = self.build_client_for_provider(&fb.provider)?;
    return Ok(LlmClient::Fallback(FallbackClient::new(primary, fallback)));
}
Ok(primary)
```

When `route.fallback.is_none()`, the factory returns the bare `LlmClient`
unchanged — zero behavioral change for users who don't opt in.

## 3. Config Schema Changes

### 3.1 New `fallback` field

```rust
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CapabilityRoute {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Box<CapabilityRoute>>,
}
```

`Box` because `CapabilityRoute` would otherwise be infinitely recursive.
`skip_serializing_if = "Option::is_none"` keeps existing configs lean.

### 3.2 Example user config

```yaml
providers:
  azure-prod:
    kind: azure_openai
    endpoint: https://<your-resource>.openai.azure.com
    api_key_env: AZURE_OPENAI_API_KEY
  ollama-local:
    kind: ollama
    host: http://127.0.0.1:11434

llm:
  chat:
    provider: azure-prod
    model: gpt-5.4-mini
    fallback:
      provider: ollama-local
      model: qwen3:1.7b
  embeddings:
    provider: ollama-local
    model: qwen3-embedding:0.6b
```

## 4. Per-Project Config Override

### 4.1 Discovery & loading

A new function `Config::load_layered() -> Result<Config, ConfigError>`:

1. Build a `figment::Figment` with these layers, lowest precedence first:
   - Built-in defaults (`Config::default()`).
   - `Yaml::file(global_config_path())` — `~/.clx/config.yaml`.
   - `Yaml::file(project_config_path())` — first match walking up from `CWD`,
     filtered through the inert-keys allowlist (§4.3).
   - `Env::prefixed("CLX_")` — env-var overrides.
2. `.extract::<Config>()` to materialize.
3. Apply existing `translate_legacy_in_place()` for the legacy `ollama:` block.
4. Apply existing `apply_env_overrides()` (the dedicated `CLX_LLM_CHAT_*`
   shortcuts).

### 4.2 Walk-up

```rust
fn project_config_path() -> Option<PathBuf> {
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
```

Walk-up stops at `$HOME` to avoid the cargo "unbounded discovery" footgun
the April 2026 pre-RFC flagged.

### 4.3 Inert-keys allowlist

Project configs are filtered through a private function before merging:

```rust
const INERT_PROJECT_KEYS: &[&str] = &[
    "validator.layer1_enabled",
    "validator.layer1_timeout_ms",
    "validator.default_decision",
    "context.embedding_model",
    "auto_recall.*",
    "user_learning.*",
    "llm.chat.provider",
    "llm.chat.model",
    "llm.chat.fallback",
    "llm.embeddings.provider",
    "llm.embeddings.model",
    "llm.embeddings.fallback",
    "logging.level",
];
```

(`fallback` recurses; the allowlist for nested `fallback.*` is the same as
`llm.chat.*` minus `fallback` itself to bound depth.)

Non-inert keys present in the project file generate one `WARN` log on load:
`"project config key '<dotted.path>' is not inert; ignored. See clx trust (v0.7.x)."`

Explicitly **non-inert** (rejected from project config):

- `providers.*.endpoint`, `providers.*.host`, `providers.*.api_key_env`,
  `providers.*.api_key_file`, `providers.*.api_version` — all of these
  influence where credentials and traffic flow.
- `logging.file` — a project config could write logs to an attacker-controlled
  path.
- `validator.enabled` (master switch) — a hostile project shouldn't be able
  to disable validation entirely.

### 4.4 Merge semantics

`figment`'s `merge` strategy: scalars in the project layer override globals,
**list-typed values are replaced wholesale** (not concatenated). A project
overriding `providers:` replaces the entire provider list. `fallback:` blocks
replace at the leaf — a project setting `llm.chat.fallback: null` removes
the global fallback for that repo.

## 5. Backward Compatibility

- A user with no `fallback:` field anywhere keeps current behavior bit-for-bit.
- A user with no project config keeps current behavior; `figment` with one
  layer behaves identically to today's `serde_yml::from_str(read_to_string(...))`.
- The legacy `ollama:` block auto-translation (introduced in 0.6.0) is
  preserved unchanged — applied after `figment` materializes.
- The 0.6.x env-var overrides (`CLX_LLM_CHAT_PROVIDER`, etc.) keep working;
  `figment::Env::prefixed("CLX_")` covers them and the existing
  `apply_env_overrides()` becomes redundant but is left in place as a safety
  net during the transition.

## 6. Testing

### 6.1 Unit tests in `llm/mod.rs`

- `fallback_on_primary_503_succeeds` — wiremock primary returns 503, wiremock
  fallback returns 200, assert fallback's response is returned.
- `fallback_not_used_on_terminal_error` — primary returns 401, fallback would
  succeed; assert the 401 is propagated unchanged (no fallback).
- `cooldown_skips_primary_for_30s` — make primary fail once, then call again
  immediately; assert primary is not called the second time.
- `cooldown_expires_and_primary_retried` — same as above but with a manually
  advanced `Instant` (use a test-only constructor that takes a fake clock or
  reduce `COOLDOWN` to 0 in the test).

### 6.2 Unit tests in `config.rs` (`schema_tests` module)

- `fallback_field_round_trips` — serialize a `CapabilityRoute` with fallback,
  parse it back, assert equality.
- `project_config_overrides_chat_provider` — write two YAML files in temp
  dirs, call `load_layered()`, assert the project layer wins for `provider`.
- `project_config_drops_endpoint_with_warn` — project YAML sets a
  `providers.azure-prod.endpoint`; assert the global endpoint survives and a
  `WARN` was logged.
- `walk_up_finds_first_match_and_stops_at_home` — fixture creates `.clx/`
  in two ancestor dirs; assert the closer one wins.
- `cli_flag_beats_env_beats_project_beats_global` — assert full precedence
  ordering.

### 6.3 Wiremock for fallback

Reuses the existing pattern in `azure.rs`. Two `MockServer` instances per
fallback test. `expect(1)` on each mock to verify each backend is called
exactly once during a fallback event.

### 6.4 No real-Azure CI

Same posture as 0.6.0: no live Azure tests in CI. Real-tenant smoke checklist
in `CONTRIBUTING.md` gains a fallback section: configure `azure-prod` with a
deliberately-wrong deployment name and confirm the configured fallback fires.

## 7. Observability

Per fallback event:

```
WARN llm.fallback primary=azure fallback=ollama op=generate \
     error.kind=Timeout error.detail="..." latency_ms=30000 \
     "primary failed; falling back"
```

One `WARN` per fallback. One `INFO` after a successful primary call following
a cooldown expiry (`primary recovered after fallback period`). No log on
every successful primary call.

## 8. Crate Choices

| Crate | Why |
|---|---|
| `figment` v0.10+ | Layered config (global + project + env), explicit merge strategies, active maintenance, replaces ad-hoc YAML loading |
| `dirs` (already present) | `home_dir()` for walk-up bounds |
| `serde_yml` (already present) | Schema types and existing derives |
| `tracing` (already present) | Structured fallback logging |
| **Not added** | `failsafe` (overkill for 1–10 calls/min), `tower-retry` (forces Service trait refactor), `reqwest-retry` (operates on HTTP not cross-backend), `backon` (retry, not fallback) |

## 9. Versioning

- 0.6.1 → 0.7.0. Minor bump because:
  - New behavior (fallback) is opt-in; default remains "primary fails loudly."
  - New config fields are backward-compatible (`Option`/`default`).
  - Per-project file is opt-in (no file = unchanged behavior).
- Auto-Tag Release fires on merge → tag `v0.7.0` → release workflow → brew tap.

## 10. Risks & Mitigations

1. **`figment`'s YAML provider is less battle-tested than its TOML provider.**
   Mitigation: snapshot tests for the merge output; fall back to keeping
   `serde_yml::from_str` for the global file if `figment::Yaml` mishandles
   our tagged-enum providers list.
2. **Cooldown TTL during partial outages.** If Azure flaps (works for 30s,
   fails for 5s, works for 30s), users may pay Azure for some calls and route
   to Ollama for others. Mitigation: log every fallback so users can see
   the pattern; document that `COOLDOWN` is intentionally short.
3. **Project-config trust is too lenient.** Silently dropping risky keys is
   safer than honoring them but less safe than gating behind explicit trust.
   Mitigation: ship the WARN log loud and clear; add `clx trust` UX in v0.7.x
   on demand.
4. **Walk-up behavior in nested-repo edge cases.** If a project under
   `~/projects/inner-repo/` is a sub-repo of `~/projects/outer-repo/`, the
   inner config wins (closer to CWD). Mitigation: documented; matches cargo.
5. **Embedding model identity (0.6.0's column) interacting with fallback.**
   If the primary embedding provider succeeds for some calls and the fallback
   for others, the snapshots table gets mixed `embedding_model` values, and
   recall mismatches will misidentify the "current" model. Mitigation:
   recommendation in CHANGELOG: don't enable fallback on the embeddings route
   if you care about recall consistency; v0.7.0 disables fallback on embed
   path by default, requires explicit opt-in.

## 11. Implementation Order (informational; plan owns this)

1. Add `figment` to workspace deps.
2. Move `is_transient` from `azure.rs` to `LlmError::is_transient` method.
3. Add `fallback` field to `CapabilityRoute`.
4. Add `LlmClient::Fallback` variant + `FallbackClient` struct + trait impl.
5. Modify `Config::create_llm_client` factory to wrap with fallback when set.
6. Migrate `Config::load` to layered `figment` loader.
7. Implement `project_config_path()` walk-up and `CLX_CONFIG_PROJECT` escape.
8. Implement inert-keys allowlist filter for project layer.
9. Wiremock unit tests (fallback policy + cooldown).
10. Schema tests (project override + walk-up + precedence + WARN).
11. Bump version 0.6.1 → 0.7.0; CHANGELOG entry.
12. Update `CONTRIBUTING.md` smoke checklist with a fallback validation step.
13. Update `using-clx` skill to mention fallback exists.
