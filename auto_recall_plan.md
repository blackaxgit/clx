# Auto-Context Recall Implementation Plan

**Date:** 2026-03-12
**Status:** Architecture Blueprint
**Branch:** `feat/auto-context-recall`

---

## Summary

Add automatic context recall to CLX's `UserPromptSubmit` hook. On every user prompt, the hook embeds the prompt text, runs hybrid search (semantic + FTS5) against stored snapshots, and injects the top-K relevant results as `additionalContext`. This gives Claude automatic awareness of past sessions without requiring explicit `clx_recall` calls.

---

## Critical Discovery

**UserPromptSubmit DOES receive the user's prompt text** in a `prompt` field (confirmed from official Claude Code docs at code.claude.com/docs/en/hooks). CLX's `HookInput` struct is currently MISSING this field — it must be added. This enables true semantic search on the actual user input.

---

## Current State

- **SessionStart** — auto-injects previous session summary + project rules (via `systemMessage`)
- **UserPromptSubmit** — only injects a static orchestrator reminder (no context recall)
- **clx_recall** — must be called explicitly by Claude (semantic + FTS5 hybrid search)
- **No auto-recall on each prompt** — this is the gap we're filling

---

## 1. Architecture Overview

### Data Flow

```
UserPromptSubmit event fires (Claude Code sends JSON with `prompt` field)
         |
         v
clx-hook main.rs: parse HookInput (now includes `prompt` field)
         |
         v
handle_user_prompt_submit(input: HookInput)
         |
         +-- load Config::load() -> read auto_recall config
         |
         +-- prompt.len() > min_prompt_len? and auto_recall.enabled?
         |     NO -> output existing ORCHESTRATOR_CONTEXT only
         |     YES ->
         |       tokio::time::timeout(auto_recall.timeout_ms = 500ms)
         |         |
         |         v
         |       RecallEngine::query(prompt, config) -> Vec<RecallHit>
         |         |
         |         +-- Try: ollama.embed(prompt) -> EmbeddingStore::find_similar()
         |         |     filter by similarity_threshold -> semantic hits
         |         |
         |         +-- Try: storage.search_snapshots_fts(prompt, limit) -> FTS hits
         |         |
         |         +-- hybrid_merge(semantic, fts) -> sorted top-K
         |         |
         |         returns: Vec<RecallHit>
         |
         +-- format_recall_context(hits, max_chars) -> Option<String>
         |
         +-- build final additionalContext:
               ORCHESTRATOR_CONTEXT + "\n\n" + recall_context
         |
         v
output_generic("UserPromptSubmit", Some(&final_context), None)
         |
         v
Claude receives additionalContext with relevant past context
```

### Fallback Tiers

1. **Semantic + FTS5 hybrid** (best quality, requires Ollama + sqlite-vec)
2. **FTS5 only** (good keyword match, <10ms, always available in v3+ DB)
3. **No recall context** (any error, timeout, disabled) -> existing ORCHESTRATOR_CONTEXT only

---

## 2. New Config: `AutoRecallConfig`

**File:** `crates/clx-core/src/config.rs`

```yaml
# ~/.clx/config.yaml
auto_recall:
  enabled: true              # master switch
  max_results: 3             # top-K results to inject
  similarity_threshold: 0.5  # minimum relevance score (0.0-1.0)
  max_context_chars: 1000    # budget for recall block (avoid silent truncation)
  timeout_ms: 500            # hard timeout for entire recall operation
  fallback_to_fts: true      # use FTS5 if semantic fails/times out
  include_key_facts: true    # include key_facts field from snapshots
  min_prompt_len: 10         # skip recall for very short prompts
```

### Struct Definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutoRecallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_auto_recall_max_results")]
    pub max_results: usize,                    // default: 3, range: 1-10

    #[serde(default = "default_auto_recall_similarity_threshold")]
    pub similarity_threshold: f64,             // default: 0.5, range: 0.0-1.0

    #[serde(default = "default_auto_recall_max_context_chars")]
    pub max_context_chars: usize,              // default: 1000, range: 100-5000

    #[serde(default = "default_auto_recall_timeout_ms")]
    pub timeout_ms: u64,                       // default: 500, range: 100-10000

    #[serde(default = "default_true")]
    pub fallback_to_fts: bool,

    #[serde(default = "default_true")]
    pub include_key_facts: bool,

    #[serde(default = "default_auto_recall_min_prompt_len")]
    pub min_prompt_len: usize,                 // default: 10
}
```

### Environment Variables

| Variable | Type | Default | Range |
|----------|------|---------|-------|
| `CLX_AUTO_RECALL_ENABLED` | bool | `true` | true/false |
| `CLX_AUTO_RECALL_MAX_RESULTS` | usize | `3` | 1-10 |
| `CLX_AUTO_RECALL_SIMILARITY_THRESHOLD` | f64 | `0.50` | 0.0-1.0 |
| `CLX_AUTO_RECALL_MAX_CONTEXT_CHARS` | usize | `1000` | 100-5000 |
| `CLX_AUTO_RECALL_TIMEOUT_MS` | u64 | `500` | 100-10000 |
| `CLX_AUTO_RECALL_FALLBACK_TO_FTS` | bool | `true` | true/false |
| `CLX_AUTO_RECALL_INCLUDE_KEY_FACTS` | bool | `true` | true/false |

---

## 3. HookInput Change

**File:** `crates/clx-hook/src/types.rs`

Add after `hook_event_name`:

```rust
/// User prompt text (for UserPromptSubmit)
pub prompt: Option<String>,
```

`Option<String>` because only UserPromptSubmit sends this field. Serde silently ignores missing fields for other hook events.

---

## 4. RecallEngine — Shared Logic Extraction

**File:** `crates/clx-core/src/recall.rs` (NEW)

Extract recall algorithm from `clx-mcp/src/tools/recall.rs` into a reusable struct in `clx-core`, avoiding code duplication between MCP tool and hook.

### Public API

```rust
pub struct RecallHit {
    pub snapshot_id: i64,
    pub session_id: String,
    pub created_at: String,
    pub summary: Option<String>,
    pub key_facts: Option<String>,
    pub score: f64,
    pub search_type: RecallSearchType,
}

pub enum RecallSearchType {
    Semantic,
    Fts5,
    Hybrid,
    Text,
}

pub struct RecallQueryConfig {
    pub max_results: usize,
    pub similarity_threshold: f64,
    pub fallback_to_fts: bool,
    pub include_key_facts: bool,
}

pub struct RecallEngine<'a> {
    storage: &'a Storage,
    ollama: Option<&'a OllamaClient>,
    embedding_store: Option<&'a EmbeddingStore>,
}

impl<'a> RecallEngine<'a> {
    pub fn new(...) -> Self;
    pub async fn query(&self, query: &str, config: &RecallQueryConfig) -> Vec<RecallHit>;
}
```

### Algorithm (ported from clx_recall MCP tool)

- Semantic: `ollama.embed(query)` -> `embedding_store.find_similar()` -> filter by threshold
- Score formula: `1.0 - (distance / 2.0).min(1.0)`
- FTS5: `storage.search_snapshots_fts(query, limit)`
- Hybrid merge: semantic weight 0.6 + FTS5 weight 0.4, dedup by snapshot_id
- Sort descending, take top-K

### MCP Refactor

After extraction, `clx-mcp/src/tools/recall.rs` delegates to `RecallEngine::query()` and formats `Vec<RecallHit>` into its existing verbose JSON response.

---

## 5. UserPromptSubmit Handler Redesign

**File:** `crates/clx-hook/src/hooks/subagent.rs`

### Pseudocode

```rust
async fn handle_user_prompt_submit(input: HookInput) -> Result<()> {
    const ORCHESTRATOR_CONTEXT: &str = "You are the Orchestrator...";

    let recall_ctx = build_recall_context(&input).await;

    let additional_context = match recall_ctx {
        Some(recall) => format!("{ORCHESTRATOR_CONTEXT}\n\n{recall}"),
        None => ORCHESTRATOR_CONTEXT.to_string(),
    };

    output_generic("UserPromptSubmit", Some(&additional_context), None);
    Ok(())
}

async fn build_recall_context(input: &HookInput) -> Option<String> {
    let config = Config::load().ok()?;
    if !config.auto_recall.enabled { return None; }

    let prompt = input.prompt.as_deref()?;
    if prompt.len() < config.auto_recall.min_prompt_len { return None; }

    let timeout = Duration::from_millis(config.auto_recall.timeout_ms);
    tokio::time::timeout(timeout, do_recall(prompt, &config)).await.ok()?
}

async fn do_recall(prompt: &str, config: &Config) -> Option<String> {
    let storage = Storage::open_default().ok()?;
    // Create Ollama client with tight timeout, 0 retries
    let ollama = OllamaClient::new(OllamaConfig {
        timeout_ms: config.auto_recall.timeout_ms.saturating_sub(50),
        max_retries: 0,
        ..config.ollama.clone()
    }).ok();
    let embedding_store = EmbeddingStore::open(...).ok()?;

    let engine = RecallEngine::new(&storage, ollama.as_ref(), embedding_store_ref);
    let hits = engine.query(prompt, &recall_config).await;

    if hits.is_empty() { return None; }
    Some(format_recall_context(&hits, config.auto_recall.max_context_chars))
}
```

---

## 6. Context Formatting Strategy

**Budget:** 1000 chars max (conservative — reports suggest ~1000-2000 char silent drop)

### Format

```
[Relevant past context]:
• 2026-03-11 (score 0.87): Implemented RecallEngine with hybrid search. [Facts: sqlite-vec distance threshold 1.5]
• 2026-03-10 (score 0.72): Fixed UserPromptSubmit hook — prompt field was missing.
• 2026-03-09 (score 0.65): Added dashboard Settings tab with config editing.
```

### Allocation per hit (~325 chars each for 3 hits in 1000 chars)

- Header: 25 chars
- Bullet prefix + date + score: ~35 chars
- Summary (truncated to 200 chars): ~200 chars
- Key facts (truncated to 80 chars): ~80 chars

---

## 7. Performance Budget

| Operation | P50 | P99 | Notes |
|-----------|-----|-----|-------|
| Config::load() | 1ms | 5ms | File I/O, YAML parse |
| Storage::open_default() | 2ms | 10ms | SQLite open |
| ollama.embed() | 50ms | 400ms | Cold: model load; warm: fast |
| find_similar() | 1ms | 5ms | sqlite-vec KNN |
| search_snapshots_fts() | 1ms | 8ms | FTS5 BM25 |
| hybrid_merge + format | 0ms | 1ms | Pure CPU |
| **Total (warm Ollama)** | **55ms** | **430ms** | Within 500ms budget |
| **Total (FTS5 fallback)** | **5ms** | **25ms** | Always fast |

**Key optimization:** Create `OllamaClient` with `max_retries: 0` in the hook to avoid retry delays.

---

## 8. File Changes

### New Files

| File | Purpose |
|------|---------|
| `crates/clx-core/src/recall.rs` | `RecallEngine`, `RecallHit`, `RecallQueryConfig` |

### Modified Files

| File | Change |
|------|--------|
| `crates/clx-core/src/config.rs` | Add `AutoRecallConfig` struct, add to `Config`, add env overrides |
| `crates/clx-core/src/lib.rs` | Add `pub mod recall;` |
| `crates/clx-hook/src/types.rs` | Add `prompt: Option<String>` to `HookInput` |
| `crates/clx-hook/src/hooks/subagent.rs` | Full redesign with `build_recall_context`, `do_recall`, `format_recall_context` |
| `crates/clx-mcp/src/tools/recall.rs` | Refactor to use `RecallEngine` (remove duplicated methods) |
| `crates/clx/src/dashboard/settings/sections.rs` | Add Auto Recall section (9th section) |
| `crates/clx/src/dashboard/settings/fields.rs` | Add field definitions for auto_recall config |
| `crates/clx/src/dashboard/settings/config_bridge.rs` | Add get/set/toggle for auto_recall fields |

---

## 9. Dashboard Settings Integration

Add "Auto Recall" as the 9th section in the existing Settings tab (from `feat/dashboard-settings` branch).

### Fields to add

| Field | Type | Widget | Validation | Default |
|-------|------|--------|------------|---------|
| `enabled` | `bool` | Toggle | none | true |
| `max_results` | `usize` | Number input | 1..=10 | 3 |
| `similarity_threshold` | `f64` | Number input (2 dec) | 0.0..=1.0 | 0.50 |
| `max_context_chars` | `usize` | Number input | 100..=5000 | 1000 |
| `timeout_ms` | `u64` | Number input | 100..=10000 | 500 |
| `fallback_to_fts` | `bool` | Toggle | none | true |
| `include_key_facts` | `bool` | Toggle | none | true |
| `min_prompt_len` | `usize` | Number input | 1..=100 | 10 |

---

## 10. Phased Implementation Plan

### Phase 1 — Foundation: Config + Types (no behavior change)

- [ ] 1.1 Add `AutoRecallConfig` struct to `clx-core/src/config.rs` with all 8 fields and defaults
- [ ] 1.2 Add `auto_recall: AutoRecallConfig` to `Config` struct with `#[serde(default)]`
- [ ] 1.3 Add env override block in `apply_env_overrides()` for 7 fields
- [ ] 1.4 Add `pub prompt: Option<String>` to `HookInput` in `clx-hook/src/types.rs`
- [ ] 1.5 Verify: `cargo build --workspace && cargo test --workspace` passes

### Phase 2 — RecallEngine Extraction

- [ ] 2.1 Create `crates/clx-core/src/recall.rs` with `RecallHit`, `RecallSearchType`, `RecallQueryConfig`
- [ ] 2.2 Implement `RecallEngine::new()` with lifetime-tied references
- [ ] 2.3 Port `try_semantic()` from MCP's `try_semantic_search`
- [ ] 2.4 Port `try_fts()` from MCP's `text_based_search` + `text_based_search_fallback`
- [ ] 2.5 Implement `hybrid_merge()` — dedup, weight 0.6/0.4, sort, top-K
- [ ] 2.6 Implement `query()` as public async entry point
- [ ] 2.7 Add `pub mod recall;` to `clx-core/src/lib.rs`
- [ ] 2.8 Write unit tests (merge dedup, weights, format truncation, graceful degradation)
- [ ] 2.9 Refactor `clx-mcp/src/tools/recall.rs` to delegate to `RecallEngine`
- [ ] 2.10 Verify: all existing MCP tests still pass

### Phase 3 — Hook Integration

- [ ] 3.1 Redesign `handle_user_prompt_submit` in `clx-hook/src/hooks/subagent.rs`
- [ ] 3.2 Add `build_recall_context()` with config check, prompt length check
- [ ] 3.3 Add `do_recall()` with storage/ollama/embedding setup + RecallEngine
- [ ] 3.4 Add `format_recall_context()` with char budget truncation
- [ ] 3.5 Wire `tokio::time::timeout` around recall operation
- [ ] 3.6 Add tests: disabled, short prompt, missing prompt, timeout degradation
- [ ] 3.7 Manual test: `echo '{"hook_event_name":"UserPromptSubmit",...,"prompt":"..."}' | clx-hook`
- [ ] 3.8 Verify: `cargo test --workspace && cargo clippy -- -D warnings`

### Phase 4 — Dashboard + Polish

- [ ] 4.1 Add Auto Recall section to dashboard settings (sections.rs, fields.rs, config_bridge.rs)
- [ ] 4.2 Update SECTIONS const (9 sections), add field definitions
- [ ] 4.3 Add get/set/toggle for all auto_recall fields in config_bridge
- [ ] 4.4 Manual end-to-end test with real Claude Code session
- [ ] 4.5 Verify latency: time the hook with `time echo '...' | clx-hook`
- [ ] 4.6 Final `cargo test --workspace && cargo clippy -- -D warnings && cargo fmt --check`

---

## 11. Test Strategy

### Unit Tests (in `clx-core/src/recall.rs`)

- `test_recall_hit_score_from_distance` — verify formula
- `test_hybrid_merge_dedup_by_snapshot_id` — same snapshot in both lists
- `test_hybrid_merge_weights` — semantic 0.6 + FTS 0.4
- `test_hybrid_merge_sorts_descending` — highest score first
- `test_hybrid_merge_takes_top_k` — respects max_results
- `test_format_context_under_budget` — total chars <= max_context_chars
- `test_format_context_empty_returns_none` — no hits -> None
- `test_query_graceful_no_ollama` — returns FTS results only
- `test_query_graceful_no_vecstore` — returns FTS results only

### Hook Tests (in `clx-hook`)

- `test_user_prompt_submit_recall_disabled` — enabled=false -> no recall
- `test_user_prompt_submit_short_prompt` — prompt < min_prompt_len -> no recall
- `test_user_prompt_submit_missing_prompt` — prompt=None -> orchestrator context only
- `test_user_prompt_submit_timeout_degrades` — slow recall -> orchestrator context only

### Integration Tests

- `test_hook_no_snapshots` — empty DB -> no recall context, hook still outputs
- `test_hook_with_snapshots` — DB has snapshot -> recall context in output
- `test_hook_output_valid_json` — output parses as valid hook JSON

---

## 12. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| additionalContext silently truncated at ~1000 chars | Partial context loss | Default max_context_chars=1000, configurable |
| Ollama cold start exceeds 500ms timeout | No recall on first prompt | Acceptable; subsequent prompts work after warmup |
| SQLite WAL contention between hook and MCP | Hook hangs | Hook is read-only; SQLite allows concurrent readers |
| `prompt` field missing in older Claude Code | Deserialization fail | `Option<String>` — missing field = None, zero risk |
| FTS5 returns irrelevant results for short prompts | Noisy context | min_prompt_len=10 filter + similarity_threshold |
| Recall context increases context pressure | Earlier compaction | 1000 chars is ~250 tokens; minimal impact |
| RecallEngine extraction breaks MCP behavior | Different recall results | Same algorithm, same weights; add regression tests |

---

## 13. Verification Commands

```bash
# Full test suite
cargo test --workspace

# Clippy
cargo clippy --workspace -- -D warnings

# Format check
cargo fmt --all -- --check

# Manual hook test
echo '{"hook_event_name":"UserPromptSubmit","session_id":"test","cwd":"/tmp","prompt":"implement OAuth authentication"}' | ~/.clx/bin/clx-hook

# Verify JSON output
echo '...' | ~/.clx/bin/clx-hook | python3 -m json.tool

# Test disabled
CLX_AUTO_RECALL_ENABLED=false echo '...' | ~/.clx/bin/clx-hook

# Latency test
time echo '...' | ~/.clx/bin/clx-hook
```
