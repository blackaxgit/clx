# CLX 0.8.0 Pre-Release Spec — Memory & Recall

Domain: memory + recall pipeline. Behavior described is ACTUAL behavior read
from source on branch `feat/0.8.0-memory-skills-coverage`. Every behavioral
claim cites `file:line`. QA: treat each "Verification" block as a runnable gate
before tagging v0.8.0.

---

## 1. Overview

### 1.1 Pipeline stages (text diagram)

```
user query (MCP clx_recall  OR  UserPromptSubmit auto-recall)
   |
   v
[1] candidate generation  (RecallEngine::query, engine.rs:100)
     - FTS5 first, always (<10ms): try_fts            engine.rs:104-107
     - semantic second (embedder + repo.semantic_enabled): try_semantic
                                                        engine.rs:110-114
     - last-resort FTS5 if fallback off & semantic empty engine.rs:117-119
   |
   v
[2] fusion
     - rrf_enabled=true  -> rrf_fuse(k)   engine.rs:121-122 ; rrf.rs:55
     - rrf_enabled=false -> hybrid_merge (0.6 sem / 0.4 fts) engine.rs:124 ; mod.rs:145
   |
   v
[3] cross-encoder rerank (optional)        engine.rs:131-137
     - only if reranker_enabled && backend attached && !fused.is_empty()
     - apply_reranker wraps backend in tokio timeout  rerank.rs:98-178
     - timeout / not-ready / error / len-mismatch -> input unchanged (RRF order)
   |
   v
[4] multiplicative time-decay (if half_life>0)  engine.rs:139-145 ; decay.rs:46
   |
   v
[5] percentile gate (if percentile>0)           engine.rs:147-149 ; decay.rs:82
   |
   v
ranked Vec<RecallHit>
   |
   +-- MCP: verbose JSON + redact_secrets        recall.rs:77-120
   +-- hook: format_recall_context (XML-escaped)  mod.rs:194 ; subagent.rs:238
            (+ optional pinned-sessions block)    subagent.rs:227,244-249
```

### 1.2 Trigger points

| Trigger | Entry | Config gate | Budget |
| --- | --- | --- | --- |
| `UserPromptSubmit` auto-recall | `handle_user_prompt_submit` `subagent.rs:33` -> `build_recall_context` `subagent.rs:138` -> `do_recall` `subagent.rs:157` | `auto_recall.enabled` `subagent.rs:116` | `tokio::time::timeout(auto_recall.timeout_ms)` `subagent.rs:144-147`, default 500 ms (`config/mod.rs:910-912`) |
| MCP `clx_recall` | `tool_recall` `recall.rs:26` | none (user-invoked) | none on the recall itself; `runtime.block_on` `recall.rs:67` |

### 1.3 Latency budget breakdown (auto-recall default path)

Total wall clock is bounded by `auto_recall.timeout_ms` = 500 ms
(`config/mod.rs:910`). Within that budget:

- FTS5 query: <10 ms (documented invariant, `engine.rs:98-99`).
- Semantic embed round-trip: remote Ollama/Azure call, variable; on error
  returns empty and pipeline continues (`engine.rs:163-169`).
- Rerank stage: capped by `reranker_timeout_ms` = 250 ms
  (`config/mod.rs:930-932`). On expiry returns RRF order
  (`rerank.rs:140-148`). The cold model load is INSIDE the same
  `spawn_blocking` as inference so the 250 ms governs load+score together
  (`fastembed.rs:18-22, 490-554`).
- Decay + gate: pure CPU, microseconds (`decay.rs`).

If the whole `do_recall` exceeds 500 ms it is dropped via `.ok()?` and the
hook still emits the orchestrator context with no recall block
(`subagent.rs:44-52, 145-147`).

---

## 2. Feature inventory (REAL defaults from code)

### 2.1 `AutoRecallConfig` (`config/mod.rs:373-467`)

| Field | Default | Default fn / line |
| --- | --- | --- |
| `enabled` | `true` | `default_true` `config/mod.rs:779` |
| `max_results` | `3` | `default_auto_recall_max_results` `:898-900` |
| `similarity_threshold` | `0.35` (f32) | `:902-904` |
| `max_context_chars` | `1000` | `:906-908` |
| `timeout_ms` | `500` | `:910-912` |
| `fallback_to_fts` | `true` | `default_true` `:779` |
| `include_key_facts` | `true` | `default_true` `:779` |
| `min_prompt_len` | `10` | `:914-916` |
| `pin_recent_sessions` | disabled struct | `PinRecentSessionsConfig::default` `:486-494` |
| `rrf_enabled` | `true` | `default_true` `:779` |
| `rrf_k` | `60` | `:918-920` |
| `time_decay_half_life_days` | `30.0` | `:922-924` |
| `percentile_gate` | `0.70` (fraction) | `:926-928` |
| `reranker_enabled` | `true` | `default_true` `:779` |
| `reranker_timeout_ms` | `250` | `:930-932` |

Note: `auto_recall.percentile_gate` is a FRACTION (0.0-1.0). It is converted
to the engine's integer percentile (0-100) by `query_percentile_gate`
(`subagent.rs:252-258`, mirrored in `recall.rs:131-137`): non-finite or `<=0`
-> `0` (gate disabled); otherwise `clamp(0,1)*100` rounded.

### 2.2 `RecallQueryConfig` engine defaults (`recall/mod.rs:109-124`)

These are the DOMAIN defaults used when callers do `..Default::default()`;
the hook overrides them from `AutoRecallConfig` (`subagent.rs:188-199`):
`max_results 10`, `similarity_threshold 0.35`, `fallback_to_fts true`,
`include_key_facts true`, `rrf_enabled true`, `rrf_k 60`,
`time_decay_half_life_days 30.0`, `percentile_gate 70`,
`reranker_enabled true`, `reranker_timeout_ms 250`.

### 2.3 `MemoryConfig.auto_summarize` (`config/mod.rs:509-562`)

| Field | Default | Line |
| --- | --- | --- |
| `enabled` | `false` (opt-in) | `:528-529, 555` |
| `every_n_turns` | `5` | `default_auto_summarize_every_n_turns` `:564-566` |
| `summarizer_capability` | `"chat"` | `default_summarizer_capability` `:568` |
| `max_summary_chars` | `500` | `default_max_summary_chars` `:572` |
| `skip_when_idle` | `true` | `default_true` `:548-549` |

### 2.4 `RetentionConfig` (`config/mod.rs:335-365`)

| Field | Default | Line |
| --- | --- | --- |
| `tool_events_days` | `30` | `default_retention_tool_events_days` `:350-352` |
| `events_days` | `7` | `default_retention_events_days` `:353-355` |
| `snapshots_days` | `0` (keep forever) | `serde(default)` `:346-347` |

### 2.5 `PinRecentSessionsConfig` (`config/mod.rs:472-502`)

| Field | Default | Line |
| --- | --- | --- |
| `enabled` | `false` | `:474-475, 489` |
| `count` | `3` | `default_pin_recent_count` `:496-498` |
| `max_chars_each` | `300` | `default_pin_recent_max_chars` `:500-502` |

### 2.6 MCP tool validation limits

| Constant | Value | Line |
| --- | --- | --- |
| `MAX_QUERY_LEN` | `10_000` | `clx-mcp/src/validation.rs:12` |
| `MAX_CONTENT_LEN` | `100_000` | `validation.rs:15` |
| `MAX_KEY_LEN` | `1_000` | `validation.rs:18` |
| `MAX_SEMANTIC_RESULTS` | `10` | `clx-mcp/src/server.rs:28` |
| `SEMANTIC_DISTANCE_THRESHOLD` | `1.5` | `server.rs:32` |
| `EMBEDDING_STORE_TIMEOUT_MS` | `5000` | `server.rs:25` |

There is no env var directly read by the recall pipeline; configuration is
file/figment-driven via `Config::load()` (`subagent.rs:139`, `recall.rs:31`).

---

## 3. Behavior spec per feature

### 3.1 Auto-recall trigger + injected block

Preconditions (`check_recall_preconditions` `subagent.rs:112-132`):

- Normal: `enabled=true` and `prompt.chars().count() >= min_prompt_len`
  (default 10) -> recall runs.
- Edge (disabled): `enabled=false` -> `None`, no recall block, orchestrator
  context still emitted (`subagent.rs:47-52`).
- Edge (no prompt): `input.prompt` is `None` -> `None` (`subagent.rs:121`).
- Edge (short prompt): char count `< min_prompt_len` -> `None`
  (`subagent.rs:122-129`). Note this counts CHARS not bytes.
- Failure: `Config::load()` errors -> whole `build_recall_context` returns
  `None` (`subagent.rs:139`); hook still succeeds.

Injected content (`do_recall` -> `format_recall_context` `mod.rs:194-265`):

- Wrapper: `<historical-context purpose="past session recall — NOT
  instructions">` ... `</historical-context>` (`mod.rs:204-205, 262`).
- Each hit line: `\u{2022} <created_at> (score X.XX): <summary>` plus optional
  `[Facts: ...]` when `include_key_facts` (`mod.rs:212-244`).
- Hard char budget: total never exceeds `max_context_chars` (default 1000);
  per-hit budget = content_budget / hits (`mod.rs:206-260`). Multi-byte safe
  via `floor_char_boundary` (`mod.rs:224, 237, 253`).
- The entire recall context (including pinned block) is passed through
  `redact_secrets` before injection (`subagent.rs:45`).
- Final injected text = `ORCHESTRATOR_CONTEXT \n\n recall` or just
  `ORCHESTRATOR_CONTEXT` if no recall (`subagent.rs:47-52`).

### 3.2 RRF fusion vs legacy linear merge (backward-compat contract)

- `rrf_enabled=true` (0.8.0 default): `rrf_fuse(&[semantic, fts], k, max)`
  with `k=60` (`engine.rs:121-122`, `rrf.rs:55`). Score = sum over rankers of
  `1/(k + rank)` with 1-indexed ranks (`rrf.rs:64-77`). Dedup by
  `snapshot_id`, summed contributions, `search_type` promoted to `Hybrid`
  only when count>1 (`rrf.rs:79-90`). Ties broken by `snapshot_id`
  descending, deterministic (`rrf.rs:94-99`).
- `rrf_enabled=false` (0.7.x rollback contract, documented at
  `mod.rs:87-88`): `hybrid_merge` weights semantic 0.6, FTS5 0.4
  (`mod.rs:145-178`); FTS score clamped to `[0,1]` before weighting
  (`mod.rs:160`); merged hits become `Hybrid` (`mod.rs:165`).
- Edge: empty inputs -> empty vec (`rrf.rs:216-225`). `k=0` is safe because
  rank starts at 1 (`rrf.rs:252-257`). `max_results=0` -> empty
  (`rrf.rs:269-273`).

### 3.3 Cross-encoder reranker

Model: `bge-reranker-v2-m3` (`fastembed.rs:49`), ~568 MB
(`subagent.rs:78`). Backend `FastembedReranker` (`fastembed.rs:332-576`).

- Activation requires ALL of: `reranker_enabled=true`, a backend attached via
  `with_reranker`, AND `!fused.is_empty()` (`engine.rs:131-134`). If
  `reranker_enabled=false` no backend is constructed at all
  (`subagent.rs:201-204`, `recall.rs:32-34`).
- Timeout: `tokio::time::timeout(reranker_timeout_ms)` default 250 ms
  (`engine.rs:135-136`, `rerank.rs:131`). The cold model load runs inside the
  same `spawn_blocking` as inference so the timeout governs load+score
  (`fastembed.rs:490-554`; regression test `fastembed.rs:901-921`).
- Graceful fallback (input returned unchanged, RRF order preserved):
  `hits empty`; `!backend.is_ready()` (one-shot WARN, `rerank.rs:108-121`);
  backend `Err` (`rerank.rs:135-139`); timeout elapsed
  (`rerank.rs:140-148`); output length != input length
  (`rerank.rs:150-158`). `RERANK_FALLBACK_TOTAL` counter incremented on
  error/timeout/len-mismatch (`rerank.rs:71, 136, 141, 151`).
- Success path: score replaced by `squash_to_unit` logistic map
  (`rerank.rs:160-187`), sorted desc with `snapshot_id` tiebreak, all hits
  `search_type=Hybrid` (`rerank.rs:160-177`).
- `.ready` sentinel lifecycle (F9 hardening, `fastembed.rs:362-431`):
  `is_ready()` -> `ready_at` (process-memoized via `OnceLock`,
  `fastembed.rs:393-396`) -> `verify_ready_uncached` reads sentinel, requires
  header `clx-model-sentinel v1` (`fastembed.rs:58, 100-105`), parses pinned
  artifacts (SHA-256 + size + rel path), then `verify_sentinel_against_disk`
  re-hashes every artifact (`fastembed.rs:274-325`). Legacy opaque markers
  (`ready`/`dryrun`), malformed sentinels, size mismatch, SHA mismatch, or
  path traversal -> NOT ready -> RRF-only (`fastembed.rs:419-430, 252-268`).
- First-run background prefetch: `maybe_prefetch_reranker_model`
  (`subagent.rs:63-86`) runs on first `UserPromptSubmit`; returns early if
  model ready (`subagent.rs:65-67`) or `reranker_enabled=false`
  (`subagent.rs:70-74`); otherwise spawns `clx model fetch --background`
  exactly once per process via `std::sync::Once`
  (`subagent.rs:14, 76-86, 89-106`) and emits one WARN.

### 3.4 Time-decay + percentile gate

- Time-decay (`decay.rs:46-69`): multiplicative
  `score *= 0.5 ^ (age_days / half_life_days)`. `half_life_days <= 0` is a
  no-op passthrough (`decay.rs:47-50`). Negative age (clock skew /
  future-dated snapshot) clamped to 0 so score never amplified
  (`decay.rs:61-67`). Unparseable `created_at` leaves score untouched, no
  panic (`decay.rs:52-56`). Default half-life 30 days.
- Percentile gate (`decay.rs:82-102`): passthrough when `percentile == 0`,
  `hits.len() <= 1`, or `percentile > 100` (`decay.rs:83-85`). Otherwise
  nearest-rank index `round((p/100)*(n-1))` and keep `score >= threshold`
  (`>=`, ties survive) (`decay.rs:95-101`). Default p70 keeps ~top 30%
  (test `decay.rs:260-277` asserts 4 of 10).

### 3.5 `pin_recent_sessions`

`build_pinned_block` (`subagent.rs:265-291`):

- Opt-in: `None` when `enabled=false` OR `count==0` (`subagent.rs:271-273`).
- Excludes the current session by passing `session_id` as
  `exclude_session_id` (`subagent.rs:275-281`); empty `session_id` -> no
  exclusion, all sessions eligible (`subagent.rs:275-279`,
  test `subagent.rs:441-455`).
- Empty DB / no eligible sessions -> `None`
  (`subagent.rs:282-285`, test `:457-466`).
- Rendered by `format_pinned_block` (`mod.rs:274-299`): header
  `## Pinned recent sessions`, one bullet per session
  `- <YYYY-MM-DD> [<sid>]: <summary>`, per-summary truncation to
  `max_chars_each` chars on UTF-8 boundary, embedded newlines flattened to
  spaces (`mod.rs:282-296`).
- Combination with hits (`do_recall` `subagent.rs:227-249`): when hits empty
  the pinned block alone is still emitted (`subagent.rs:229-234`); otherwise
  `format!("{pinned}\n{body}")`.

### 3.6 `tool_events` aggregation

- Mutator tools: `Edit`, `Write`, `MultiEdit`, `NotebookEdit`
  (`aggregator.rs:26`); `Bash` only if `is_mutator_bash` matches the
  conservative leading-verb regex (`aggregator.rs:42-71`) covering
  `git commit|push|reset|rebase|merge|cherry-pick|checkout -`, `rm `,
  `cargo/npm/pip install`, `mv `, `cp `, `chmod `, `chown `, `> /`. Reads
  (`Read`, `Grep`, `git status`, `ls`) are NOT aggregated
  (`aggregator.rs:252-297` tests).
- Emission: `handle_post_tool_use` calls `should_aggregate`, derives target +
  deterministic summary, then `append_or_extend_tool_event`
  (`post_tool_use.rs:56-81`). Outcome = `Success` if `tool_response` present
  else `Error` (`post_tool_use.rs:62-66`).
- 60-second dedup window: bucket = `window_end_unix / 60`
  (`tool_events.rs:21, 82`). UPSERT `INSERT ... ON CONFLICT
  (session_id, tool_name, IFNULL(target,''), (window_end_unix/60)) DO UPDATE`
  increments `occurrence_count`, replaces `summary`/`outcome`/
  `window_end_unix`, preserves original `window_start_unix`/`created_at`
  (`tool_events.rs:57-78`).
- v7 unique index `tool_events_dedup_idx` on the same expression
  (`migration.rs:394-399`) makes cross-process inserts atomic: two parallel
  writers in one bucket collapse to one row with `occurrence_count==2`
  (`tool_events.rs:521-552` regression).
- FK safety: `INSERT OR IGNORE INTO sessions ... 'audit-placeholder'` before
  the event insert (`tool_events.rs:43-47`).
- Retention trim: `cleanup_old_tool_events(days)`; `days==0` -> no-op keep
  all (`tool_events.rs:151-161`); driven by `retention.tool_events_days`
  default 30 via `clx maintenance trim`.

### 3.7 `auto_summarize` (Stop hook)

`handle_stop_auto_summary` -> `run_inner` (`stop_auto_summary.rs:50-165`):

- Opt-in: returns `Ok(())` immediately if
  `memory.auto_summarize.enabled=false` (`stop_auto_summary.rs:63-66`).
- `every_n_turns`: `turns_since_last_auto_summary` counts `tool_events` after
  the last `auto_summary` snapshot, or all if none
  (`snapshot.rs:265-294`); skip if `turns_since < every_n_turns.max(1)`
  (`stop_auto_summary.rs:69-97`). `every_n_turns==0` clamps to 1 with WARN
  (`stop_auto_summary.rs:69-72`).
- `skip_when_idle` (default true): `had_mutator_activity_since_last_auto_
  summary` (`snapshot.rs:332-370`); `Ok(false)` -> skip cleanly; query error
  -> conservatively PROCEED, not skip (`stop_auto_summary.rs:99-111`,
  `snapshot.rs:361-368`).
- Transcript: last `2*every_n_turns` (min 2) turns
  (`stop_auto_summary.rs:44-47, 117-122`).
- Summary build (`build_summary` `:167-191`): LLM via configured capability
  (`summarizer_capability`, unknown -> `Chat`, `stop_auto_summary.rs:196-201`)
  with deterministic-template fallback inside `summarize_turns`. Empty/blank
  summary -> not persisted (`stop_auto_summary.rs:124-131`).
- Snapshot tagged `SnapshotTrigger::AutoSummary` (`stop_auto_summary.rs:144`).
- TOCTOU-safe single snapshot: `create_snapshot_if_no_recent_auto_summary`
  runs the freshness `WHERE NOT EXISTS` probe and the INSERT in one
  `BEGIN IMMEDIATE` transaction (`snapshot.rs:55-120`). Returns `Ok(false)`
  when a sibling handler already wrote within `within_secs`
  (`snapshot.rs:97-114`; `stop_auto_summary.rs:142-163`). Whole handler is
  wrapped in a 10 s soft timeout (`stop_auto_summary.rs:39, 53`).
- All error paths swallow into `Ok(())` so Stop never fails the session
  (`stop_auto_summary.rs:17-21, 74-164`).

### 3.8 MCP tools

- `clx_recall` (`recall.rs:26-128`): input `query` validated to
  `MAX_QUERY_LEN` 10_000 (`recall.rs:27`). Uses a MORE permissive threshold
  than auto-recall: `1.0 - (SEMANTIC_DISTANCE_THRESHOLD/2.0)` = `0.25`
  (`recall.rs:52-56`), `max_results=10` (`recall.rs:55`). RRF/decay/gate/
  reranker pulled from `AutoRecallConfig` (`recall.rs:31-65`). Output is
  verbose pretty JSON list (`session_id`, `created_at`, `relevance_score`,
  `search_type`, `summary`, `key_facts`) passed through `redact_secrets`
  (`recall.rs:77-120`); empty -> `"No relevant context found ..."`.
- `clx_remember` (`remember.rs:17-86`): `text` <= 100_000
  (`MAX_CONTENT_LEN`), up to 50 tags each <= 1_000 (`MAX_KEY_LEN`)
  (`remember.rs:18-19`). Creates a `SnapshotTrigger::Manual` snapshot
  (`remember.rs:47`), summary `Remembered: <text> [tags: ...]`, key_facts =
  text, then best-effort embedding with 5 s timeout
  (`remember.rs:92-150`). Embedding failure does not fail the call.
- `clx_checkpoint` (`checkpoint.rs:14-56`): optional `note` <=
  `MAX_CONTENT_LEN`, `SnapshotTrigger::Checkpoint`
  (`checkpoint.rs:24`); embeds the note if present (`checkpoint.rs:32-42`).
- `clx_session_info` (`session_info.rs:11-70`): returns `db_path`,
  `session_id`, project/started/status/message+command counts, snapshot
  count, active-sessions count, rules count. No redaction (metadata only).
- `clx_stats` (`stats.rs:11-71`): `days` clamped 1-365 default 7
  (`stats.rs:12`); returns session counts, audit decision distribution,
  risk distribution, top denied patterns; tolerant of query errors via
  `unwrap_or_default`.

### 3.9 Backends / no-embeddings

- Auto-recall builds the embedder via
  `config.create_llm_client(Capability::Embeddings)`
  (`subagent.rs:166-172`) and `EmbeddingStore::open_with_dimension`
  (`subagent.rs:179-186`). Either failing logs WARN and proceeds without the
  semantic stage.
- `semantic_enabled()` is false unless an `EmbeddingStore` is attached AND
  vector search enabled (`recall_repo.rs:60-63`); the engine then skips
  semantic entirely (`engine.rs:110-114`) and runs FTS5-only.
- Ollama vs Azure: identical path through `LlmQueryEmbedder` adapter
  (`adapters.rs:36-43`); Azure requires a bare model/deployment name passed
  through `capability_route` (`subagent.rs:210-216`); Ollama tolerates
  `None`.

---

## 4. Edge / failure matrix

| Scenario | Expected behavior | Source |
| --- | --- | --- |
| Empty store | recall returns `[]`; MCP prints "No relevant context found"; hook emits orchestrator only | `engine.rs` tests `mod.rs:724-747`; `recall.rs:105-119` |
| No embeddings provider | semantic skipped, FTS5-only results | `engine.rs:110-114`; `recall_repo.rs:54-63` |
| Reranker model missing | `is_ready()` false -> one-shot WARN, RRF-only; background fetch spawned once | `rerank.rs:108-121`; `subagent.rs:63-86` |
| Azure key absent | `create_llm_client` errs -> WARN, no embedder, FTS5-only degradation; recall still returns | `subagent.rs:166-172` |
| Huge transcript for auto-summary | only last `2*every_n_turns` turns sampled; 10 s soft timeout caps cost | `stop_auto_summary.rs:44-47, 39, 53` |
| Concurrent Stop hooks | single `AutoSummary` row guaranteed via `BEGIN IMMEDIATE` + `WHERE NOT EXISTS`; loser gets `Ok(false)` | `snapshot.rs:55-120` |
| Prompt < `min_prompt_len` | recall skipped (char count), orchestrator context still emitted | `subagent.rs:122-129` |
| `tool_events` under concurrent hooks | v7 UNIQUE INDEX + UPSERT collapse to one row, `occurrence_count` increments | `tool_events.rs:521-552`; `migration.rs:394-399` |
| Malicious stored summary | `<`/`>` escaped to `&lt;`/`&gt;`; cannot close `<historical-context>` | `mod.rs:189-191, 219-235`; test `mod.rs:496-511` |
| Reranker model poisoned post-pin | SHA-256 re-verify fails -> NOT ready -> RRF-only | `fastembed.rs:274-325`; tests `:646-670` |
| Malformed snapshot timestamp | decay leaves score untouched, no panic | `decay.rs:52-56, 220-233` |

---

## 5. Verification steps (runnable)

### 5.1 Unit + property tests

```
cargo test -p clx-core --lib recall
cargo test -p clx-core --lib decay
cargo test -p clx-core --lib rrf
cargo test -p clx-core --lib tool_events
cargo test -p clx-core --lib auto_summary
cargo test -p clx-hook --lib subagent
cargo test -p clx-hook --lib stop_auto_summary
cargo test -p clx-hook --lib aggregator
```

Expected: all green. Key regressions to confirm present and passing:
`test_format_context_escapes_xml_in_summary` (`mod.rs:496`),
`upsert_concurrent_simulated` (`tool_events.rs:528`),
`cold_load_respects_outer_timeout` (`fastembed.rs:901`),
`is_ready_false_when_model_bytes_mutated_after_pin` (`fastembed.rs:646`).

### 5.2 RAGAS recall accuracy bench

```
cargo bench --bench recall_accuracy
```

- Golden set: `tests/fixtures/recall_golden.yaml`, 30 synthetic pairs over a
  ~38-row synthetic corpus (`recall_golden.yaml:14-232`).
- Bench runs two configs: `rrf_enabled=true` (0.8.0) and `false` (rollback),
  both with decay+gate disabled and reranker off to isolate fusion
  (`recall_accuracy.rs:376-396`).
- Reports `context_precision@10` / `context_recall@10` mean/p50/p95
  (`recall_accuracy.rs:420-440`).
- CI gate is WARN-ONLY in 0.8.0: precision < 0.85 emits a `::warning::` but
  does NOT fail (`recall_accuracy.rs:19-21, 441-446`). QA records the printed
  numbers; no hard threshold to enforce for the tag.

### 5.3 Observe pinned-session injection

Config snippet (figment config file):

```toml
[auto_recall.pin_recent_sessions]
enabled = true
count = 3
max_chars_each = 300
```

Run two CLX sessions creating snapshots, then in a third session submit a
prompt >= 10 chars. The injected `additionalContext` must contain a
`## Pinned recent sessions` block listing the prior two sessions and NOT the
current one (`subagent.rs:227, 265-291`; `mod.rs:274-299`). Inspect via the
UserPromptSubmit hook stdout / Claude Code transcript.

### 5.4 Trigger auto_summarize and verify exactly one snapshot

```toml
[memory.auto_summarize]
enabled = true
every_n_turns = 2
skip_when_idle = true
```

Drive >= 2 mutator tool calls (e.g. `Edit`) then end the session (Stop).
Verify exactly one `auto_summary` snapshot:

```
sqlite3 ~/.clx/clx.db \
 "SELECT COUNT(*) FROM snapshots WHERE session_id='<sid>' AND trigger='auto_summary';"
```

Expect `1`. Trigger Stop again with no new mutator activity:
`skip_when_idle` -> still `1` (`snapshot.rs:332-370`).

### 5.5 Inspect tool_events / snapshots

```
sqlite3 ~/.clx/clx.db "SELECT tool_name,target,occurrence_count,window_start_unix,window_end_unix FROM tool_events ORDER BY id DESC LIMIT 20;"
clx stats --days 7
clx session-info     # or MCP clx_session_info
```

Two `Edit`s to the same file within 60 s must yield ONE row with
`occurrence_count = 2` (`tool_events.rs:232-257`).

### 5.6 Reranker readiness / fallback

- Without the model: submit a prompt; logs show one WARN
  `bge-reranker-v2-m3 not yet downloaded ...` and recall still returns
  (RRF-only) (`rerank.rs:115-119`; `subagent.rs:77-81`).
- `clx model status` to track the background fetch.
- Tamper test: after fetch, overwrite `~/.clx/models/bge-reranker-v2-m3/
  model.onnx`; next process must log a SHA-mismatch WARN and degrade to
  RRF-only (`fastembed.rs:303-313`).

---

## 6. Known limitations / out of scope for 0.8.0

- Golden set is fully SYNTHETIC, public-spec-derived only; no real session
  content / PHI (`recall_golden.yaml:1-7`, `recall_accuracy.rs:15-17`).
  Precision/recall numbers are indicative, not a hard release gate.
- `context_precision >= 0.85` target is WARN-ONLY, not enforced
  (`recall_accuracy.rs:19-21, 441-446`).
- Reranker defaults to ON (`reranker_enabled=true`, `config/mod.rs:437-438`),
  which triggers a ~568 MB first-run background download
  (`subagent.rs:77-81`). This is intentional 0.8.0 UX; offline installs run
  RRF-only until the model lands.
- `ready_at` memoizes verification per process via `OnceLock`
  (`fastembed.rs:393-396`): a same-size same-hash mid-session swap is the
  documented unavoidable residual of a same-uid local scheme
  (`fastembed.rs:386-392`).
- `pin_recent_sessions` and `auto_summarize` are both opt-in (default off) to
  preserve 0.7.x behavior (`config/mod.rs:473-475, 528-529`).
- Schema downgrade is implicitly tolerated: migration only runs when
  `current_version < SCHEMA_VERSION`; a DB written by a NEWER CLX is opened
  without error and without forward migration (`migration.rs:47-85`). No
  explicit "refuse newer schema" guard exists despite the golden corpus row
  describing one (`recall_golden.yaml:108-110`) — see RISKS.

---

## RISKS / SUSPECTED GAPS

1. No newer-schema guard. `migration.rs:47` only acts on
   `current_version < SCHEMA_VERSION`. Opening a DB created by a future CLX
   (version > 7) silently proceeds against an unknown schema instead of
   refusing. The synthetic golden corpus asserts such a guard exists
   (`recall_golden.yaml:108-110` "refuses downgrade") but the code path does
   not implement it. QA should treat "open newer DB" as untested behavior.

2. MCP `clx_recall` doc comment is stale. `recall.rs:21-25` still documents
   the legacy "Hybrid merge: semantic 0.6 / FTS5 0.4" pipeline, but the
   actual call defaults to RRF (`recall.rs:59`, `rrf_enabled` from config
   default `true`). Doc/behavior drift; not a functional bug but misleading
   for QA reading the source.

3. `had_mutator_activity_since_last_auto_summary` conservative-on-error
   (`snapshot.rs:361-368`) combined with `turns_since_last_auto_summary`
   counting `tool_events` (`snapshot.rs:277-290`): if the v6/v7 migration has
   not run, both queries error. `turns_since` would propagate the error and
   abort (`stop_auto_summary.rs:83-89`) while the idle-check would proceed —
   inconsistent failure handling between the two gates. Low risk on a
   migrated DB but worth a note.

4. `query_percentile_gate` is duplicated verbatim in `subagent.rs:252-258`
   and `recall.rs:131-137`. Logic divergence risk if one is edited; QA
   should treat MCP vs hook percentile behavior as needing parallel checks.

5. Reranker `RERANK_FALLBACK_TOTAL` is process-global and never reset
   (`rerank.rs:71`); cross-test contamination is handled by reading a
   baseline, but there is no telemetry export wired, so the counter is
   currently observable only in tests (documented as "future telemetry",
   `rerank.rs:70`). Not a bug; flag that fallback frequency is NOT
   user-observable in 0.8.0.

6. `do_recall` opens `Storage` and `EmbeddingStore` on EVERY user prompt
   (`subagent.rs:162-186`) inside the 500 ms budget. No connection reuse;
   under a slow disk this competes with the embed round-trip for the budget.
   Behaviorally correct (timeout drops it) but a latency cliff to validate
   on the pre-release perf pass.
