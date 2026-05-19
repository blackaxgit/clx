# CLX 0.8.1 Provider-Bound Coverage Gap Map

**Date:** 2026-05-19
**Branch / version:** main / 0.8.0 (read-only investigation)
**Goal of the 0.8.1 effort:** make the embedding/LLM provider injectable so
currently-unreachable provider-bound logic is covered by offline tests,
raising instrumented line coverage from the documented **85.72%** to
**>= 97%** on the published denominator.
**Scope of this doc:** the exact engineering surface. No source modified.

---

## 0. Executive summary

There are **two** missing seams and **one** clean seam already in place:

1. **Recall CLI seam (MISSING).** `clx/src/commands/recall.rs` calls
   `Config::create_llm_client()` + `EmbeddingStore::find_similar()`
   directly. There is no port, no trait object, no `#[cfg(test)]` hook.
   The post-embedding ranking + format logic (`recall.rs:96-178`) is
   unreachable offline.
2. **Embeddings CLI seam (MISSING).** `clx/src/commands/embeddings.rs`
   (`cmd_embeddings` Rebuild, `cmd_embed_backfill`) calls
   `Config::create_llm_client()` then a per-snapshot
   `client.embed()` loop. The loops (`embeddings.rs:246-282` and
   `:394-445`) are unreachable offline.
3. **L1 validator seam (ALREADY CLEAN at core; CLI-level wiring is the
   gap).** `clx-core::policy::llm::evaluate_with_llm` already takes
   `ollama: &LlmClient` as a parameter and is fully wiremock-tested in
   `crates/clx-core/tests/validation_behavior.rs`. The *uncovered*
   region is the orchestration in
   `clx-hook/src/hooks/pre_tool_use.rs:223-549` (cache hit/write arms,
   the `tokio::time::timeout` timeout arm, the `LLM unavailable`
   fallback arm) because `handle_pre_tool_use` builds the client
   internally via `Config::load()` + `config.create_llm_client()` with
   no injection point.

Root cause is identical in all three: `Config::create_llm_client()`
(`config/mod.rs:1695-1708`) and `EmbeddingStore::find_similar()`
(`embeddings.rs:161`) are called by concrete name inside the command /
hook handlers, so an offline fake cannot be substituted.

The **MCP recall path is the proof the seam pattern works**:
`clx-mcp/src/tools/recall.rs:26-128` already drives recall purely
through `RecallEngine` + the `QueryEmbedder` port + `LlmQueryEmbedder`
adapter, and `crates/clx-core/tests/recall_behavior.rs:431-472` covers
the semantic path offline with a wiremock Ollama. The 0.8.1 work is to
bring `recall.rs` / `embeddings.rs` / `pre_tool_use.rs` to the same
port-or-injected-client discipline.

---

## 1. The published coverage denominator (confirmed)

### 1a. `Cargo.toml` — the authoritative exclusion

`Cargo.toml:149-150`:

```toml
[workspace.metadata.cargo-llvm-cov]
ignore-filename-regex = "(dashboard/event\\.rs|main\\.rs|dashboard/runtime\\.rs|credentials/keychain_acl\\.rs|dashboard/mod\\.rs|commands/keychain_trust\\.rs)"
```

Per-pattern rationale is documented inline at `Cargo.toml:123-148`.
Excluded = unreachable terminal/FFI/shell glue only:

| Pattern | What it excludes | Why unreachable offline |
|---|---|---|
| `dashboard/event\.rs` | crossterm raw-mode TUI event loop | real-TTY input |
| `main\.rs` | clx-hook stdin wiring + clx clap dispatch | shell entrypoints; logic in `router::handle_event`/command modules |
| `dashboard/runtime\.rs` | reserved terminal runtime glue name | forward-compat placeholder |
| `credentials/keychain_acl\.rs` | macOS CFArray `SecAccess` FFI | `cfg(target_os="macos")`, only `#[ignore]` real-keychain tests |
| `dashboard/mod\.rs` | ratatui init/restore, panic-hook terminal reset, real-TTY `run_event_loop` | same class as `dashboard/event.rs` |
| `commands/keychain_trust\.rs` | macOS keychain ACL repair | only `#[ignore = "Requires keychain access"]` tests |

Note: every excluded file matches by *basename* regex, so e.g. **all**
`main.rs` across crates are excluded (intended — confirmed by the
campaign spec section 1).

### 1b. `scripts/test.sh` — the gate

`scripts/test.sh:30-31`:

```bash
COV_IGNORE_REGEX='(dashboard/event\.rs|main\.rs|dashboard/runtime\.rs|credentials/keychain_acl\.rs|dashboard/mod\.rs|commands/keychain_trust\.rs)'
COV_FAIL_UNDER=97
```

Byte-identical to `Cargo.toml` (verified char-for-char).
`run_cov()` (`scripts/test.sh:136-157`) runs:

```
cargo llvm-cov nextest --profile ci --workspace \
  --ignore-filename-regex "${COV_IGNORE_REGEX}" \
  --fail-under-lines 97 --summary-only
```

Hermetic env forced at `scripts/test.sh:40-42`:
`CLX_MODEL_FETCH_DRYRUN=1`, `CLX_CREDENTIALS_BACKEND=age`,
`RUST_BACKTRACE=1`. The harness never passes `--run-ignored`, so the
10 `#[ignore]` real-keychain tests stay skipped.

### 1c. `.config/nextest.toml`

`[profile.ci]` (used by `cov`): `fail-fast=false`, `retries=0`,
`slow-timeout = { period="60s", terminate-after=4 }`,
`final-status-level="slow"`, JUnit to `junit.xml`. This guarantees the
coverage run executes every test and emits a complete gap picture
rather than aborting on first red.

### 1d. `justfile`

`just cov` -> `bash scripts/test.sh cov` (thin wrapper; shell script is
the single source of truth). All targets (`fast`, `cov`, `snapshots`,
`mutants`, `all`, `pre-release`) mirror `scripts/test.sh`.

### 1e. How 85.72% is measured / what is excluded

- **Denominator** = all workspace `.rs` lines EXCEPT the 6 basename
  patterns above (terminal/FFI/shell glue, each with covered logic
  elsewhere). Nothing provider-bound is excluded — excluding it would
  be "test theater," explicitly forbidden by campaign spec section 1.
- **Measured result** (campaign spec section 6, line 70-74): **85.72%
  line** (85.79% region, 89.01% function), suite 1693 pass / 0 fail /
  10 ignored.
- **The gap** is provider-bound core logic (recall ranking/format,
  embeddings rebuild/backfill loops, L1 timeout/cache arms) that needs
  a live embedding/LLM provider — deferred to 0.8.1 (the work this doc
  grounds).
- **Live measurement not run here:** `cargo-llvm-cov` and
  `cargo-nextest` are not on PATH in this environment and `rustup` is
  absent, so a quick `bash scripts/test.sh cov` is not feasible. The
  gap is derived from code reading + campaign spec section 6 as the
  task permits. The per-file uncovered regions are pinned in §4 from
  source analysis.

---

## 2. The embedding provider boundary

### 2a. The core trait already exists (clean port)

`crates/clx-core/src/recall/ports.rs:97-102`:

```rust
#[async_trait]
pub trait QueryEmbedder: Send + Sync {
    /// Produce an embedding vector for `text`. Errors are caller-visible
    /// so the pipeline can warn and fall back to FTS5.
    async fn embed_query(&self, text: &str) -> crate::Result<Vec<f32>>;
}
```

Production adapter `crates/clx-core/src/recall/adapters.rs:20-43`:

```rust
pub struct LlmQueryEmbedder<'a> {
    client: &'a LlmClient,
    model: Option<&'a str>,
}
impl QueryEmbedder for LlmQueryEmbedder<'_> {
    async fn embed_query(&self, text: &str) -> crate::Result<Vec<f32>> {
        self.client.embed(text, self.model).await
            .map_err(|e| crate::Error::InvalidInput(format!("embedding failed: {e}")))
    }
}
```

`RecallEngine` (`recall/engine.rs:20-74`) holds
`embedder: Option<&'a dyn QueryEmbedder>` and is built with
`.with_embedder(&dyn QueryEmbedder)` — **the port is already a trait
object seam.** Any offline fake implementing `QueryEmbedder` works
(and one is effectively exercised already; `recall_behavior.rs` uses a
wiremock-backed `LlmQueryEmbedder`).

### 2b. The concrete LLM client surface

`crates/clx-core/src/llm/mod.rs:22-124`:

- Trait `LocalLlmBackend` / `LlmBackend` (`mod.rs:22-27`):
  `generate`, `embed`, `is_available`.
- Static-dispatch enum `LlmClient` (`mod.rs:84-124`):
  `Ollama(OllamaBackend) | Azure(AzureOpenAIBackend) | Fallback(FallbackClient)`.
  **It is a concrete enum, not a trait object.** There is no
  `LlmClient::Fake` variant and no trait-object alternative on the
  production call paths outside the recall port.

### 2c. Construction / call sites (where the seam is missing)

| Call site | What it does | Seam present? |
|---|---|---|
| `clx-mcp/src/tools/recall.rs:39-50` | `LlmQueryEmbedder::new(client, ..)` -> `RecallEngine::with_embedder` | YES (port) — reference impl |
| `clx-core/tests/recall_behavior.rs:431-472` | wiremock Ollama -> `LlmQueryEmbedder` -> engine | YES (test proves it) |
| `clx/src/commands/recall.rs:40` | `config.create_llm_client(Capability::Embeddings)` then `:69 ollama.embed(...)` then `:96 emb_store.find_similar(...)` | **NO** — no port, no `RecallEngine`, raw `EmbeddingStore` |
| `clx/src/commands/embeddings.rs:187` (Rebuild) | `config.create_llm_client(...)` then `:262 client.embed(text,..)` loop | **NO** |
| `clx/src/commands/embeddings.rs:339` (backfill) | `config.create_llm_client(...)` then `:421 client.embed(text,..)` loop | **NO** |

`Config::create_llm_client` at `config/mod.rs:1695-1708` ->
`build_client_for_provider` (`:1726-1752`) returns a concrete
`LlmClient`. There is **no test-mode env hook, no injectable
parameter, no trait return.**

### 2d. Exactly what blocks an offline fake today

- `recall.rs::cmd_recall` constructs `LlmClient` from `Config::load()`
  (real config) and calls `ollama.embed()` (real network) and
  `EmbeddingStore::find_similar()` directly on a concrete struct. No
  parameter is injectable; the function signature is
  `cmd_recall(cli: &Cli, query: &str)`. An offline test can only reach
  the *early-return guards* (no DB / no client / embed error) — which
  `cli_recall_deep_e2e.rs` already covers — but never the
  post-embedding ranking/format because `ollama.embed()` must succeed
  with a real vector first.
- `embeddings.rs` is the same: the per-snapshot `client.embed()` loop
  body only runs when a real provider returns `Ok(embedding)`.
- The blocker is structural: command fns own client construction
  internally. The fix is to thread an injected embedder/client (a port
  or a `Capability`->client factory closure) through the command
  signature, or refactor the rank/format core out of `cmd_recall` into
  a pure, port-driven function (mirroring `tool_recall`).

---

## 3. The LLM / validator L1 client boundary

### 3a. The core seam already exists and is covered

`crates/clx-core/src/policy/llm.rs:74-176` —
`PolicyEngine::evaluate_with_llm(self, _tool_name, command, working_dir,
ollama: &LlmClient, model, cache: Option<&ValidationCache>,
sensitivity)`. The LLM client is **already a parameter**. Internal arms
already covered offline via wiremock in
`crates/clx-core/tests/validation_behavior.rs` (helper
`ollama_client(server, timeout_ms)` at lines 33-42,
`mount_generate_body` at 46-58; tests cover allow/ask/deny, parse
failure, suspicious response, HTTP 500 -> `LLM unavailable`, rate
limit). The pure helpers `parse_llm_response` (`llm.rs:531-548`),
`risk_score_to_decision` (`llm.rs:551-571`),
`is_suspicious_llm_response` (`llm.rs:495-528`),
`validate_prompt_template` (`llm.rs:241-384`),
`load_validator_prompt` (`llm.rs:395-423`) all have in-file unit tests
(`llm.rs:573-696`).

### 3b. The actual uncovered region: the hook orchestration

`crates/clx-hook/src/hooks/pre_tool_use.rs` —
`handle_pre_tool_use(input: HookInput)`. It builds the client
**internally** at `pre_tool_use.rs:276-280`:

```rust
let (ollama, chat_model) = match config.create_llm_client(Capability::Chat).and_then(|c| {
    config.capability_route(Capability::Chat).map(|r| (c, r.model.clone()))
}) { ... };
```

There is no way to inject a fake client into `handle_pre_tool_use`; it
takes only `HookInput`. The covered-only-by-real-provider arms:

| Region | Lines | What it is | Why unreachable offline |
|---|---|---|---|
| L1-CACHE hit arm | `pre_tool_use.rs:223-252` | SQLite decision-cache lookup -> early return with cached decision + audit | Only reached after a prior L1 run wrote a cache row; needs an L1 verdict first (provider) OR a pre-seeded cache row (reachable without provider — see §4) |
| LLM-client creation error arm | `:281-307` | `create_llm_client` Err -> `default_decision` fallback + audit | Reachable offline by giving a config whose provider is unknown — partly testable, but the *path through to here* requires L0=Ask first |
| health-cache `Unknown` -> `is_available()` arm | `:321-326` | network probe + `write_health` | needs a live/fake provider socket |
| `!ollama_available` fallback | `:328-353` | `default_decision` fallback + audit | needs `is_available()==false` from a real client (or unreachable host) |
| **L1 timeout arm** | `:374-400` | `tokio::time::timeout(l1_timeout, l1_future)` Err -> `write_health(false)` + `default_decision` + audit "L1 timeout after Nms" | needs an L1 future that exceeds budget — i.e. a slow provider |
| **`LLM unavailable` post-call arm** | `:405-429` | `PolicyDecision::Ask{reason=="LLM unavailable"}` -> `default_decision` fallback | needs `evaluate_with_llm` to actually run and its `ollama.generate` to fail |
| L1 Allow + **cache-write** arm | `:434-460` | success -> `output_decision("allow")` + `storage.cache_decision(...allow ttl)` | needs a real L1 Allow verdict |
| L1 Deny + `track_user_decision` arm | `:461-487` | deny -> `track_user_decision(storage,..,false)` (V-R5 denial_count) | needs a real L1 Deny verdict |
| L1 Ask + cache-write arm (read-only auto-allow vs ask) | `:488-545` | ask -> cache `allow`/`ask` + envelope | needs a real L1 Ask verdict |

Note: the in-file `#[cfg(test)] mod tests` at
`pre_tool_use.rs:558-684` already asserts the *envelope mapping* and
the `tokio::time::timeout` *primitive* in isolation (V-R2/V-R4/V-R5
mapping tests), but it does **not** drive `handle_pre_tool_use`
end-to-end, so the cache-write side effects, audit-row writes, and the
`write_health` calls in those arms are uncovered.

### 3c. What a minimal injected fake must return

To exercise the real `handle_pre_tool_use` arms offline, the fake
`LlmClient` (or an injected `&dyn` chat client) must support:

- `is_available() -> true` (to pass the health gate at `:322`).
- **Allow path:** `generate()` returns
  `{"risk_score":2,"reasoning":"read only","category":"safe"}`
  -> `risk_score_to_decision` -> `Allow` -> exercises `:434-460`
  (cache-write allow).
- **Deny path:** `generate()` returns
  `{"risk_score":9,"reasoning":"rm -rf /","category":"critical"}`
  -> `Deny` -> exercises `:461-487` (`track_user_decision`).
- **Ask path:** `risk_score:5` -> `Ask` -> exercises `:488-545`
  (cache-write ask, and the read-only branch with a read-only cmd).
- **Timeout path:** `generate()` sleeps longer than
  `config.validator.layer1_timeout_ms` -> `:374-400` (the timeout
  arm + `write_health(false)`).
- **`LLM unavailable` path:** `generate()` returns `Err` ->
  `evaluate_with_llm` returns `Ask{"LLM unavailable"}` -> `:405-429`.
- **client-unavailable path:** `is_available() -> false` -> `:328-353`.

A **wiremock Ollama already provides all of these** (proven in
`validation_behavior.rs`). The only missing piece is a way to point
`handle_pre_tool_use`'s client at the wiremock URL — i.e. either an
injectable client parameter, or an env-driven provider base-URL the
hermetic test can set (the Ollama backend already reads a configurable
base URL via `OllamaConfig`, so a config-file-driven e2e through the
real `clx-hook` binary against a wiremock server is the lowest-risk
route — see §5).

---

## 4. Pinned uncovered provider-bound regions + the fake input that exercises each

### 4a. `clx/src/commands/recall.rs` — results ranking + format

Current line ranges (verified against the file as of this commit):

| Region | Lines | Reached only when | Minimal fake input to exercise |
|---|---|---|---|
| spinner setup | `recall.rs:60-67` | always after client OK | n/a (covered) |
| `ollama.embed(query,..)` success bind | `:69-93` | embed returns `Ok(vec)` | fake embedder returns `vec![0.1f32; 1024]` |
| **`emb_store.find_similar` call** | **`:96`** | embed succeeded | DB seeded with >=1 snapshot + a stored embedding (see `recall_behavior.rs:437-439` pattern: `EmbeddingStore::open_in_memory` + `store_embedding`) |
| **JSON results loop + truncation + RecallResult build** | **`:102-124`** | `cli.json` + `similar` non-empty | fake `find_similar` -> `[(snapshot_id, 0.12)]`; storage has that snapshot with summary/key_facts/todos |
| **human "no matching" branch + embedding_count** | **`:132-142`** | `similar` empty | fake `find_similar` -> `[]`; assert "No matching context found" + count text |
| **human results loop (rank header, distance, summary/facts .lines().take(3))** | **`:143-178`** | non-`json`, `similar` non-empty | fake `find_similar` -> 2+ hits; storage snapshots with multi-line summary + key_facts |

Provider call that makes it unreachable: `ollama.embed()` at
`recall.rs:69`. Without a real vector the code returns at the embed-
error arm (`:71-92`, already covered by
`cli_recall_deep_e2e.rs:83-148`). `cli_recall_deep_e2e.rs:23` itself
documents: *"produce a query vector before find_similar runs. Left
for [0.8.1]."*

What a minimal injected fake needs to return: a fixed-length
`Vec<f32>` of `DEFAULT_EMBEDDING_DIM` (1024) — content can be uniform;
`find_similar` runs against the in-memory sqlite-vec store, so the
distances are deterministic from the seeded `store_embedding` vectors.

### 4b. `clx/src/commands/embeddings.rs` — rebuild + backfill loops

`EmbeddingStore` API surface (all on the concrete struct,
`embeddings.rs`): `find_similar:161`, `store_embedding:130`,
`store_with_model:309`, `has_embedding:207`, `count_embeddings:218`,
`rebuild_table:243`, `iter_snapshots_for_rebuild:353`,
`open_in_memory:79`, `DEFAULT_EMBEDDING_DIM:11`.

| Region | Lines | Reached only when | Minimal fake input |
|---|---|---|---|
| Rebuild: `client.is_available()` true gate | `embeddings.rs:213-234` | provider available | fake client `is_available()->true` |
| Rebuild: re-read snapshots after table rebuild | `:236-244` | got past availability | seed >=2 snapshots before rebuild |
| **Rebuild: per-snapshot `client.embed()` loop** | **`:246-282`** | provider returns `Ok(embedding)` | fake `embed()->Ok(vec![..;1024])`; one snapshot with empty text to also hit the `skipped` branch (`:247-250`); one that triggers `store_with_model` Err to hit `errors` (`:264-270`) |
| Rebuild: JSON / human summary | `:284-311` | after loop | assert processed/skipped/errors counts |
| backfill: `client.is_available()` true gate | `:357-376` | provider available | fake `is_available()->true` |
| **backfill: per-snapshot loop (has_embedding skip, empty skip, dry-run, embed+store)** | **`:394-445`** | provider returns `Ok` | seed: 1 already-embedded (skip `:396-399`), 1 empty-text (skip `:401-404`), 1 fresh -> `embed()->Ok` -> `store_with_model` OK (`:421-435`); plus a `dry_run=true` variant for `:411-419` |
| backfill: JSON / human summary | `:447-477` | after loop | assert totals |

Provider call: `client.embed(text, Some(&embed_model))` at
`embeddings.rs:262` (rebuild) and `:421` (backfill). The
`is_available()` gate at `:213` / `:358` and `create_llm_client` at
`:187` / `:339` are the earlier provider couplings that also block
reaching the loop offline.

Existing coverage (from `cli_embeddings_deep_e2e.rs`, 213 lines): the
*status* path, *dry-run* path, and the provider-unavailable early
returns are reachable offline today; the **actual embed loop bodies are
not**.

### 4c. `clx-hook/src/hooks/pre_tool_use.rs` — L1 timeout / cache arms

Pinned in §3b table. The headline 0.8.1 targets:

- Timeout arm `:374-400` (the `tokio::time::timeout(l1_timeout,
  l1_future)` Err branch + `write_health(false)` + audit).
- `LLM unavailable` post-call arm `:405-429`.
- L1 success arms with cache-write side effects `:434-545`.
- The L1-CACHE *hit* arm `:223-252` is partially reachable **without a
  provider**: pre-seed a row via `storage.cache_decision(...)` then run
  the hook on an L0=Ask command with `cache_enabled=true`. This is a
  cheap win that does not even need the seam (callout for the plan).

### 4d. Residual non-provider gap

From the risk-triage (`specs/_prerelease/risk-triage.md`) and campaign
spec section 6, the residual gap is **dominated by the three provider-
bound regions above**. Non-provider residuals are small and already
have *pinning* tests (accepted-behavior) rather than coverage gaps:

- CHEAP-FIX-NOW items already landed (recent commit `1011d5f` resolved
  4 HIGH blockers incl. V-R5 `denial_count`, L1 deny band, L1 timeout;
  M-R1/C-R1/I-R2 are the documented cheap-fix list).
- ACCEPTED-0.8.0 items (V-R3, V-R7, V-R8, V-R9, M-R3, M-R5, M-R6,
  C-R3, C-R4, C-R6, I-R3, I-R4, V-R6) are documented-and-pinned, not
  coverage holes.
- The only genuinely non-provider uncovered glue is already excluded by
  the denominator (terminal/FFI/`main.rs`) — see §1a.

Conclusion: closing the two seams (recall CLI, embeddings CLI) and the
hook-orchestration seam (pre_tool_use) captures essentially the entire
85.72% -> ~97% delta. There is no significant hidden non-provider gap.

---

## 5. Reusable test infrastructure (reuse, do not duplicate)

### 5a. Hook subprocess harness — `crates/clx-hook/tests/support/mod.rs`

- `isolated_clx_home() -> tempfile::TempDir` (`support/mod.rs:52-57`):
  RAII temp `HOME`, parallel-safe, removed on Drop even on panic.
- `harden_command(&mut Command, &Path) -> &mut Command`
  (`:70-74`): stamps `HOME`, `CLX_LOG=error`,
  `CLX_MODEL_FETCH_DRYRUN=1`.
- `assert_home_size_bounded(&Path)` (`:107-130`) +
  `MAX_HOME_BYTES` (`:43`): regression guard against a leaked model
  download.
- `assert_tempdir_removed_even_on_panic()` (`:136-154`).

This is the harness for any new e2e that drives the real `clx-hook`
binary. A wiremock-Ollama-backed config written into the isolated
`HOME` is the lowest-risk way to cover the `pre_tool_use.rs` L1 arms
end-to-end without a production injection point.

### 5b. wiremock provider pattern — already established

- `crates/clx-core/tests/validation_behavior.rs:33-58`:
  `ollama_client(server, timeout_ms) -> LlmClient::Ollama` pointed at
  a `MockServer`; `mount_generate_body(server, body)` mounts
  `POST /api/generate`. Reuse verbatim for L1 verdict shaping.
- `crates/clx-core/tests/recall_behavior.rs:431-472`: wiremock Ollama
  mounting `POST /api/embeddings` -> `LlmQueryEmbedder` ->
  `RecallEngine`. This is the **template for the recall-CLI seam test**
  (the new code should let the CLI path reach the same wiremock).
- `OllamaBackend::new(OllamaConfig{ base_url, .. })` accepts a
  configurable base URL — so an e2e that writes a config pointing the
  `ollama` provider at `127.0.0.1:<wiremock port>` needs **no new
  production API**, only a small refactor to make `cmd_recall` /
  `cmd_embeddings` reachable (or a port).

### 5c. Existing behavior/e2e files (extend, owned-disjoint)

- `crates/clx-core/tests/recall_behavior.rs` (498 ln): `RecallEngine`
  port-driven; semantic path via wiremock. Add CLI-equivalent here or
  in a new file.
- `crates/clx-core/tests/validation_behavior.rs` (883 ln): full L1
  `evaluate_with_llm` wiremock matrix.
- `crates/clx/tests/cli_recall_deep_e2e.rs` (184 ln): covers the
  recall early-return guards; explicitly defers post-embedding
  ranking/format to 0.8.1 (`:23`).
- `crates/clx/tests/cli_embeddings_deep_e2e.rs` (213 ln): status /
  dry-run / unavailable arms.
- `crates/clx-hook/tests/validation_e2e.rs` (505 ln): hook envelope
  round-trips.
- `crates/clx-hook/tests/hooks_router_e2e.rs`,
  `crates/clx-hook/tests/memory_hooks_e2e.rs`,
  `crates/clx-mcp/tests/mcp_protocol_e2e.rs`,
  `crates/clx/tests/cli_e2e.rs`, `crates/clx/tests/dashboard_pixel.rs`.

### 5d. `#[ignore]` real-provider/keychain tests (do not unignore)

10 `#[ignore = "Requires keychain access"]` in
`crates/clx-core/src/credentials.rs` (1138-1272) +
`crates/clx-mcp/src/tests.rs:346`. No real-model `#[ignore]` test
exists; model is dry-run-stubbed via `CLX_MODEL_FETCH_DRYRUN`. The
0.8.1 seam must keep these ignored (the harness never passes
`--run-ignored`).

### 5e. insta / pixel snapshots

`scripts/test.sh:161-176` (`cargo insta test`), existing
`dashboard_pixel.rs` + `crates/clx/src/dashboard/ui/snapshots/`. Not
on the provider-bound path; reuse only if the new format output is
snapshot-asserted (recommended for `recall.rs:143-178` human format).

---

## 6. The two seams to introduce (engineering surface for 0.8.1)

### Seam A — Recall CLI embedding seam

**Problem:** `cmd_recall` (`recall.rs:13`) owns
`config.create_llm_client` + `ollama.embed` + `emb_store.find_similar`.

**Recommended fix (lowest risk, mirrors MCP):** refactor the post-
embedding ranking/format into a pure function driven by the existing
`QueryEmbedder` port (and/or `RecallEngine`), exactly as
`tool_recall` (`clx-mcp/src/tools/recall.rs:26-128`) already does.
`cmd_recall` becomes: build `LlmQueryEmbedder` (prod) or accept an
injected `&dyn QueryEmbedder` (test), call the shared core, format.
This unifies CLI + MCP recall and deletes the duplicated raw
`find_similar` path. Covered offline by the
`recall_behavior.rs:431-472` wiremock pattern.

Alternative (smaller diff, weaker architecture): add a test-only
constructor or `#[cfg(test)]`-gated client factory parameter. Less
preferred — violates "architecture over minimalism" (CLAUDE.md).

### Seam B — Embeddings CLI client seam

**Problem:** `cmd_embeddings` Rebuild (`embeddings.rs:35`) and
`cmd_embed_backfill` (`:319`) own `config.create_llm_client` + the
`client.embed()` loop.

**Recommended fix:** extract the per-snapshot embed loop into a pure
function `fn rebuild_embeddings<E: EmbedClient>(store, snapshots,
&E, model_ident) -> Counts` where `EmbedClient` is a tiny trait with
`async fn embed(&self,&str,Option<&str>) -> Result<Vec<f32>,_>` and
`async fn is_available(&self) -> bool` (or reuse the existing
`LocalLlmBackend`/`LlmBackend` trait — `llm/mod.rs:22-27` — which
already has exactly these methods). Production passes `&LlmClient`
(which already implements the surface via its inherent methods; a thin
blanket adapter or making `LlmClient` impl the trait closes it). Tests
pass a fake `EmbedClient`. The loop bodies (`:246-282`, `:394-445`)
then become unit-coverable with no network.

### Seam C — Hook L1 client seam (orchestration)

**Problem:** `handle_pre_tool_use` (`pre_tool_use.rs:21`) builds the
chat client internally at `:276-280`.

**Recommended fix (lowest risk):** prefer the **config-driven e2e**
route — write a config into the `support::isolated_clx_home()` sandbox
pointing the `ollama` provider `base_url` at a wiremock server, drive
the real `clx-hook` binary with a known L0=Ask command. This needs
**zero production change** (the Ollama backend already takes a base
URL) and covers `:223-545` end-to-end including cache/audit side
effects. If a unit-level seam is also wanted, thread an optional
injected client through an internal `handle_pre_tool_use_with(input,
client_factory)` and keep the public fn as a thin wrapper. The cache-
*hit* arm (`:223-252`) is additionally coverable today by pre-seeding
`storage.cache_decision(...)` with no provider at all (cheap win;
schedule first).

---

## 7. Multi-agent plan grounding (disjoint file ownership)

Suggested disjoint streams for the 0.8.1 implementation (each owns
NEW test files / NEW `#[cfg(test)]` modules; production changes are
the seam refactors, reviewed separately):

- **Stream 1 — Seam A (recall):** refactor `commands/recall.rs` to the
  port; new `crates/clx/tests/cli_recall_semantic_e2e.rs` (wiremock
  Ollama via config-in-sandbox) covering `recall.rs:96-178`
  (json + human, empty + non-empty).
- **Stream 2 — Seam B (embeddings):** extract embed-loop core; new
  `crates/clx-core/tests/embeddings_loop_behavior.rs` (fake
  `EmbedClient`) covering `embeddings.rs:246-282` and `:394-445`
  (processed/skipped/errors/dry-run permutations).
- **Stream 3 — Seam C (hook L1):** new
  `crates/clx-hook/tests/pre_tool_use_l1_e2e.rs` reusing
  `tests/support/mod.rs` + wiremock; covers `pre_tool_use.rs:223-545`
  (cache hit/write, timeout, LLM-unavailable, allow/deny/ask side
  effects). Cache-hit-via-preseed sub-task has no production dep —
  land first.
- **Stream 4 — Review/measure:** run `bash scripts/test.sh cov` after
  each stream merges; verify the denominator is unchanged (no new
  exclusions — forbidden) and the number climbs toward >=97%; adversarial
  review of the three seam refactors for layering (ports stay in
  `recall::`, infra confined to adapters, per CLAUDE.md).

Disjoint ownership: Stream 1 ↔ `commands/recall.rs` +
`cli_recall_semantic_e2e.rs`; Stream 2 ↔ `commands/embeddings.rs` +
`embeddings_loop_behavior.rs`; Stream 3 ↔ `hooks/pre_tool_use.rs` +
`pre_tool_use_l1_e2e.rs`. No file overlap.

---

## 8. Key file:line index

| Concern | Location |
|---|---|
| Denominator (authoritative) | `Cargo.toml:149-150` (rationale `:123-148`) |
| Denominator (gate) | `scripts/test.sh:30-31`, run at `:136-157` |
| nextest ci profile | `.config/nextest.toml` `[profile.ci]` |
| QueryEmbedder port | `crates/clx-core/src/recall/ports.rs:97-102` |
| LlmQueryEmbedder adapter | `crates/clx-core/src/recall/adapters.rs:20-43` |
| RecallEngine seam | `crates/clx-core/src/recall/engine.rs:20-74,100` |
| LlmClient concrete enum | `crates/clx-core/src/llm/mod.rs:22-27,84-124` |
| create_llm_client factory | `crates/clx-core/src/config/mod.rs:1695-1752` |
| MCP recall (reference seam) | `crates/clx-mcp/src/tools/recall.rs:26-128` |
| evaluate_with_llm (covered) | `crates/clx-core/src/policy/llm.rs:74-176` |
| **Gap: recall CLI** | `crates/clx/src/commands/recall.rs:69,96,102-124,132-178` |
| **Gap: embeddings CLI** | `crates/clx/src/commands/embeddings.rs:187,213-282,339,358-445` |
| **Gap: hook L1 orchestration** | `crates/clx-hook/src/hooks/pre_tool_use.rs:223-545` |
| EmbeddingStore API | `crates/clx-core/src/embeddings.rs:79,130,161,207,218,243,309,353` |
| Hook test harness | `crates/clx-hook/tests/support/mod.rs:43,52,70,107` |
| wiremock L1 pattern | `crates/clx-core/tests/validation_behavior.rs:33-58` |
| wiremock embed pattern | `crates/clx-core/tests/recall_behavior.rs:431-472` |
| Recall deep e2e (defers 0.8.1) | `crates/clx/tests/cli_recall_deep_e2e.rs:23,83-183` |
| Risk register status | `specs/_prerelease/risk-triage.md:21-55` |
| Campaign honest disposition | `specs/2026-05-18-test-coverage-campaign.md:68-101` |
