# Coverage Hardening Research — Injectable Provider Seams, 2026 Test Stack, Ralph Loop

- **Date:** 2026-05-19
- **Scope:** CLX 0.8.0 workspace (`clx-core`, `clx-hook`, `clx-mcp`, `clx`), Rust 2024 edition, tokio async, `trait-variant` traits.
- **Goal this informs:** lift instrumented line coverage 85.72% → ≥97% by making provider-bound code (recall RRF + `bge-reranker-v2-m3` via `fastembed = "5"`/`ort`, embeddings rebuild/backfill, L1 LLM validation hook) injectable with deterministic in-process fakes (no network, no keychain, no 568 MB model), plus mutation kill ≥80% on hot modules.
- **Decision posture:** This is a decision-oriented brief. Each section gives the recommended approach, the rejected alternatives and why, and sources (URL + date). It ends with a concrete seam architecture and one-command runner recommendation for the implementation plan.

---

## 0. TL;DR — Decisions

| Area | Decision | Rejected |
|---|---|---|
| Async seam shape | **Generic type parameter `P: EmbeddingProvider` (monomorphized), real trait declared with `#[trait_variant::make(Send)]`. Box-future erasure only where `dyn` is structurally required (hook registry).** | `Box<dyn>` over a native AFIT trait (not object-safe); `async-trait` everywhere (boxing tax, legacy). |
| Test substitution | **Hand-rolled deterministic fakes implementing the real trait, behind a `#[cfg(test)]`/`testkit` feature.** mockall only for pure call-assertion edge cases. | mockall as the primary mechanism (expectation-setting = test theater; exercises mock, not logic). |
| ONNX/fastembed offline | **Trait-abstract the embedder/reranker so `fastembed`/`ort` is never constructed in tests; in CI/build also pin `ort` with `download-binaries` off + `load-dynamic` (or `ort-tract`) so no build/runtime fetch.** | Letting `fastembed` auto-download weights; mocking ONNX at the FFI layer. |
| Coverage tool | **Keep `cargo-llvm-cov` + `cargo-nextest`, `[workspace.metadata.cargo-llvm-cov]` + byte-identical CLI regex (already in place). Track region coverage as the stricter informational metric.** | tarpaulin (macOS-weak); branch coverage gate (still nightly/unstable in 2026). |
| Honest denominator | **Current practice is already correct: exclude only unreachable glue, document per-pattern rationale in Cargo.toml/script/docs in sync.** Keep it; add a CI drift check. | Excluding modules with reachable logic; or refusing all exclusions ("100% or bust") and inflating with theater tests. |
| Ralph loop | **Generator + adversarial critic with a dual gate: coverage AND mutation-kill, plus behavior-contract review. Critic mutates the impl to prove tests fail.** | Coverage-only gate (overfits); single-agent self-grading. |

---

## 1. Injectable async provider seams in Rust (2026)

### 1.1 The structural fact that drives everything

Native `async fn` in traits (AFIT) and `-> impl Trait` in traits (RPITIT) have been stable since **Rust 1.75 (2023-12-28)** and are the idiomatic default in 2026. **They are not object-safe** — you cannot make `Box<dyn EmbeddingProvider>` from a trait that uses bare `async fn`. `#[trait_variant::make]` adds a `Send` bound variant for multithreaded runtimes (tokio) but **does not by itself restore `dyn`**; the trait-variant project still only "hopes to enable dynamic dispatch in a future version."

- Sources: [Announcing async fn and RPITIT in traits — Rust Blog, 2023-12-21](https://blog.rust-lang.org/2023/12/21/async-fn-rpit-in-traits.html); [trait-variant crate now available for AFIT and RPITIT — Rust Internals](https://internals.rust-lang.org/t/trait-variant-crate-now-available-for-afit-and-rpitit/20050); [async in Traits — Async Book](https://rust-lang.github.io/async-book/07_workarounds/05_async_in_traits.html) (accessed 2026-05-19).

**Implication for the seam:** the choice is between (a) **generics** (`fn pipeline<P: EmbeddingProvider>(p: &P, …)`) — zero-cost, monomorphized, fully `dyn`-free, and the cheapest to make testable; or (b) reintroducing future-boxing *only at the boundary that truly needs `dyn`* (a heterogeneous runtime registry such as the hook router). You do not need `dyn` for the recall pipeline or backfill path — they have one provider per run — so generics are the right tool there.

### 1.2 Pattern comparison (for "real logic exercised, only the I/O boundary faked")

| Pattern | Coverage of provider-bound logic | Test theater risk | dyn-safe | 2026 verdict |
|---|---|---|---|---|
| **Hand-rolled fake impl of the trait** | High — the *real* pipeline (RRF, cache arms, timeout arms) runs against deterministic inputs | **Low** — fake returns canned data, all your logic executes | n/a (works with generics) | **Recommended primary** |
| `mockall` 0.13 `#[automock]` | Medium — you assert *that* methods were called with args; the unit under test runs, but tests drift toward verifying interaction not outcome | **High** if used for outcome logic | works with `async_trait`/`trait_variant` (note `#[automock]` must precede the trait-variant attribute) | Edge cases only (assert "called once with X", error injection) |
| Trait-object injection (`Box<dyn>`) | High | Low | requires `async-trait`/boxed-future seam trait | Use *only* where `dyn` is structurally required |
| `#[cfg(test)]` constructor seam | Medium — swaps the constructor, but couples test build to prod type; brittle | Medium | n/a | Acceptable as a stopgap, not a seam architecture |
| Feature-gated provider (`--features fake-provider`) | High | Low | n/a | Good for *integration/e2e* binaries; overkill for unit layer |

- Sources: [mockall docs.rs (latest, 0.13.x)](https://docs.rs/mockall/latest/mockall/); [Mocking in Rust: Mockall and alternatives — LogRocket](https://blog.logrocket.com/mocking-rust-mockall-alternatives/); [All the ways to mock your Rust code — drmorr (Applied Computing)](https://blog.appliedcomputing.io/p/all-the-ways-to-mock-your-rust-code); [Mocking in Async Rust — VorTECHsa/Medium](https://medium.com/vortechsa/mocking-in-async-rust-248b012c5e99) (accessed 2026-05-19).

**Why hand-rolled fakes win for the coverage goal specifically:** the objective is to *execute* RRF reranking, cache hit/miss arms, and L1 timeout arms — not to assert that `embed()` was called. A mockall expectation (`expect_embed().returning(...)`) makes the test pass by satisfying the mock, which can pass even if your pipeline logic is wrong, and it does not exercise alternate arms unless you hand-script every expectation — that is the definition of test theater the user wants to avoid. A hand-rolled `FakeEmbedder { vectors: HashMap<…> }` lets the genuine pipeline run end-to-end against deterministic vectors so the *logic* is what gets covered and mutation-tested.

### 1.3 async-trait crate status in 2026

`async-trait` is **not formally deprecated** but is now **legacy / discouraged for new code**: it boxes every returned future (heap alloc + dynamic dispatch tax) and blocks compiler optimization. The ecosystem (e.g. sqlx tracking issue #3059) is actively migrating off it. Keep `trait-variant` as the project already does; reach for boxed futures only at a genuine `dyn` boundary, and prefer a hand-written `Pin<Box<dyn Future>>`-returning trait there over pulling in `async-trait`.

- Sources: [Moving away from async_trait — sqlx#3059](https://github.com/launchbadge/sqlx/issues/3059); [Rust Blog 2023-12-21 (above)](https://blog.rust-lang.org/2023/12/21/async-fn-rpit-in-traits.html); [Design meeting 2024-01-24: Send bound problem — Rust team HackMD](https://hackmd.io/@rust-lang-team/rJks8OdYa) (accessed 2026-05-19).

---

## 2. fastembed 5.x / ort 2.x — making provider code testable offline

### 2.1 Current state (2026)

- **fastembed-rs v5.13.4** released **2026-04-27**, Apache-2.0, wraps **`@pykeio/ort`** for inference and HF tokenizers; no tokio dependency. Models constructed via `try_new()` + options structs (`InitOptions`, `RerankInitOptions`, …). By default it **downloads model weights at runtime** (the 568 MB `bge-reranker-v2-m3` problem). Source: [fastembed-rs GitHub](https://github.com/Anush008/fastembed-rs); [fastembed crates.io](https://crates.io/crates/fastembed) (accessed 2026-05-19).
- **`ort` 2.x** (current line `2.0.0-rc.x`, e.g. rc.10–rc.12; still RC, not a final 2.0 stable as of 2026-05). Relevant cargo features (docs last updated **2026-03-06**):
  - `download-binaries` (**default on**) — fetches prebuilt ONNX Runtime from pyke's CDN at build time. Network at build.
  - `load-dynamic` — runtime dynamic linking; you set **`ORT_DYLIB_PATH`** to a local `libonnxruntime.{so,dylib,dll}` (relative paths allowed). No build-time fetch.
  - `alternative-backend` + **`ort-tract`** — pure-Rust ONNX inference backend (no C++ ONNX Runtime, no CDN). Configure with `default-features = false`, disable `download-binaries`, enable the tract backend.
  - Sources: [ort — Cargo features](https://ort.pyke.io/setup/cargo-features); [ort — Linking](https://ort.pyke.io/setup/linking); [ort-tract backend](https://ort.pyke.io/backends/tract); [pykeio/ort cargo-features.mdx](https://github.com/pykeio/ort/blob/main/docs/pages/setup/cargo-features.mdx) (accessed 2026-05-19).
- Known failure mode confirmed by the ecosystem: "auto-downloading shared libraries works locally but breaks in sandboxed/CI environments" — fix is to turn off auto-download and resolve a predictable local path. Source: [Bundling ONNX Runtime in Rust with Nix/Docker/GHA — stark.pub](https://blog.stark.pub/posts/bundling-onnxruntime-rust-nix/); [fastembed-rs#6 wrong onnxruntime.dll in integration tests](https://github.com/Anush008/fastembed-rs/issues/6) (accessed 2026-05-19).

### 2.2 Recommended testability strategy (two independent layers)

**Layer A — the seam (covers the goal):** abstract the embedder and reranker behind your own trait (`EmbeddingProvider`, `Reranker`). In unit/integration tests inject a deterministic fake; **`fastembed`/`ort` is never constructed**, so no model, no ONNX runtime, no network. This is what actually moves coverage on the recall pipeline and backfill path — the provider-bound logic runs; only the embed/rerank I/O boundary is faked. This is the same trait seam from §1, reused.

**Layer B — defense in depth for the rare test that *does* touch fastembed (and for build hygiene):** in the workspace, pin `ort` with `default-features = false` and either `load-dynamic` (point `ORT_DYLIB_PATH` at a CI-cached dylib) or `ort-tract` (pure Rust, nothing to download). Gate any real-model test behind `#[ignore]` exactly as the project already gates real-keychain tests, and keep the existing `CLX_MODEL_FETCH_DRYRUN=1` stub so `clx model fetch` never pulls the 568 MB weights in the harness.

**Rejected:** mocking at the ONNX FFI / `ort::Session` layer — brittle, couples tests to ONNX internals, and still drags in the runtime. Trait abstraction one level up is strictly better and is the ecosystem-recommended pattern.

---

## 3. 2026 Rust test taxonomy & tooling — current vs deprecated

| Tool | 2026 status | Recommendation for CLX |
|---|---|---|
| **cargo-nextest** | Actively maintained; up to ~3× faster than `cargo test`; native IDE support landed (RustRover 2026.1, Apr 2026). | Keep as the default runner (already wired in `scripts/test.sh`). Use a `ci` profile with `fail-fast=false`, `retries=0` for coverage runs — **already done in `.config/nextest.toml`**. |
| **cargo-llvm-cov** | 0.8.7 line; **branch coverage still unstable/nightly in 2026**, MC/DC experimental. `--ignore-filename-regex`, `--no-default-ignore-filename-regex`, and `[workspace.metadata.cargo-llvm-cov]` are supported and stable. Region coverage is the stricter, LLVM-native metric. | Keep line gate `--fail-under-lines 97` on the published denominator. Track **region** coverage as an informational stricter signal. Do **not** gate on branch coverage yet. |
| **insta** | Actively maintained 1.x; inline vs file snapshots; `cargo insta test` review workflow; CI verification via no-pending-snapshots. | Keep. For CI use a non-interactive verify (`--unreferenced=reject`, as already in the script). Prefer inline snapshots for small protocol fragments, file snapshots for TUI pixel buffers. |
| **proptest** | **Passive/feature-complete maintenance** in 2026 (explicitly stated by the project) — this is *stable*, not abandoned; Rust 2024 compatible. | Recommended for config fuzz, FTS query safety, RRF score invariants. Per-value `Strategy` model is the reason to prefer it. |
| **quickcheck** | Still exists, type-driven shrinking only; less flexible. | Not recommended for new suites; proptest supersedes it. |
| **cargo-mutants** | Actively maintained (~monthly releases through 2026). Supports `.cargo/mutants.toml`, `--file`/`--re`/`--exclude`, `--shard`, `--error` (mutate `Result` to a chosen error). | Run only on hot modules via `mutants.toml` (already the project's plan). Gate ≥80% caught on those modules. Shard in CI if runtime is large. |
| **wiremock** | Stable 0.6.x, no breaking changes since 0.6.0. | Use for the L1 LLM validation hook's *HTTP* arm where you want a real reqwest round-trip; the trait fake covers the no-network path. Both have a place. |
| **assert_cmd / assert_fs / predicates** | Stable, idiomatic; "avoid over-abstraction, repetition is fine" is current guidance. | Keep for CLI e2e (`tests/cli_e2e.rs` already exists). |
| **Contract/snapshot for JSON protocols** | insta JSON snapshots + schema assertion is current best practice for MCP/hook protocol stability. | Snapshot the MCP/hook JSON envelopes; redact non-deterministic fields (session id, timestamp). |
| **async-trait (as a testing enabler)** | Legacy; boxing tax. | Avoid; use the trait seam + hand fakes. |
| **tarpaulin** | Linux-first, weak on macOS; the project is macOS-centric. | Rejected; llvm-cov is correct. |

- Sources: [cargo-nextest changelog](https://nexte.st/changelog/); [Faster Rust Tests With cargo-nextest — JetBrains, 2026-05-01](https://blog.jetbrains.com/rust/2026/05/01/faster-rust-tests-with-cargo-nextest/); [RustRover 2026.1 nextest — JetBrains, 2026-04-03](https://blog.jetbrains.com/rust/2026/04/03/rustrover-2026-1-professional-testing-with-native-cargo-nextest-integration/); [cargo-llvm-cov GitHub / 0.8.7 docs](https://github.com/taiki-e/cargo-llvm-cov); [Test coverage — cargo-nextest](https://nexte.st/docs/integrations/test-coverage/); [proptest GitHub](https://github.com/proptest-rs/proptest) and [Proptest vs Quickcheck](https://proptest-rs.github.io/proptest/proptest/vs-quickcheck.html); [cargo-mutants docs](https://mutants.rs/) and [changelog](https://mutants.rs/changelog.html); [wiremock-rs](https://github.com/LukeMathWalker/wiremock-rs) (accessed 2026-05-19). Tool-version baseline corroborated by the project's own 2026-03 validation in `docs/research-prep/rust-testing/validation-2026.md`.

**2026 layered strategy (recommended):**
1. **Unit (in-crate `#[cfg(test)]`)** — pure logic + hand-fake-injected provider logic. Fast inner loop (`just fast`).
2. **Property (proptest)** — invariants: RRF monotonicity, config round-trip, FTS query never panics/ReDoS.
3. **Integration (`tests/`)** — cross-crate, real reqwest+wiremock for the HTTP arm, in-memory SQLite.
4. **Snapshot (insta)** — JSON protocol envelopes + TUI pixel buffers.
5. **CLI e2e (assert_cmd/assert_fs)** — binary behavior.
6. **Mutation (cargo-mutants)** — hot modules only, ≥80% caught gate.

**Anti-patterns now explicitly called out in 2026 sources:** mockall expectation-setting standing in for behavior tests; gating on unstable branch coverage; snapshotting non-redacted timestamps; one giant `tests/` file recompiled as one crate when shared helpers should live in `tests/common/mod.rs`.

---

## 4. Honest coverage denominator practice in 2026

**Community consensus (2026):** excluding *genuinely unreachable* glue is accepted and expected; what is disreputable is (a) excluding code that has reachable logic, or (b) the opposite extreme — chasing 100% by writing tests that assert nothing meaningful ("test theater"). The accepted bar: each exclusion is *unreachable in the test process* (real-TTY event loops, `main.rs` shell wiring, `cfg(target_os)` FFI, `#[ignore]`-only paths) **and its logic is covered elsewhere**, with the rationale documented and the include/exclude list kept in one authoritative place.

- Sources: [Instrumentation-based Code Coverage — rustc book](https://doc.rust-lang.org/rustc/instrument-coverage.html); [cargo-llvm-cov README / `--ignore-filename-regex`, `--no-default-ignore-filename-regex`](https://github.com/taiki-e/cargo-llvm-cov); [Reaching 100% Code Coverage in Rust — Trane book](https://trane-project.github.io/blog/100_code_coverage.html); [How to Check Code Coverage in Rust (2026) — Barrett's Club](https://barretts.club/posts/how-to-test-code-coverage-rust-2026/); [rust-lang/rust#80549 — don't count `unreachable!()`](https://github.com/rust-lang/rust/issues/80549) (accessed 2026-05-19).

**Assessment of CLX's current practice:** it is *already best-in-class*. `Cargo.toml` `[workspace.metadata.cargo-llvm-cov]`, `scripts/test.sh` `COV_IGNORE_REGEX`, and `docs/testing.md` carry a byte-identical regex with a **per-pattern rationale** (event loop glue, `main.rs` shell, macOS keychain FFI behind `cfg`, `#[ignore]`-only repair paths) and each excluded file's logic is asserted to be covered elsewhere (the pure `update` reducer in `dashboard/state.rs`, `router::handle_event`). This is exactly the documented-and-justified model the community endorses.

**Recommended hardening (gap):** the three copies of the regex are kept in sync *by convention*. Add a CI guard that fails if `Cargo.toml`'s metadata regex, the `scripts/test.sh` constant, and the `docs/testing.md` table diverge — turn the convention into an enforced invariant. This is the one concrete improvement on §4.

---

## 5. The "Ralph" test-harden loop (2026)

**What it is:** the Ralph (Ralph Wiggum) loop wraps a one-shot prompt in an iteration loop that restarts the agent and forces it to verify itself until a completion signal or iteration cap. The mature test-hardening variant is **GAN-shaped**: a **generator** proposes tests + a proof packet; an **adversarial critic/evaluator** (a separate, deliberately skeptical agent) tries to break them; iterate to a gate. Public writeups exist and are recent.

- Sources: [2026 — The year of the Ralph Loop Agent — DEV](https://dev.to/alexandergekov/2026-the-year-of-the-ralph-loop-agent-1gkj); [Ralph Loop — The Agent Loop Pattern Where AI Tests and Fixes Itself](https://ice-ice-bear.github.io/posts/2026-03-06-ralph-loop-ai-automation/); [Own the Loop — Agent-Agnostic Guide to Long-Running Agents — Vinodh Thiagarajan, Mar 2026](https://medium.com/@vinodh.thiagarajan/own-the-loop-an-agent-agnostic-guide-to-long-running-agents-42cbdd632533); [Self-Healing Feature Loops with Ralph Loops, BAML, Promptfoo — Chris Cooley, Feb 2026](https://medium.com/techtrends-digest/self-healing-feature-loops-with-ralph-loops-repomix-baml-and-promptfoo-67648aa408e4); [Ralph Wiggum Loop — January 2026 Snapshot](https://ai-assisted-software-development.com/ralph-wiggum-loop-january-2026-snapshot/); [Ralph Wiggum AI Agents: The Coding Loop of 2026 — Leanware](https://www.leanware.co/insights/ralph-wiggum-ai-coding) (accessed 2026-05-19).

**Documented pitfalls and the 2026 guards:**

| Pitfall | Why it happens | Guard (2026 best practice) |
|---|---|---|
| Overfitting tests to the coverage number | Coverage is a single scalar an agent can game (call the function, assert nothing) | **Dual gate: coverage AND mutation-kill.** A test that doesn't assert behavior is killed by mutation testing even if it covers the line. cargo-mutants is the discriminator. |
| Asserting implementation, not behavior | Schema/type-correct ≠ correct behavior ("a well-typed response that patches the wrong file is still a bug" — BAML writeup) | Critic agent reviews each test against a *behavior contract*; reject tests that pin internal structure instead of observable outcome. |
| Self-grading optimism | Single agent that both writes and judges its own work | **Separate adversarial critic** with few-shot skeptic tuning; the critic *mutates the implementation* and the test suite must catch it. |
| Runaway / budget burn | Loop with no cap | Hard caps: max iterations, budget awareness, scoped permissions, explicit completion gate (consensus across all 2026 writeups). |
| Weak tests still ship | "If tests are weak, the agent still ships mediocre work" — test design is first-class | Proof packet must include: the failing-before/passing-after diff, the mutation-kill delta on hot modules, and the coverage delta on the *published denominator* (not raw). |

**Recommended loop for CLX:** generator proposes provider-seam fakes + tests + proof packet → critic mutates hot modules (cargo-mutants) and hand-tampers the recall/L1 logic → iterate until `just cov` ≥97% **and** `just mutants` ≥80% caught on hot modules **and** critic finds no behavior-contract violation. The mutation gate is the antidote to coverage overfitting; this is why the project already pairs the two in `scripts/test.sh`.

---

## 6. Recommended architecture — the injectable provider seam

### 6.1 Seam traits (in `clx-core`)

Declare one trait per I/O boundary, with the Send variant for tokio, kept dyn-free at the call site by using generics:

```rust
// clx-core/src/provider/mod.rs  (illustrative — names/signatures to be finalized in impl plan)
#[trait_variant::make(Send)]
pub trait EmbeddingProvider {
    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, ProviderError>;
}

#[trait_variant::make(Send)]
pub trait Reranker {
    async fn rerank(&self, query: &str, docs: &[String]) -> Result<Vec<(usize, f32)>, ProviderError>;
}

#[trait_variant::make(Send)]
pub trait ValidationLlm {
    async fn classify(&self, prompt: &str) -> Result<L1Verdict, ProviderError>;
}
```

- The recall pipeline, backfill path, and L1 hook take these **as generic parameters** (`fn run<P: EmbeddingProvider, R: Reranker>(…)`), so production stays monomorphized and zero-cost and there is no object-safety problem.
- The **real** implementations (`FastembedEmbedder`, `BgeRerankerV2M3`, `HttpValidationLlm`) live behind the same traits and are the only code that constructs `fastembed`/`ort`/`reqwest`.

### 6.2 Test doubles (a `testkit` module, `#[cfg(test)]` + optional `testkit` feature)

```rust
// Hand-rolled, deterministic — real pipeline logic runs against these.
pub struct FakeEmbedder { pub table: HashMap<String, Vec<f32>> } // canned vectors
pub struct FakeReranker { pub scores: Vec<f32> }                  // canned ranking
pub struct ScriptedLlm  { pub script: Vec<L1Verdict>, pub delay: Option<Duration> } // drives timeout/cache arms
```

- These satisfy the same traits, so **RRF fusion, cache hit/miss, and L1 timeout/cache arms all execute for real** — only the embed/rerank/classify I/O is substituted. This is what lifts coverage *without* test theater, and what survives cargo-mutants.
- `mockall::automock` is added **only** to the traits where a specific test needs call-count/argument assertions or injected transport errors — never as the default substitution mechanism.
- `ScriptedLlm` with an injectable `delay` is how you cover the L1 timeout arm deterministically (no real clock dependence — drive it with `tokio::time::pause()`/`advance`).

### 6.3 Boundary where `dyn` is unavoidable

If the hook router must hold heterogeneous providers at runtime, introduce **one** narrow object-safe trait at that single registry boundary that returns `Pin<Box<dyn Future<…> + Send>>` (hand-written, no `async-trait` crate), and adapt the generic providers into it there. Keep this confined to the registry; the rest of the codebase stays generic.

### 6.4 Offline guarantees (already partly in place)

- Tests never construct `fastembed`/`ort` (Layer A trait seam).
- Workspace pins `ort` with `default-features = false` + `load-dynamic` (CI-cached dylib via `ORT_DYLIB_PATH`) **or** `ort-tract` pure-Rust backend → no build/runtime CDN fetch.
- `CLX_MODEL_FETCH_DRYRUN=1` keeps `clx model fetch` stubbed (already in `scripts/test.sh`).
- `CLX_CREDENTIALS_BACKEND=age` keeps the keychain untouched (already in `scripts/test.sh`).

---

## 7. Recommended one-command local test runner

**CLX already has the right design** (`scripts/test.sh` + mirrored `justfile`): hermetic env exports, graceful skip of absent tools, dual coverage+mutation gate, byte-identical denominator regex. Recommended deltas for the implementation plan:

1. **Keep** `just fast | cov | snapshots | mutants | all | pre-release` and the shell script as single source of truth.
2. **Add** a `just verify-denominator` (or fold into `all`) that diffs the regex across `Cargo.toml`, `scripts/test.sh`, and `docs/testing.md` and fails on drift — converts the §4 convention into an enforced invariant.
3. **Add** a `testkit` cargo feature exposing the hand-rolled fakes so integration tests (`tests/`, separate crates) can use them without `#[cfg(test)]` visibility limits.
4. **Mutation gate**: in `mutants.toml`, scope to the hot modules (recall RRF, L1 hook, backfill) and wire `just mutants` to fail under 80% caught — the discriminator that prevents Ralph-loop coverage overfitting.
5. **Region coverage as informational**: add `--summary-only` region output to the `cov` run for visibility; do not gate on it (line gate at 97% remains the contract).

---

## 8. Confidence & residual gaps

- **High confidence:** trait-variant/AFIT non-object-safety and its consequence for the seam; hand-fakes > mockall for the no-theater coverage goal; ort feature-flag offline story; current 2026 tool stack and deprecation of `async-trait`-as-enabler; honest-denominator consensus.
- **Medium confidence:** exact `ort` 2.x release channel — it remains in the `2.0.0-rc.x` line in 2026-05 (not a final 2.0 stable); pin to the specific rc the workspace already resolves and re-verify before tagging. fastembed 5.13.4 confirmed 2026-04-27.
- **Lower confidence / not independently deep-verified:** Ralph-loop specifics are from practitioner blogs (Feb–Mar 2026), not a standard; treat the dual-gate guard as the load-bearing, well-supported claim and the loop choreography as a reasonable synthesis.
- **WebFetch was unavailable** this session (permission denied); all external claims rest on WebSearch result summaries plus the project's own 2026-03 tool-validation doc. URLs are cited for the implementation team to re-verify ort rc pinning and fastembed feature flags directly before code.
