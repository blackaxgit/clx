# CLX 0.8.0 Pre-Release Risk Triage

Date: 2026-05-18
Branch: `feat/0.8.0-memory-skills-coverage`
Scope: the 12 MEDIUM and 11 LOW risks from the Consolidated Risk Register
(`specs/2026-05-17-pre-release-functional-spec.md` section 3). The 4 HIGH
risks (I-R1, V-R2, V-R4, V-R5) are already fixed and committed and are not
re-triaged here.

Verdict buckets:

- ACCEPTED-0.8.0: real but low blast radius given the encrypted file
  credential backend default plus the shipped HIGH fixes; documented as a
  known issue, ship as is.
- CHEAP-FIX-NOW: genuine defect with a small, low-risk, behavior-preserving
  fix that should land before tag (listed precisely below for a follow-up
  code wave).
- DEFER-0.8.1: legitimate follow-up, not blocking, tracked for next minor.
- FALSE-POSITIVE: re-reading the cited code shows the risk is not real.

## Decision table (23 rows: 12 MEDIUM + 11 LOW)

| ID | Severity | Verdict | Rationale (file:line) | Action |
|----|----------|---------|------------------------|--------|
| V-R3 | MEDIUM | ACCEPTED-0.8.0 | L1 parse-failure / suspicious response returns a plain `ask` and does not route through `default_decision` (`policy/llm.rs:131-158`, `pre_tool_use.rs` L1 path). Real, but only weakens an already-soft L1 (L1 never hard-denies anyway); L0 + learned rules still block. | Document in CHANGELOG Known issues. Re-route through `default_decision` deferred. |
| V-R7 | MEDIUM | ACCEPTED-0.8.0 | Redaction is a prefix/keyword heuristic, not a regex; novel secret shapes can be stored verbatim (`redaction.rs:20-70`). Inherent to a heuristic redactor; expanding patterns is open-ended. | Document (avoid raw secrets on argv). Pattern expansion deferred. |
| V-R8 | MEDIUM | ACCEPTED-0.8.0 | Malformed `~/.clx/config.yaml` swallowed by `Config::load().unwrap_or_default()` in the hook (`pre_tool_use.rs:24`); validation silently reverts to defaults (still `enabled=true`, `default_decision=ask`). Surfacing an error in a fail-open hook risks blocking Claude Code. | Document (validate with `clx config show`). Hook-path surfacing deferred. |
| V-R9 | MEDIUM | ACCEPTED-0.8.0 | Legacy plain-text trust token accepted on `mtime < 3600s` regardless of content (`pre_tool_use.rs:114-121`). Requires `trust_mode: true` (config-file-only, opt-in) AND an attacker-touched legacy token; bounded to 1 h; JSON token is the supported path. | Document (use `clx trust off`; prefer JSON token). Removing legacy token format deferred to 0.8.1. |
| M-R1 | MEDIUM | CHEAP-FIX-NOW | `migration.rs:47` only acts on `current_version < SCHEMA_VERSION`; no refuse-newer guard despite the golden corpus asserting one (`recall_golden.yaml:108-110`). | Add an explicit `current_version > SCHEMA_VERSION` refuse-newer branch (see CHEAP-FIX list). |
| M-R6 | MEDIUM | ACCEPTED-0.8.0 | `do_recall` opens `Storage` (`subagent.rs:163`) and `EmbeddingStore` (`subagent.rs:180`) per prompt inside `tokio::time::timeout(timeout_ms)` (`subagent.rs:144-147`, default 500 ms). Timeout-bounded with correct degradation; per-process hooks cannot pool connections so no small in-process fix exists. | Document the latency-cliff behavior. Perf work deferred. |
| C-R1 | MEDIUM | CHEAP-FIX-NOW | List annotation strips `:api-key` (colon) (`commands/credentials.rs:159`) while resolver/set/migrate use `<provider>-api-key` (hyphen) (`config/mod.rs:1803,1828`); `validate_key` rejects colons so the colon branch is unreachable for real keys. Annotation is dead for canonical naming. | One-line fix: change the strip suffix from `:api-key` to `-api-key` (see CHEAP-FIX list). |
| C-R3 | MEDIUM | ACCEPTED-0.8.0 | `read_file_credential` does `metadata()` then `read_to_string()` (TOCTOU) and the file is plaintext (`config/mod.rs:1842-1861`). Local-file/same-user only; `api_key_file` is an opt-in escape hatch; the default encrypted file backend avoids it; an fd-then-fstat rewrite is non-trivial. | Document (prefer `clx credentials set`). Atomic open+fstat deferred. |
| C-R4 | MEDIUM | ACCEPTED-0.8.0 | `load_from_file_only` reads only the raw global file, bypassing project layer / trust gate / env overrides (`config/mod.rs:1190-1200`). Intentional raw-editing view for the dashboard Settings tab; not the effective-runtime resolver. | Document that the Settings tab is not the effective-config source of truth. No code change. |
| I-R5 | MEDIUM | DEFER-0.8.1 | `clx maintenance trim` uses `audit_days.unwrap_or(90)` (`commands/maintenance.rs:56`). `RetentionConfig` (`config/mod.rs:335-348`) has NO audit field, so nothing is actually "bypassed"; the `--audit-days` flag already works. Proper fix is adding an `audit_log_days` config key, a schema addition (not a behavior-preserving <=15 LoC change). | Document the 90-day default and `--audit-days` workaround. Add `retention.audit_log_days` in 0.8.1. |
| I-R2 | MEDIUM | CHEAP-FIX-NOW | Only 7 fixtures; `stop.json` carries `hook_event_name:"SessionEnd"` (verified) (`tests/fixtures/hook_envelopes/stop.json`, `router_smoke.rs:195-197`). The `Stop` envelope is contract-untested. | Add a real `Stop` fixture + parse/emit smoke pair (see CHEAP-FIX list). |
| I-R4 | MEDIUM | ACCEPTED-0.8.0 | `clx install` is sequential with `?` early-returns; `write_claude_settings` writes `settings.json.backup` before mutating (`install.rs:331-335`). Every step is idempotent and re-run-safe (tested); full FS+SQLite transactionality is a large architectural change. | Document recovery (re-run `clx install`; restore `settings.json.backup`). No code change. |
| V-R1 | LOW | FALSE-POSITIVE | `DefaultDecision` has an explicit `#[default]` on `Ask` (`config/mod.rs:152-162`); the validator default fn sets `DefaultDecision::Ask` (`config/mod.rs:940`) and tests assert it (`config/mod.rs:2120`). The live default is `ask` and is test-covered; the "no explicit default / confirm live value" concern does not hold. | None. Note resolved. |
| V-R6 | LOW | ACCEPTED-0.8.0 | `PromptSensitivity::Custom` maps to STANDARD built-in text unless a `.clx/prompts/validator.txt` override exists, with no warning (`policy/llm.rs:465`). Cosmetic UX; behavior is safe (standard prompt). | Document as a 0.8.1 polish item. |
| M-R2 | LOW | DEFER-0.8.1 | MCP `clx_recall` doc comment still describes the legacy 0.6/0.4 hybrid merge; actual path is RRF (`tools/recall.rs:21-25` vs `recall.rs:59`). Doc-only drift, no functional impact. | Fix the stale doc comment in 0.8.1. |
| M-R3 | LOW | ACCEPTED-0.8.0 | `turns_since_last_auto_summary` propagates a query error and aborts while the idle-check proceeds-on-error (`stop_auto_summary.rs:83-89`, `snapshot.rs:361-368`); only divergent on an un-migrated v6/v7 DB. Auto-summarize is opt-in (default off) and Stop never fails the session. | Document as low-risk inconsistency. Harmonize error handling in 0.8.1. |
| M-R4 | LOW | DEFER-0.8.1 | `query_percentile_gate` duplicated verbatim in `subagent.rs:252-258` and `recall.rs:131-137`. Divergence risk only if one is edited; behavior currently identical. | Extract to a shared helper in 0.8.1. |
| M-R5 | LOW | ACCEPTED-0.8.0 | `RERANK_FALLBACK_TOTAL` is process-global, observable only in tests; no telemetry export (`rerank.rs:70-71`). Documented as future telemetry; not user-visible. | Document. Surface in stats/dashboard in 0.8.1. |
| C-R2 | LOW | DEFER-0.8.1 | Figment `Env::prefixed` plus `apply_env_overrides` double-apply with no test for conflicting/out-of-range precedence (`config/mod.rs:1164-1181`). `apply_env_overrides` is authoritative and range-checked; no observed defect, only missing test coverage. | Add a precedence regression test (e.g. out-of-range `CLX_VALIDATOR_LAYER1_TIMEOUT_MS`) in 0.8.1. |
| C-R5 | LOW | FALSE-POSITIVE | `AgeFileBackend::get`/`list_keys` take no lock, but writes are atomic temp+fsync+rename on the same filesystem (`backend.rs:199-206,292-326,399-423`); a concurrent reader observes either the complete old or complete new file, never a partial. The flagged transient window does not exist with atomic rename. | None. Add a concurrent-read-during-rename test in 0.8.1 for explicit coverage (optional). |
| C-R6 | LOW | ACCEPTED-0.8.0 | `CLX_CONFIG_PROJECT` can select an arbitrary config path, but that file still passes through `apply_project_layer` so non-inert keys are filtered unless the hash is trusted (`config/project.rs:31-36`, `config/mod.rs:1150-1162`). Behavior is safe; it is a threat-model knob to call out, not a defect. | Document in the threat model. No code change. |
| I-R3 | LOW | ACCEPTED-0.8.0 | Hook provenance trusts inherited env vars a same-uid attacker can set (`router.rs:80-126`); documented defense-in-depth, not auth. Claude Code 2026 provides no unforgeable token. | Documented residual risk per threat model. No code change. |
| I-R6 | LOW | DEFER-0.8.1 | `install-local.sh` check #5 greps the literal `clx-mcp` substring anywhere in settings.json (`install-local.sh:392`); an unrelated path containing `clx-mcp` would false-pass. Verification weakness only, not a runtime defect; out of the allowed file scope for this pass. | Tighten to a JSON-key assertion in 0.8.1. |

## Summary counts per verdict bucket

- ACCEPTED-0.8.0: 13 — V-R3, V-R7, V-R8, V-R9, M-R6, C-R3, C-R4, I-R4,
  V-R6, M-R3, M-R5, C-R6, I-R3
- CHEAP-FIX-NOW: 3 — M-R1, C-R1, I-R2
- DEFER-0.8.1: 5 — I-R5, M-R2, M-R4, C-R2, I-R6
- FALSE-POSITIVE: 2 — V-R1, C-R5

Total: 13 + 3 + 5 + 2 = 23 (matches 12 MEDIUM + 11 LOW).

## CHEAP-FIX-NOW ordered list (for a follow-up code wave)

Execute in this order. Each is small, low-risk, and behavior-preserving for
all normal paths. None require an architecture change.

1. **C-R1** — `crates/clx/src/commands/credentials.rs:159`
   Change `key.strip_suffix(":api-key")` to
   `key.strip_suffix("-api-key")` so the provider-kind annotation matches
   the canonical `<provider>-api-key` key naming used by the resolver,
   `set`, and `migrate`. One-line change, cosmetic-only output. Add/adjust
   a unit test asserting `azure-prod-api-key` gets the `(azure_openai)`
   annotation when the `azure` provider is in config.

2. **M-R1** — `crates/clx-core/src/storage/migration.rs:47` (inside
   `run_migrations`, before/around the `current_version < SCHEMA_VERSION`
   block)
   Add an explicit guard: if `current_version > SCHEMA_VERSION`, return a
   descriptive `Err` (refuse to open a database written by a newer CLX)
   instead of silently proceeding against an unknown schema. Roughly
   `if current_version > SCHEMA_VERSION { return Err(... "database schema
   vN is newer than supported vM; upgrade clx" ...); }`. Add a unit test
   that stamps a future `user_version` and asserts the open errors. This
   aligns code with the golden-corpus assertion at
   `tests/fixtures/recall_golden.yaml:108-110`.

3. **I-R2** — `crates/clx-hook/tests/fixtures/hook_envelopes/` (new
   fixture) plus `crates/clx-hook/tests/router_smoke.rs`
   Add a new fixture (suggested name `stop_event.json`) whose
   `hook_event_name` is literally `"Stop"` with the standard sanitized
   envelope fields (zeroed `session_id`, `cwd: "/tmp/test-project"`,
   `transcript_path`). Add a `parse_stop_event_fixture` insta snapshot
   test and an `emit_stop_event_smoke` test mirroring the existing 7
   pairs, asserting empty-or-valid JSON. Test-only change; no production
   code is modified. (Note: this pass is forbidden from touching
   `crates/**`, so it is listed for the follow-up wave, not done here.)
