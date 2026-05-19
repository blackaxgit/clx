# CLX 0.8.0 Pre-Release Spec — 04 INTEGRATION

Scope: Claude Code hooks, MCP server, install/uninstall, plugin + 6 skills,
dashboard TUI, ancillary CLI.
Branch: `feat/0.8.0-memory-skills-coverage` (HEAD `1b8515a`).
All claims cite `file:line` against real code. QA uses this before tagging
`v0.8.0`. Behavior described is ACTUAL code behavior, not aspiration.

---

## 1. Overview

CLX integrates with Claude Code through three independent surfaces, all
wired by one installer:

1. **Hooks** — `~/.claude/settings.json` registers 8 events, each running
   `~/.clx/bin/clx-hook <subcommand>`. The `clx-hook` binary reads a JSON
   envelope on stdin, dispatches by `hook_event_name`, performs side effects
   (audit, snapshots, context injection), and writes a JSON response on
   stdout. Source: `crates/clx-hook/src/main.rs:33`,
   `crates/clx-hook/src/router.rs:206`.
2. **MCP server** — `~/.claude/settings.json` `mcpServers.clx` runs
   `~/.clx/bin/clx-mcp`, a JSON-RPC 2.0 line server exposing 7 tools
   (`crates/clx-mcp/src/server.rs:133`, `:413`).
3. **Skills** — 6 personal skills installed to `~/.claude/skills/<name>/SKILL.md`
   (`crates/clx/src/commands/install.rs:24`, `:103`); also shipped as a
   2026-schema plugin (`plugin/.claude-plugin/plugin.json:1`).

Binary topology:

| Binary | Role | Installed location |
|--------|------|--------------------|
| `clx` | CLI / installer / dashboard | `~/.clx/bin/clx`, plus user PATH copy via install-local.sh `--prefix` (default `~/.local/bin`) |
| `clx-hook` | Claude Code hook handler | `~/.clx/bin/clx-hook` |
| `clx-mcp` | MCP JSON-RPC server | `~/.clx/bin/clx-mcp` |

`clx install` copies all 3 into `~/.clx/bin` (`install.rs:910-940`) and
stamps `~/.clx/bin/.clx-version` (`install.rs:51`, `:944`).
`scripts/install-local.sh` is the brew-free path: it builds with cargo,
copies binaries to `--prefix`, then delegates ALL wiring to the freshly
built `clx install` (`install-local.sh:325-333`) so the end state is
byte-identical to `brew install clx && clx install`.

---

## 2. Feature Inventory

### 2.1 CLI subcommands (`crates/clx/src/main.rs:60-167`)

| Subcommand | Does | file:line |
|---|---|---|
| `recall <query>` | Search context DB, print results | `main.rs:203` -> `commands::cmd_recall` |
| `config [action]` | Show/edit/reset config | `main.rs:204` |
| `rules <action>` | Manage validation rules | `main.rs:205` |
| `install` | Install CLX integration | `main.rs:206` -> `install.rs:556` |
| `uninstall [--purge]` | Remove integration | `main.rs:207` -> `install.rs:1192` |
| `version` | Show version info | `main.rs:208` -> `version.rs:10` |
| `credentials <action>` | Keychain/file credential mgmt | `main.rs:209` |
| `keychain-trust` | Repair macOS keychain ACL | `main.rs:210` |
| `embed-backfill [--dry-run]` | Backfill embeddings | `main.rs:211` |
| `completions <shell>` | Shell completions | `main.rs:214` |
| `embeddings <action>` | Embedding status/rebuild | `main.rs:218` |
| `trust <action>` | Trust mode mgmt | `main.rs:219` |
| `config-trust <action>` | Trusted per-project config | `main.rs:220` |
| `health [--json]` | System health check | `main.rs:221` |
| `dashboard [--days N --refresh S]` | TUI dashboard | `main.rs:222` -> `dashboard/mod.rs:10` |
| `maintenance <action>` | Retention trim | `main.rs:224` -> `maintenance.rs:35` |
| `model <action>` | Manage reranker/embeddings models | `main.rs:225` |
| (none) | Default banner | `main.rs:226` -> `version.rs:38` |

### 2.2 Hook events (`router.rs:179-194`, `install.rs:351-382`)

| Event | settings.json command | matcher | Handler | file:line |
|---|---|---|---|---|
| PreToolUse | `clx-hook pre-tool-use` | `Bash\|Write\|Edit` | `handle_pre_tool_use` | `hooks/pre_tool_use.rs:20` |
| PostToolUse | `clx-hook post-tool-use` | `Bash\|Write\|Edit` | `handle_post_tool_use` | `hooks/post_tool_use.rs:16` |
| PreCompact | `clx-hook pre-compact` | (none) | `handle_pre_compact` | `hooks/pre_compact.rs:13` |
| SessionStart | `clx-hook session-start` | (none) | `handle_session_start` | `hooks/session_start.rs:14` |
| SessionEnd | `clx-hook session-end` | (none) | `handle_session_end` | `hooks/session_end.rs:29` |
| SubagentStart | `clx-hook subagent-start` | `*` | `handle_subagent_start` | `hooks/subagent.rs:17` |
| UserPromptSubmit | `clx-hook user-prompt-submit` | `*` | `handle_user_prompt_submit` | `hooks/subagent.rs:33` |
| Stop | `clx-hook stop` | (none) | `handle_stop_auto_summary` | `hooks/stop_auto_summary.rs:50` |

Note: the hook subcommand argv string (`pre-tool-use` etc.) is NOT parsed
by the binary; dispatch is purely on the `hook_event_name` JSON field
(`router.rs:179`). The argv is cosmetic / documentary only.

### 2.3 MCP tools (`server.rs:133-258`, `tools/mod.rs`)

| Tool | Does | Required args | file:line |
|---|---|---|---|
| `clx_recall` | Hybrid semantic+FTS5 search | `query` | `tools/recall.rs:26` |
| `clx_remember` | Persist fact as snapshot + embedding | `text` (`tags?`) | `tools/remember.rs:17` |
| `clx_checkpoint` | Manual snapshot | `note?` | `tools/checkpoint.rs:14` |
| `clx_rules` | CLAUDE.md rules / whitelist mgmt | `action` | `tools/rules.rs:15` |
| `clx_session_info` | Current session details | (none) | `tools/session_info.rs:11` |
| `clx_credentials` | Credential store CRUD | `action` | `tools/credentials.rs:16` |
| `clx_stats` | Usage statistics | `days?` | `tools/stats.rs:11` |

### 2.4 Skills (`plugin/.claude-plugin/plugin.json:8-15`)

| Skill | Maps to | Trigger gist | file |
|---|---|---|---|
| clx-recall | `mcp__clx__clx_recall` | "what did I do", references prior sessions | `skills/clx-recall/SKILL.md` |
| clx-remember | `mcp__clx__clx_remember` | durable preference/decision/fact | `skills/clx-remember/SKILL.md` |
| clx-checkpoint | `mcp__clx__clx_checkpoint` | before risky/large change | `skills/clx-checkpoint/SKILL.md` |
| clx-rules | `mcp__clx__clx_rules` | "what rules apply", refresh rules | `skills/clx-rules/SKILL.md` |
| clx-resume | `clx_recall` + snapshot reads | "resume earlier work" | `skills/clx-resume/SKILL.md` |
| clx-doctor | shell (`clx doctor`, `clx embeddings status`, `clx providers ping`) | recall returns empty/broken | `skills/clx-doctor/SKILL.md` |

---

## 3. Behavior Spec

### 3.1 Hook router (`handle_event`, `router.rs:206-255`)

**Normal flow:**
1. `read_input` reads stdin into a String, capped via
   `reader.take(MAX_INPUT_SIZE)` where `MAX_INPUT_SIZE = 1_048_576` bytes
   (`types.rs:7`, `router.rs:149-161`). If `n >= MAX_INPUT_SIZE`
   -> `TooLarge`.
2. On `TooLarge`: emit a `PreToolUse` block decision JSON
   (`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"block","permissionDecisionReason":"Input too large"}}`)
   to the `writer`, return `HookExit::InputTooLarge` (`router.rs:213-224`).
3. On `ReadFailed`: `output_decision("allow", ...)` to stdout,
   return `HookExit::ReadError` (`router.rs:225-229`).
4. `redact_secrets(&raw)` is logged at debug only (`router.rs:232`).
5. `parse_input` (`serde_json::from_str::<HookInput>`). On parse error:
   `output_decision("ask", Some("CLX: Input parse error, manual
   confirmation required"), ...)`, return `HookExit::ParseError`
   (`router.rs:234-246`).
6. `dispatch(input)` matches `hook_event_name` (`router.rs:178-194`).
   Unknown event -> WARN + `output_decision("allow", ...)` + `Ok`
   (`router.rs:188-192`).
7. Handler `Ok` -> `HookExit::Ok`; handler `Err` -> ERROR log,
   `HookExit::HandlerError` (`router.rs:248-254`).

**Exit codes:** `main()` maps EVERY `HookExit` variant to
`ExitCode::SUCCESS` (`main.rs:92-93`), because Claude Code treats non-zero
hook exits as failure noise. QA must verify the binary always exits 0.

**Provenance (F7, fail-safe).** Before any dispatch, `main()` reads
`CLAUDE_PROJECT_DIR` and `CLAUDE_PLUGIN_ROOT`
(`CLAUDE_PROVENANCE_ENV_VARS`, `router.rs:105`) and calls
`classify_provenance` (`router.rs:117-126`). An env var counts as present
only when set AND non-empty after trim. If none present ->
`Provenance::Unverified` -> a WARN is logged and processing CONTINUES
(`main.rs:79-86`). This is defense-in-depth, NOT auth: Claude Code 2026
provides no unforgeable token (`router.rs:80-99`). The contract tests call
`handle_event` directly so they bypass this check by design.

**Terminal / help short-circuit:** `--help`/`-h` or a TTY stdin prints
usage and exits SUCCESS before any I/O (`main.rs:38-47`).

**Storage open failure:** if `HookDeps::from_process_defaults()` returns
`None` (storage cannot open), `main()` returns SUCCESS without dispatch
(`main.rs:56-58`, `router.rs:56-60`).

### 3.2 Each hook event

Common envelope fields (`types.rs:24-59`): required `session_id`, `cwd`,
`hook_event_name`; optional `transcript_path`, `tool_name`,
`tool_use_id`, `tool_input`, `tool_response`, `source`, `trigger`,
`prompt`. Keys are snake_case (Claude Code convention). Output structs
serialize camelCase (`hookSpecificOutput`, `hookEventName`,
`permissionDecision`, `permissionDecisionReason`, `additionalContext`,
`systemMessage`), `Option::None` fields skipped (`types.rs:62-109`).

**PreToolUse** — fixture `tests/fixtures/hook_envelopes/pre_tool_use.json`
(`{"session_id":...,"hook_event_name":"PreToolUse","tool_name":"Read",
"tool_use_id":...,"tool_input":{"file_path":...}}`).
- Bash: extract `tool_input.command`; MCP command tools: `extract_mcp_command`;
  other tools (Read/Write/etc.): immediate `output_decision("allow",...,
  Some(RULES_REMINDER),...)` (`pre_tool_use.rs:28-53`).
- Empty command -> allow (`:55-58`). Validator disabled -> allow (`:66-69`).
- Trust mode: JSON `.trust_mode_token` checked for expiry + session match;
  valid -> audit `TRUST`/Allowed + allow; expired/invalid -> remove token,
  fall through to validation (`:72-147`).
- Layer 0 deterministic rules: Allow/Deny/Ask; read-only commands
  auto-allow on Ask (`:166-220`).
- SQLite decision cache hit -> replay cached decision (`:222-251`).
- Layer 1 LLM: when LLM client cannot be created OR Ollama unavailable
  OR generation fails -> `config.validator.default_decision` fallback,
  audit logged with reason (`:274-395`). Health cache read/write
  (`:309-325`, `:374`, `:398`).
- Output JSON: `output_decision` -> `HookOutput` with `hookEventName:
  "PreToolUse"`, `permissionDecision` one of allow/deny/ask,
  `additionalContext` = `RULES_REMINDER` (`output.rs:7,10-35`).
- Failure/fallback: all error paths still emit a decision and return Ok.

**PostToolUse** — fixture `post_tool_use.json`. Side-effect-only; usually
emits NOTHING on stdout (smoke test accepts empty,
`router_smoke.rs:108-114`).
- Opens storage; on failure WARN + `Ok` (`post_tool_use.rs:26-32`).
- Persists `Event` with `redact_json_value` applied to `tool_input` and
  `tool_response` (recursive JSON redaction, Issue-1 0.8.0 audit fix,
  `:42-49`).
- Aggregates mutator tools into `tool_events` (60s windowed dedup),
  read-only tools skipped (`:56-81`).
- Increments command count (`:84`).
- Audit log entry with `redact_secrets(command)` for Bash/MCP commands
  (`:121-138`).
- Context pressure: when `mode != Disabled` and `total_tokens >=
  window*threshold`, Auto mode creates a `ContextPressure` snapshot, then
  both Auto+Notify inject a `WARNING: Context at ~N% capacity ...` via
  `output_generic("PostToolUse", Some(warning), None)` and return
  (`:140-179`).

**PreCompact** — fixture `pre_compact.json`. `trigger` defaults `"auto"`
(`pre_compact.rs:14`). Opens storage (error -> Ok, `:22-28`). If
`transcript_path` present, `process_transcript(path, true)` else empty
result (`:31-42`). Creates a `Snapshot` (Manual/Auto by trigger,
`:45-57`), stores it, generates+stores embedding for summary, updates
session token counts (`:60-93`). Smoke test accepts empty stdout.

**SessionStart** — fixture `session_start.json`. `source` default
`"startup"` (`session_start.rs:15`). Storage failure still allows session
start, prints `CLX: Session started (storage unavailable)` to stderr
(`:23-31`). Resume vs new session distinguished by `get_session`
(`:34-66`). Session recovery: marks stale active sessions abandoned,
loads latest snapshot of most recent abandoned session into
`recovery_context` (`:68-106`). Loads previous session summary + project
rules from CLAUDE.md (`:108-112`). stderr: session id + CLX tools reminder
(`:114-121`). Emits `output_generic("SessionStart", None, Some(
systemMessage))` where systemMessage joins recovery context + prev
summary + project rules + a mandatory CLX tools line (`:124-151`).

**SessionEnd** — fixture `stop.json` carries
`hook_event_name:"SessionEnd"` (NOTE: the file is named stop.json but the
event is SessionEnd; smoke test `emit_stop_smoke` asserts `"SessionEnd"`,
`router_smoke.rs:195-197`). Wrapped in a 1.0s `tokio::time::timeout`
(`SESSION_END_TIMEOUT`, `session_end.rs:18,29-41`); on timeout prints a
stderr note and returns Ok. Reads cached Ollama health; skips all LLM
work if not `Available` (`:52-59`). Processes transcript, creates
`Checkpoint` snapshot, updates session tokens, generates embedding only
if Ollama available AND elapsed < `EMBEDDING_TIME_BUDGET` (500ms,
`:23,102-115`). Ends session (`:124`). stderr `CLX: Session <id> ended
(~N tokens)`.

**SubagentStart** — fixture `subagent_start.json`. Emits
`output_generic("SubagentStart", Some(SPECIALIST_CONTEXT), None)` where
`SPECIALIST_CONTEXT = "[SPECIALIST RULES] Execute task directly. Do NOT
delegate. Follow CLAUDE.md rules. Output format: Summary, Changes,
Verification, Risks."` (`subagent.rs:23-26`). No storage, no failure
modes; always Ok.

**UserPromptSubmit** — fixture `user_prompt_submit.json`.
- `maybe_prefetch_reranker_model`: if `bge-reranker-v2-m3` not present and
  `auto_recall.reranker_enabled`, spawn `clx model fetch --background`
  exactly once per process via `std::sync::Once` (`subagent.rs:42,63-86`).
  `clx` binary resolved next to the hook binary (`:89-106`).
- `build_recall_context`: gated by `auto_recall.enabled`, prompt present,
  prompt length >= `min_prompt_len` (`:112-148`). Runs `RecallEngine`
  (hexagonal ports) under `timeout_ms` (`:157-250`). Pinned recent
  sessions block prepended when configured, current session excluded
  (`:260-291`).
- Output: `output_generic("UserPromptSubmit", Some(ORCHESTRATOR_CONTEXT +
  "\n\n" + recall), None)`; recall portion is `redact_secrets`'d
  (`:45-52`). `ORCHESTRATOR_CONTEXT = "You are the Orchestrator. Delegate
  via Task tool. Check agent descriptions. Maximize parallelization."`
  (`:30`). On any recall error, only `ORCHESTRATOR_CONTEXT` is emitted.

**Stop** — fixture none (event delivered via Stop hook command). Opt-in:
gated by `memory.auto_summarize.enabled` (default FALSE,
`stop_auto_summary.rs:62-66`; default asserted
`stop_auto_summary.rs:277-284`). Whole handler wrapped in a 10s
`HANDLER_TIMEOUT` (`:39,53`). Logic: count assistant turns since last
`AutoSummary` snapshot; skip if `< every_n_turns` (default 5,
clamped >=1); skip if `skip_when_idle` and no mutator activity; read
trailing `2*every_n_turns` turns (min 2) from transcript; summarize via
LLM with deterministic fallback; persist `AutoSummary` snapshot via
`create_snapshot_if_no_recent_auto_summary` (atomic TOCTOU-safe
duplicate guard, `:133-163`). All error paths -> Ok.

### 3.3 Contract test fixtures + router_smoke

7 fixtures: pre_tool_use, post_tool_use, user_prompt_submit,
subagent_start, stop, session_start, pre_compact
(`tests/fixtures/hook_envelopes/*.json`). Sanitized: zeroed session ids,
`/tmp/test-project` cwd.

`tests/router_smoke.rs` has **14 `#[test]` functions** (verified by
`grep -c`):
- 7 parse-side (`parse_*_fixture`): each parses the fixture to
  `serde_json::Value`, redacts session_id/tool_use_id/transcript_path/
  timestamps, and `insta::assert_debug_snapshot!`s. This locks the
  upstream envelope schema; any new/renamed field fails loudly
  (`router_smoke.rs:77-100, 134-167`).
- 7 emit-side (`emit_*_smoke`): drive the fixture through the real
  `clx-hook` binary with isolated `HOME`, assert stdout is empty OR a
  valid JSON object whose `hookSpecificOutput.hookEventName` equals the
  expected event OR `"PreToolUse"` (fallback) (`:108-128, 174-207`).

### 3.4 MCP server (`server.rs`)

JSON-RPC 2.0 over stdin/stdout, one message per line, `MAX_LINE_SIZE =
10 MiB` (`server.rs:358`). `read_bounded_line` returns a `PARSE_ERROR`
response if a line exceeds the cap, consuming the rest of the line
(`:364-410, 423-435`). Non-2.0 jsonrpc -> `INVALID_REQUEST` (`:314-320`).
Methods: `initialize` (protocolVersion `2024-11-05`, serverInfo
`clx-mcp`/`clx_core::VERSION`, `:262-276`), `initialized` (ack),
`tools/list` (`:279-283`), `tools/call` (`:286-310`),
`notifications/cancelled`, `ping`. Unknown method -> `METHOD_NOT_FOUND`
(`:347-352`). Notifications (no `id`) get no response unless an error
(`:462-467`). Debug logs run through `redact_secrets` (`:297,444,464`).

Error code constants (`protocol/types.rs:7-11`): PARSE_ERROR -32700,
INVALID_REQUEST -32600, METHOD_NOT_FOUND -32601, INVALID_PARAMS -32602,
INTERNAL_ERROR -32603. Tool methods return `Result<Value,(i32,String)>`;
errors become JSON-RPC `error` objects (`:335-338`).

Validation limits (`validation.rs:12-18`): `MAX_QUERY_LEN = 10_000`,
`MAX_CONTENT_LEN = 100_000`, `MAX_KEY_LEN = 1_000`. Over-limit ->
`INVALID_PARAMS` with `"exceeds max length of N (got M)"`. Missing
required string -> `INVALID_PARAMS` `"Missing or invalid parameter: X"`.

Per-tool:
- `clx_recall`: `query` (<=MAX_QUERY_LEN). Runs `RecallEngine` with a
  more permissive similarity threshold than auto-recall
  (`recall.rs:52-65`). Output: `{"content":[{"type":"text","text": "Found
  N results (search method: ...)\n\n<json>"}]}` or `"No relevant context
  found ..."`, fully `redact_secrets`'d (`recall.rs:104-127`).
- `clx_remember`: `text` (<=MAX_CONTENT_LEN), `tags` (<=50 of <=MAX_KEY_LEN).
  Creates session if missing, Manual snapshot, async embedding (5s
  timeout, non-fatal). Success text `"Successfully remembered information
  (snapshot id: N)"`; storage failure -> `INTERNAL_ERROR`
  (`remember.rs:17-86`).
- `clx_checkpoint`: `note?`. Checkpoint snapshot; embedding only if note
  given. Success `"Checkpoint created (id: N): <note>"`; failure
  `INTERNAL_ERROR` (`checkpoint.rs:14-56`).
- `clx_rules`: `action` enum get_project_rules/list/add/remove; failures
  -> `INTERNAL_ERROR`, bad args -> `INVALID_PARAMS` (`rules.rs:15-167`).
- `clx_session_info`: no args; returns db_path, session_id, project_path,
  started_at, status, message/command/snapshot counts, active sessions,
  rules count as pretty JSON text (`session_info.rs:11-70`).
- `clx_credentials`: `action` get/set/delete/list; per-op failure ->
  `INTERNAL_ERROR`, unknown action -> error tuple
  (`credentials.rs:16-138`).
- `clx_stats`: `days?` (validated i64 range); usage metrics
  (`stats.rs:11`).

Claude Code invokes these as `mcp__clx__clx_<tool>` once the MCP server
is registered and Claude Code restarted.

### 3.5 `clx install` (`install.rs:556-1162`)

Ordered steps (each idempotent; re-run is safe):

0. **Version-skew warning** — read `~/.clx/bin/.clx-version`; if
   `Mismatch{stamped,running}` print/queue "Version skew ..." warning
   (`:572-587`, `version_stamp_status :69-78`).
1. **Ollama prerequisites** — detect binary/server/models; optionally
   `brew install ollama`, start `ollama serve`, pull
   `default_ollama_model` + `default_embedding_model` (`:589-755`). Best
   effort; missing Ollama just disables L1.
2. **Directory tree** — create `~/.clx`, `bin`, `data`, `logs`, `rules`,
   `prompts`, `learned`, `docker`; existing dirs reported as Exists
   (`:757-780`). `chmod 0700` on `~/.clx` root (Unix, `:794-799`).
3. **Config scaffold** — if `config.yaml` absent: write
   `Config::default()` YAML. If present: `merge_missing_config_keys`
   ADDITIVELY adds only missing top-level keys, never clobbers user
   values; non-mapping config is left untouched
   (`:801-857`, `merge_missing_config_keys :149-182`).
4. `rules/default.yaml` via `ensure_default_rules_file` (`:859-869`).
5. Prompt templates `validator-{standard,high,low}.txt` + active
   `validator.txt` (standard) (`:871-908`).
6. **Binary copy** — `find_binary` then `install_binary` copies
   `clx`/`clx-hook`/`clx-mcp` to `~/.clx/bin`, `chmod 0755`
   (`:910-940`, `install_binary :294-317`). Then **write version stamp**
   `~/.clx/bin/.clx-version` = `CLX_VERSION\n` (`:942-959`).
7. **SQLite DB** — `Storage::open_default()` runs migrations
   (`:961-981`).
8. **settings.json** — ensure `~/.claude`; `read_claude_settings`;
   `settings["hooks"] = get_hooks_config()` (all 8 events incl Stop,
   `:1001-1010`); ensure `mcpServers` object and insert `clx` server
   (`:1012-1025`); `write_claude_settings` makes a `settings.json.backup`
   copy of the prior file before writing pretty JSON (`:330-348,
   :1027-1031`).
9. **6 skills** — `install_skills` writes embedded SKILL.md to
   `~/.claude/skills/<name>/SKILL.md`, overwriting on every run
   (`:103-113, :1033-1053`).
10. **CLAUDE.md injection** — append `# CLX Integration` section to
    `~/.claude/CLAUDE.md` only if marker absent (`:228-249, :1055-1089`).

Output: human summary or `--json` machine object (`:1092-1159`).

**Idempotency:** re-running detects existing dirs/config/skills, merges
config additively, overwrites binaries+skills+stamp, replaces the entire
`hooks` key (so duplicate hooks are impossible), re-inserts the single
`clx` MCP key, skips CLAUDE.md if marker present. Verified by
`install_then_uninstall_skills_roundtrip` and
`merge_*` tests (`install.rs:1428-1528`).

### 3.6 `clx uninstall` (`install.rs:1192-1362`)

Removes: the entire `hooks` key, the `clx` key from `mcpServers`
(deleting `mcpServers` if then empty) (`remove_clx_from_settings
:1165-1189`); writes `settings.json` with `.json.backup`. Removes the 6
CLX skills, but ONLY our `SKILL.md` / an empty dir — user-authored files
in a same-named dir survive (`uninstall_skills :118-144`, regression test
`:1453-1467`). Removes the version stamp (`:1266-1273`).

Preserves: `~/.clx/` (config, credentials, DB, logs) unless `--purge`.
With `--purge` + non-JSON, prompts y/N before `remove_dir_all`; `--json`
deletes without prompt (`:1275-1317`). Symmetric with install GAP-2/GAP-3.

### 3.7 Skills + plugin schema

`plugin.json` (2026 schema, `plugin/.claude-plugin/plugin.json`): top
keys `name`, `version` (`0.8.0`), `description`, `author`, `license`
(MPL-2.0), `homepage`, `skills` array of 6 `./skills/<name>` paths. Each
`skills/<name>/SKILL.md` has YAML frontmatter `name` (kebab-case,
matches dir) + `description` (a `>`-folded block that starts with
"Use when ..."). Verified: all 6 descriptions start with "Use when"
(read confirmed for all 6).

`validate.sh --strict` checks (`plugin/scripts/validate.sh`): plugin.json
valid JSON with name+version; each SKILL.md starts with `---`
frontmatter; name kebab-case <=64 chars matches parent dir; description
non-empty <=1024 chars; bidirectional orphan check (every manifest skill
exists on disk AND every on-disk skill is declared); `--strict`
additionally requires description to start with "Use when". Exit 0 with
`OK: ... 6 SKILL.md file(s) valid (strict=1).`

`migrate.sh` (`plugin/scripts/migrate.sh`): migrates 2025 layout
(`<root>/plugin.json` + `<root>/skills/using-clx/SKILL.md`) to 2026
(`<root>/.claude-plugin/...`). Archives originals to `.archive/2025`,
refuses mixed layouts (exit 2), supports `--dry-run`, `--yes`,
`--rollback`, `--root`. The legacy monolithic skill is archived, NOT
auto-converted; user must `clx install` for the 6 named skills (`:146-155`).

### 3.8 `scripts/install-local.sh`

Flow (`main :518-560`): preflight (assert CLX repo, read workspace
version from Cargo.toml without network, assert cargo, rustc minor >= 85,
prefix writable, platform check) -> `detect_shadowing` -> build (`cargo
build [--release]`) -> assert binaries exist -> `place_binaries` (copy 3
binaries to `--prefix`, chmod 0755) -> `run_clx_install` (invoke
`<prefix>/clx install`, the brew-identical path) -> `verify_installation`
-> next steps.

Flags (`:101-136`): `--prefix <dir>` (default `${HOME}/.local/bin`),
`--debug` (debug profile), `--skip-build`, `--yes`, `--uninstall`,
`-h/--help`.

`detect_shadowing` (`:225-254`): warns if a `clx` already on PATH would
shadow `<prefix>/clx`; warns if `~/.clx/bin/.clx-version` != the version
about to build (skew). `--uninstall` (`run_uninstall :427-461`) delegates
to `<prefix>/clx uninstall` then removes the 3 binaries it placed.

**6-point verification checklist** (`verify_installation :338-422`),
each prints `✓ ...` on pass:
1. `Version stamp matches <V>`
2. `<prefix>/clx --version == <V>`
3. `~/.clx/bin/clx-hook present`
4. `~/.claude/settings.json contains Stop hook`
5. `~/.claude/settings.json contains clx MCP server` (matches literal
   `clx-mcp` in command path)
6. `All 6 CLX skills present in ~/.claude/skills/`
Any FAIL -> non-zero exit with remediation hint. Brew-identical guarantee:
all wiring delegated to the same `clx install` code path the Homebrew
formula calls (`:6-9, 325-333`).

### 3.9 Dashboard TUI (`crates/clx/src/dashboard/*`)

Launch: `clx dashboard [--days N] [--refresh S]` (`main.rs:222`,
`dashboard/mod.rs:10-28`). Installs a panic hook that restores the
terminal, `ratatui::init()`, initial `refresh_data()`, `run_event_loop`.

Tabs (`DashboardTab`): Sessions / AuditLog / Rules / Settings
(`state.rs` references; nav `1`/`2`/`3`/`4`, Tab/BackTab cycle). Pure
reducer `update(AppState, DashboardEvent) -> (AppState,
Vec<DashboardCmd>)` (`state.rs:196-231`). `DashboardEvent` =
Key/Resize/Tick/Quit (`state.rs:135-144`). `DashboardCmd` = RefreshData,
EnterSessionDetail, LeaveSessionDetail, EnterSettings, SettingsSave,
SettingsReload, SettingsDiscardChanges, SettingsResetConfirmed,
ExecuteExitTarget, SettingsEditField, SettingsCommitEdit,
SettingsResetField, Quit (`state.rs:154-182`).

Runtime (`event.rs:28-89`): render -> poll crossterm with refresh-derived
timeout -> snapshot `App`->`AppState` -> `update` -> apply back -> execute
cmds -> quit on `should_quit`. Ctrl-C mapped to `DashboardEvent::Quit`
(`event.rs:46-51`). Tick triggers `refresh_data` when interval elapsed
(`:66-71`).

Key bindings (Normal, `state.rs:237-275`): `q`/Esc quit, Enter on
Sessions (count>0) -> session detail, Tab/BackTab cycle, `j/k`/arrows
scroll, PageUp/Down, `g`/Home top, `G`/End bottom, `r` refresh, `s` cycle
sort column, `S` toggle sort dir, `/` filter mode, `1-4` tab jump.
Session detail (`:281-306`): Esc/`q` leave, sub-tabs Info/Commands/Audit/
Snapshots (`1-4`). Settings nav (`:331-480`): dirty-exit guard prompt
(s=save+exit, x=discard+exit, Esc=cancel), reload/reset confirm dialogs,
`h/l` section nav, Space/Enter edit field, `s` save, `d` reset field,
`R` reset all (when dirty), `r` reload. Settings edit popup
(`:486-506`): Esc cancel, Enter commit, Backspace, Ctrl-U clear, chars
append.

What tabs show: Sessions = session list (sort col default 2 desc,
`state.rs:97-98`); AuditLog = audit entries; Rules = scrollable rules
view (offset-based); Settings = config field editor backed by
`settings::config_bridge` with validation on commit (`event.rs:292-311`).
Empty-DB behavior: pure reducer guards every list op on `*_count > 0`
(`state.rs:546-663`) so empty Sessions/Audit never panics; Enter on empty
Sessions is a no-op (`state.rs:243-247`, `event.rs:193-197`).

### 3.10 `clx maintenance trim` + `clx version`

`maintenance trim` (`maintenance.rs:35-115`): args `--tool-events-days`,
`--audit-days`, `--dry-run`. Defaults: tool_events from
`config.retention.tool_events_days`, audit default 90. `days = 0` skips
that sweep. `--dry-run` reports the would-delete tool_events count
(audit not estimated). Real run calls `cleanup_old_tool_events` /
`cleanup_old_audit_logs`, prints/`--json` reports deleted counts.

`clx version` (`version.rs:10-34`): prints `clx vX.Y.Z` + config dir, or
`--json` `{"version","name":"clx","description"}`. Note: human output
says `License: MIT` while plugin.json declares `MPL-2.0` (see RISKS).

---

## 4. Edge / Failure Matrix

| Scenario | Expected behavior | file:line |
|---|---|---|
| Hook run outside Claude Code (no provenance env) | WARN logged, processing continues (fail-safe) | `main.rs:79-86`, `router.rs:117-126` |
| Oversize hook input (> 1 MiB) | `PreToolUse` block JSON to writer, exit SUCCESS | `router.rs:213-224` |
| Malformed hook JSON | `ask` decision "Input parse error", exit SUCCESS | `router.rs:234-246` |
| Stdin read error | `allow` fallback, exit SUCCESS | `router.rs:225-229` |
| Unknown `hook_event_name` | WARN + `allow`, Ok | `router.rs:188-192` |
| Storage cannot open at startup | exit SUCCESS, no dispatch | `main.rs:56-58` |
| settings.json already has CLX entries (re-install) | `hooks` key fully replaced, single `clx` MCP key, no duplicates | `install.rs:1003,1017-1021` |
| Existing config.yaml | only missing top-level keys added, user values preserved | `install.rs:801-857` |
| Empty/scalar config.yaml | left untouched (no-op) | `install.rs:158-163`, test `:1523-1528` |
| Stale `~/.clx/bin` shadowing newer CLX | version-skew WARN at install + install-local | `install.rs:572-587`, `install-local.sh:244-254` |
| Plugin 2025 -> 2026 migration | move manifest, archive legacy skills, refuse mixed layout (exit 2) | `migrate.sh:109-158` |
| Skills missing after partial install | install_skills overwrites every run; install-local check #6 FAILs and exits non-zero | `install.rs:103-113`, `install-local.sh:399-412` |
| Dashboard with empty DB | reducer count guards prevent panic; Enter no-op on empty Sessions | `state.rs:546-663,243-247` |
| MCP tool oversize input | `INVALID_PARAMS` "exceeds max length"; >10 MiB line -> `PARSE_ERROR` | `validation.rs:33-44`, `server.rs:381-389` |
| MCP non-2.0 / unknown method | `INVALID_REQUEST` / `METHOD_NOT_FOUND` | `server.rs:314-320,347-352` |
| Install without write perms | `clx install` errors on first failed `create_dir_all`/copy; install-local preflight `assert_prefix_writable` errors early | `install.rs:772`, `install-local.sh:199-208` |
| Uninstall when never installed | "No CLX configuration found"/"settings.json not found"; clean Ok | `install.rs:1235-1246,1339-1340` |
| Transcript `/dev/zero` or > 64 MiB | rejected by `safe_transcript_path`, handlers return empty result (non-fatal) | `transcript.rs:21,37-50` |
| Ollama down during Stop/SessionEnd | LLM skipped, deterministic fallback summary, completes within timeout | `session_end.rs:52-59`, `stop_auto_summary.rs:39,53` |

---

## 5. Verification Steps (copy-pasteable)

```bash
cd /Users/blackax/Projects/clx

# A. Hook contract tests (14 tests in router_smoke)
cargo test -p clx-hook --test router_smoke
# Expect: 14 passed. 7 parse_* lock the envelope schema via insta;
# 7 emit_* drive the binary and assert empty-or-valid JSON with the
# right hookEventName.

# B. Install command unit tests (GAP-1/2/3/5)
cargo test -p clx --lib commands::install
# Expect: hooks_config_includes_all_eight_events_with_stop,
# stop_hook_uses_clx_hook_command, six_skills_embedded_*,
# install_then_uninstall_skills_roundtrip,
# uninstall_skills_preserves_user_authored_files,
# version_stamp_* , merge_* all pass.

# C. MCP validation limits
cargo test -p clx-mcp validation
# Expect: string/optional/i64/array bound tests pass.

# D. Plugin static validator (strict)
bash plugin/scripts/validate.sh --strict
# Expect exit 0, final line:
#   OK: <...>/plugin.json and 6 SKILL.md file(s) valid (strict=1).
bash plugin/scripts/tests/validate_test.sh   # validator self-tests

# E. Brew-free local install + 6-point checklist
bash scripts/install-local.sh --yes
# Expect 6 success lines:
#   ✓ Version stamp matches 0.8.0
#   ✓ <prefix>/clx --version == 0.8.0
#   ✓ ~/.clx/bin/clx-hook present
#   ✓ ~/.claude/settings.json contains Stop hook
#   ✓ ~/.claude/settings.json contains clx MCP server
#   ✓ All 6 CLX skills present in ~/.claude/skills/
#   ✓ All checks passed.

# F. Verify all 8 hooks + Stop registered
python3 -c "import json;h=json.load(open('$HOME/.claude/settings.json'))['hooks'];print(sorted(h));assert len(h)==8 and 'Stop' in h"

# G. Verify MCP server registered
python3 -c "import json;m=json.load(open('$HOME/.claude/settings.json'))['mcpServers'];print(m['clx'])"

# H. Verify 6 skills installed
for s in clx-recall clx-remember clx-checkpoint clx-rules clx-resume clx-doctor; do test -f "$HOME/.claude/skills/$s/SKILL.md" && echo "ok $s"; done

# I. settings.json backup created
test -f "$HOME/.claude/settings.json.backup" && echo "backup present"

# J. Drive the dashboard (manual): launch, press 2 (AuditLog), 3 (Rules),
#    4 (Settings), 1 (Sessions), q to quit. Verify tab header changes and
#    no panic on an empty DB.
clx dashboard --refresh 2

# K. Idempotent re-install (no duplicates)
clx install --json | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['success'])"
python3 -c "import json;h=json.load(open('$HOME/.claude/settings.json'))['hooks'];assert len(h)==8"

# L. Symmetric uninstall (preserves ~/.clx)
clx uninstall --json | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['removed'])"
python3 -c "import json;s=json.load(open('$HOME/.claude/settings.json'));assert 'hooks' not in s and 'clx' not in s.get('mcpServers',{})"
test -d "$HOME/.clx" && echo "~/.clx preserved (config/DB/creds intact)"
test ! -f "$HOME/.clx/bin/.clx-version" && echo "version stamp removed"
for s in clx-recall clx-remember clx-checkpoint clx-rules clx-resume clx-doctor; do test ! -e "$HOME/.claude/skills/$s/SKILL.md" && echo "removed $s"; done

# M. Dashboard reducer purity (no terminal needed)
cargo test -p clx --lib dashboard::state

# N. maintenance trim dry-run
clx maintenance trim --dry-run --json
```

---

## 6. Known Limitations / Out of Scope for 0.8.0

- **Homebrew formula** lives in a separate tap repo; this spec only
  guarantees `scripts/install-local.sh` reproduces the brew end state via
  the shared `clx install` path (`install-local.sh:6-9,325-333`). The
  formula itself is not validated here.
- **Reranker model lazy**: `bge-reranker-v2-m3` (~568 MB) is fetched
  on-demand on the first UserPromptSubmit; until ready, recall is
  RRF-only (`subagent.rs:63-86`). Not an error state.
- **`output::*` still uses `println!`** on process stdout; the
  `handle_event` `writer` parameter is only wired for the oversize/read
  fallback (`router.rs:16-20,204-205`). Contract tests therefore drive
  the real binary for emit-side checks rather than an in-memory writer.
- **stop.json fixture naming**: file is `stop.json` but its
  `hook_event_name` is `SessionEnd`; there is no dedicated `Stop`-event
  fixture. The Stop handler (`handle_stop_auto_summary`) is exercised by
  unit tests in `stop_auto_summary.rs`, not by router_smoke.
- Flaky `llm::fallback` test is acknowledged out of scope for the
  integration surface (lives in clx-core).

---

## RISKS / SUSPECTED GAPS

1. **License inconsistency.** `clx version` human output prints
   `License: MIT` (`crates/clx/src/commands/version.rs:31`) while
   `plugin/.claude-plugin/plugin.json:7` declares `"license": "MPL-2.0"`.
   One is wrong; QA should confirm the canonical license before tagging.

2. **No `Stop`-event contract fixture.** The Stop hook is the only one of
   the 8 registered events with no router_smoke parse/emit fixture
   (`tests/fixtures/hook_envelopes/` has 7 files; stop.json is SessionEnd,
   `router_smoke.rs:195-197`). Schema drift in the real Stop envelope
   would not be caught by the contract suite. Coverage gap, not a bug.

3. **Provenance is forgeable by design.** `classify_provenance` trusts
   inherited env vars a same-uid attacker can set
   (`router.rs:80-126`). This is documented as defense-in-depth, but a
   piped fabricated `Stop`/`PostToolUse` envelope CAN poison CLX memory /
   audit state. Accepted residual risk per threat model; flagged so QA
   does not treat it as a regression.

4. **`clx install` partial-failure is non-transactional.** Steps run
   sequentially; a mid-run failure (e.g. `fs::create_dir_all` at
   `install.rs:772` returns `?`) aborts AFTER earlier mutations
   (settings backup, partial binary copy) with no rollback. Re-run is
   safe (idempotent) but the intermediate state is observable. Verify
   re-run recovers cleanly under simulated mid-run failure.

5. **`maintenance trim` audit default hard-coded to 90.** `au_days =
   audit_days.unwrap_or(90)` (`maintenance.rs:56`) ignores any
   `config.retention.audit_*` setting (unlike tool_events which reads
   config). If such a config key exists it is silently bypassed. Confirm
   intended.

6. **install-local.sh check #5 substring match.** It greps the literal
   `clx-mcp` anywhere in settings.json (`install-local.sh:392`). A user
   whose unrelated MCP server path contains `clx-mcp` would false-pass.
   Low risk, but the check is weaker than a JSON-key assertion.
