//! Depth e2e for `clx_remember` / `clx_rules` / `clx_credentials`.
//!
//! Companion to `mcp_protocol_e2e.rs`. That suite locks the protocol
//! envelope and the per-tool happy/oversize smoke; this one drives the
//! *branch* depth those three tools' coverage misses: every `clx_rules`
//! and `clx_credentials` action arm (including the actionable
//! not-found / invalid-action messages), the `clx_remember` tags-in-summary
//! success path and its no-embedding warn branch, plus the file-backend
//! credential round-trip and value masking.
//!
//! Hermeticity contract (stricter than the sibling suite, which only sets
//! `CLX_DB_PATH=:memory:`): every spawned `clx-mcp` child also gets an
//! isolated RAII `HOME` (`tempfile::TempDir`, `mkdtemp(3)` unique name,
//! removed on `Drop` even on panic) and `CLX_CREDENTIALS_BACKEND=file`.
//! `AgeFileBackend::new()` resolves its `credentials.age` under
//! `paths::clx_dir()` == `$HOME/.clx`, so the redirected `HOME` fully
//! sandboxes the credential file: zero real keychain, zero network, zero
//! model download, no `~/.clx` pollution. The DB stays `:memory:` so the
//! snapshot/rule rows never touch disk.

// e2e: prose references protocol identifiers; json! builders take owned args.
#![allow(clippy::doc_markdown, clippy::needless_pass_by_value)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const INVALID_PARAMS: i64 = -32602;

/// Mirrors `clx-mcp::validation::MAX_CONTENT_LEN` (crate is a binary, not a
/// lib, so the constant cannot be imported — kept in lockstep by the
/// oversize tests in `mcp_protocol_e2e.rs`).
const MAX_CONTENT_LEN: usize = 100_000;

/// Upper bound for the isolated `HOME` footprint. A hermetic MCP run writes
/// only a tiny age credential file plus its lockfile; well under a MiB.
/// 50 MiB is ~40x below a single real model artifact, so a regression that
/// re-enables a download trips this instantly.
const MAX_HOME_BYTES: u64 = 50 * 1024 * 1024;

/// RAII isolated `HOME`. The `TempDir` must outlive every child spawned
/// against it; its `Drop` removes the dir recursively, including on
/// panic/unwind. `mkdtemp` guarantees a unique name (no PID reuse), so
/// parallel tests never collide.
struct HermeticHome {
    _tmp: tempfile::TempDir,
    home: std::path::PathBuf,
}

impl HermeticHome {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("clx-mcp-depth-")
            .tempdir()
            .expect("create isolated temp HOME");
        // Canonicalize so `$HOME` matches what `std::fs::canonicalize`
        // returns for paths *under* it. On macOS the system temp dir lives
        // under `/var`, a symlink to `/private/var`; without this, the
        // `clx_rules get_project_rules` path-traversal guard (which
        // canonicalizes `cwd` but compares against the raw `dirs::home_dir()`
        // == `$HOME`) would reject every in-sandbox project path.
        let home = tmp
            .path()
            .canonicalize()
            .unwrap_or_else(|_| tmp.path().to_path_buf());
        Self { _tmp: tmp, home }
    }

    /// Spawn `clx-mcp` with an in-memory DB, the isolated `HOME`, and the
    /// file credential backend forced. Pipes `input` (newline-delimited
    /// JSON-RPC) on stdin and returns `(stdout, stderr)`.
    fn run_mcp(&self, input: &str) -> (String, String) {
        let binary = env!("CARGO_BIN_EXE_clx-mcp");
        let mut child = Command::new(binary)
            .env("CLX_DB_PATH", ":memory:")
            .env("HOME", &self.home)
            .env("CLX_LOG", "error")
            .env("CLX_MODEL_FETCH_DRYRUN", "1")
            .env("CLX_CREDENTIALS_BACKEND", "file")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn clx-mcp");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).expect("write stdin");
        }
        let output = child.wait_with_output().expect("wait clx-mcp");
        assert_home_size_bounded(&self.home);
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }
}

/// Recursively sum regular-file bytes under `root`.
fn dir_size_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file()
                && let Ok(meta) = entry.metadata()
            {
                total += meta.len();
            }
        }
    }
    total
}

/// Loud regression guard: the isolated `HOME` must stay tiny (no model
/// download leaked into the throwaway dir).
fn assert_home_size_bounded(home: &Path) {
    let total = dir_size_bytes(home);
    assert!(
        total < MAX_HOME_BYTES,
        "isolated test HOME at {} grew to {total} bytes (limit {MAX_HOME_BYTES}); \
         a model download likely leaked into the throwaway HOME",
        home.display(),
    );
}

fn parse(line: &str) -> serde_json::Value {
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("invalid JSON-RPC line: {e}\nline: {line}"))
}

fn assert_envelope(v: &serde_json::Value) {
    assert_eq!(v["jsonrpc"], "2.0", "jsonrpc must be 2.0: {v}");
    let has_result = v.get("result").is_some();
    let has_error = v.get("error").is_some();
    assert!(
        has_result ^ has_error,
        "exactly one of result/error required: {v}"
    );
}

fn req(id: i64, method: &str, params: serde_json::Value) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string()
}

fn tool_call(id: i64, name: &str, arguments: serde_json::Value) -> String {
    req(
        id,
        "tools/call",
        serde_json::json!({ "name": name, "arguments": arguments }),
    )
}

/// Extract the `result.content[0].text` string from a successful tool call.
fn result_text(v: &serde_json::Value) -> String {
    v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected result text, got: {v}"))
        .to_string()
}

/// Drive `initialize` then a single `tools/call`; return the call response.
fn call_once(home: &HermeticHome, name: &str, args: serde_json::Value) -> serde_json::Value {
    let input = format!(
        "{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        tool_call(2, name, args),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "expected >=2 response lines, got {lines:?}; stderr: {stderr}"
    );
    parse(lines[1])
}

// ===========================================================================
// clx_remember: tags-in-summary success + no-embedding warn branch
// ===========================================================================

/// Success: a valid `text` with `tags` returns a "Successfully remembered"
/// message carrying a numeric snapshot id (the `Ok(id)` arm). With no
/// Ollama client configured in the hermetic env, `store_embedding_for_snapshot`
/// takes its early `(None, _) => false` branch and the tool still succeeds
/// (the "continuing without embedding" warn path).
#[test]
fn remember_with_tags_succeeds_without_embedding_and_returns_snapshot_id() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_remember",
        serde_json::json!({"text":"use conventional commits","tags":["policy","commits"]}),
    );
    assert_envelope(&v);
    let text = result_text(&v);
    assert!(
        text.contains("Successfully remembered information (snapshot id:"),
        "remember must report the persisted snapshot id: {text}"
    );
    // The numeric id must parse: proves we hit the storage Ok(id) arm, not a
    // canned string.
    let id_part = text
        .rsplit("snapshot id:")
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches(')')
        .trim();
    assert!(
        id_part.parse::<i64>().is_ok(),
        "snapshot id must be numeric, got {id_part:?} in {text}"
    );
}

/// Success with no tags: exercises the `tags.is_empty()` arm of the summary
/// builder (the `String::new()` branch, distinct from the joined-tags
/// branch above).
#[test]
fn remember_without_tags_uses_empty_tag_suffix_branch() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_remember",
        serde_json::json!({"text":"a durable fact with no tags"}),
    );
    assert_envelope(&v);
    assert!(result_text(&v).contains("Successfully remembered"));
}

// ===========================================================================
// clx_rules: every action arm + invalid-action / invalid-rule_type errors
// ===========================================================================

/// `add` (whitelist -> Allow) then `list` shows the rule, then `remove`
/// deletes it: drives the `add` Ok arm, the populated-`list` pretty-print
/// arm (not the "No rules configured" empty arm), and the `remove` Ok arm,
/// all in one process so the in-memory DB carries state across calls.
#[test]
fn rules_add_list_remove_full_lifecycle() {
    let home = HermeticHome::new();
    let input = format!(
        "{}\n{}\n{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        tool_call(
            2,
            "clx_rules",
            serde_json::json!({"action":"add","pattern":"git status","rule_type":"whitelist"})
        ),
        tool_call(3, "clx_rules", serde_json::json!({"action":"list"})),
        tool_call(
            4,
            "clx_rules",
            serde_json::json!({"action":"remove","pattern":"git status"})
        ),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 4, "expected 4 lines: {lines:?}; {stderr}");

    let add = parse(lines[1]);
    assert_envelope(&add);
    // The confirmation echoes `rule_type.as_str()` ("allow"/"deny"), the
    // canonical RuleType label, NOT the request word ("whitelist").
    assert!(
        result_text(&add).contains("Added allow rule for pattern: git status"),
        "add arm must confirm the (allow) rule: {add}"
    );

    let list = parse(lines[2]);
    assert_envelope(&list);
    let list_text = result_text(&list);
    // `list` serializes `rule_type.as_str()` -> "allow" (canonical label).
    assert!(
        list_text.contains("git status") && list_text.contains("\"allow\""),
        "populated list must pretty-print the added rule: {list_text}"
    );
    assert!(
        !list_text.contains("No rules configured"),
        "populated list must not take the empty arm: {list_text}"
    );

    let remove = parse(lines[3]);
    assert_envelope(&remove);
    assert!(
        result_text(&remove).contains("Removed rule for pattern: git status"),
        "remove arm must confirm deletion: {remove}"
    );
}

/// `add` with `rule_type = "blacklist"` maps to `RuleType::Deny` (the
/// second match arm, distinct from the whitelist arm above).
#[test]
fn rules_add_blacklist_maps_to_deny() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_rules",
        serde_json::json!({"action":"add","pattern":"rm -rf /","rule_type":"blacklist"}),
    );
    assert_envelope(&v);
    // `blacklist` maps to RuleType::Deny; the confirmation echoes the
    // canonical label "deny" (not the request word "blacklist").
    assert!(
        result_text(&v).contains("Added deny rule for pattern: rm -rf /"),
        "blacklist must map to a deny rule: {v}"
    );
}

/// `add` with an unrecognized `rule_type` takes the `_ =>` INVALID_PARAMS
/// arm with the actionable "Must be 'whitelist' or 'blacklist'" message.
#[test]
fn rules_add_invalid_rule_type_is_invalid_params() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_rules",
        serde_json::json!({"action":"add","pattern":"x","rule_type":"greylist"}),
    );
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Must be 'whitelist' or 'blacklist'"),
        "invalid rule_type must be actionable: {v}"
    );
}

/// An unknown `action` takes the trailing `_ =>` INVALID_PARAMS arm whose
/// message enumerates the valid actions.
#[test]
fn rules_unknown_action_is_invalid_params_with_actionable_message() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_rules",
        serde_json::json!({"action":"frobnicate"}),
    );
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Must be 'get_project_rules', 'list', 'add', or 'remove'"),
        "unknown action message must list valid actions: {v}"
    );
}

/// `get_project_rules` with a `cwd` *outside* the home directory takes the
/// path-traversal guard -> INVALID_PARAMS "must be under home directory".
/// `/etc` can never be under the isolated temp `HOME`.
#[test]
fn rules_get_project_rules_outside_home_is_rejected() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_rules",
        serde_json::json!({"action":"get_project_rules","cwd":"/etc"}),
    );
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("must be under home directory"),
        "path-traversal guard must fire for a non-home cwd: {v}"
    );
}

/// `get_project_rules` with a `cwd` *under* the isolated HOME and a seeded
/// `CLAUDE.md` containing a `category`-matching section returns those rules
/// (the project-CLAUDE.md read + `extract_rules_by_category` success arm).
#[test]
fn rules_get_project_rules_extracts_category_section_from_project_claude_md() {
    let home = HermeticHome::new();
    let proj = home.home.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("CLAUDE.md"),
        "# Security\nNever commit secrets.\n\n# Style\nUse tabs.\n",
    )
    .unwrap();

    let v = call_once(
        &home,
        "clx_rules",
        serde_json::json!({
            "action":"get_project_rules",
            "cwd": proj.to_string_lossy(),
            "category":"security"
        }),
    );
    assert_envelope(&v);
    let text = result_text(&v);
    assert!(
        text.contains("Never commit secrets"),
        "category-filtered project rules must surface the matching section: {text}"
    );
    assert!(
        !text.contains("Use tabs"),
        "non-matching section must be filtered out: {text}"
    );
}

// ===========================================================================
// clx_credentials: file-backend round-trip + masking + not-found + invalid
// ===========================================================================

/// `set` then `get` against the file backend in one process: the `set` Ok
/// arm confirms storage, the `get` Ok(Some) arm returns the value MASKED
/// (never the plaintext). Drives the age-file backend success path with
/// zero keychain.
///
/// B3-1 fix: the mask is now a fixed-form `[REDACTED:<bracket>]` token —
/// no head/tail plaintext and no exact char count. "supersecret42" is 13
/// chars which falls in the "short" bracket (1–15).
#[test]
fn credentials_set_then_get_masks_value_via_file_backend() {
    let home = HermeticHome::new();
    let secret = "supersecret42"; // 13 chars -> "short" bracket
    let input = format!(
        "{}\n{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        tool_call(
            2,
            "clx_credentials",
            serde_json::json!({"action":"set","key":"DEPTH_API_KEY","value":secret})
        ),
        tool_call(
            3,
            "clx_credentials",
            serde_json::json!({"action":"get","key":"DEPTH_API_KEY"})
        ),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 3, "expected 3 lines: {lines:?}; {stderr}");

    let set_resp = parse(lines[1]);
    assert_envelope(&set_resp);
    assert!(
        result_text(&set_resp).contains("stored successfully"),
        "set must confirm storage: {set_resp}"
    );

    let get_resp = parse(lines[2]);
    assert_envelope(&get_resp);
    let get_text = result_text(&get_resp);
    // B3-1 fix: mask is a fixed-form token, no exact char count, no plaintext.
    assert!(
        get_text.contains("Value (masked):") && get_text.contains("[REDACTED:short]"),
        "get must return the fixed-form redacted token (B3-1 fix): {get_text}"
    );
    // No exact length leaked (pre-fix: "(13 chars)").
    assert!(
        !get_text.contains("(13 chars)"),
        "B3-1: exact char count must not appear in get response: {get_text}"
    );
    assert!(
        !get_text.contains(secret),
        "SECURITY: get must NEVER echo the plaintext credential: {get_text}"
    );
    // Plaintext must not leak to stderr logs either.
    assert!(
        !stderr.contains(secret),
        "credential plaintext leaked to stderr"
    );
    // age credential file must have materialized under the isolated HOME,
    // proving the file backend (not keychain) handled the write.
    assert!(
        home.home.join(".clx/credentials.age").exists(),
        "file backend must write credentials.age under the isolated HOME"
    );
}

/// `get` for a key that was never stored takes the `Ok(None)` arm: a
/// non-error envelope whose text is the actionable "Credential not found"
/// message and `isError: true`.
#[test]
fn credentials_get_missing_key_returns_actionable_not_found() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_credentials",
        serde_json::json!({"action":"get","key":"NEVER_SET_THIS"}),
    );
    assert_envelope(&v);
    let text = result_text(&v);
    assert!(
        text.contains("Credential not found: NEVER_SET_THIS"),
        "missing key must yield an actionable not-found message: {text}"
    );
    assert_eq!(
        v["result"]["isError"], true,
        "not-found result must set isError: {v}"
    );
}

/// `delete` on the file backend returns the deletion confirmation (the
/// `delete` Ok arm). Deleting a never-set key is still Ok (idempotent
/// backend delete), so this also covers the no-op branch of the backend.
#[test]
fn credentials_delete_returns_confirmation() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_credentials",
        serde_json::json!({"action":"delete","key":"DEPTH_GONE"}),
    );
    assert_envelope(&v);
    assert!(
        result_text(&v).contains("Credential deleted for key: DEPTH_GONE"),
        "delete arm must confirm deletion: {v}"
    );
}

/// `list` with a stored credential takes the non-empty pretty-print arm
/// (distinct from the "No credentials stored" empty arm covered by the
/// sibling suite's empty-DB list test).
#[test]
fn credentials_list_after_set_shows_key() {
    let home = HermeticHome::new();
    let input = format!(
        "{}\n{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        tool_call(
            2,
            "clx_credentials",
            serde_json::json!({"action":"set","key":"DEPTH_LISTED","value":"v1"})
        ),
        tool_call(3, "clx_credentials", serde_json::json!({"action":"list"})),
    );
    let (stdout, stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 3, "expected 3 lines: {lines:?}; {stderr}");
    let list = parse(lines[2]);
    assert_envelope(&list);
    let text = result_text(&list);
    assert!(
        text.contains("DEPTH_LISTED"),
        "populated list must show the stored key: {text}"
    );
    assert!(
        !text.contains("No credentials stored"),
        "populated list must not take the empty arm: {text}"
    );
}

/// `set` with a short value takes `mask_credential_value`'s fixed-form
/// `[REDACTED:short]` token when read back via `get`.
///
/// B3-1 fix: the old `**** (N chars)` form leaked the exact character count.
/// The new form uses a coarse bracket and leaks neither plaintext nor exact length.
#[test]
fn credentials_short_value_is_fully_masked() {
    let home = HermeticHome::new();
    let input = format!(
        "{}\n{}\n{}\n",
        req(1, "initialize", serde_json::json!({})),
        tool_call(
            2,
            "clx_credentials",
            serde_json::json!({"action":"set","key":"DEPTH_SHORT","value":"abc"})
        ),
        tool_call(
            3,
            "clx_credentials",
            serde_json::json!({"action":"get","key":"DEPTH_SHORT"})
        ),
    );
    let (stdout, _stderr) = home.run_mcp(&input);
    let lines: Vec<&str> = stdout.lines().collect();
    let get_text = result_text(&parse(lines[2]));
    // B3-1 fix: fixed-form token, no exact char count.
    assert!(
        get_text.contains("[REDACTED:short]"),
        "a short value must produce the fixed-form redacted token (B3-1 fix): {get_text}"
    );
    // No exact length (pre-fix: "**** (3 chars)").
    assert!(
        !get_text.contains("(3 chars)"),
        "B3-1: exact char count must not appear: {get_text}"
    );
    assert!(
        !get_text.contains("abc"),
        "short value plaintext must not appear: {get_text}"
    );
}

/// Unknown `action` takes the trailing `_ =>` INVALID_PARAMS arm with the
/// actionable "Must be 'get', 'set', 'delete', or 'list'" message.
#[test]
fn credentials_unknown_action_is_invalid_params_with_actionable_message() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_credentials",
        serde_json::json!({"action":"rotate"}),
    );
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Must be 'get', 'set', 'delete', or 'list'"),
        "unknown credential action must be actionable: {v}"
    );
}

/// `set` missing the required `value` param hits `validate_string_param`'s
/// missing-param branch -> INVALID_PARAMS (failure path for the set arm).
#[test]
fn credentials_set_missing_value_is_invalid_params() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_credentials",
        serde_json::json!({"action":"set","key":"DEPTH_NOVAL"}),
    );
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Missing or invalid parameter: value"),
        "missing value must name the offending param: {v}"
    );
}

/// `set` with an oversize `value` hits the length-cap branch of
/// `validate_string_param` -> INVALID_PARAMS "exceeds max length".
#[test]
fn credentials_set_oversize_value_is_invalid_params() {
    let home = HermeticHome::new();
    let v = call_once(
        &home,
        "clx_credentials",
        serde_json::json!({
            "action":"set",
            "key":"DEPTH_BIG",
            "value":"z".repeat(MAX_CONTENT_LEN + 1)
        }),
    );
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("exceeds max length"),
        "oversize credential value must be rejected: {v}"
    );
}
