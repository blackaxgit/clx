//! P7: canonical tool-name adapter + learned-rule load-time migration.
//!
//! Two contracts are pinned here:
//!
//! 1. **Canonical tool names per host** - each host collapses its
//!    file-mutating tool(s) onto the shared `FileEdit` class and its shell
//!    tool onto `Bash`, so learned rules and L0 matching share one tool-name
//!    space across Claude / Codex / Cursor. Driven through the crate-public
//!    `clx_hook::testing` seam (the `Host` trait itself stays crate-private).
//! 2. **Downgrade-safe learned-rule migration** - a rule stored by an older,
//!    Claude-only CLX as `Edit(*)` must still fire after `load_learned_rules`
//!    rewrites it (in memory only) to the canonical `FileEdit(*)`. The stored
//!    row is never rewritten on disk.

use clx_core::policy::{PolicyDecision, PolicyEngine};
use clx_core::storage::Storage;
use clx_core::types::{LearnedRule, RuleType};

use clx_hook::testing;

// ---------------------------------------------------------------------------
// 1. Canonical tool names
// ---------------------------------------------------------------------------

#[test]
fn claude_file_mutators_canonicalize_to_file_edit() {
    for tool in ["Edit", "Write", "MultiEdit", "NotebookEdit"] {
        assert_eq!(
            testing::canonical_tool_name("claude", tool),
            "FileEdit",
            "Claude {tool} must canonicalize to FileEdit"
        );
    }
    // Bash keeps its canonical name; reads pass through unchanged.
    assert_eq!(testing::canonical_tool_name("claude", "Bash"), "Bash");
    assert_eq!(testing::canonical_tool_name("claude", "Read"), "Read");
}

#[test]
fn codex_apply_patch_canonicalizes_to_file_edit() {
    assert_eq!(
        testing::canonical_tool_name("codex", "apply_patch"),
        "FileEdit"
    );
    // Unknown / shell tools pass through (Bash already canonical).
    assert_eq!(testing::canonical_tool_name("codex", "Bash"), "Bash");
    assert_eq!(
        testing::canonical_tool_name("codex", "some_other"),
        "some_other"
    );
}

#[test]
fn cursor_edit_file_and_shell_canonicalize() {
    assert_eq!(
        testing::canonical_tool_name("cursor", "edit_file"),
        "FileEdit"
    );
    assert_eq!(
        testing::canonical_tool_name("cursor", "run_terminal_cmd"),
        "Bash"
    );
    assert_eq!(testing::canonical_tool_name("cursor", "Bash"), "Bash");
    assert_eq!(
        testing::canonical_tool_name("cursor", "read_file"),
        "read_file"
    );
}

#[test]
fn is_mutator_truth_table_per_host() {
    // (label, tool, expected_is_mutator)
    let cases: &[(&str, &str, bool)] = &[
        // Claude: the four text-mutators are mutators; Bash + reads are not.
        ("claude", "Edit", true),
        ("claude", "Write", true),
        ("claude", "MultiEdit", true),
        ("claude", "NotebookEdit", true),
        ("claude", "Bash", false),
        ("claude", "Read", false),
        ("claude", "apply_patch", false),
        // Codex: only apply_patch is a (text) mutator.
        ("codex", "apply_patch", true),
        ("codex", "Edit", false),
        ("codex", "Bash", false),
        // Cursor: only edit_file is a (text) mutator.
        ("cursor", "edit_file", true),
        ("cursor", "apply_patch", false),
        ("cursor", "run_terminal_cmd", false),
        ("cursor", "Bash", false),
    ];
    for (label, tool, expected) in cases {
        assert_eq!(
            testing::is_mutator_tool(label, tool),
            *expected,
            "is_mutator_tool({label}, {tool}) should be {expected}"
        );
    }
}

#[test]
fn adapter_covers_all_three_hosts() {
    assert_eq!(testing::host_labels().len(), 3);
    assert_eq!(testing::host_id_count(), 3);
}

// ---------------------------------------------------------------------------
// 2. Learned-rule load-time migration (downgrade-safe)
// ---------------------------------------------------------------------------

/// An existing Claude learned rule stored as `Edit(*)` must still fire after
/// `load_learned_rules` migrates it in memory to the canonical `FileEdit(*)`.
#[test]
fn legacy_edit_learned_rule_fires_under_canonical_name() {
    let storage = Storage::open_in_memory().expect("in-memory storage");
    // Older CLX stored a per-tool allow rule. Use a scoped pattern (not the
    // bare `Edit(*)` overbroad shell) so the load-time overbroad-allow gate
    // does not skip it; this is the realistic learned-rule shape.
    let rule = LearnedRule::new(
        "Edit(src/*)".to_string(),
        RuleType::Allow,
        "user_decision".to_string(),
    );
    storage.add_rule(&rule).expect("store legacy rule");

    let mut engine = PolicyEngine::new();
    // Before load: the canonical FileEdit tool is unknown -> Ask.
    assert_eq!(
        engine.evaluate("FileEdit", "src/foo.rs"),
        PolicyDecision::Ask {
            reason: "Unknown command, requires review".to_string()
        }
    );

    engine
        .load_learned_rules(&storage)
        .expect("load learned rules");

    // After load: the stored `Edit(src/*)` was migrated in memory to
    // `FileEdit(src/*)`, so evaluating the canonical tool name now allows.
    assert_eq!(
        engine.evaluate("FileEdit", "src/foo.rs"),
        PolicyDecision::Allow,
        "migrated Edit(src/*) rule must fire under canonical FileEdit"
    );

    // Downgrade-safe: the row on disk is untouched - still `Edit(src/*)`.
    let stored = storage.get_rules().expect("read back rules");
    assert!(
        stored.iter().any(|r| r.pattern == "Edit(src/*)"),
        "stored pattern must remain Edit(src/*) on disk (downgrade-safe); \
         got {:?}",
        stored.iter().map(|r| &r.pattern).collect::<Vec<_>>()
    );
}

/// A legacy `Write(*)` / `MultiEdit(*)` / `NotebookEdit(*)` rule also
/// canonicalizes to `FileEdit` at load time.
#[test]
fn all_legacy_file_mutator_rules_migrate() {
    for legacy in ["Write(out/*)", "MultiEdit(lib/*)", "NotebookEdit(nb/*)"] {
        let storage = Storage::open_in_memory().expect("in-memory storage");
        storage
            .add_rule(&LearnedRule::new(
                legacy.to_string(),
                RuleType::Allow,
                "user_decision".to_string(),
            ))
            .expect("store rule");

        let mut engine = PolicyEngine::new();
        engine
            .load_learned_rules(&storage)
            .expect("load learned rules");

        // The argument segment is preserved, so the matching path stays
        // scoped to the original prefix.
        let probe = match legacy {
            "Write(out/*)" => "out/x.txt",
            "MultiEdit(lib/*)" => "lib/y.rs",
            _ => "nb/z.ipynb",
        };
        assert_eq!(
            engine.evaluate("FileEdit", probe),
            PolicyDecision::Allow,
            "{legacy} should fire under canonical FileEdit for {probe}"
        );
    }
}

/// A stored `Bash(...)` rule is NOT touched by the migration: it still
/// matches under the `Bash` tool name and never becomes `FileEdit`.
#[test]
fn bash_learned_rule_is_unaffected_by_migration() {
    let storage = Storage::open_in_memory().expect("in-memory storage");
    storage
        .add_rule(&LearnedRule::new(
            "Bash(echo:*)".to_string(),
            RuleType::Allow,
            "user_decision".to_string(),
        ))
        .expect("store rule");

    let mut engine = PolicyEngine::new();
    engine
        .load_learned_rules(&storage)
        .expect("load learned rules");

    assert_eq!(engine.evaluate("Bash", "echo hi"), PolicyDecision::Allow);
    // It must NOT have leaked into the FileEdit space.
    assert_eq!(
        engine.evaluate("FileEdit", "echo hi"),
        PolicyDecision::Ask {
            reason: "Unknown command, requires review".to_string()
        }
    );
}
