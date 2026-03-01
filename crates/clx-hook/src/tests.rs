//! Tests for clx-hook modules.

#[cfg(test)]
use crate::embedding::{resolve_command_paths, truncate_to_char_boundary};
#[cfg(test)]
use crate::learning::{extract_command_pattern, is_pattern_too_broad, is_restricted_command};
#[cfg(test)]
use crate::output::RULES_REMINDER;
#[cfg(test)]
use crate::transcript::{build_transcript_text, parse_summary_response};
#[cfg(test)]
use crate::types::{
    HookGenericOutput, HookGenericSpecificOutput, HookOutput, HookSpecificOutput, TranscriptEntry,
    TranscriptMessage,
};

#[test]
fn test_extract_command_pattern_git() {
    assert_eq!(extract_command_pattern("git status"), "Bash(git:status*)");
    assert_eq!(
        extract_command_pattern("git log --oneline"),
        "Bash(git:log*)"
    );
    assert_eq!(extract_command_pattern("git"), "Bash(git:*)");
}

#[test]
fn test_extract_command_pattern_npm() {
    assert_eq!(extract_command_pattern("npm test"), "Bash(npm:test*)");
    assert_eq!(
        extract_command_pattern("npm install lodash"),
        "Bash(npm:install*)"
    );
}

#[test]
fn test_extract_command_pattern_rm() {
    assert_eq!(
        extract_command_pattern("rm -rf node_modules"),
        "Bash(rm:-rf *)"
    );
    assert_eq!(extract_command_pattern("rm file.txt"), "Bash(rm:*)");
}

#[test]
fn test_extract_command_pattern_other() {
    assert_eq!(extract_command_pattern("ls -la"), "Bash(ls:*)");
    assert_eq!(extract_command_pattern("cat file.txt"), "Bash(cat:*)");
}

#[test]
fn test_hook_output_serialization() {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "allow".to_string(),
            permission_decision_reason: None,
            additional_context: None,
        },
        system_message: None,
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("hookSpecificOutput"));
    assert!(json.contains("permissionDecision"));
    assert!(json.contains("allow"));
    // Optional fields should not appear when None
    assert!(!json.contains("additionalContext"));
    assert!(!json.contains("systemMessage"));
}

#[test]
fn test_hook_output_with_reason() {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "deny".to_string(),
            permission_decision_reason: Some("Dangerous command".to_string()),
            additional_context: None,
        },
        system_message: None,
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("permissionDecisionReason"));
    assert!(json.contains("Dangerous command"));
}

#[test]
fn test_hook_output_with_additional_context() {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "allow".to_string(),
            permission_decision_reason: None,
            additional_context: Some("RULES: Test context".to_string()),
        },
        system_message: None,
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("additionalContext"));
    assert!(json.contains("RULES: Test context"));
    assert!(!json.contains("systemMessage"));
}

#[test]
fn test_hook_output_with_system_message() {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "allow".to_string(),
            permission_decision_reason: None,
            additional_context: None,
        },
        system_message: Some("Session context here".to_string()),
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("systemMessage"));
    assert!(json.contains("Session context here"));
}

#[test]
fn test_generic_output_subagent_start() {
    let output = HookGenericOutput {
        hook_specific_output: HookGenericSpecificOutput {
            hook_event_name: "SubagentStart".to_string(),
            additional_context: Some("[SPECIALIST RULES] Execute task directly.".to_string()),
        },
        system_message: None,
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("hookSpecificOutput"));
    assert!(json.contains("\"hookEventName\":\"SubagentStart\""));
    assert!(json.contains("additionalContext"));
    assert!(json.contains("[SPECIALIST RULES]"));
    // Must NOT contain permission decision fields
    assert!(!json.contains("permissionDecision"));
    assert!(!json.contains("systemMessage"));
}

#[test]
fn test_generic_output_user_prompt_submit() {
    let output = HookGenericOutput {
        hook_specific_output: HookGenericSpecificOutput {
            hook_event_name: "UserPromptSubmit".to_string(),
            additional_context: Some("You are the Orchestrator.".to_string()),
        },
        system_message: None,
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("\"hookEventName\":\"UserPromptSubmit\""));
    assert!(json.contains("additionalContext"));
    assert!(json.contains("You are the Orchestrator."));
    assert!(!json.contains("permissionDecision"));
}

#[test]
fn test_generic_output_session_start_with_system_message() {
    let output = HookGenericOutput {
        hook_specific_output: HookGenericSpecificOutput {
            hook_event_name: "SessionStart".to_string(),
            additional_context: None,
        },
        system_message: Some("Previous session summary here".to_string()),
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("\"hookEventName\":\"SessionStart\""));
    assert!(json.contains("systemMessage"));
    assert!(json.contains("Previous session summary here"));
    assert!(!json.contains("additionalContext"));
}

#[test]
fn test_generic_output_skips_none_fields() {
    let output = HookGenericOutput {
        hook_specific_output: HookGenericSpecificOutput {
            hook_event_name: "SubagentStart".to_string(),
            additional_context: None,
        },
        system_message: None,
    };

    let json = serde_json::to_string(&output).unwrap();
    assert!(!json.contains("additionalContext"));
    assert!(!json.contains("systemMessage"));
}

#[test]
fn test_rules_reminder_content() {
    // Verify the RULES_REMINDER constant contains expected keywords
    assert!(RULES_REMINDER.contains("Delegate via Task tool"));
    assert!(RULES_REMINDER.contains("clx_recall"));
    assert!(RULES_REMINDER.contains("clx_rules"));
    assert!(RULES_REMINDER.contains("parallelization"));
}

#[test]
fn test_parse_summary_response() {
    let response = r#"{"summary": "Test summary", "key_facts": ["fact1"], "todos": ["todo1"]}"#;
    let parsed = parse_summary_response(response).unwrap();
    assert_eq!(parsed.summary, "Test summary");
    assert_eq!(parsed.key_facts.unwrap(), vec!["fact1"]);
    assert_eq!(parsed.todos.unwrap(), vec!["todo1"]);
}

#[test]
fn test_parse_summary_response_with_extra_text() {
    let response = r#"Here is the summary:
{"summary": "Test", "key_facts": null, "todos": null}
Done."#;
    let parsed = parse_summary_response(response).unwrap();
    assert_eq!(parsed.summary, "Test");
}

#[test]
fn test_build_transcript_text() {
    let entries = vec![
        TranscriptEntry {
            entry_type: Some("user".to_string()),
            message: Some(TranscriptMessage::String("Hello".to_string())),
            tool: None,
        },
        TranscriptEntry {
            entry_type: Some("assistant".to_string()),
            message: Some(TranscriptMessage::String("Hi there!".to_string())),
            tool: None,
        },
    ];

    let text = build_transcript_text(&entries);
    assert!(text.contains("[user]: Hello"));
    assert!(text.contains("[assistant]: Hi there!"));
}

// =========================================================================
// Security fix tests (redact_secrets tests are in clx_core::redaction)
// =========================================================================

#[test]
fn test_resolve_command_paths_no_paths() {
    let cmd = "git status";
    let resolved = resolve_command_paths(cmd);
    assert_eq!(resolved, "git status");
}

#[test]
fn test_resolve_command_paths_nonexistent_path() {
    // Non-existent paths should be left unchanged
    let cmd = "cat /nonexistent/path/to/file.txt";
    let resolved = resolve_command_paths(cmd);
    assert!(resolved.contains("/nonexistent/path/to/file.txt"));
}

#[test]
fn test_resolve_command_paths_existing_path() {
    // /tmp should exist and canonicalize to itself (or /private/tmp on macOS)
    let cmd = "ls /tmp";
    let resolved = resolve_command_paths(cmd);
    // On macOS /tmp -> /private/tmp, on Linux it stays /tmp
    assert!(resolved.starts_with("ls /"));
}

// =========================================================================
// UTF-8 safety tests
// =========================================================================

#[test]
fn test_truncate_to_char_boundary_ascii() {
    assert_eq!(truncate_to_char_boundary("hello world", 5), "hello");
    assert_eq!(truncate_to_char_boundary("hello", 10), "hello");
    assert_eq!(truncate_to_char_boundary("", 5), "");
}

#[test]
fn test_truncate_to_char_boundary_multibyte() {
    // Each emoji is 4 bytes; slicing at byte 5 would split a character
    let emoji_str = "\u{1F600}\u{1F601}\u{1F602}"; // 12 bytes total
    let truncated = truncate_to_char_boundary(emoji_str, 5);
    // Should truncate to the nearest char boundary <= 5, which is byte 4 (1 emoji)
    assert_eq!(truncated, "\u{1F600}");
}

#[test]
fn test_truncate_to_char_boundary_exact_boundary() {
    let s = "\u{1F600}abc"; // 4 + 3 = 7 bytes
    assert_eq!(truncate_to_char_boundary(s, 4), "\u{1F600}");
    assert_eq!(truncate_to_char_boundary(s, 5), "\u{1F600}a");
}

#[test]
fn test_build_transcript_text_multibyte_content() {
    // Ensure build_transcript_text does not panic on multi-byte content > 500 chars
    let long_content = "\u{1F600}".repeat(200); // 200 emojis = 800 bytes
    let entries = vec![TranscriptEntry {
        entry_type: Some("user".to_string()),
        message: Some(TranscriptMessage::String(long_content)),
        tool: None,
    }];
    // Should not panic
    let text = build_transcript_text(&entries);
    assert!(text.contains("[user]:"));
    assert!(text.contains("..."));
}

// =========================================================================
// Restricted command auto-whitelist tests (M25)
// =========================================================================

#[test]
fn test_is_restricted_command_destructive() {
    assert!(is_restricted_command("rm -rf /"));
    assert!(is_restricted_command("rm file.txt"));
    assert!(is_restricted_command("rmdir somedir"));
    assert!(is_restricted_command("dd if=/dev/zero of=/dev/sda"));
    assert!(is_restricted_command("chmod 777 /etc/passwd"));
    assert!(is_restricted_command("chown root:root /etc/shadow"));
    assert!(is_restricted_command("kill -9 1234"));
    assert!(is_restricted_command("killall nginx"));
    assert!(is_restricted_command("shutdown -h now"));
    assert!(is_restricted_command("reboot"));
    assert!(is_restricted_command("mount /dev/sda1 /mnt"));
    assert!(is_restricted_command("umount /mnt"));
    assert!(is_restricted_command("systemctl stop sshd"));
    assert!(is_restricted_command("iptables -F"));
}

#[test]
fn test_is_restricted_command_safe() {
    assert!(!is_restricted_command("git status"));
    assert!(!is_restricted_command("npm test"));
    assert!(!is_restricted_command("cargo build"));
    assert!(!is_restricted_command("ls -la"));
    assert!(!is_restricted_command("cat file.txt"));
    assert!(!is_restricted_command("echo hello"));
    assert!(!is_restricted_command("python script.py"));
}

#[test]
fn test_is_restricted_command_empty() {
    assert!(!is_restricted_command(""));
    assert!(!is_restricted_command("   "));
}

// =========================================================================
// Pattern structure validation tests (M25 - is_pattern_too_broad)
// =========================================================================

#[test]
fn test_pattern_too_broad_pipe() {
    assert!(is_pattern_too_broad("git status | grep main"));
    assert!(is_pattern_too_broad("ls | wc -l"));
    assert!(is_pattern_too_broad("echo hello | bash"));
}

#[test]
fn test_pattern_too_broad_chaining_operators() {
    assert!(is_pattern_too_broad("git status && echo done"));
    assert!(is_pattern_too_broad("test -f file || echo missing"));
    assert!(is_pattern_too_broad("echo one; echo two"));
    assert!(is_pattern_too_broad("git status; rm -rf /"));
}

#[test]
fn test_pattern_too_broad_output_redirection() {
    assert!(is_pattern_too_broad("echo secret > /etc/passwd"));
    assert!(is_pattern_too_broad("echo data >> logfile"));
    assert!(is_pattern_too_broad("cat file > output.txt"));
}

#[test]
fn test_pattern_too_broad_subshell_substitution() {
    assert!(is_pattern_too_broad("echo $(whoami)"));
    assert!(is_pattern_too_broad("echo `whoami`"));
    assert!(is_pattern_too_broad("diff <(sort a.txt) <(sort b.txt)"));
    assert!(is_pattern_too_broad("tee >(wc -l)"));
}

#[test]
fn test_pattern_too_broad_shell_execution() {
    assert!(is_pattern_too_broad("bash -c 'echo hello'"));
    assert!(is_pattern_too_broad("sh -c 'rm -rf /'"));
    assert!(is_pattern_too_broad("zsh script.sh"));
    assert!(is_pattern_too_broad("eval dangerous_command"));
    assert!(is_pattern_too_broad("exec /bin/sh"));
    assert!(is_pattern_too_broad("source ~/.bashrc"));
}

#[test]
fn test_pattern_too_broad_overly_broad_wildcards() {
    assert!(is_pattern_too_broad("*"));
    assert!(is_pattern_too_broad("* "));
    assert!(is_pattern_too_broad("* something"));
    assert!(is_pattern_too_broad(""));
    assert!(is_pattern_too_broad("   "));
}

#[test]
fn test_pattern_too_broad_legitimate_commands_pass() {
    // Common safe commands must NOT be flagged
    assert!(!is_pattern_too_broad("git status"));
    assert!(!is_pattern_too_broad("git log --oneline"));
    assert!(!is_pattern_too_broad("git diff HEAD~1"));
    assert!(!is_pattern_too_broad("cargo test"));
    assert!(!is_pattern_too_broad("cargo build --release"));
    assert!(!is_pattern_too_broad("cargo clippy -p clx-hook"));
    assert!(!is_pattern_too_broad("npm run build"));
    assert!(!is_pattern_too_broad("npm test"));
    assert!(!is_pattern_too_broad("npm install lodash"));
    assert!(!is_pattern_too_broad("ls -la"));
    assert!(!is_pattern_too_broad("cat file.txt"));
    assert!(!is_pattern_too_broad("python script.py"));
    assert!(!is_pattern_too_broad("go build ./..."));
    assert!(!is_pattern_too_broad("mkdir -p new_dir"));
}

#[test]
fn test_pattern_too_broad_shell_exec_not_substring() {
    // "sh" should only match as a standalone token, not as a substring
    assert!(!is_pattern_too_broad("git show HEAD"));
    assert!(!is_pattern_too_broad("git push origin main"));
    assert!(!is_pattern_too_broad("bashrc_check"));
    // But standalone "sh" and "bash" must be caught
    assert!(is_pattern_too_broad("sh script.sh"));
    assert!(is_pattern_too_broad("bash script.sh"));
}

#[test]
fn test_pattern_too_broad_social_engineering_attack() {
    // The motivating attack scenario from the task description
    assert!(is_pattern_too_broad("git status; echo harmless"));
    assert!(is_pattern_too_broad(
        "git status; echo \"malicious\" | bash"
    ));
}
