//! Pattern matching for policy rules.
//!
//! Supports glob-style patterns with `*` wildcards and the
//! `ToolName(command:args)` format used by Claude Code.

/// Parse a pattern in the format `ToolName(command_pattern)`
///
/// Returns (`tool_name`, `command_pattern`) or None if parsing fails.
#[must_use]
pub fn parse_pattern(pattern: &str) -> Option<(String, String)> {
    // Find the opening parenthesis
    let paren_start = pattern.find('(')?;

    // Find the closing parenthesis
    let paren_end = pattern.rfind(')')?;

    // Ensure valid structure
    if paren_end <= paren_start {
        return None;
    }

    let tool_name = &pattern[..paren_start];
    let command_pattern = &pattern[paren_start + 1..paren_end];

    Some((tool_name.to_string(), command_pattern.to_string()))
}

/// Convert a learned pattern to Claude Code style pattern
///
/// Learned patterns may be stored in different formats, this normalizes them.
/// Accepts any `ToolName(...)` format (e.g., `Bash(git:*)`, `Write(path)`)
/// and wraps bare patterns in `Bash(...)`.
#[must_use]
pub fn convert_learned_pattern(pattern: &str) -> String {
    // If already in ToolName(...) format, return as-is
    if pattern.contains('(') && pattern.ends_with(')') {
        return pattern.to_string();
    }

    // Otherwise, wrap in Bash(...)
    format!("Bash({pattern})")
}

/// Simple glob pattern matching
///
/// Supports:
/// - `*` matches any sequence of characters
/// - Literal character matching
/// - Pattern in format `command:args` where `:` separates command from args
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    // Handle the special command:args format
    // Pattern like "git:status*" should match "git status --short"
    let normalized_pattern = pattern.replace(':', " ");
    let normalized_pattern = normalized_pattern.trim();

    glob_match_impl(normalized_pattern, text.trim())
}

/// Internal glob matching implementation
fn glob_match_impl(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    glob_match_recursive(&pattern_chars, 0, &text_chars, 0, 0)
}

/// Maximum recursion depth for glob matching to prevent ReDoS-style
/// exponential backtracking on adversarial patterns.
const GLOB_MAX_RECURSION_DEPTH: usize = 1000;

/// Recursive glob matching with a depth limit to prevent exponential
/// backtracking on adversarial patterns (e.g., "a*a*a*a*b" vs "aaaa...c").
fn glob_match_recursive(
    pattern: &[char],
    p_idx: usize,
    text: &[char],
    t_idx: usize,
    depth: usize,
) -> bool {
    // Safety limit: treat as no match if recursion is too deep
    if depth > GLOB_MAX_RECURSION_DEPTH {
        return false;
    }

    // Both exhausted - match
    if p_idx >= pattern.len() && t_idx >= text.len() {
        return true;
    }

    // Pattern exhausted but text remains - no match
    // (unless pattern ended with *)
    if p_idx >= pattern.len() {
        return false;
    }

    // Current pattern character
    let p_char = pattern[p_idx];

    // Handle wildcard
    if p_char == '*' {
        // Try matching * with zero characters
        if glob_match_recursive(pattern, p_idx + 1, text, t_idx, depth + 1) {
            return true;
        }

        // Try matching * with one or more characters
        if t_idx < text.len() && glob_match_recursive(pattern, p_idx, text, t_idx + 1, depth + 1) {
            return true;
        }

        return false;
    }

    // Text exhausted but pattern has more (non-wildcard) characters
    if t_idx >= text.len() {
        return false;
    }

    // Match literal character
    if p_char == text[t_idx] {
        return glob_match_recursive(pattern, p_idx + 1, text, t_idx + 1, depth + 1);
    }

    false
}
