//! Pattern matching for policy rules.
//!
//! Supports glob-style patterns with `*` wildcards and the canonical
//! `ToolName(command:args)` rule format (host-neutral; tool names are
//! mapped to their canonical form per host before matching).

/// Parse a pattern in the format `ToolName(command_pattern)`
///
/// Returns (`tool_name`, `command_pattern`) or None if parsing fails.
///
/// # Security invariant (R-B1-4 / B3-2)
///
/// The closing `)` **must** be the last non-whitespace character of the
/// string.  Patterns with trailing non-whitespace (e.g. `Bash(*)x`) are
/// rejected rather than silently trimmed.  Without this check, `rfind(')')`
/// would find the inner `)` and return `Some(("Bash", "*"))` for the pattern
/// `Bash(*)x`, causing the `PolicyEngine` to evaluate it as a wildcard allow
/// rule that matches every Bash command.
#[must_use]
pub fn parse_pattern(pattern: &str) -> Option<(String, String)> {
    // Find the opening parenthesis
    let paren_start = pattern.find('(')?;

    // Find the closing parenthesis using rfind so nested parens in the
    // command body (e.g. fork-bomb patterns) still parse correctly.
    let paren_end = pattern.rfind(')')?;

    // Ensure valid structure: opening must precede closing.
    if paren_end <= paren_start {
        return None;
    }

    // Security: reject patterns where non-whitespace characters follow the
    // closing `)`.  Trailing whitespace is harmless; trailing text is not.
    let after_paren = &pattern[paren_end + 1..];
    if !after_paren.trim().is_empty() {
        return None;
    }

    let tool_name = &pattern[..paren_start];
    let command_pattern = &pattern[paren_start + 1..paren_end];

    Some((tool_name.to_string(), command_pattern.to_string()))
}

/// Convert a learned pattern to the canonical `ToolName(command:args)` pattern
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

/// Returns `true` if `raw` (a learned/added rule pattern, pre-conversion)
/// is an **overbroad allow** — i.e. it would whitelist arbitrary commands
/// (B1-4 / B3-2). A pattern is overbroad when, after unwrapping an
/// optional `Tool(...)` shell and normalising `:`/whitespace, nothing but
/// `*` wildcards remains (the empty string, `*`, `**`, `Bash(*)`,
/// `Bash( * )`, `Bash(**)`). Scoped patterns that retain any literal (e.g.
/// `Bash(git status)`, `git:status*`, `Bash(npm *)`) are NOT overbroad —
/// this is deliberately conservative to avoid rejecting legitimate
/// per-project allow rules. Only ever used to gate `Allow`/whitelist
/// rules; `Deny` rules are never restricted.
#[must_use]
pub fn is_overbroad_allow_pattern(raw: &str) -> bool {
    let trimmed = raw.trim();
    // Unwrap a single `Tool(...)` wrapper if present.
    let inner = match (trimmed.find('('), trimmed.ends_with(')')) {
        (Some(open), true) => &trimmed[open + 1..trimmed.len() - 1],
        _ => trimmed,
    };
    // Normalise the command:args separator to whitespace, then strip all
    // wildcards and whitespace. If nothing literal remains, the pattern
    // matches everything.
    inner
        .replace(':', " ")
        .chars()
        .all(|c| c == '*' || c.is_whitespace())
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
