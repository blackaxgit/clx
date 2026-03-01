//! Output and display types for CLI commands.

/// JSON output structure for rules list
#[derive(serde::Serialize)]
pub struct RulesOutput {
    pub builtin_whitelist: Vec<RuleInfo>,
    pub builtin_blacklist: Vec<RuleInfo>,
    pub learned: Vec<LearnedRuleInfo>,
    pub config_whitelist: Vec<RuleInfo>,
    pub config_blacklist: Vec<RuleInfo>,
}

#[derive(serde::Serialize)]
pub struct RuleInfo {
    pub pattern: String,
    pub description: Option<String>,
}

#[derive(serde::Serialize)]
pub struct LearnedRuleInfo {
    pub pattern: String,
    pub rule_type: String,
    pub confirmation_count: i32,
    pub denial_count: i32,
    pub project_path: Option<String>,
}

/// JSON output structure for recall command
#[derive(serde::Serialize)]
pub struct RecallOutput {
    pub query: String,
    pub results: Vec<RecallResult>,
}

#[derive(serde::Serialize)]
pub struct RecallResult {
    pub session_id: String,
    pub content: String,
    pub timestamp: String,
    pub distance: f32, // Lower distance = more similar
}

/// JSON output structure for credentials list
#[derive(serde::Serialize)]
pub struct CredentialsListOutput {
    pub credentials: Vec<String>,
}

/// Safely truncate a string to `max_len` bytes, appending "..." if truncated.
/// Uses char boundaries to avoid panicking on multi-byte UTF-8.
pub fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    if max_len < 4 {
        return s.chars().take(max_len).collect();
    }
    let target = max_len - 3;
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= target)
        .last()
        .unwrap_or(0);
    format!("{}...", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_str_max_len_zero() {
        assert_eq!(truncate_str("hello", 0), "");
    }

    #[test]
    fn test_truncate_str_max_len_one() {
        assert_eq!(truncate_str("hello", 1), "h");
    }

    #[test]
    fn test_truncate_str_max_len_two() {
        assert_eq!(truncate_str("hello", 2), "he");
    }

    #[test]
    fn test_truncate_str_max_len_three() {
        assert_eq!(truncate_str("hello", 3), "hel");
    }

    #[test]
    fn test_truncate_str_max_len_four() {
        // max_len=4, string="hello" (len 5) => "h..."
        assert_eq!(truncate_str("hello", 4), "h...");
    }

    #[test]
    fn test_truncate_str_no_truncation() {
        assert_eq!(truncate_str("hi", 10), "hi");
    }

    #[test]
    fn test_truncate_str_exact_fit() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_str_empty() {
        assert_eq!(truncate_str("", 10), "");
    }

    #[test]
    fn test_truncate_str_utf8_emoji() {
        // Each emoji is 4 bytes. "😀😁😂😃😄" = 20 bytes, 5 chars
        let input = "😀😁😂😃😄";
        // max_len=3 (< 4), should take 3 chars without "..."
        let result = truncate_str(input, 3);
        assert_eq!(result, "😀😁😂");
    }

    #[test]
    fn test_truncate_str_utf8_with_ellipsis() {
        // max_len=7 (>= 4), "😀😁😂😃😄" is 20 bytes
        // target = 7-3 = 4 bytes; first emoji is 4 bytes, so "😀..."
        let input = "😀😁😂😃😄";
        let result = truncate_str(input, 7);
        assert_eq!(result, "😀...");
    }
}
