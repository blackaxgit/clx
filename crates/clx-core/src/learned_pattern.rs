//! Pure detectors for the learned-rules pipeline (Issue 1).
//!
//! These functions decide whether a candidate learned pattern (or the raw
//! command it is derived from) is safe to persist into the `learned_rules`
//! table. They are deliberately pure and infallible so the same logic can be
//! reused by both the `clx-hook` learning path and the `clx-core` v9 migration
//! purge.
//!
//! Three primitives are provided:
//! - [`strip_env_assignments`] removes a leading `ENV=VALUE` run (quote-aware)
//!   so the secret-bearing value never reaches a stored pattern.
//! - [`pattern_contains_secret`] flags patterns that trip the shared secret
//!   redactor or a high-entropy fallback.
//! - [`is_well_formed_pattern`] gates the `Tool(body)` shape, rejecting shell
//!   metacharacters while deliberately allowing `*` (wildcards) and `/` (paths).

/// Strip a leading run of `ENV=VALUE` assignments from `cmd`, returning the
/// remainder of the *original* string (leading whitespace trimmed).
///
/// The scan is quote-aware: an assignment value may be unquoted, single-quoted,
/// or double-quoted and may contain spaces inside the quotes
/// (e.g. `SSHPASS='p w'`). Scanning stops at the first whitespace-separated
/// token that is not a valid assignment; the slice from that token onward is
/// returned. If every token is an assignment, `""` is returned.
///
/// A valid leading assignment token starts with an identifier matching
/// `^[A-Za-z_][A-Za-z0-9_]*` immediately followed by `=`. Tokens such as
/// `./path=x` are not assignments and leave the command unchanged.
#[must_use]
pub fn strip_env_assignments(cmd: &str) -> &str {
    let mut rest = cmd;
    loop {
        // Skip leading whitespace, remembering where the next token begins.
        let token_start_offset = rest.len() - rest.trim_start().len();
        let after_ws = &rest[token_start_offset..];
        if after_ws.is_empty() {
            // Only whitespace remained after a run of assignments.
            return after_ws;
        }

        match assignment_token_len(after_ws) {
            Some(len) => {
                // Advance past this assignment token; keep scanning for more.
                rest = &after_ws[len..];
            }
            None => {
                // First non-assignment token: this is the real command start.
                return after_ws;
            }
        }
    }
}

/// If `s` begins with a valid `IDENT=...` assignment token, return the byte
/// length of that token (including any quoted value, up to the next unquoted
/// whitespace). Otherwise return `None`.
fn assignment_token_len(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();

    // Identifier: ^[A-Za-z_][A-Za-z0-9_]*
    let first = *bytes.first()?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }

    // Must be immediately followed by '='.
    if bytes.get(i) != Some(&b'=') {
        return None;
    }
    i += 1; // consume '='

    // Consume the value, honoring single/double quotes (which may hold spaces).
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'\'' || c == b'"' {
                    quote = Some(c);
                } else if c.is_ascii_whitespace() {
                    break;
                }
            }
        }
        i += 1;
    }

    Some(i)
}

/// Minimum token length (in chars) for the high-entropy secret fallback.
const ENTROPY_MIN_LEN: usize = 20;

/// Minimum Shannon entropy (bits/char) for the high-entropy secret fallback.
const ENTROPY_MIN_BITS_PER_CHAR: f64 = 3.5;

/// Return `true` if `p` appears to contain a secret.
///
/// A pattern is considered secret-bearing when either:
/// - the shared [`crate::redaction::redact_secrets`] redactor changes it
///   (a known prefix/keyword secret shape), or
/// - it contains a whitespace-separated token of length `>= 20` whose Shannon
///   entropy is `>= 3.5` bits/char (a high-entropy fallback for opaque tokens
///   the keyword redactor does not recognize).
#[must_use]
pub fn pattern_contains_secret(p: &str) -> bool {
    if crate::redaction::redact_secrets(p) != p {
        return true;
    }
    p.split_whitespace().any(is_high_entropy_token)
}

/// High-entropy fallback: a long token whose per-char Shannon entropy is high
/// enough to look like an opaque credential rather than English/code.
fn is_high_entropy_token(token: &str) -> bool {
    if token.chars().count() < ENTROPY_MIN_LEN {
        return false;
    }
    shannon_entropy_bits_per_char(token) >= ENTROPY_MIN_BITS_PER_CHAR
}

/// Compute the Shannon entropy of `s` in bits per character.
fn shannon_entropy_bits_per_char(s: &str) -> f64 {
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let total_f = total as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        #[allow(clippy::cast_precision_loss)]
        let p = count as f64 / total_f;
        entropy -= p * p.log2();
    }
    entropy
}

/// Shell metacharacter sequences that make a pattern body malformed/over-broad.
///
/// Mirrors the reject-set used by `clx-hook`'s `is_pattern_too_broad`, with the
/// deliberate exception that `*` and `/` are NOT rejected here: legitimate
/// learned patterns use `*` for wildcards and `/` for paths.
const METACHAR_SEQUENCES: &[&str] = &[";", "&&", "||", "|", "$(", "`", "<(", ">(", ">>", ">"];

/// Return `true` if `p` is a well-formed `Tool(body)` pattern.
///
/// Requirements:
/// - There is a `(` and the last character is `)`.
/// - The tool segment (everything before the first `(`) matches
///   `^[A-Za-z0-9._-]+$`.
/// - The body (between the first `(` and the last `)`) contains none of the
///   shell metacharacters in [`METACHAR_SEQUENCES`].
///
/// `*` and `/` are explicitly allowed in the body so that legitimate wildcard
/// and path patterns (e.g. `FileEdit(*/x/*)`, `Bash(npm run build*)`) pass.
#[must_use]
pub fn is_well_formed_pattern(p: &str) -> bool {
    // Last char must be ')'.
    if !p.ends_with(')') {
        return false;
    }
    // There must be an opening '(' before the trailing ')'.
    let Some(open) = p.find('(') else {
        return false;
    };
    // The closing ')' we trust is the last char; its index:
    let close = p.len() - 1;
    if open >= close {
        return false;
    }

    let tool = &p[..open];
    if tool.is_empty() || !tool.bytes().all(is_tool_segment_byte) {
        return false;
    }

    let body = &p[open + 1..close];
    !METACHAR_SEQUENCES.iter().any(|m| body.contains(m))
}

/// Allowed bytes in a tool segment: `[A-Za-z0-9._-]`.
fn is_tool_segment_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("SSHPASS='p w' ssh host", "ssh host")]
    #[case("FOO=bar rm -rf /", "rm -rf /")]
    #[case("ls -la", "ls -la")]
    #[case("A=1 B=2 cmd", "cmd")]
    #[case("./path=x", "./path=x")]
    #[case("A=1", "")]
    #[case("VAR='a b' cmd arg", "cmd arg")]
    #[case("VAR=\"a b\" cmd", "cmd")]
    #[case("  FOO=bar baz", "baz")]
    #[case("", "")]
    fn strip_env_assignments_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(strip_env_assignments(input), expected);
    }

    #[rstest]
    // Secret-bearing: bearer token, sk- key, long high-entropy token.
    #[case("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789", true)]
    #[case("Bash(curl -H 'token: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345')", true)]
    #[case("deploy aGVsbG93b3JsZHNlY3JldHRva2VuMTIzNDU2Nzg5", true)]
    // Not secrets: ordinary patterns and benign keyword-first wildcards.
    #[case("Bash(ls:*)", false)]
    #[case("Bash(git:diff*)", false)]
    #[case("Bash(make build)", false)]
    #[case("ls -la", false)]
    fn pattern_contains_secret_cases(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(pattern_contains_secret(input), expected);
    }

    #[rstest]
    // Well-formed: '*' and '/' must be allowed.
    #[case("Bash(make build)", true)]
    #[case("Bash(npm run build:prod)", true)]
    #[case("FileEdit(*/x/*)", true)]
    #[case("Bash(npm run build*)", true)]
    #[case("Bash(ls:*)", true)]
    #[case("Bash(git:diff*)", true)]
    // Malformed: metachars / missing parens.
    #[case("Bash(a; b)", false)]
    #[case("Bash(x > y)", false)]
    #[case("Bash($(x))", false)]
    #[case("Bad pattern no parens", false)]
    #[case("Bash(a && b)", false)]
    #[case("Bash(a || b)", false)]
    #[case("Bash(a | b)", false)]
    #[case("Bash(a >> b)", false)]
    #[case("Bash(`x`)", false)]
    #[case("Bash(<(x))", false)]
    fn is_well_formed_pattern_cases(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_well_formed_pattern(input), expected);
    }
}
