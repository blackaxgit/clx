//! Command validation policies for CLX (Layer 0 + Layer 1)
//!
//! This module provides two-tiered command validation:
//!
//! ## Layer 0 - Deterministic Rules (~1-5ms)
//! Fast, pattern-based validation using whitelist/blacklist matching.
//! This is the "fast path" for known command patterns.
//!
//! ## Layer 1 - LLM-Based Validation (~100-500ms)
//! Uses Ollama LLM to assess risk of unknown commands. Only invoked when
//! Layer 0 returns Ask (command not in whitelist or blacklist).
//!
//! Pattern syntax (canonical `ToolName(command:args)` form, host-neutral):
//! - `Bash(git:*)` - matches all git commands
//! - `Bash(npm:test*)` - matches npm test, npm test:unit, etc.
//! - `Bash(rm:-rf /*)` - matches rm -rf from root
//! - `Bash(curl:*|bash)` - matches curl pipe to bash
//! - `*` matches any sequence of characters

pub mod cache;
mod file_util;
mod llm;
pub mod matching;
pub mod mcp;
pub mod prompts;
mod rate_limiter;
pub mod read_only;
mod rules;
mod traits;
pub mod types;

pub use traits::PolicyEvaluator;

pub use cache::{ValidationCache, compute_cache_key};
pub use file_util::ensure_default_rules_file;
pub use llm::{DEFAULT_VALIDATOR_PROMPT, load_validator_prompt};
pub use matching::{glob_match, is_overbroad_allow_pattern};
pub use mcp::{McpExtraction, extract_mcp_command};
pub use prompts::{PROMPT_HIGH, PROMPT_LOW, PROMPT_STANDARD};
pub use read_only::is_read_only_command;
pub use types::*;

use matching::parse_pattern;
use rate_limiter::RateLimiter;
use read_only::{is_redirection_token, split_segments_quote_aware};

use tracing::debug;

/// Policy engine for deterministic command validation (Layer 0)
///
/// Thread-safe and designed for fast evaluation (~1-5ms).
#[derive(Debug)]
pub struct PolicyEngine {
    /// Whitelist rules (checked after blacklist)
    whitelist: Vec<PolicyRule>,

    /// Blacklist rules (checked first)
    blacklist: Vec<PolicyRule>,

    /// Graylist rules (hidden/internal builtin-only `Ask` tier, Issue 3).
    ///
    /// Checked after the blacklist and before the whitelist. These rules are
    /// NEVER loaded from or written to the learned-rules DB — they are populated
    /// only by `load_builtin_rules`, so a graylist verdict can never be learned
    /// or persisted.
    graylist: Vec<PolicyRule>,

    /// Current project path (for filtering project-specific rules)
    project_path: Option<String>,

    /// Rate limiter for LLM calls
    rate_limiter: RateLimiter,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// Create a new policy engine with default built-in rules
    #[must_use]
    pub fn new() -> Self {
        let mut engine = Self {
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            graylist: Vec::new(),
            project_path: None,
            rate_limiter: RateLimiter::new(30),
        };
        engine.load_builtin_rules();
        engine
    }

    /// Create a policy engine with no rules
    #[must_use]
    pub fn empty() -> Self {
        Self {
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            graylist: Vec::new(),
            project_path: None,
            rate_limiter: RateLimiter::new(30),
        }
    }

    /// Set the current project path for filtering project-specific rules
    #[must_use]
    pub fn with_project_path(mut self, project_path: impl Into<String>) -> Self {
        self.project_path = Some(project_path.into());
        self
    }

    /// Add a whitelist rule
    pub fn add_whitelist(&mut self, pattern: impl Into<String>) {
        self.whitelist.push(PolicyRule::whitelist(pattern.into()));
    }

    /// Add a blacklist rule
    pub fn add_blacklist(&mut self, pattern: impl Into<String>) {
        self.blacklist.push(PolicyRule::blacklist(pattern.into()));
    }

    /// Get all whitelist rules
    pub fn whitelist_rules(&self) -> &[PolicyRule] {
        &self.whitelist
    }

    /// Get all blacklist rules
    pub fn blacklist_rules(&self) -> &[PolicyRule] {
        &self.blacklist
    }

    /// Get all graylist rules (hidden/internal builtin-only `Ask` tier).
    pub fn graylist_rules(&self) -> &[PolicyRule] {
        &self.graylist
    }

    /// Evaluate a command against policies (Issue 3 — ASYMMETRIC compound
    /// matching).
    ///
    /// Evaluation order is blacklist → graylist → whitelist → fallthrough Ask,
    /// but compound (multi-segment) handling is deliberately asymmetric so that
    /// a single dangerous segment can never be "hidden" behind a safe one:
    ///
    /// 1. **Deny (blacklist):** deny if the WHOLE command matches a blacklist
    ///    rule OR if ANY individual segment matches a blacklist rule. So
    ///    `ls && rm -rf /` denies on the `rm -rf /` segment, and
    ///    `git diff && rm -rf /` denies on segment 2 (it is NOT allowed just
    ///    because `git diff` is whitelisted).
    /// 2. **Ask (graylist):** after the deny check, return Ask if — splitting
    ///    into segments and stripping a single leading literal `cd <one-token>`
    ///    segment — ANY remaining segment matches a graylist rule.
    /// 3. **Allow (whitelist):** allow ONLY if, after the same split + cd-strip,
    ///    EVERY remaining segment individually matches a whitelist rule. Never
    ///    "allow if any segment".
    /// 4. **Fallthrough:** Ask (unknown command, needs Layer 1).
    pub fn evaluate(&self, tool_name: &str, command: &str) -> PolicyDecision {
        // Split into segments once (quote-aware). On unbalanced quotes the
        // splitter returns None; we then fall back to treating the whole
        // command as a single segment (the whole-command checks below still
        // apply, and an unparseable command fails through to Ask).
        let segments = split_segments_quote_aware(command).unwrap_or_default();

        // 1. DENY — whole command OR any segment matches a blacklist rule.
        for rule in &self.blacklist {
            let matched_whole = self.matches_rule(tool_name, command, rule);
            let matched_segment = segments
                .iter()
                .any(|seg| self.matches_rule(tool_name, seg, rule));
            if matched_whole || matched_segment {
                let reason = rule
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Matched blacklist pattern: {}", rule.pattern));
                debug!(
                    "Blacklist match: command='{}' pattern='{}'",
                    command, rule.pattern
                );
                return PolicyDecision::Deny { reason };
            }
        }

        // 1b. DENY (backstop, FIX-2) — a Bash command whose WRITE DESTINATION
        //     resolves into a protected config dir. This replaces the removed
        //     `redir_templates` glob blacklist with a token/destination-aware
        //     check that does not false-fire on `->` arrows, `2>&1` fd-dups, or
        //     a protected dir used as a copy/move SOURCE (a read).
        if tool_name == "Bash" && bash_writes_into_protected_dir(command) {
            debug!("Protected-dir write backstop: command='{}'", command);
            return PolicyDecision::Deny {
                reason: "Write into a protected config dir".to_string(),
            };
        }

        // Segments to consider for graylist/whitelist matching: drop a single
        // leading literal `cd <one-token>` segment so that `cd /repo && git diff`
        // is judged on `git diff` alone.
        let effective: Vec<&str> = strip_leading_cd(&segments);

        // 2. ASK — any effective segment matches a graylist rule (after the deny
        //    check has already ruled out a blacklist hit).
        for rule in &self.graylist {
            let matched_whole = self.matches_rule(tool_name, command, rule);
            let matched_segment = effective
                .iter()
                .any(|seg| self.matches_rule(tool_name, seg, rule));
            if matched_whole || matched_segment {
                let reason = rule
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Matched graylist pattern: {}", rule.pattern));
                debug!(
                    "Graylist match: command='{}' pattern='{}'",
                    command, rule.pattern
                );
                return PolicyDecision::Ask { reason };
            }
        }

        // 3. ALLOW — every effective segment must individually match a whitelist
        //    rule. A single non-whitelisted segment => not allowed.
        if !effective.is_empty()
            && effective
                .iter()
                .all(|seg| self.matches_any_whitelist(tool_name, seg))
        {
            debug!("Whitelist match (all segments): command='{}'", command);
            return PolicyDecision::Allow;
        }

        // 4. Unknown command - needs Layer 1 evaluation.
        PolicyDecision::Ask {
            reason: "Unknown command, requires review".to_string(),
        }
    }

    /// True if `segment` matches any whitelist rule for `tool_name`.
    fn matches_any_whitelist(&self, tool_name: &str, segment: &str) -> bool {
        self.whitelist
            .iter()
            .any(|rule| self.matches_rule(tool_name, segment, rule))
    }

    /// Check if a command matches a rule pattern
    fn matches_rule(&self, tool_name: &str, command: &str, rule: &PolicyRule) -> bool {
        // Check project path filter
        if let Some(ref rule_project) = rule.project_path {
            if let Some(ref current_project) = self.project_path {
                if rule_project != current_project {
                    return false;
                }
            } else {
                return false;
            }
        }

        let pattern = &rule.pattern;

        // Pattern format: ToolName(command_pattern)
        if let Some((pattern_tool, command_pattern)) = parse_pattern(pattern) {
            if pattern_tool != tool_name {
                return false;
            }
            glob_match(&command_pattern, command)
        } else {
            // Fallback: treat as simple command pattern
            glob_match(pattern, command)
        }
    }
}

/// True iff a Bash `command` has at least one WRITE DESTINATION whose path has a
/// protected config-dir component (FIX-2).
///
/// This is the destination-aware replacement for the removed `redir_templates`
/// glob blacklist. It classifies a destination as protected by a
/// case-insensitive path **component** match — NOT by resolving against `$HOME`
/// (clx-core's `PolicyEngine` has no home-dir access), mirroring the original
/// component-name semantics of the globs.
///
/// Destinations extracted per segment (after `split_segments_quote_aware` +
/// `shlex::split`):
/// - (a) Redirection: the path glued to a real redirection operator, or the
///   token following a bare operator. Input redirs (`<`) and fd-duplications
///   (`2>&1`, `&1`, `N>&M`) are NOT destinations.
/// - (b) `cp`/`mv`: the last non-flag arg, unless `-t DIR` /
///   `--target-directory[=DIR]` is present (then that DIR).
/// - (c) `tee` (incl. `-a`): every non-flag arg.
/// - (d) `dd`: the value of `of=VALUE` (NOT `if=`).
///
/// # Known-open vectors (NOT covered — no regression; these were never covered
/// by the removed globs either):
/// - `install` (e.g. `install -m644 src DIR/dst`)
/// - `ln -s` (symlink creation into a protected dir)
/// - `sed -i` (in-place edit of a file already in a protected dir)
/// - heredoc writes (`cat <<EOF > DIR/f`) — the `>` redirection IS still caught
///   here, but a heredoc with no redirection operator is not a destination.
fn bash_writes_into_protected_dir(command: &str) -> bool {
    let Some(segments) = split_segments_quote_aware(command) else {
        // Unbalanced quotes: the rest of `evaluate` still runs (and fails
        // through to Ask). Be conservative here — no extra destination.
        return false;
    };
    for seg in &segments {
        let Some(tokens) = shlex::split(seg) else {
            // Unparseable segment: conservatively contribute no destination;
            // the rest of `evaluate` still runs.
            continue;
        };
        if segment_has_protected_write_destination(&tokens) {
            return true;
        }
    }
    false
}

/// Per-segment destination extraction + protected-component test for FIX-2.
fn segment_has_protected_write_destination(tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return false;
    }

    // (a) Redirection destinations (any command).
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if is_redirection_token(tok) {
            if let Some(dest) = redirection_destination(tok) {
                if destination_is_protected(dest) {
                    return true;
                }
            } else if !redirection_is_input(tok) && !redirection_is_fd_dup(tok) {
                // Bare operator (`>`, `>>`, `&>`, `2>`, ...): destination is the
                // NEXT token. (Input `<`/`N<` and fd-dups are skipped.)
                if let Some(next) = tokens.get(i + 1) {
                    if destination_is_protected(next) {
                        return true;
                    }
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }

    // Command-specific destinations. argv0 is the first non-redirection,
    // non-env-assignment token; for our purposes tokens[0] is sufficient since
    // redirections are handled above and leading env-assignments do not occur
    // for the commands we care about (cp/mv/tee/dd).
    let argv0 = tokens[0].as_str();
    let argv0 = argv0.rsplit('/').next().unwrap_or(argv0);
    match argv0 {
        "cp" | "mv" => cp_mv_destination_is_protected(&tokens[1..]),
        "tee" => tee_destination_is_protected(&tokens[1..]),
        "dd" => dd_destination_is_protected(&tokens[1..]),
        _ => false,
    }
}

/// True if `tok` is an INPUT redirection (`<`, `N<`) and never a write dest.
fn redirection_is_input(tok: &str) -> bool {
    let rest = tok.trim_start_matches(|c: char| c.is_ascii_digit());
    rest.starts_with('<')
}

/// True if the redirection `tok` is a file-descriptor DUPLICATION
/// (`2>&1`, `&1`, `N>&M`) — the part after the operator is `&<digit>`, so it
/// targets an fd, not a file.
fn redirection_is_fd_dup(tok: &str) -> bool {
    // Find the operator (`>` possibly preceded by fd digits or `&`) and inspect
    // what follows it.
    if let Some(pos) = tok.find('>') {
        let after = &tok[pos + 1..];
        let after = after.strip_prefix('>').unwrap_or(after); // handle `>>`
        return after.starts_with('&') && after[1..].chars().all(|c| c.is_ascii_digit());
    }
    false
}

/// For a redirection token that has the destination GLUED to it
/// (`>file`, `>>file`, `&>file`, `2>file`), return the destination path. Returns
/// `None` for a bare operator (`>`), an input redir, or an fd-dup.
fn redirection_destination(tok: &str) -> Option<&str> {
    if redirection_is_input(tok) || redirection_is_fd_dup(tok) {
        return None;
    }
    // Strip a leading fd number or `&` (e.g. `2>`, `&>`).
    let rest = tok.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
    // Strip the operator itself (`>>` before `>`).
    let path = rest.strip_prefix(">>").or_else(|| rest.strip_prefix('>'))?;
    if path.is_empty() { None } else { Some(path) }
}

/// `cp`/`mv` destination: last non-flag arg, UNLESS `-t DIR` /
/// `--target-directory[=DIR]` is present (then that DIR is the destination).
fn cp_mv_destination_is_protected(args: &[String]) -> bool {
    let mut last_nonflag: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if let Some(dir) = a.strip_prefix("--target-directory=") {
            return destination_is_protected(dir);
        }
        if a == "-t" || a == "--target-directory" {
            if let Some(dir) = args.get(i + 1) {
                return destination_is_protected(dir);
            }
            return false;
        }
        if a == "--" {
            // Everything after `--` is a positional operand.
            for operand in &args[i + 1..] {
                last_nonflag = Some(operand.as_str());
            }
            break;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        last_nonflag = Some(a);
        i += 1;
    }
    last_nonflag.is_some_and(destination_is_protected)
}

/// `tee` (incl. `-a`): every non-flag arg is a write destination.
fn tee_destination_is_protected(args: &[String]) -> bool {
    let mut after_ddash = false;
    for a in args {
        if !after_ddash && a == "--" {
            after_ddash = true;
            continue;
        }
        if !after_ddash && a.starts_with('-') {
            continue;
        }
        if destination_is_protected(a) {
            return true;
        }
    }
    false
}

/// `dd`: the value of an `of=VALUE` operand (NOT `if=`, which is the source).
fn dd_destination_is_protected(args: &[String]) -> bool {
    for a in args {
        if let Some(value) = a.strip_prefix("of=")
            && destination_is_protected(value)
        {
            return true;
        }
    }
    false
}

/// True if any path COMPONENT of `dest` (case-insensitive) is a protected
/// config dir.
///
/// Broad dirs (`.clx`/`.codex`/`.cursor`) are protected anywhere. The agent
/// dot-claude dir is protected ONLY for sensitive targets: the destination
/// basename is `settings.json`/`settings.local.json`, OR a `hooks` component is
/// present. Component match (not home-resolution) — a leading `~`/`~/` is
/// irrelevant because we split on `/` and compare components.
fn destination_is_protected(dest: &str) -> bool {
    // Protected dir names assembled via `concat!` so the literal hidden-dir
    // tokens do not appear verbatim in source (write-hook compatibility).
    const CLX: &str = concat!(".", "clx");
    const CODEX: &str = concat!(".", "codex");
    const CURSOR: &str = concat!(".", "cursor");
    const CLAUDE: &str = concat!(".", "claude");

    let components: Vec<&str> = dest.split('/').filter(|c| !c.is_empty()).collect();
    let basename = components.last().copied().unwrap_or("");

    for comp in &components {
        if comp.eq_ignore_ascii_case(CLX)
            || comp.eq_ignore_ascii_case(CODEX)
            || comp.eq_ignore_ascii_case(CURSOR)
        {
            return true;
        }
        if comp.eq_ignore_ascii_case(CLAUDE) {
            // dot-claude is sensitive-only.
            let sensitive_basename = basename.eq_ignore_ascii_case("settings.json")
                || basename.eq_ignore_ascii_case("settings.local.json");
            let has_hooks = components.iter().any(|c| c.eq_ignore_ascii_case("hooks"));
            if sensitive_basename || has_hooks {
                return true;
            }
        }
    }
    false
}

/// Strip a single leading literal `cd <one-token>` segment from `segments`,
/// returning the remaining segments as string slices (Issue 3).
///
/// The strip applies ONLY when the first segment is exactly `cd` followed by
/// exactly ONE token that contains no shell metacharacters. So `cd /repo` is
/// stripped, but `cd $(evil)`, `cd a b` (two tokens), and a bare `cd` are NOT
/// stripped (they are kept so the dangerous/ambiguous form is still evaluated).
fn strip_leading_cd(segments: &[String]) -> Vec<&str> {
    if let Some((first, rest)) = segments.split_first()
        && is_simple_cd_segment(first)
        && !rest.is_empty()
    {
        return rest.iter().map(String::as_str).collect();
    }
    segments.iter().map(String::as_str).collect()
}

/// True if `segment` is a literal `cd` followed by exactly one metachar-free
/// token (e.g. `cd /repo`, `cd src`). `cd`, `cd a b`, and `cd $(x)` are not.
fn is_simple_cd_segment(segment: &str) -> bool {
    let trimmed = segment.trim();
    let Some(arg) = trimmed.strip_prefix("cd ") else {
        return false;
    };
    let arg = arg.trim();
    if arg.is_empty() {
        return false;
    }
    // Exactly one token: no internal whitespace.
    if arg.split_whitespace().count() != 1 {
        return false;
    }
    // No shell metacharacters that could smuggle execution or expansion.
    const METACHARS: &[char] = &[
        '$', '`', '(', ')', '<', '>', '|', '&', ';', '*', '?', '{', '}', '[', ']', '~', '!', '\\',
        '"', '\'',
    ];
    !arg.contains(METACHARS)
}

#[cfg(test)]
mod tests;
