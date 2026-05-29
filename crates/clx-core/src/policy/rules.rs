//! Built-in rule definitions and rule loading.
//!
//! Contains the whitelist/blacklist pattern definitions and methods
//! for loading rules from files and the database.

use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::storage::Storage;
use crate::types::RuleType;

use super::PolicyEngine;
use super::matching::convert_learned_pattern;
use super::types::{PolicyRule, RuleSource, RulesConfig};

impl PolicyEngine {
    /// Load built-in default rules
    pub(super) fn load_builtin_rules(&mut self) {
        // Whitelist: Safe read-only commands
        let whitelist_patterns = [
            // File browsing
            "Bash(ls:*)",
            "Bash(pwd)",
            "Bash(cat:*)",
            "Bash(head:*)",
            "Bash(tail:*)",
            "Bash(less:*)",
            "Bash(more:*)",
            "Bash(file:*)",
            "Bash(stat:*)",
            "Bash(wc:*)",
            // Git read operations
            "Bash(git:status*)",
            "Bash(git:log*)",
            "Bash(git:diff*)",
            "Bash(git:branch*)",
            "Bash(git:show*)",
            "Bash(git:blame*)",
            "Bash(git:remote -v*)",
            "Bash(git:config --list*)",
            // Package manager test/build commands
            "Bash(npm:test*)",
            "Bash(npm:run test*)",
            "Bash(npm:run lint*)",
            "Bash(npm:run build*)",
            "Bash(yarn:test*)",
            "Bash(yarn:lint*)",
            "Bash(yarn:build*)",
            "Bash(pnpm:test*)",
            "Bash(pnpm:lint*)",
            "Bash(pnpm:build*)",
            // Rust
            "Bash(cargo:test*)",
            "Bash(cargo:build*)",
            "Bash(cargo:check*)",
            "Bash(cargo:clippy*)",
            "Bash(cargo:fmt*)",
            "Bash(cargo:doc*)",
            // Python
            "Bash(python:-m pytest*)",
            "Bash(pytest:*)",
            "Bash(python:-m mypy*)",
            "Bash(ruff:*)",
            "Bash(black:--check*)",
            // Go
            "Bash(go:test*)",
            "Bash(go:build*)",
            "Bash(go:vet*)",
            // System info
            "Bash(which:*)",
            "Bash(whereis:*)",
            "Bash(type:*)",
            "Bash(echo:*)",
            "Bash(date)",
            "Bash(whoami)",
            "Bash(hostname)",
            "Bash(uname:*)",
            "Bash(env)",
            "Bash(printenv:*)",
        ];

        for pattern in whitelist_patterns {
            self.whitelist.push(
                PolicyRule::whitelist(pattern).with_description("Built-in safe command pattern"),
            );
        }

        // Blacklist: Dangerous patterns
        let blacklist_patterns = [
            // Recursive deletion from dangerous paths
            ("Bash(rm:-rf /*)", "Recursive deletion from root"),
            ("Bash(rm:-rf ~/*)", "Recursive deletion from home"),
            ("Bash(rm:-rf $HOME/*)", "Recursive deletion from home"),
            ("Bash(rm:-rf /home/*)", "Recursive deletion from /home"),
            ("Bash(rm:-rf /Users/*)", "Recursive deletion from /Users"),
            ("Bash(rm:-rf /var/*)", "Recursive deletion from /var"),
            ("Bash(rm:-rf /etc/*)", "Recursive deletion from /etc"),
            ("Bash(rm:-rf /usr/*)", "Recursive deletion from /usr"),
            ("Bash(rm:-rf /System/*)", "Recursive deletion from /System"),
            (
                "Bash(rm:-rf /Library/*)",
                "Recursive deletion from /Library",
            ),
            // Overly permissive permissions
            ("Bash(chmod:777 *)", "Overly permissive file permissions"),
            (
                "Bash(chmod:-R 777 *)",
                "Recursive overly permissive permissions",
            ),
            // Pipe to shell (remote code execution risk)
            ("Bash(curl:*|sh)", "Piping curl to shell"),
            ("Bash(curl:*|bash)", "Piping curl to bash"),
            ("Bash(curl:*| sh)", "Piping curl to shell"),
            ("Bash(curl:*| bash)", "Piping curl to bash"),
            ("Bash(wget:*|sh)", "Piping wget to shell"),
            ("Bash(wget:*|bash)", "Piping wget to bash"),
            ("Bash(wget:*| sh)", "Piping wget to shell"),
            ("Bash(wget:*| bash)", "Piping wget to bash"),
            // Dangerous sudo commands
            ("Bash(sudo:rm*)", "Sudo rm command"),
            ("Bash(sudo:dd*)", "Sudo dd command"),
            ("Bash(sudo:mkfs*)", "Sudo mkfs command"),
            ("Bash(sudo:fdisk*)", "Sudo fdisk command"),
            ("Bash(sudo:parted*)", "Sudo parted command"),
            // Fork bombs and resource exhaustion - need wildcards to catch variations
            ("Bash(*:()*{*:*|*:*&*}*;*:*)", "Fork bomb pattern"),
            ("Bash(*(){*|*&*};*)", "Fork bomb pattern variant"),
            // Disk wiping
            ("Bash(dd:if=/dev/zero*)", "Disk wiping with /dev/zero"),
            ("Bash(dd:if=/dev/urandom*)", "Disk wiping with /dev/urandom"),
            ("Bash(dd:if=/dev/random*)", "Disk wiping with /dev/random"),
            // History manipulation (potential cover-up)
            ("Bash(history:-c)", "Clearing shell history"),
            ("Bash(rm:*/.bash_history*)", "Removing bash history"),
            ("Bash(rm:*/.zsh_history*)", "Removing zsh history"),
            // Network attacks
            ("Bash(nc:-e*)", "Netcat with execution"),
            ("Bash(ncat:-e*)", "Ncat with execution"),
            // Container security
            (
                "Bash(docker:run*--privileged*)",
                "Privileged container - potential escape vector",
            ),
            (
                "Bash(docker:run*--pid=host*)",
                "Host PID namespace - container escape risk",
            ),
            (
                "Bash(docker:run*-v /*)",
                "Host filesystem mount - container escape risk",
            ),
            // Supply chain
            (
                "Bash(pip:install*--index-url*)",
                "Custom PyPI index - supply chain risk",
            ),
            (
                "Bash(npm:install*--registry*)",
                "Custom npm registry - supply chain risk",
            ),
            // Destructive - recursive world-writable permissions
            (
                "Bash(chmod:777*-R*)",
                "Recursive world-writable permissions",
            ),
            (
                "Bash(chmod:-R*777*)",
                "Recursive world-writable permissions",
            ),
            // Shell escape techniques
            ("Bash(*`*)", "Backtick command substitution"),
            ("Bash(*<(*)*)", "Process substitution input"),
            ("Bash(*>(*)*)", "Process substitution output"),
            ("Bash(*${*:-*}*)", "Shell parameter expansion with default"),
            ("Bash(eval *)", "Eval command execution"),
            ("Bash(exec *)", "Exec command replacement"),
            ("Bash(source *)", "Source file execution"),
            ("Bash(*xargs*rm*)", "Xargs with destructive command"),
            (
                "Bash(python*-c*import*os*)",
                "Python one-liner with os module",
            ),
            ("Bash(perl*-e*system*)", "Perl one-liner with system call"),
        ];

        for (pattern, description) in blacklist_patterns {
            self.blacklist
                .push(PolicyRule::blacklist(pattern).with_description(description));
        }

        debug!(
            "Loaded {} whitelist and {} blacklist built-in rules",
            self.whitelist.len(),
            self.blacklist.len()
        );
    }

    /// Load rules from a YAML file
    ///
    /// Rules are merged with existing rules (not replaced).
    pub fn load_rules_from_file<P: AsRef<Path>>(&mut self, path: P) -> crate::Result<()> {
        let path = path.as_ref();

        if !path.exists() {
            debug!("Rules file not found: {}", path.display());
            return Ok(());
        }

        let content = fs::read_to_string(path)?;
        let config: RulesConfig = serde_yml::from_str(&content)?;

        let whitelist_count = config.whitelist.len();
        let blacklist_count = config.blacklist.len();

        for pattern in config.whitelist {
            // B1-4 / B3-2: apply the same overbroad gate that guards the
            // learned-rule load path.  A file-supplied `whitelist: ["Bash(*)"]`
            // must not become a permanent L0 wildcard allow.  WARN and skip;
            // do NOT abort the load (other valid rules in the file are kept).
            // Deny rules are never restricted — a broad deny only fails safe.
            if super::matching::is_overbroad_allow_pattern(&pattern) {
                warn!(
                    %pattern,
                    "Skipping overbroad file-loaded ALLOW rule (would whitelist \
                     arbitrary commands); ignored at load"
                );
                continue;
            }
            self.whitelist
                .push(PolicyRule::whitelist(pattern).with_source(RuleSource::Config));
        }

        for pattern in config.blacklist {
            self.blacklist
                .push(PolicyRule::blacklist(pattern).with_source(RuleSource::Config));
        }

        info!(
            "Loaded rules from {}: {} whitelist, {} blacklist",
            path.display(),
            whitelist_count,
            blacklist_count
        );

        Ok(())
    }

    /// Load the default rules file from ~/.clx/rules/default.yaml
    pub fn load_default_rules(&mut self) -> crate::Result<()> {
        let rules_path = crate::paths::default_rules_path();
        self.load_rules_from_file(rules_path)?;
        Ok(())
    }

    /// Return a copy of this engine with project-local config loading disabled.
    ///
    /// This is the P6 safety gate for untrusted / not-seen Codex projects.
    /// When a Codex project has `ProjectTrust::Untrusted` or
    /// `ProjectTrust::NotSeen`, P4 calls this method before loading any
    /// project-local rules so that a hostile `.clx/config.yaml` or
    /// project-scoped learned rules cannot influence policy evaluation for
    /// that session.
    ///
    /// ## What this changes
    ///
    /// Clears `project_path` on the returned engine so that
    /// `load_learned_rules` (which filters by project path) will fetch only
    /// global rules, and so that `matches_rule` will not apply
    /// project-specific rule filters.
    ///
    /// ## What this does NOT change
    ///
    /// - Built-in blacklist / whitelist rules are preserved.
    /// - File-loaded rules already present in `self` are preserved (the
    ///   caller controls whether to call `load_rules_from_file` on the result).
    /// - Rate-limiter state is preserved.
    ///
    /// ## Calling convention
    ///
    /// This is a pure, builder-style method: it consumes `self` and returns a
    /// new `PolicyEngine`.  Existing behaviour is unchanged when this method
    /// is not called.
    #[must_use]
    pub fn without_project_config(mut self) -> Self {
        self.project_path = None;
        self
    }

    /// Load learned rules from the database
    pub fn load_learned_rules(&mut self, storage: &Storage) -> crate::Result<()> {
        let learned_rules = if let Some(ref project_path) = self.project_path {
            storage.get_rules_for_project(project_path)?
        } else {
            storage.get_rules()?
        };

        let rules_count = learned_rules.len();

        for rule in learned_rules {
            // P7: canonical tool-name migration at the LOAD boundary only.
            // Stored rules written by older (Claude-only) CLX use the four
            // per-tool prefixes `Edit(`/`Write(`/`MultiEdit(`/`NotebookEdit(`.
            // v0.10.0 collapses all four into the canonical `FileEdit(` class
            // so multi-host matching does not bifurcate. The pattern is
            // rewritten IN MEMORY only - the row on disk is left untouched so
            // an older CLX build still reads its own patterns
            // (downgrade-safe). Existing Claude `Edit(*)` rules therefore
            // still fire after the in-memory migration to `FileEdit(*)`.
            let migrated = migrate_learned_pattern_to_canonical(&rule.pattern);

            // B1-4: defense-in-depth at the load boundary. An overbroad
            // allow pattern (`*`, `Bash(*)`, ...) loaded into the L0
            // whitelist would make every L0-unknown command hard-Allow and
            // skip L1 entirely. Skip + WARN such rows; Deny rows are never
            // restricted (a broad deny only ever fails safe).
            if matches!(rule.rule_type, RuleType::Allow)
                && super::matching::is_overbroad_allow_pattern(&migrated)
            {
                warn!(
                    pattern = %rule.pattern,
                    "Skipping overbroad learned ALLOW rule (would whitelist \
                     arbitrary commands); ignored at load"
                );
                continue;
            }
            let pattern = convert_learned_pattern(&migrated);
            let policy_rule = match rule.rule_type {
                RuleType::Allow => PolicyRule::whitelist(pattern),
                RuleType::Deny => PolicyRule::blacklist(pattern),
            }
            .with_source(RuleSource::Learned);

            match rule.rule_type {
                RuleType::Allow => self.whitelist.push(policy_rule),
                RuleType::Deny => self.blacklist.push(policy_rule),
            }
        }

        debug!("Loaded {} learned rules from database", rules_count);
        Ok(())
    }
}

/// Rewrite a stored learned-rule pattern to use the canonical `FileEdit(`
/// tool-name class (P7). The four historical Claude file-mutator prefixes
/// (`Edit(`, `Write(`, `MultiEdit(`, `NotebookEdit(`) all collapse to
/// `FileEdit(` so that learned rules and L0 matching share one tool-name space
/// across hosts (Codex `apply_patch`, Cursor `edit_file` also canonicalize to
/// `FileEdit`).
///
/// This is an IN-MEMORY load-time transform only - callers never persist the
/// result back to storage, keeping older CLX builds able to read their own
/// rows (downgrade-safe). Patterns that do not start with one of the four
/// prefixes (including any pattern already written as `FileEdit(`, and all
/// `Bash(` / MCP patterns) are returned unchanged.
///
/// The match is anchored at the start so only the tool-name segment is
/// rewritten; the argument portion after the `(` is preserved verbatim.
#[must_use]
fn migrate_learned_pattern_to_canonical(pattern: &str) -> String {
    const LEGACY_FILE_EDIT_PREFIXES: &[&str] = &["Edit(", "Write(", "MultiEdit(", "NotebookEdit("];
    for prefix in LEGACY_FILE_EDIT_PREFIXES {
        if let Some(rest) = pattern.strip_prefix(prefix) {
            return format!("FileEdit({rest}");
        }
    }
    pattern.to_string()
}

#[cfg(test)]
mod migrate_learned_pattern_tests {
    use super::migrate_learned_pattern_to_canonical;

    #[test]
    fn migrates_all_four_legacy_prefixes() {
        assert_eq!(
            migrate_learned_pattern_to_canonical("Edit(*)"),
            "FileEdit(*)"
        );
        assert_eq!(
            migrate_learned_pattern_to_canonical("Write(*)"),
            "FileEdit(*)"
        );
        assert_eq!(
            migrate_learned_pattern_to_canonical("MultiEdit(*)"),
            "FileEdit(*)"
        );
        assert_eq!(
            migrate_learned_pattern_to_canonical("NotebookEdit(*)"),
            "FileEdit(*)"
        );
    }

    #[test]
    fn preserves_argument_portion_verbatim() {
        assert_eq!(
            migrate_learned_pattern_to_canonical("Edit(src/foo.rs)"),
            "FileEdit(src/foo.rs)"
        );
        assert_eq!(
            migrate_learned_pattern_to_canonical("Write(./out (1).txt)"),
            "FileEdit(./out (1).txt)"
        );
    }

    #[test]
    fn already_canonical_is_unchanged() {
        assert_eq!(
            migrate_learned_pattern_to_canonical("FileEdit(*)"),
            "FileEdit(*)"
        );
    }

    #[test]
    fn non_file_edit_patterns_pass_through() {
        // Bash and MCP patterns are not file-edit and must be untouched.
        assert_eq!(
            migrate_learned_pattern_to_canonical("Bash(git:*)"),
            "Bash(git:*)"
        );
        assert_eq!(
            migrate_learned_pattern_to_canonical("mcp__server__tool(*)"),
            "mcp__server__tool(*)"
        );
    }

    #[test]
    fn only_matches_anchored_prefix() {
        // A pattern that merely contains "Edit(" mid-string is NOT rewritten;
        // only the leading tool-name segment is canonicalized.
        assert_eq!(
            migrate_learned_pattern_to_canonical("Bash(Edit(foo))"),
            "Bash(Edit(foo))"
        );
    }
}

#[cfg(test)]
mod without_project_config_tests {
    use super::*;
    use crate::policy::types::PolicyDecision;

    // T1: without_project_config clears project_path
    #[test]
    fn clears_project_path() {
        let engine = PolicyEngine::new()
            .with_project_path("/home/user/myrepo")
            .without_project_config();

        // After calling without_project_config the project path is None,
        // so project-specific rule filtering is disabled.
        assert!(
            engine.project_path.is_none(),
            "project_path must be None after without_project_config"
        );
    }

    // T2: without_project_config preserves built-in rules
    #[test]
    fn preserves_builtin_rules() {
        let baseline = PolicyEngine::new();
        let wl_count = baseline.whitelist_rules().len();
        let bl_count = baseline.blacklist_rules().len();

        let engine = PolicyEngine::new()
            .with_project_path("/some/repo")
            .without_project_config();

        assert_eq!(
            engine.whitelist_rules().len(),
            wl_count,
            "whitelist rule count must be unchanged"
        );
        assert_eq!(
            engine.blacklist_rules().len(),
            bl_count,
            "blacklist rule count must be unchanged"
        );
    }

    // T3: without_project_config is idempotent (calling twice has the same
    // result as calling once)
    #[test]
    fn is_idempotent() {
        let once = PolicyEngine::new()
            .with_project_path("/some/repo")
            .without_project_config();

        let twice = PolicyEngine::new()
            .with_project_path("/some/repo")
            .without_project_config()
            .without_project_config();

        assert!(once.project_path.is_none());
        assert!(twice.project_path.is_none());
        assert_eq!(once.whitelist_rules().len(), twice.whitelist_rules().len());
    }

    // T4: without_project_config on an engine with no project_path is a no-op
    #[test]
    fn no_op_when_already_none() {
        let baseline = PolicyEngine::new();
        let bl_count = baseline.blacklist_rules().len();

        let engine = PolicyEngine::new().without_project_config();

        assert!(engine.project_path.is_none());
        assert_eq!(engine.blacklist_rules().len(), bl_count);
    }

    // T5: evaluate still works correctly after without_project_config;
    // Claude is not affected (deny for a known-dangerous pattern still fires)
    #[test]
    fn deny_still_fires_after_without_project_config() {
        let engine = PolicyEngine::new()
            .with_project_path("/any/repo")
            .without_project_config();

        let decision = engine.evaluate("Bash", "rm -rf /");
        assert!(
            matches!(decision, PolicyDecision::Deny { .. }),
            "built-in deny rule must still fire; got {decision:?}"
        );
    }
}
