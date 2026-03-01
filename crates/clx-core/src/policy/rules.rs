//! Built-in rule definitions and rule loading.
//!
//! Contains the whitelist/blacklist pattern definitions and methods
//! for loading rules from files and the database.

use std::fs;
use std::path::Path;
use tracing::{debug, info};

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

    /// Load learned rules from the database
    pub fn load_learned_rules(&mut self, storage: &Storage) -> crate::Result<()> {
        let learned_rules = if let Some(ref project_path) = self.project_path {
            storage.get_rules_for_project(project_path)?
        } else {
            storage.get_rules()?
        };

        let rules_count = learned_rules.len();

        for rule in learned_rules {
            let pattern = convert_learned_pattern(&rule.pattern);
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
