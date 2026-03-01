//! Read-only command detection.
//!
//! Determines whether a shell command is read-only (does not modify files
//! or system state). Read-only commands can be safely auto-allowed without
//! showing a confirmation dialog.

/// Check if a command is read-only (doesn't modify files or system state)
///
/// Read-only commands are safe to auto-allow without showing confirmation dialog.
/// This includes file viewing, searching, system info, and version checks.
///
/// For composite commands (pipes, &&, ||, ;), ALL parts must be read-only.
/// Subshells (`$()`, backtick-substitution) are never considered read-only (potential injection).
#[must_use]
pub fn is_read_only_command(command: &str) -> bool {
    let trimmed = command.trim();

    // Empty command is not read-only (could be anything)
    if trimmed.is_empty() {
        return false;
    }

    // Backtick command substitution is NEVER read-only
    if trimmed.contains('`') {
        return false;
    }

    // Command substitution $(cmd) is NEVER read-only
    // But arithmetic expansion $((expr)) without command substitution is OK
    // We need to check for $( that's not immediately followed by (
    if let Some(pos) = trimmed.find("$(") {
        // Check if it's actually $((
        if pos + 2 < trimmed.len() {
            let next_char = trimmed.as_bytes()[pos + 2];
            // If the character after $( is not (, then it's command substitution
            if next_char != b'(' {
                return false;
            }
        } else {
            // $( at end of string is command substitution
            return false;
        }
    }

    // Process substitution is NEVER read-only
    if trimmed.contains("<(") || trimmed.contains(">(") {
        return false;
    }

    // Arithmetic expansion with command substitution is NEVER read-only
    // We need to detect $(($(cmd))) pattern specifically
    if trimmed.contains("$(($(") {
        return false;
    }

    // For composite commands, check if ALL parts are read-only
    if trimmed.contains('|')
        || trimmed.contains("&&")
        || trimmed.contains("||")
        || trimmed.contains(';')
    {
        return is_composite_read_only(trimmed);
    }

    // Simple command - check if it's read-only
    is_simple_command_read_only(trimmed)
}

/// Check if a composite command (with pipes, &&, ||, ;) is entirely read-only
fn is_composite_read_only(command: &str) -> bool {
    // Split by various command separators
    // Order matters: || and && before | to avoid partial matches
    let normalized = command
        .replace("||", "\x00")
        .replace("&&", "\x00")
        .replace([';', '|'], "\x00");

    let parts: Vec<&str> = normalized
        .split('\x00')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    // ALL parts must be read-only
    for part in parts {
        if !is_simple_command_read_only(part) {
            return false;
        }
    }

    true
}

/// Check if a simple (non-composite) command is read-only
fn is_simple_command_read_only(command: &str) -> bool {
    let trimmed = command.trim();

    if trimmed.is_empty() {
        return false;
    }

    // Get the first word (command name)
    let first_word = trimmed.split_whitespace().next().unwrap_or("");

    // List of read-only commands
    let read_only_commands = [
        // File viewing
        "cat", "less", "more", "head", "tail", "bat", // Directory listing
        "ls", "dir", "tree", "exa", "eza", // File info
        "file", "stat", "wc", "du", "df", // Searching
        "grep", "rg", "ag", "ack", "find", "fd", "locate", "which", "whereis", "type",
        // Text processing (read-only variants)
        "awk", "sed", // Note: only read-only when not using -i flag
        // System info
        "pwd", "whoami", "hostname", "uname", "uptime", "date", "cal", "env", "printenv", "set",
        // Process info
        "ps", "top", "htop", "pgrep", // Network info (truly read-only only)
        "host", "ifconfig", // Version checks
        "node", "npm", "yarn", "pnpm", "cargo", "rustc", "python", "python3", "go", "java",
        "javac", "ruby", "perl", "php", // Help commands
        "man", "help", "info", // Diff/compare (viewing only)
        "diff", "cmp", // JSON/YAML viewing
        "jq", "yq", // Archive listing (not extraction)
        "tar", "zip", "unzip", // Note: only read-only for listing flags
    ];

    // Check if command starts with a read-only command
    if read_only_commands.contains(&first_word) {
        // Special cases: some commands need flag checking
        match first_word {
            // sed -i is NOT read-only
            "sed" => !trimmed.contains(" -i") && !trimmed.contains(" --in-place"),
            // find/fd with -exec, -execdir, -delete, -ok can modify/delete files
            "find" | "fd" => {
                !trimmed.contains("-exec")
                    && !trimmed.contains("-execdir")
                    && !trimmed.contains("-delete")
                    && !trimmed.contains("-ok")
            }
            // awk with output redirection, system(), or pipe-to-command is NOT read-only
            "awk" => {
                !trimmed.contains('>') && !trimmed.contains("system(") && !trimmed.contains("| \"")
            }
            // tar with x (extract) or c (create) is NOT read-only
            "tar" => {
                let has_create_extract = trimmed.contains(" -c")
                    || trimmed.contains(" -x")
                    || trimmed.contains(" --create")
                    || trimmed.contains(" --extract");
                // tar -t (list) or tar -tvf is read-only
                !has_create_extract || trimmed.contains(" -t") || trimmed.contains(" --list")
            }
            // unzip -l (list) is read-only, but unzip without -l extracts
            "unzip" => trimmed.contains(" -l") || trimmed.contains(" --list"),
            // Version checks
            "node" | "npm" | "yarn" | "pnpm" | "cargo" | "rustc" | "python" | "python3"
            | "java" | "javac" | "ruby" | "perl" | "php" => {
                trimmed.contains("--version")
                    || trimmed.contains(" -v")
                    || trimmed.contains(" -V")
                    || trimmed == first_word // Just the command name alone
            }
            // Go has "go version" as the version command
            "go" => {
                trimmed == "go"
                    || trimmed.starts_with("go version")
                    || trimmed.contains("--version")
            }
            _ => true,
        }
    } else {
        // Check for git read-only commands
        if first_word == "git" {
            let git_cmd = trimmed.strip_prefix("git ").unwrap_or("");
            let git_subcommand = git_cmd.split_whitespace().next().unwrap_or("");

            let git_read_only = [
                "status",
                "log",
                "diff",
                "show",
                "blame",
                "branch",
                "tag",
                "remote",
                "config",
                "describe",
                "shortlog",
                "rev-parse",
                "ls-files",
                "ls-tree",
                "cat-file",
                "rev-list",
                "for-each-ref",
            ];

            // git remote -v, git branch -a, etc. are read-only
            // git push, commit, merge, rebase are NOT read-only
            return git_read_only.contains(&git_subcommand);
        }

        // Check for echo (read-only unless redirecting)
        if first_word == "echo" || first_word == "printf" {
            return !trimmed.contains('>');
        }

        false
    }
}
