//! Read-only command detection (token-first, fail-closed).
//!
//! Determines whether a shell command is read-only (does not modify files
//! or system state). Read-only commands can be safely auto-allowed without
//! showing a confirmation dialog.
//!
//! # Design: token-first, default-deny
//!
//! The classifier never matches raw substrings against the command. Instead
//! it (1) screens the raw string for shell metacharacters that `shlex` cannot
//! reason about, (2) tokenizes with `shlex::split`, (3) segments on shell
//! control operators, and (4) requires EVERY segment to be *provably*
//! side-effect-free via a curated allow-set plus per-tool token deny rules.
//!
//! Every uncertain path returns `false` (fail-closed): an unparseable command,
//! an unknown program, or a recognized program used with an option we cannot
//! prove safe all fall through to a confirmation prompt rather than being
//! auto-allowed.

/// Check if a command is read-only (doesn't modify files or system state).
///
/// Read-only commands are safe to auto-allow without showing a confirmation
/// dialog. For composite commands (pipes, `&&`, `||`, `;`, `&`), EVERY segment
/// must be read-only. Command/process substitution, redirection, and embedded
/// newlines make a command never read-only.
#[must_use]
pub fn is_read_only_command(command: &str) -> bool {
    // 1. Raw-string metacharacter screen. `shlex` is not a shell parser; these
    //    constructs can smuggle execution past token analysis, so any
    //    occurrence is an immediate fail-closed reject.
    if contains_dangerous_metachar(command) {
        return false;
    }

    // 2. Quote-aware split into segments on unquoted control operators
    //    (`;`, `|`, `||`, `&`, `&&`). Shell operators do not require surrounding
    //    whitespace and `shlex` does not model them, so we segment the raw string
    //    ourselves, respecting quotes (so `grep 'a|b'` is not split). Unbalanced
    //    quotes => None => fail-closed.
    let Some(segments) = split_segments_quote_aware(command) else {
        return false;
    };
    if segments.is_empty() {
        return false;
    }

    // 3-5. Every segment must tokenize and be provably read-only.
    for seg in &segments {
        let Some(tokens) = shlex::split(seg) else {
            return false;
        };
        if tokens.is_empty() {
            return false;
        }
        // A redirection operator anywhere => never read-only (write target).
        if tokens.iter().any(|t| is_redirection_token(t)) {
            return false;
        }
        if !segment_is_read_only(&tokens) {
            return false;
        }
    }
    true
}

/// Raw-string screen for shell metacharacters `shlex` cannot model.
///
/// Returns `true` (=> reject) for backticks, command substitution `$(` (ANY
/// occurrence, including the arithmetic-nested `$(($(` form), process
/// substitution `<(` / `>(`, and embedded newlines / carriage returns.
fn contains_dangerous_metachar(command: &str) -> bool {
    if command.contains('`')
        || command.contains("<(")
        || command.contains(">(")
        || command.contains('\n')
        || command.contains('\r')
    {
        return true;
    }
    // `$(` is command substitution and is rejected. Arithmetic expansion `$((`
    // is allowed UNLESS it nests a command substitution. So reject any `$(`
    // occurrence that is NOT immediately followed by another `(`. The nested
    // `$(($(cmd)))` form is caught because its inner `$(` is followed by `c`.
    let bytes = command.as_bytes();
    let mut from = 0;
    while let Some(rel) = command[from..].find("$(") {
        let after = from + rel + 2;
        if after >= bytes.len() || bytes[after] != b'(' {
            return true;
        }
        from = after;
    }
    false
}

/// True if `token` is, starts with, or ends with a redirection operator —
/// including arbitrary file descriptors (`3>`, `4>>`) and `&>`/`&>>`. Strips an
/// optional leading fd number or `&` before checking for a leading `>`/`<`, so
/// `3>/tmp/o` is caught as a write target (fail-closed).
fn is_redirection_token(token: &str) -> bool {
    let mut rest = token.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
    // Bash named file descriptor: `{varname}>file`.
    if rest.starts_with('{')
        && let Some(close) = rest.find('}')
    {
        rest = &rest[close + 1..];
    }
    rest.starts_with('>')
        || rest.starts_with('<')
        || token.ends_with('>')
        || token.ends_with('<')
}

/// Quote-aware split of a raw command into segments on unquoted control
/// operators (`;`, `|`, `||`, `&`, `&&`). Operators inside single/double quotes
/// (e.g. `grep 'a|b'`) or backslash-escaped are kept literally. Consecutive
/// operators collapse and empty segments are dropped. Returns `None` on
/// unbalanced quotes (fail-closed). Redirection (`>`/`<`) is NOT a separator —
/// it stays in the segment and is rejected later by `is_redirection_token`.
fn split_segments_quote_aware(command: &str) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for c in command.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if !in_single => {
                current.push(c);
                escaped = true;
            }
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(c);
            }
            ';' | '|' | '&' if !in_single && !in_double => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    segments.push(trimmed.to_string());
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }

    if in_single || in_double {
        return None; // unbalanced quotes => fail-closed
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed.to_string());
    }
    Some(segments)
}

/// True if `token` looks like a leading `NAME=VALUE` environment assignment.
///
/// Shell assignment names are `[A-Za-z_][A-Za-z0-9_]*`. The `=` must be present
/// and the name non-empty and valid; otherwise it is a normal argument.
fn is_env_assignment(token: &str) -> bool {
    let Some(eq) = token.find('=') else {
        return false;
    };
    let name = &token[..eq];
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap_or(' ');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Decide whether a single segment (one simple command) is read-only.
fn segment_is_read_only(tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return false;
    }

    // a. Leading NAME=VALUE assignments. If any assignment is followed by a
    //    program token, the program runs in a tampered environment
    //    (LD_PRELOAD, NODE_OPTIONS, RUBYOPT, ...) => never read-only. Bare
    //    `env`/`set` with ONLY assignments and no program is read-only.
    let mut idx = 0;
    while idx < tokens.len() && is_env_assignment(&tokens[idx]) {
        idx += 1;
    }
    if idx > 0 {
        // There was at least one leading assignment. A trailing program after
        // the assignments means tampered-env exec => reject.
        return idx >= tokens.len();
    }

    let argv0 = tokens[0].as_str();
    let args = &tokens[1..];

    // `env` / `set` with only assignment-shaped args (handled above when the
    // assignments lead) — here argv0 is the program itself.
    match argv0 {
        // b. argv0 must be in the scrubbed read-only allow-set.
        "cat" | "less" | "more" | "head" | "tail" | "bat" | "ls" | "dir" | "exa" | "eza"
        | "file" | "stat" | "wc" | "du" | "df" | "ag" | "ack" | "locate" | "which"
        | "whereis" | "type" | "pwd" | "whoami" | "uname" | "uptime" | "cal" | "printenv"
        | "ps" | "top" | "htop" | "pgrep" | "host" | "help" | "info" | "diff" | "cmp" | "jq"
        | "echo" | "zipinfo" => true,

        // `env` / `set` are read-only only with no trailing program. Any
        // non-assignment operand (a program, `-x`, ...) => reject.
        "env" | "set" => args.iter().all(|a| is_env_assignment(a)),

        // c. Per-tool token deny rules (default-deny).
        "node" | "npm" | "yarn" | "pnpm" | "cargo" | "rustc" | "python" | "python3" | "go"
        | "java" | "javac" | "ruby" | "perl" | "php" => interpreter_is_read_only(argv0, args),
        "awk" | "gawk" | "mawk" => awk_is_read_only(args),
        "sed" | "gsed" => sed_is_read_only(args),
        "find" => find_is_read_only(args),
        "fd" | "fdfind" => fd_is_read_only(args),
        "tar" => tar_is_read_only(args),
        "unzip" => args.iter().any(|a| a == "-l" || a == "--list"),
        "git" => git_is_read_only(args),
        "date" => !args.iter().any(|a| a == "-s" || a == "--set"),
        "hostname" => args.is_empty(),
        "ifconfig" => ifconfig_is_read_only(args),
        "yq" => !args.iter().any(|a| a == "-i" || a == "--inplace"),
        "tree" => tree_is_read_only(args),
        "rg" | "ripgrep" => rg_is_read_only(args),
        "grep" => true,
        "man" => man_is_read_only(args),

        // d. Default-deny.
        _ => false,
    }
}

/// Interpreters are read-only ONLY when every arg is a bare version flag.
/// Any script path, `-e`/`-c`, or subcommand (`build`, `version`, ...) => false.
fn interpreter_is_read_only(argv0: &str, args: &[String]) -> bool {
    args.iter().all(|a| {
        a == "--version"
            || a == "-v"
            || a == "-V"
            || a == "-version" // java/javac use a single-dash -version
            || (argv0 == "go" && (a == "version" || a == "env"))
    })
}

/// awk: deny `-f`/`--file`/`-i`/`--include`/`-l`, and any program token that
/// (word-boundary, whitespace-insensitive) contains `system`/`getline`/
/// `close`/`fflush`, a `print` combined with `>`/`|`, or any `>`/`|`.
fn awk_is_read_only(args: &[String]) -> bool {
    for a in args {
        if a == "-f" || a == "--file" || a == "-i" || a == "--include" || a == "-l" {
            return false;
        }
        if awk_program_is_dangerous(a) {
            return false;
        }
    }
    true
}

/// Heuristic danger check for an awk program token. Fail-closed: any
/// uncertainty (a dangerous builtin, redirection, or pipe) => dangerous.
fn awk_program_is_dangerous(prog: &str) -> bool {
    if prog.contains('>') || prog.contains('|') {
        return true;
    }
    let squished: String = prog.chars().filter(|c| !c.is_whitespace()).collect();
    const DANGEROUS: &[&str] = &["system", "getline", "close", "fflush"];
    DANGEROUS.iter().any(|kw| squished.contains(kw))
}

/// sed: deny `-i`/`--in-place`/`-f`/`--file`, and any script token containing a
/// sed command letter in {w, W, e, r, R} (file/exec commands). Pure
/// `s///`/`p`/`d` scripts are allowed.
fn sed_is_read_only(args: &[String]) -> bool {
    let mut expect_script = false;
    let mut first_nonopt_seen = false;
    for a in args {
        if a == "-i" || a == "--in-place" || a == "-f" || a == "--file" {
            return false;
        }
        if expect_script {
            if sed_script_is_dangerous(a) {
                return false;
            }
            expect_script = false;
            continue;
        }
        if a == "-e" || a == "--expression" {
            expect_script = true;
            continue;
        }
        // Other options (-n, -E, -r, -s, -z, --posix, ...) are benign for reads.
        if a.starts_with('-') {
            continue;
        }
        // The first non-option token is the script (when no `-e` is given);
        // subsequent non-option tokens are input filenames (reads) — ignore.
        if !first_nonopt_seen {
            first_nonopt_seen = true;
            if sed_script_is_dangerous(a) {
                return false;
            }
        }
    }
    true
}

/// Heuristic: is a sed *script* token a file-writing/executing command?
///
/// Flags the `w`/`W` (write file), `r`/`R` (read file), and `e` (execute)
/// commands and the substitution write/execute flags (`s/././w`, `s/././e`, in
/// any flag order and with any delimiter), without false-firing on substitution
/// *content* (e.g. the `r` in `s/foo/bar/`).
///
/// It parses each `s` substitution to locate its real flag region (after the
/// third unescaped delimiter) so `s/.*/id/ep`, `s/.*/id/pe`, and `s#.*#id#e` are
/// all caught, while `s/e/x/` (where `e` is pattern content) is not. Standalone
/// `w`/`r`/`e` commands are flagged when they sit at a command position and take
/// an argument. Conservative: ambiguous cases lean dangerous (fail-closed).
fn sed_script_is_dangerous(script: &str) -> bool {
    let bytes = script.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        let ch = bytes[i];

        // Standalone file/exec command (`w file`, `r file`, `e cmd`, ...): a
        // command-position w/W/r/R/e that is at end-of-script or takes an arg.
        if matches!(ch, b'w' | b'W' | b'r' | b'R' | b'e')
            && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b';' | b'}' | b'\n'))
            && (i + 1 >= len || matches!(bytes[i + 1], b' ' | b'\t'))
        {
            return true;
        }

        // Substitution `s<D>pat<D>repl<D>flags`: parse to the flag region.
        if ch == b's' && i + 1 < len {
            let delim = bytes[i + 1];
            let delim_ok = !delim.is_ascii_alphanumeric()
                && !delim.is_ascii_whitespace()
                && delim != b'\\';
            if delim_ok {
                // Walk to just past the third delimiter (end of replacement),
                // honoring backslash escapes.
                let mut j = i + 2;
                let mut seen = 0u8;
                while j < len && seen < 2 {
                    if bytes[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == delim {
                        seen += 1;
                    }
                    j += 1;
                }
                // Read flag characters; a write/execute flag anywhere => danger.
                while j < len {
                    match bytes[j] {
                        b'e' | b'w' | b'W' => return true,
                        b'g' | b'p' | b'i' | b'I' | b'm' | b'M' | b'0'..=b'9' => j += 1,
                        _ => break,
                    }
                }
                i = j;
                continue;
            }
        }

        i += 1;
    }
    false
}

/// find: deny tokens that execute or write.
fn find_is_read_only(args: &[String]) -> bool {
    const DENY: &[&str] = &[
        "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf",
        "-fls",
    ];
    !args.iter().any(|a| DENY.contains(&a.as_str()))
}

/// fd / fdfind: deny exec flags.
fn fd_is_read_only(args: &[String]) -> bool {
    const DENY: &[&str] = &["-x", "-X", "--exec", "--exec-batch"];
    !args.iter().any(|a| DENY.contains(&a.as_str()))
}

/// tar: read-only ONLY in list mode (`t`). Reject any create/extract/append/
/// update/catenate/delete mode letter and any program-running option.
fn tar_is_read_only(args: &[String]) -> bool {
    let mut saw_list = false;
    for (idx, a) in args.iter().enumerate() {
        // Program-running / write options regardless of mode.
        if a == "-I"
            || a == "--use-compress-program"
            || a == "--to-command"
            || a.starts_with("--checkpoint-action")
            || a.starts_with("--use-compress-program=")
            || a.starts_with("--to-command=")
        {
            return false;
        }
        if a == "--list" {
            saw_list = true;
            continue;
        }
        // Long-form write modes.
        if matches!(
            a.as_str(),
            "--create" | "--extract" | "--get" | "--append" | "--update" | "--catenate"
                | "--concatenate" | "--delete"
        ) {
            return false;
        }
        // Short/clustered mode tokens like `-tf`, `tf`, `-xf`. Inspect the
        // mode letters (everything that is not an option dash).
        if a.starts_with("--") {
            continue;
        }
        // Only a `-`-prefixed token, or the FIRST argument (old-style `tar tf`),
        // carries mode letters. Later bare tokens are operands (filenames) and
        // must not be scanned (e.g. the `r` in `a.tar` is not append mode).
        if !a.starts_with('-') && idx != 0 {
            continue;
        }
        let letters = a.trim_start_matches('-');
        for c in letters.chars() {
            match c {
                't' => saw_list = true,
                'c' | 'x' | 'r' | 'u' | 'A' | 'd' => return false,
                _ => {}
            }
        }
    }
    saw_list
}

/// git: read-subcommands stay read-only with subcommand-specific guards.
/// Supports a leading `-C <dir>` (allowed) before a read subcommand, but
/// DENIES global `-c`/`--output*` (config injection / write redirection).
fn git_is_read_only(args: &[String]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            // Allowed global: change directory before a read subcommand.
            "-C" => {
                // Consume the directory operand.
                i += 2;
            }
            // Denied globals: -c injects config (e.g. core.pager=sh -c x),
            // --output* redirects to a file.
            "-c" => return false,
            _ if a == "--output"
                || a.starts_with("--output=")
                || a.starts_with("--output-indicator") =>
            {
                return false;
            }
            // First non-global token is the subcommand.
            _ => return git_subcommand_is_read_only(a, &args[i + 1..]),
        }
    }
    // No subcommand (bare `git` or only `-C dir`) => not provably a read.
    false
}

/// Per-subcommand git read-only rules.
fn git_subcommand_is_read_only(subcommand: &str, rest: &[String]) -> bool {
    // A global config-injection or output-redirection flag anywhere in the
    // remaining args is always disqualifying.
    if rest.iter().any(|a| {
        a == "-c"
            || a == "--output"
            || a.starts_with("--output=")
            || a.starts_with("--output-indicator")
    }) {
        return false;
    }

    const READ_SUBCOMMANDS: &[&str] = &[
        "status",
        "log",
        "diff",
        "show",
        "blame",
        "describe",
        "shortlog",
        "rev-parse",
        "ls-files",
        "ls-tree",
        "cat-file",
        "rev-list",
        "for-each-ref",
        "grep",
    ];

    match subcommand {
        "config" => {
            // Read-only only with an explicit getter and no value-setting.
            rest.iter().any(|a| {
                a == "--get"
                    || a == "--get-all"
                    || a == "--get-regexp"
                    || a == "--list"
                    || a == "-l"
            }) && git_config_has_no_value_token(rest)
        }
        "branch" | "tag" => {
            // Listing form only: every arg must be a known read/list flag. Any
            // positional operand (a new branch/tag name) or any mutation flag
            // (`--unset-upstream`, `-d`, `-m`, `--set-upstream-to`, ...) => not
            // read-only (default-deny on unrecognized flags).
            rest.iter().all(|a| is_git_branch_tag_read_flag(a))
        }
        "remote" => {
            // Bare, or read forms only.
            rest.is_empty()
                || rest.iter().all(|a| {
                    a == "-v" || a == "show" || a == "get-url"
                })
        }
        _ => READ_SUBCOMMANDS.contains(&subcommand),
    }
}

/// True if `arg` is a recognized read/list flag for `git branch`/`git tag`.
///
/// Default-deny: a positional operand (a new branch/tag name) or any flag not in
/// this set (mutations like `-d`, `-m`, `--unset-upstream`, `--set-upstream-to`)
/// makes the command not read-only. Value-attached forms (`--sort=...`) are
/// allowed; value-separated forms leave the value as a positional => denied.
fn is_git_branch_tag_read_flag(arg: &str) -> bool {
    const READ_FLAGS: &[&str] = &[
        "-l", "--list", "-v", "-vv", "--verbose", "-a", "--all", "-r", "--remotes", "-n",
        "--color", "--no-color", "--column", "--no-column", "--merged", "--no-merged",
        "--contains", "--no-contains", "--points-at", "--sort", "--format", "-i",
        "--ignore-case", "--omit-empty",
    ];
    if !arg.starts_with('-') {
        return false; // positional operand (e.g. a new branch/tag name)
    }
    let head = arg.split('=').next().unwrap_or(arg);
    READ_FLAGS.contains(&head)
}

/// `git config --get*`/`--list` is read-only only when there is no value token
/// (a second positional after the key would be a write).
fn git_config_has_no_value_token(rest: &[String]) -> bool {
    // Count positional (non-flag) operands. A getter takes at most one (the
    // key / regexp); two positionals means `key value` => a write.
    let positionals = rest.iter().filter(|a| !a.starts_with('-')).count();
    positionals <= 1
}

/// ifconfig: read-only only when bare or querying a single interface name.
/// Any config operand (`up`, `down`, an address, `add`, ...) => reject.
fn ifconfig_is_read_only(args: &[String]) -> bool {
    match args.len() {
        0 => true,
        1 => {
            let a = args[0].as_str();
            // A lone interface name (no dash, not a known config verb).
            !a.starts_with('-') && !matches!(a, "up" | "down")
        }
        _ => false,
    }
}

/// tree: deny output-to-file flags.
fn tree_is_read_only(args: &[String]) -> bool {
    !args.iter().any(|a| a == "-o" || a == "-O")
}

/// rg / ripgrep: deny preprocessor and archive-search flags.
fn rg_is_read_only(args: &[String]) -> bool {
    const DENY: &[&str] = &["--pre", "--search-zip", "-z", "--hostname-bin"];
    !args.iter().any(|a| DENY.contains(&a.as_str()))
}

/// man: deny pager-override flags.
fn man_is_read_only(args: &[String]) -> bool {
    const DENY: &[&str] = &["-P", "-H", "--pager"];
    !args.iter().any(|a| DENY.contains(&a.as_str()))
}
