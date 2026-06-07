//! FIX-1 regression corpus for `is_read_only_command`.
//!
//! Three corpora:
//!   1. MUST be false — exec/write bypasses that the old substring classifier
//!      let through (or accepted false-denies, which are safe in this direction).
//!   2. MUST stay true — genuine reads that must remain auto-allowable.
//!   3. Composite commands — every segment must be read-only for the whole to be.
//!
//! Each assertion names the case so a failure points straight at the input.

use clx_core::policy::is_read_only_command;

/// Commands that MUST classify as NOT read-only (fail-closed / bypass defenses).
const MUST_BE_FALSE: &[&str] = &[
    // Tampered-environment exec.
    "env X=1 rm -rf /tmp/x",
    // Verification round (Codex): arbitrary-fd redirection write targets.
    "ls 3>/tmp/o",
    "ls 2>>/tmp/o",
    "ls {fd}>/tmp/o",
    // Verification round (Codex): GNU sed exec/write flags in any order/delimiter.
    "sed 's/.*/id/ep' f",
    "sed 's/.*/id/pe' f",
    "sed 's#.*#id#e' f",
    "LD_PRELOAD=./pwn.so ls",
    "NODE_OPTIONS='--require ./pwn.js' node --version",
    "RUBYOPT=-r./pwn ruby -v",
    // awk / gawk code execution and file commands.
    "awk 'BEGIN { system (\"id\") }'",
    "awk -f script.awk file",
    "gawk -i inplace 's/a/b/' f",
    // fd / find exec & write.
    "fd -x rm {}",
    "find . -fprint0 out",
    "find . -exec rm {} ;",
    // Interpreter code execution / non-version flags (some accepted false-deny).
    "ruby -v -e 'system(\"id\")'",
    "python -v script.py",
    "cargo build -v",
    "npm version",
    "cargo metadata",
    // git write / config-injection / output-redirection.
    "git config user.email a@b.c",
    "git config alias.pwn '!sh'",
    "git -c core.pager='sh -c x' log",
    "git diff --output=/tmp/out",
    "git branch newbranch",
    "git branch --unset-upstream",
    "git remote add evil https://x",
    "git tag v1",
    // tar extract / program-running options.
    "tar -xf \"a -table.tar\"",
    "tar -tf a.tar --checkpoint-action=exec='touch /tmp/p'",
    "tar -tf a.tar -I 'sh -c x'",
    // zip removed from allow-set entirely.
    "zip out.zip f",
    // sed file/exec commands.
    "sed 's/a/b/w /tmp/out' file",
    "sed -f s.sed file",
    // Misc tools with side-effecting options.
    "date -s '2020-01-01'",
    "hostname newname",
    "ifconfig lo0 down",
    "yq -i '.a=1' f",
    "tree -o out",
    "rg --pre ./pp pattern",
    "man -P 'sh -c x' ls",
    // Redirection.
    "ls > /tmp/out",
    "git status 2> /tmp/out",
    // Background / composite with a write segment.
    "ls & rm -rf /tmp/x",
    // Arithmetic-nested command substitution.
    "echo $((1 + $(rm -rf /tmp/x)))",
    // Literal embedded newline.
    "ls\nrm -rf /tmp/x",
];

/// Commands that MUST stay read-only (genuine reads).
const MUST_BE_TRUE: &[&str] = &[
    "ls -la",
    "cat f",
    "git status",
    "git -C repo status",
    "git log --oneline",
    "git diff",
    "git show HEAD",
    "rg pattern src/",
    "grep 'a|b' file",
    "sed 's/foo/bar/' f",
    "sed 's/a/b/g' f",
    "sed 's/e/x/' f",
    "cargo --version",
    "python --version",
    "node -v",
    "java -version",
    "tar -tf a.tar",
    "unzip -l a.zip",
    "git config --get user.email",
    "git config --list",
    "git branch",
    "git branch -l",
    "git remote -v",
    "go version",
    "find . -name '*.rs'",
    "awk '{print $1}' f",
];

#[test]
fn bypasses_are_not_read_only() {
    for cmd in MUST_BE_FALSE {
        assert!(
            !is_read_only_command(cmd),
            "MUST be NOT read-only but was allowed: {cmd:?}"
        );
    }
}

#[test]
fn genuine_reads_stay_read_only() {
    for cmd in MUST_BE_TRUE {
        assert!(
            is_read_only_command(cmd),
            "MUST stay read-only but was denied: {cmd:?}"
        );
    }
}

#[test]
fn composite_commands_require_every_segment_read_only() {
    assert!(
        is_read_only_command("ls && cat f"),
        "both segments read-only => read-only: 'ls && cat f'"
    );
    assert!(
        !is_read_only_command("ls && rm f"),
        "one write segment => not read-only: 'ls && rm f'"
    );
    assert!(
        is_read_only_command("ls | grep x"),
        "piped reads => read-only: 'ls | grep x'"
    );
}
