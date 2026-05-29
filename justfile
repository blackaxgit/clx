# CLX 0.8.0 test-harness mirror targets.
#
# Thin wrappers over scripts/test.sh so `just <target>` and
# `scripts/test.sh <subcommand>` are interchangeable. The shell script is the
# single source of truth (hermetic env, prerequisite checks, graceful skip).

# List available targets.
default:
    @just --list

# Quick inner loop: cargo nextest run --workspace.
fast:
    bash scripts/test.sh fast

# Instrumented coverage summary (honest ceiling ~90%; warn-only, no theater).
#
# Self-contained so it works WITHOUT rustup: cargo-llvm-cov needs an llvm-cov
# and llvm-profdata that match the rustc LLVM. On a Homebrew-Rust machine there
# is no `rustup component add llvm-tools-preview`, so we point cargo-llvm-cov at
# the Homebrew LLVM (`brew install llvm`) when its binaries are present.
# On a rustup setup these vars are simply left unset and cargo-llvm-cov finds
# the llvm-tools-preview component as usual. The frozen ignore-filename-regex
# in Cargo.toml [workspace.metadata.cargo-llvm-cov] is honored automatically.
cov:
    #!/usr/bin/env bash
    set -euo pipefail
    BREW_LLVM_COV=/opt/homebrew/opt/llvm/bin/llvm-cov
    BREW_LLVM_PROFDATA=/opt/homebrew/opt/llvm/bin/llvm-profdata
    if [ -x "$BREW_LLVM_COV" ] && [ -x "$BREW_LLVM_PROFDATA" ]; then
        export LLVM_COV="$BREW_LLVM_COV"
        export LLVM_PROFDATA="$BREW_LLVM_PROFDATA"
        echo "cov: using Homebrew LLVM ($LLVM_COV)"
    else
        echo "cov: Homebrew LLVM not found; relying on rustup llvm-tools-preview"
    fi
    CLX_MODEL_FETCH_DRYRUN=1 CLX_CREDENTIALS_BACKEND=age \
        cargo llvm-cov --workspace --summary-only

# TUI pixel snapshots: cargo insta test --review.
snapshots:
    bash scripts/test.sh snapshots

# Mutation testing on the seven hot modules (long-running; opt-in).
mutants:
    bash scripts/test.sh mutants

# Pre-release gate: fast + cov + snapshot verify.
all:
    bash scripts/test.sh all

# Full sign-off: all + plugin validate --strict + e2e suite.
pre-release:
    bash scripts/test.sh pre-release
