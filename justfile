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

# Instrumented coverage gate (>= 97% on the published denominator).
cov:
    bash scripts/test.sh cov

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
