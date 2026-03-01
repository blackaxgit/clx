# Contributing to CLX

Thank you for your interest in contributing to CLX (Claude Code Extension Layer). This document covers everything you need to get started.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Project Architecture](#project-architecture)
- [Building](#building)
- [Testing](#testing)
- [Code Style](#code-style)
- [Commit Format](#commit-format)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## Prerequisites

Before contributing, ensure you have the following installed:

**Required:**
- Rust toolchain (edition 2024) — install via [rustup](https://rustup.rs/)
- `cargo fmt` and `cargo clippy` (included with standard Rust toolchain)

**Required for LLM features:**
- [Ollama](https://ollama.com/) running locally or via Docker
- Models pulled:
  - `qwen3:1.7b` (or compatible) for command validation and context summarization
  - `qwen3-embedding:0.6b` for semantic search / vector embeddings

**Optional:**
- Docker and Docker Compose (for the bundled Ollama setup in `scripts/`)

To verify your Rust installation supports edition 2024:

```sh
rustc --version   # should be 1.85.0 or later
cargo --version
```

---

## Project Architecture

CLX is a Cargo workspace with four crates. Understanding the boundaries helps you place new code correctly.

| Crate | Role | Key contents |
|-------|------|--------------|
| `clx` | CLI entry point and dashboard | `commands/`, `dashboard/` |
| `clx-core` | Core library shared by all crates | `config`, `policy/`, `storage/`, `ollama`, `embeddings`, `credentials`, `paths`, `types`, `error` |
| `clx-hook` | Hook handler binary (PreToolUse / PostToolUse / PreCompact / SessionStart / SessionEnd) | `hooks/`, `audit`, `learning`, `transcript`, `context`, `embedding` |
| `clx-mcp` | MCP server exposing CLX tools to Claude Code | `server`, `protocol/`, `tools/` (7 tools), `validation` |

**Guiding principles:**
- `clx-core` must remain free of binary-only concerns.
- Each hook handler in `clx-hook/src/hooks/` has one responsibility.
- MCP tool implementations live in `clx-mcp/src/tools/`, one file per tool.
- Business logic belongs in `clx-core`; I/O belongs at the edges.

---

## Building

Build all crates in release mode:

```sh
cargo build --release --workspace
```

Build a single crate:

```sh
cargo build -p clx
cargo build -p clx-hook
cargo build -p clx-mcp
```

Install binaries locally (mirrors the `install.sh` script):

```sh
cargo install --path crates/clx
cargo install --path crates/clx-hook
cargo install --path crates/clx-mcp
```

---

## Testing

Run the full test suite:

```sh
cargo test --workspace
```

Run tests for a single crate:

```sh
cargo test -p clx-core
```

Run a specific test by name:

```sh
cargo test -p clx-core policy::tests::test_whitelist_match
```

**Notes on integration tests:**
- Some integration tests require Ollama to be running. They are gated behind the `integration` feature or will be skipped automatically when Ollama is unavailable.
- Tests that depend on environment variables are serialized with `serial_test` to avoid flaky failures under parallel execution.

---

## Code Style

CLX enforces strict code quality standards. All of the following must pass before a PR can be merged.

**Formatting:**

```sh
cargo fmt --all -- --check
```

To auto-format (do this before committing):

```sh
cargo fmt --all
```

**Linting — `clippy::pedantic` is enabled project-wide:**

```sh
cargo clippy --workspace --all-targets -- -D warnings
```

Zero warnings are acceptable. If a lint is a false positive, suppress it with `#[allow(...)]` on the smallest possible scope and add a comment explaining why.

**Additional style rules:**
- Prefer immutability (`let` over `let mut` where possible).
- Use descriptive names; avoid abbreviations except for well-known conventions (`fn`, `impl`, `pub`).
- Keep functions small and single-purpose. Methods over ~40–60 lines are a signal to split.
- Error paths are first-class: use `clx_core::Error` and propagate with `?`.
- No `unwrap()` or `expect()` in library code — use proper error handling.
- `expect()` is acceptable in tests with a message explaining the invariant.

---

## Commit Format

CLX uses a structured commit format. Each commit message must follow:

```
<type>(<scope>): <summary>
```

**Types:**

| Type | When to use |
|------|-------------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |
| `docs` | Documentation only changes |
| `chore` | Maintenance, dependency updates, build changes |
| `perf` | A code change that improves performance |

**Scope** is the affected crate or module, e.g. `clx-core`, `clx-hook`, `policy`, `dashboard`.

**Rules:**
- Summary is imperative mood ("add feature", not "added feature")
- Under 72 characters total
- No signatures, trailers, or AI attribution

**Examples:**

```
feat(clx-mcp): add rate limiting to recall tool
fix(policy): handle empty command string in whitelist check
refactor(clx-core): extract credential storage to dedicated module
test(clx-hook): add pre_tool_use integration tests
docs(contributing): clarify Ollama setup requirements
```

---

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:
   ```sh
   git checkout -b feat/my-feature
   ```

2. **Make your changes**, keeping commits focused and following the commit format above.

3. **Ensure all checks pass locally** before pushing:
   ```sh
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```

4. **Push** your branch and **open a Pull Request** against `main` on GitHub.

5. In your PR description, include:
   - What problem this solves or feature it adds
   - How you tested it
   - Any trade-offs or follow-up work you are aware of

6. A maintainer will review your PR. Please respond to review comments promptly. Discussions should be resolved before merging.

7. PRs are merged via squash-merge to keep the `main` history clean.

---

## Reporting Issues

Before opening an issue, please search existing issues to avoid duplicates.

When reporting a bug, include:
- CLX version (`clx --version`)
- Rust toolchain version (`rustc --version`)
- Operating system and version
- Ollama version and models in use (if relevant)
- Steps to reproduce
- Expected behavior vs actual behavior
- Any relevant logs (from `~/.clx/logs/` or stderr with `CLX_LOG=debug`)

For feature requests, describe the problem you are trying to solve rather than jumping straight to a proposed solution — this helps the maintainers understand the use case.

For security issues, do NOT open a public issue. Please report them through [GitHub Security Advisories](https://github.com/blackaxgit/clx/security/advisories).
