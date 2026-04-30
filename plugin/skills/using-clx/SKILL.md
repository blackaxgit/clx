---
name: using-clx
description: >
  Use when working in a Claude Code session with CLX installed and persistent
  memory is relevant — specifically when the user references prior work
  ("earlier", "we discussed", "before", "last time"), when a decision or
  preference surfaces that should survive across sessions, before a risky or
  hard-to-reverse change, or when deciding whether to call clx_recall,
  clx_remember, clx_checkpoint, or clx_rules. Covers CLX's memory model, MCP
  tool triggers, query craft, result interpretation, and how CLX memory relates
  to Claude's native auto-memory and context compression.
---

# Using CLX

_Body sections filled in by Tasks 3–7._

## Backend choice

CLX supports two LLM backends: a local Ollama server (default) and Azure OpenAI (opt-in). Which backend serves which capability is configured per-install in `~/.clx/config.yaml` under the `providers:` and `llm:` sections, with chat and embeddings routable independently. The MCP tools (`clx_recall`, `clx_remember`, `clx_checkpoint`, `clx_rules`) work the same regardless of which backend is configured — the choice is invisible at the tool level. If a recall returns "embedding model changed", the user has switched embedding providers and must run `clx embeddings rebuild`.
