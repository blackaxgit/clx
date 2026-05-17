---
name: clx-remember
description: >
  Use when the user states a durable preference, decision, or fact worth
  carrying across sessions on this machine. Invokes
  mcp__clx__clx_remember to persist a single short fact. Examples:
  "remember that we use Conventional Commits", "save this decision about
  Azure tenant routing", "note that prod uses M-series only". Do NOT use
  for transient state, draft code, speculation, secrets, PII, or large
  in-flight context (use clx-checkpoint for snapshots instead).
---

# clx-remember

Persist one durable fact, preference, or decision into CLX memory.

## When to use

Trigger phrases:

- "remember that...", "note that...", "save this fact...",
- "from now on we...", "decision: ...", "rule: ...",
- "for future sessions, know that...".

A good `clx_remember` candidate is short, declarative, and useful next
week (not just for the next reply).

## What qualifies as a durable memory

- Decisions: "we picked Postgres over MySQL for project X".
- Preferences: "user prefers functional style over OOP".
- Gotchas: "the staging DB rejects unicode-5 emoji in identifiers".
- Conventions: "commit subjects use Conventional Commits, no AI trailers".
- Environment facts: "prod runs only on M-series; no x86 binaries".

## What does NOT qualify

- One-off code or draft snippets (use git / files).
- Transient session state (already in transcript / recall covers it).
- Speculative "we might..." or "consider..." (not yet a decision).
- Secrets, API keys, tokens, PII, PHI; CLX redacts known shapes but do
  not rely on redaction as a primary safeguard.
- Long multi-paragraph contexts; use `clx-checkpoint` for those.

## How to phrase the saved fact

- Declarative, present tense: "CLX commits never include AI signatures."
- Add a date or scope if it matters: "As of 2026-05-16, reranker default
  is on."
- Self-contained: a reader two months from now should understand it
  without the current transcript.

## How it works

Invokes `mcp__clx__clx_remember(content, ...)`. CLX stores the fact as a
snapshot with trigger=`Explicit`, returns the new snapshot id. Future
`clx_recall` calls will surface it when relevant.

## Example invocation

User: "remember that we never push --force to main".

Claude: confirms intent ("Save 'never push --force to main' as a durable
rule?"), invokes `mcp__clx__clx_remember` with the declarative form,
echoes the returned snapshot id.

## Anti-pattern guard

- Do not auto-save every assistant turn; CLX is curated, not a transcript
  log (see design spec section 3.2).
- Do not save secrets even if the user pastes them; refuse and explain.
- Do not save speculative drafts; wait for the user to confirm a decision.
- If the fact is large or multi-section, suggest `clx-checkpoint` instead.

_Last verified: 2026-05-16._
