---
name: clx-checkpoint
description: >
  Use when the user is about to perform a risky, large, or hard-to-reverse
  change so the pre-change context is recoverable. Invokes
  mcp__clx__clx_checkpoint to snapshot the current session. Examples:
  "checkpoint before refactor",
  "snapshot the current state before migration", "save context before
  squash". Do NOT use on every assistant turn (that is auto-summarize, off
  by default), or for single small facts (use clx-remember instead).
version: 0.8.0
---

# clx-checkpoint

Snapshot the current session before a risky operation.

## When to use

Trigger phrases:

- "checkpoint before X", "snapshot before X",
- "save context before squash / migration / force-push",
- "before this refactor, capture where we are".

What counts as risky enough to checkpoint:

- Mass-rename or sweeping refactor across many files.
- Schema migration, especially destructive ones (drop column, rename table).
- `git rebase -i`, `git reset --hard`, squash, or any history rewrite.
- `force-push`, branch deletion, or stash drop.
- Long-running script that touches the working tree (codemods, formatters).
- A "let's try a different approach" pivot mid-task.

## How it differs from clx-remember

| Aspect          | clx-remember             | clx-checkpoint                |
|-----------------|--------------------------|-------------------------------|
| Scope           | one short fact           | full session summary          |
| Trigger         | new durable preference   | imminent risky change         |
| Frequency       | as facts appear          | rare, intentional             |
| Recovery use    | inform future replies    | reconstruct pre-change state  |

If unsure: small declarative fact -> remember; whole-context save-before-
risk -> checkpoint.

## How it works

Invokes `mcp__clx__clx_checkpoint(label?)`. CLX summarizes the active
session, writes a snapshot with `trigger=Checkpoint`, and returns the
snapshot id. The id is useful to cite if you need to recall the
pre-change state later.

## Retrieval pattern

If the risky change goes wrong:

1. Use `clx-recall` with a topic-specific query plus the date.
2. Identify the checkpoint snapshot in results (trigger=Checkpoint).
3. Read its summary to reconstruct the prior plan and pick up cleanly.

## Anti-pattern guard

- Do not checkpoint on every assistant turn; that is the job of opt-in
  `memory.auto_summarize` (off by default in 0.8.0).
- Do not checkpoint trivial edits (one-line config tweak, doc typo).
- Do not checkpoint as a substitute for `git commit`; checkpoints are
  context, not code state.

_Last verified: 2026-05-16._
