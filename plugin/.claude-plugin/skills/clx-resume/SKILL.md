---
name: clx-resume
description: >
  Use when the user wants to resume earlier work on a specific topic,
  ticket, or file area from a prior session. Orchestrates
  mcp__clx__clx_recall plus snapshot reads, then confirms before acting.
  Examples: "resume the recall accuracy work", "pick up where we left
  off on the Azure fallback", "continue the dashboard refactor". Do NOT
  use to start brand-new work, or to auto-replay prior steps without
  user confirmation; recalled context may be stale.
version: 0.8.0
---

# clx-resume

Multi-step protocol for resuming a prior thread of work.

## When to use

Trigger phrases:

- "resume X", "pick up where we left off on X", "continue the X work",
- "go back to the Y refactor", "let's keep going with Z from last time".

The user is explicitly invoking continuity, not asking a fresh question.

## When NOT to use

- A brand-new topic with no prior session history.
- Single-fact lookups ("what did we decide" -> use `clx-recall` directly).
- The current session already contains the prior work (just keep going).

## Resume protocol (5 steps)

1. Recall by topic: invoke `mcp__clx__clx_recall` with a focused query
   pulled from the user's resume phrase. Prefer distinctive nouns.
2. Inspect the top 1 to 3 hits: read their summaries plus snapshot
   timestamps. Identify the most recent relevant checkpoint or snapshot.
3. Surface the plan back to the user: "Last session on this topic on
   <date> we did A, B, and stopped at C with TODO D. Resume from D?"
4. Wait for user confirmation before taking action. Recalled state may
   be superseded (branch merged, file refactored, decision reversed).
5. Optionally invoke `mcp__clx__clx_checkpoint` to mark the resume
   point, so a future resume can find this restart cleanly.

## Worked example

User: "resume the recall accuracy work".

Claude:

- Step 1: `clx_recall("recall accuracy RAGAS pipeline")`.
- Step 2: top hit is a checkpoint from 4 days ago titled "RRF plus
  reranker design accepted; bge-reranker-v2-m3 chosen; TODO write
  rerank.rs".
- Step 3: "Last session: design accepted, file plan locked, next step
  was writing `crates/clx-core/src/recall/rerank.rs`. Pick up there?"
- Step 4: user says "yes".
- Step 5: `clx_checkpoint("resume: writing rerank.rs")`, then start.

## Anti-pattern guard

- Do not auto-execute steps from the recalled plan without user
  confirmation in step 4. Code may have moved, decisions may have
  reversed, and silent re-execution causes regressions.
- Do not chain three or more `clx_recall` calls trying to assemble a
  full history; if step 1 misses, ask the user for a sharper hint.
- Do not skip step 3; surfacing the plan is what turns recall into
  resume. Without it, this is just `clx-recall`.
- Do not invoke for fresh topics; a vacuous resume protocol wastes
  user time.

## Failure modes

- Recall returns nothing: the topic may be new, or named differently in
  prior sessions. Ask the user for a synonym or date hint.
- Recall returns stale state (file deleted, branch merged): note this
  honestly and ask whether to proceed, replan, or abandon.
- Multiple plausible threads: list the top 2 to 3 and ask which one.

_Last verified: 2026-05-16._
