---
name: clx-recall
description: >
  Use when the user references earlier sessions, prior decisions, or asks
  "what did I do" / "did we already" about past work in this repo. Invokes
  mcp__clx__clx_recall to search the local CLX snapshot store. Examples:
  "look up our Azure backend discussion", "find checkpoints from yesterday",
  "what did we decide about retries". Do NOT use for current-session
  context (already in the transcript), real-time data, or web search; do
  not use for secrets retrieval.
---

# clx-recall

Search CLX persistent memory for context from earlier sessions on this machine.

## When to use

Invoke `mcp__clx__clx_recall` when the user phrasing implies cross-session
lookup, not within-turn context. Trigger phrases include:

- "earlier we...", "last time...", "before, when we...",
- "what did we decide about X", "how did we end up doing Y",
- "find the discussion about Z", "look up the checkpoint from yesterday".

## When NOT to use

Skip recall and do not invoke this skill for:

- context already visible in the current Claude Code transcript,
- real-time or external data (weather, prices, current docs),
- secrets, API keys, or credentials (CLX redacts these on save),
- generic memory-shaped phrases without a specific topic ("remember stuff"),
- the very start of a brand-new topic with no prior session history.

## How it works

CLX runs a hybrid pipeline locally:

1. Embeddings top-50 plus FTS5 top-50.
2. Reciprocal Rank Fusion (k=60) merges the two rankings.
3. Optional cross-encoder rerank (bge-reranker-v2-m3) on the top fused set.
4. Multiplicative time-decay (30-day half-life by default).
5. Percentile gate (p70) plus pinned recent sessions if configured.

Result is up to 10 ranked hits, each with `score`, `snapshot_id`, summary,
and source session id. Latency budget: 500 ms p95.

## Query craft

- Prefer topic plus distinctive noun: "Azure tenant routing decision",
  not "memory thing".
- Include a date hint when the user gives one: "from yesterday",
  "last week's debounce work".
- Avoid stop-word-only queries ("the issue", "that thing").
- One focused query per turn beats three vague ones.

## Result interpretation

- Score bands: >= 0.8 strong match, 0.5 to 0.8 plausible, < 0.5 weak.
- Time-decay means older but high-similarity hits can still surface; check
  the snapshot timestamp before trusting it as current.
- If results look stale or contradict the current branch, recall and
  reconcile rather than guess.

## Failure modes

- Empty results: index may be cold (fresh install) or topic genuinely new.
  Suggest `clx_remember` going forward; do not fabricate history.
- "embedding model changed": user switched embedding providers; advise
  `clx embeddings rebuild` (see `clx-doctor`).
- Provider 5xx during recall: CLX falls back per its config; latency may
  spike to ~1 s. If results look inconsistent across calls, see `clx-doctor`.

## Example invocation

User: "what did we decide about the retry timeout last week?"

Claude: invokes `mcp__clx__clx_recall` with query "retry timeout decision",
inspects the top hit's summary plus snapshot timestamp, then summarizes
the decision and cites the snapshot id back to the user.

## Anti-pattern guard

Do not invoke for current-turn context (Claude already has it). Do not
invoke speculatively before every assistant reply; recall is a tool, not
a reflex. One miss is fine; two retries with reworded queries are the
upper bound before falling back to asking the user.

_Last verified: 2026-05-16._
