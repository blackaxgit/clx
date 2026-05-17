---
name: clx-rules
description: >
  Use when the user asks "what rules apply here", after a long session
  where CLAUDE.md instructions may have decayed from context, or when
  rule violations seem likely. Invokes mcp__clx__clx_rules to refresh
  project, user, and org rules in precedence order. Examples: "what
  coding rules apply", "refresh project rules", "remind me of the commit
  convention". Do NOT invoke at the start of every turn; rules are
  already injected via CLAUDE.md on session start.
---

# clx-rules

Refresh active CLAUDE.md and org-level rules into the working context.

## When to use

Trigger phrases:

- "what rules apply", "refresh rules", "remind me of the conventions",
- "what does CLAUDE.md say about X",
- "what are the org-level constraints", "what is the commit convention".

Also use proactively (without explicit ask) when:

- Session has run more than 50 turns and rule-sensitive work is starting.
- A `/compact` just ran; rule context may have been summarized away.
- About to touch a sensitive area (security, schema, public API surface).

## How it works

Invokes `mcp__clx__clx_rules`. CLX returns the active rule sets, merged
by precedence:

1. Org rules (highest; managed by administrator).
2. User rules (`~/.claude/CLAUDE.md`).
3. Project rules (`<repo>/CLAUDE.md`).
4. Per-project CLX overlay (`<repo>/.clx/config.yaml`) for routing only.

Where two rules conflict, the higher tier wins. The tool returns the
merged view so Claude can act without re-reading three files.

## Example output shape

```
[org]   No emdashes in output. No PHI. Minimal emojis.
[user]  Atomic commits per logical unit. No AI signatures.
[proj]  Conventional Commits. <type>(<scope>): <subject>.
```

The output is a structured envelope; the example above is a render hint,
not the raw payload.

## When NOT to invoke

- Start of every assistant turn; CLAUDE.md is already injected.
- After every tool call; the rule set does not change per tool.
- When the user is mid-typing a different question (do not interrupt
  flow with an unprompted rule dump).

## Staleness signals (when refresh is warranted)

- Claude proposes an action that obviously violates a known rule
  (e.g., suggests an emdash, or an AI Co-Authored-By trailer).
- A long session has compressed earlier turns; rule text may be gone.
- Cross-tier ambiguity surfaced (project says X, org says Y).

## Anti-pattern guard

- Do not invoke as a reflex. Excessive refresh wastes tokens and adds
  noise.
- Do not paraphrase rules from memory; call the tool and quote.
- Do not invoke to "look helpful"; only on a real staleness signal.

_Last verified: 2026-05-16._
