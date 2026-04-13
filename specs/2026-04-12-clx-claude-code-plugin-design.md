# CLX Claude Code Plugin — Design Spec

**Date:** 2026-04-12
**Status:** Draft, pending user review
**Target version:** ships with next CLX release (version pinned to CLX version)

## 1. Goal & Scope

### Goal

Ship a Claude Code plugin, bundled inside the `clx` repo, whose primary job is to
teach Claude *how to use CLX's memory system effectively* — so that a Claude
session with CLX installed actually leverages `clx_recall`, `clx_remember`,
`clx_checkpoint`, and `clx_rules` at the right moments, understands the memory
model under the hood, writes good recall queries, interprets results correctly,
and knows how CLX memory relates to Claude's native auto-memory and context
compression.

The plugin is a **knowledge payload**, not a wiring harness. It assumes CLX is
already installed and its MCP server is already registered. The installer owns
installation; the plugin owns "Claude knowing what to do with it".

### In scope (v1)

- A single skill `using-clx` containing all five topic areas, loaded on demand
  via progressive disclosure.
- A `plugin.json` manifest so the plugin is discoverable by Claude Code's plugin
  system.
- A `README.md` inside the plugin folder documenting what the plugin is, how to
  install it, and the hard assumptions it makes.
- A tiny `scripts/validate.sh` that statically checks `plugin.json` is valid JSON
  and `SKILL.md` has valid YAML frontmatter containing the required trigger
  keywords.

### Out of scope (v1)

- Bootstrap/install of CLX binaries. `install.sh` / `clx install` / Homebrew
  already own this.
- Hook registration and MCP server wiring. `clx install` already handles this,
  and mixing it in would muddy the plugin's purpose.
- Slash commands (`/clx-recall`, `/clx-dashboard`, etc.). Deferred to v2 if
  users actually want shortcuts; MCP tools are the v1 interface.
- Specialized subagents. Revisit if the skill grows unwieldy.
- Marketplace submission. Repo-local install is enough for v1; a marketplace
  entry is a metadata-only follow-up.

## 2. Repo Layout

A new top-level folder in the `clx` repo:

```
clx/
├── crates/                 # existing Rust workspace
├── plugin/                 # NEW
│   ├── plugin.json         # Claude Code plugin manifest
│   ├── README.md           # what it is, install steps, assumptions
│   ├── scripts/
│   │   └── validate.sh     # static checks for plugin.json + SKILL.md
│   └── skills/
│       └── using-clx/
│           └── SKILL.md    # the single skill (frontmatter + body)
└── ...
```

Rationale:

- `plugin/` at the root is symmetrical with `crates/`, `scripts/`, `docs/`.
- A single `SKILL.md` file matches the "one skill, everything inside" decision.
  Progressive disclosure is handled by the skill's frontmatter `description`
  (Claude decides whether to load the skill), not by sub-files.
- If a body section ever exceeds ~40 lines, it gets moved into a new
  `plugin/skills/using-clx/references/` folder and linked from the main file.
  Not created pre-emptively.
- If later versions add hooks or commands, they slot into `plugin/hooks/` and
  `plugin/commands/` without restructuring.

### Versioning

Plugin version equals CLX version. When CLX bumps (for example 0.5.3 → 0.5.4),
`plugin/plugin.json` bumps in the same commit. Skill content and MCP tool
surface stay in lockstep.

## 3. `plugin.json`

Minimal v1 manifest. No `mcpServers`, `hooks`, or `commands` blocks — this
plugin ships skills only.

```json
{
  "name": "clx",
  "version": "<matches CLX version>",
  "description": "Teaches Claude how to use CLX's persistent memory system effectively.",
  "skills": "./skills"
}
```

Exact field names will be validated against the current Claude Code plugin
schema during implementation. If the schema uses a different key for skill
directories, adjust accordingly — the structural decision (skills-only plugin)
is what matters.

## 4. Skill Content

### 4.1 Frontmatter

```yaml
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
```

The `description` is the load-bearing field — it is what Claude's skill matcher
weighs to decide whether to load the skill. It deliberately:

- leads with concrete phrase triggers the matcher can hit on;
- names all four MCP tools by exact identifier for keyword matching;
- ends with a topic summary so Claude can judge whether loading is worthwhile.

First draft. Will be revisited only if the behavioral smoke test in §5 shows the
skill consistently misfires.

### 4.2 Body sections

The body is organized into five sections matching the five topics in scope.
Target total length is 150–200 lines. If any section exceeds ~40 lines, move it
to `references/` and link into it from the body.

#### Section 1 — Memory Model

How CLX stores state end-to-end:

- SQLite `sessions` and `snapshots` tables.
- `PreCompact` hook captures a snapshot before Claude Code compresses context.
- Ollama generates the snapshot summary and the embedding vector.
- Hybrid retrieval: sqlite-vec semantic search plus FTS5 keyword fallback.
- Auto-recall injects relevant past sessions into every prompt as
  `additionalContext`, subject to configurable thresholds.

One paragraph per bullet, plus a small ASCII diagram of the flow. Anchors
Claude's mental model so the rest of the skill makes sense.

#### Section 2 — When to call each MCP tool

Compact decision table:

| Tool             | Trigger                                                                 | Anti-pattern                                                  |
| ---------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------- |
| `clx_recall`     | User references prior work; decision where past precedent matters.     | Using it to re-derive facts already in the open repo/git.     |
| `clx_remember`   | User states a preference, a non-obvious decision, a surprising fact.   | Saving code patterns, git history, or anything derivable.     |
| `clx_checkpoint` | Before a destructive or hard-to-reverse change.                        | Checkpointing routine edits that the next commit will cover.  |
| `clx_rules`      | Context feels stale; long session where system rules may have drifted. | Calling it on every turn.                                     |

Each row has one or two concrete trigger examples in the body.

#### Section 3 — Query Craft

How to phrase `clx_recall` queries so the hybrid retriever actually finds what
you want:

- Semantic queries work on intent — `"authentication decisions"` beats
  `"auth.rs login function"`.
- FTS5 fallback works on literal tokens — use it for error messages, exact
  function names, file paths.
- Scoping: narrow by session when possible, broaden only if nothing comes back.
- Multiple narrow queries beat one broad query when the topic is ambiguous.

#### Section 4 — Interpreting Results

Recall returns *what was true at a point in time*, which may be stale. Protocol:

1. Treat the recalled answer as a hypothesis, not ground truth.
2. Verify against live code, config, or git history before acting.
3. On conflict, prefer current observation over remembered claim.
4. Update or drop the memory if it turns out to be wrong.
5. Explicitly handle the "memory says X exists → check X actually exists"
   case before recommending X.

#### Section 5 — CLX vs. native auto-memory vs. context compression

Three persistence layers, when to use which:

- **Claude's native auto-memory** (`~/.claude/projects/.../memory/`) —
  user / feedback / project / reference facts, per-project, long-lived.
- **CLX memory** — session transcripts, snapshots, semantic search across full
  history, cross-session continuity of work.
- **Context compression** — within-session summarization, ephemeral.

Rule of thumb (the load-bearing sentence):

> Facts about the user → auto-memory. Facts about past work or sessions → CLX.
> Stuff only relevant this session → nothing, let compression handle it.

Each layer gets one concrete worked example.

## 5. Install, Assumptions, Verification

### Install (v1)

The plugin is installed manually from a `clx` checkout:

```bash
# from a clx checkout
ln -s "$(pwd)/plugin" ~/.claude/plugins/clx
# or copy instead of symlinking
```

Then restart Claude Code. Marketplace publishing is deferred; adding it later
is a metadata-only change.

### Hard assumptions

1. CLX binaries (`clx`, `clx-hook`, `clx-mcp`) are already installed and on
   `$PATH` via `install.sh`, Homebrew, or `clx install`.
2. `clx-mcp` is already registered as an MCP server in Claude Code's config —
   the skill references tools that only exist if the MCP server is wired up.
3. Ollama is running with the models CLX expects (`qwen3:1.7b`,
   `qwen3-embedding:0.6b`).

The plugin README states these upfront in bold and points at `install.sh` and
`INSTALL.md`. There is no runtime probing; if the assumptions are violated the
user sees normal Claude Code "tool not found" errors, which is honest.

### Verification

The plugin has no executable code, so there is nothing to unit test.
Verification has two parts:

**Static checks** — `plugin/scripts/validate.sh` runs in CI and checks:

- `plugin.json` parses as valid JSON.
- `SKILL.md` has valid YAML frontmatter.
- The frontmatter `description` contains every required trigger keyword
  (`earlier`, `we discussed`, `clx_recall`, `clx_remember`, `clx_checkpoint`,
  `clx_rules`, `persistent memory`).

**Behavioral smoke test** — a short checklist in `plugin/README.md` the author
runs by hand before each release:

1. Start a Claude Code session with the plugin installed.
2. Prompt: *"We talked about the retry logic earlier — can you remind me what
   we decided?"* → Claude loads the skill and calls `clx_recall`.
3. Prompt: *"From now on I want errors logged as structured JSON."* → Claude
   calls `clx_remember`.
4. Prompt: *"I'm about to drop the `snapshots` table."* → Claude calls
   `clx_checkpoint` before any destructive action.

Pass criteria: the skill loads and the correct MCP tool gets invoked in each
case. No CI integration tests against Claude Code itself — too brittle, too
much plumbing for a skill-only plugin.

## 6. Decisions Locked In

- **Scope:** A+slash-commands? No — just A. Knowledge payload only for v1.
- **Decomposition:** One skill, everything inside. Not split, not a subagent.
- **Distribution:** Bundled in the `clx` repo under `plugin/`, not a separate
  repo.
- **`requires_mcp_server` field in `plugin.json`:** No. Document the
  dependency in README and the skill body instead. If Claude Code later
  defines a standard dependency field, add it in a follow-up.
- **Pre-emptive `references/` subfolder:** No. Create it the moment a body
  section exceeds ~40 lines, not before.
- **Frontmatter `description`:** locked to the draft in §4.1, revisited only
  if smoke tests show misfires.

## 7. Risks & Mitigations

1. **Skill trigger misfires.** The whole plugin rides on Claude's skill
   matcher loading `using-clx` at the right moment.
   *Mitigation:* the behavioral smoke test catches both under- and
   over-triggering. Fix is a `description` rewrite.

2. **Drift between skill content and CLX behavior.** The skill describes MCP
   tool names, memory-model internals, and thresholds. If CLX changes and the
   skill does not, Claude starts recommending a CLX that no longer exists.
   *Mitigation:* co-location in the same repo and a `CONTRIBUTING.md` note
   that MCP tool surface changes require a skill update in the same PR.

3. **Overlap with Claude's auto-memory system.** If the "three layers" rule of
   thumb in §4.2 Section 5 is wrong or confusing, Claude will double-save or
   double-dip.
   *Mitigation:* that rule-of-thumb sentence gets a careful review pass and a
   concrete example per layer.

4. **Plugin ships but MCP server is not wired.** User installs the plugin,
   skill loads, Claude calls `clx_recall`, gets "tool not found".
   *Mitigation:* README lead paragraph states the assumption in bold; no
   runtime magic. Honest failure beats silent fallback.

## 8. Deferred to v2

- Slash commands (`/clx-recall`, `/clx-dashboard`, `/clx-health`).
- Marketplace submission and `/plugin install clx` support.
- A `clx-memory-curator` subagent, if the single skill grows too heavy.
- Any hook or MCP server registration from within the plugin.

Each of these is a purely additive change — nothing in the v1 design precludes
any of them.
