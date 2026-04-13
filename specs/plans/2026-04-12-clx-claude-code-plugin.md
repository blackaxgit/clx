# CLX Claude Code Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Claude Code plugin bundled inside the `clx` repo that teaches Claude how to use CLX's persistent memory system effectively (`clx_recall`, `clx_remember`, `clx_checkpoint`, `clx_rules`).

**Architecture:** Skills-only plugin under `plugin/` at the repo root. A single skill (`using-clx`) holds all five topic areas (memory model, MCP tool triggers, query craft, result interpretation, layer comparison). No hooks, no MCP server registration, no commands, no bootstrap — the installer already owns those.

**Tech Stack:** Plain YAML + Markdown (skill content), JSON (plugin manifest), Bash + `jq` + Python (validator script), GitHub Actions (CI wiring).

**Spec:** `specs/2026-04-12-clx-claude-code-plugin-design.md`

---

## File Structure

Files created by this plan:

| Path                                          | Responsibility                                                   |
| --------------------------------------------- | ---------------------------------------------------------------- |
| `plugin/plugin.json`                          | Plugin manifest — name, version, description, skills pointer.   |
| `plugin/README.md`                            | What the plugin is, install steps, hard assumptions, smoke test. |
| `plugin/scripts/validate.sh`                  | Static checks: valid JSON, valid frontmatter, required triggers. |
| `plugin/skills/using-clx/SKILL.md`            | The single skill file — frontmatter + 5 body sections.          |
| `.github/workflows/ci.yml` (modified)         | New `plugin-validate` job that runs `validate.sh`.              |

No Rust code is modified. No existing files outside `.github/workflows/ci.yml` are touched.

---

## Task 1: Scaffold plugin directory and `plugin.json`

**Files:**
- Create: `plugin/plugin.json`
- Create: `plugin/skills/using-clx/` (directory)
- Create: `plugin/scripts/` (directory)

- [ ] **Step 1: Create the directory tree**

```bash
mkdir -p plugin/skills/using-clx plugin/scripts
```

- [ ] **Step 2: Write `plugin/plugin.json`**

```json
{
  "name": "clx",
  "version": "0.5.3",
  "description": "Teaches Claude how to use CLX's persistent memory system effectively — memory model, MCP tool triggers (clx_recall, clx_remember, clx_checkpoint, clx_rules), query craft, result interpretation, and layer comparison with native auto-memory.",
  "skills": "./skills"
}
```

Version `0.5.3` matches the current CLX Cargo workspace version. Per the spec, plugin version always matches CLX version; future CLX releases must bump both in the same commit.

- [ ] **Step 3: Verify the JSON parses**

Run: `python3 -m json.tool plugin/plugin.json > /dev/null && echo OK`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add plugin/plugin.json
git commit -m "feat(plugin): scaffold clx Claude Code plugin manifest"
```

---

## Task 2: Write `validate.sh` (TDD-style) and minimal `SKILL.md` stub

**Files:**
- Create: `plugin/scripts/validate.sh`
- Create: `plugin/skills/using-clx/SKILL.md` (stub only, full content in later tasks)

- [ ] **Step 1: Write `plugin/scripts/validate.sh`**

```bash
#!/usr/bin/env bash
# Static validator for the CLX Claude Code plugin.
# Checks:
#   1. plugin.json parses as valid JSON.
#   2. SKILL.md has valid YAML frontmatter.
#   3. Frontmatter description contains every required trigger keyword.
# Exits non-zero on any failure.

set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$PLUGIN_DIR/plugin.json"
SKILL="$PLUGIN_DIR/skills/using-clx/SKILL.md"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# 1. plugin.json must exist and parse as valid JSON.
[ -f "$MANIFEST" ] || fail "plugin.json not found at $MANIFEST"
python3 -m json.tool "$MANIFEST" > /dev/null || fail "plugin.json is not valid JSON"

# 2. SKILL.md must exist and start with YAML frontmatter block.
[ -f "$SKILL" ] || fail "SKILL.md not found at $SKILL"
head -1 "$SKILL" | grep -qx -- '---' || fail "SKILL.md does not start with YAML frontmatter (---)"

# Extract frontmatter block (lines between the first two --- markers).
frontmatter="$(awk '/^---$/{c++; next} c==1{print} c==2{exit}' "$SKILL")"
[ -n "$frontmatter" ] || fail "SKILL.md frontmatter block is empty"

# 3. Required trigger keywords must appear in the frontmatter.
required=(
    "earlier"
    "we discussed"
    "clx_recall"
    "clx_remember"
    "clx_checkpoint"
    "clx_rules"
    "persistent memory"
)
for kw in "${required[@]}"; do
    printf '%s\n' "$frontmatter" | grep -qi -- "$kw" \
        || fail "frontmatter missing required trigger keyword: '$kw'"
done

echo "OK: plugin/plugin.json and plugin/skills/using-clx/SKILL.md are valid."
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x plugin/scripts/validate.sh`

- [ ] **Step 3: Run it — expect failure (SKILL.md missing)**

Run: `./plugin/scripts/validate.sh`
Expected: exits non-zero, prints `FAIL: SKILL.md not found at .../plugin/skills/using-clx/SKILL.md`.

- [ ] **Step 4: Write minimal `plugin/skills/using-clx/SKILL.md` stub**

```markdown
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
```

- [ ] **Step 5: Run validator again — expect success**

Run: `./plugin/scripts/validate.sh`
Expected: exits zero, prints `OK: plugin/plugin.json and plugin/skills/using-clx/SKILL.md are valid.`

- [ ] **Step 6: Commit**

```bash
git add plugin/scripts/validate.sh plugin/skills/using-clx/SKILL.md
git commit -m "feat(plugin): add validator and using-clx skill scaffold"
```

---

## Task 3: Fill SKILL.md Section 1 — Memory Model

**Files:**
- Modify: `plugin/skills/using-clx/SKILL.md` (append body section)

- [ ] **Step 1: Replace the stub body with Section 1**

Replace the line `_Body sections filled in by Tasks 3–7._` with:

````markdown
## 1. Memory Model

CLX persists session state in a local SQLite database (`~/.clx/clx.db`) with two primary tables: `sessions` (per-session metadata) and `snapshots` (summarized transcript content). The flow end-to-end:

```
Claude Code session
        |
        | PreCompact hook fires before context compression
        v
clx-hook reads transcript
        |
        | Ollama generates summary
        | Ollama generates embedding vector
        v
SQLite: sessions + snapshots + vector index
        |
        | On every new prompt:
        |   auto-recall runs hybrid search
        |   (sqlite-vec semantic + FTS5 keyword fallback)
        v
Top-K relevant past sessions injected as additionalContext
```

Key points:

- **Automatic snapshotting.** You do not have to call anything to persist a session; the `PreCompact` hook captures a snapshot before Claude Code compresses context. `clx_checkpoint` exists for the cases where you want a snapshot _now_, not later.
- **Hybrid retrieval.** `clx_recall` runs both a semantic (sqlite-vec) search and an FTS5 keyword search and merges the results. Semantic search wins on intent; FTS5 wins on literal tokens (error messages, function names, file paths).
- **Auto-recall.** Every prompt is augmented with the top-K relevant past sessions as `additionalContext`, subject to `similarity_threshold` and `max_results` in `~/.clx/config.yaml`. Explicit `clx_recall` calls are for when auto-recall did not surface what you need.
- **Ollama dependency.** Summarization and embeddings require Ollama running with `qwen3:1.7b` (summarization) and `qwen3-embedding:0.6b` (embeddings). If Ollama is down, CLX degrades to FTS5-only retrieval.
````

- [ ] **Step 2: Run the validator — expect success**

Run: `./plugin/scripts/validate.sh`
Expected: `OK: ...`

- [ ] **Step 3: Commit**

```bash
git add plugin/skills/using-clx/SKILL.md
git commit -m "docs(plugin): add memory model section to using-clx skill"
```

---

## Task 4: Fill SKILL.md Section 2 — MCP Tool Triggers

**Files:**
- Modify: `plugin/skills/using-clx/SKILL.md` (append body section)

- [ ] **Step 1: Append Section 2 to `SKILL.md`**

````markdown

## 2. When to Call Each MCP Tool

| Tool             | Call when                                                                                                      | Do not call when                                                       |
| ---------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `clx_recall`     | User references prior work ("earlier", "we discussed", "last time"); decision where past precedent matters.  | Re-deriving facts already visible in the open repo or git history.    |
| `clx_remember`   | User states a preference, makes a non-obvious decision, or a surprising fact surfaces worth cross-session.   | Saving code patterns, architecture, or anything derivable from code. |
| `clx_checkpoint` | Before a destructive or hard-to-reverse change (dropping tables, force push, rm -rf, schema migrations).    | Routine edits the next commit will cover anyway.                      |
| `clx_rules`      | Context feels stale; the session is long and system rules may have drifted out of context.                   | Calling it every turn "just in case".                                  |

Concrete examples:

- User: *"Remind me what we decided about retry backoff last week."* → call `clx_recall("retry backoff decision")`.
- User: *"From now on, log all errors as structured JSON."* → call `clx_remember("user preference: log errors as structured JSON")`.
- User: *"Go ahead and drop the `snapshots` table and recreate it."* → call `clx_checkpoint("before dropping snapshots table")` _first_, then proceed.
- You are 90 minutes into a session, user's earlier style rules are not in your context anymore → call `clx_rules` once to refresh.

**Anti-pattern:** saving things that are already derivable. Do not `clx_remember` that "the project uses Rust and SQLite" — the `Cargo.toml` and source files already prove that. Memory is for facts that cannot be recovered by reading the current state.
````

- [ ] **Step 2: Run the validator — expect success**

Run: `./plugin/scripts/validate.sh`
Expected: `OK: ...`

- [ ] **Step 3: Commit**

```bash
git add plugin/skills/using-clx/SKILL.md
git commit -m "docs(plugin): add MCP tool trigger table to using-clx skill"
```

---

## Task 5: Fill SKILL.md Section 3 — Query Craft

**Files:**
- Modify: `plugin/skills/using-clx/SKILL.md` (append body section)

- [ ] **Step 1: Append Section 3 to `SKILL.md`**

````markdown

## 3. Query Craft

`clx_recall` runs a hybrid semantic + FTS5 search. Queries that work for one do not necessarily work for the other. Rules:

- **Semantic queries describe intent, not identifiers.** `"authentication decisions"` beats `"auth.rs login function"`. The embedding model matches concepts, not exact tokens.
- **FTS5 fallback catches literal tokens.** If the thing you need is an error message, a rare function name, a file path, or a config key, include the literal string in the query. FTS5 will match it even when semantic search would miss.
- **Narrow first, broaden only if empty.** Start with a specific query. If zero results come back, widen — don't front-load a kitchen-sink query that drowns the top-K with low-relevance matches.
- **Two narrow queries beat one broad query when the topic is ambiguous.** If the user asks about "the auth thing", run `clx_recall("authentication session handling")` _and_ `clx_recall("authorization role checks")` rather than `clx_recall("auth")`.
- **Do not pad queries with stopwords.** `"what did we decide about retry backoff"` is worse than `"retry backoff decision"` — the first wastes embedding budget on filler.

Example progression:

1. User: *"What did we decide about connection pooling?"*
2. First query: `clx_recall("connection pool sizing decision")` — semantic, narrow.
3. If empty, widen: `clx_recall("database connection pool")`.
4. If still empty, try a literal token you saw in the code: `clx_recall("PgPoolOptions max_connections")`.
````

- [ ] **Step 2: Run the validator — expect success**

Run: `./plugin/scripts/validate.sh`
Expected: `OK: ...`

- [ ] **Step 3: Commit**

```bash
git add plugin/skills/using-clx/SKILL.md
git commit -m "docs(plugin): add query craft section to using-clx skill"
```

---

## Task 6: Fill SKILL.md Section 4 — Interpreting Results

**Files:**
- Modify: `plugin/skills/using-clx/SKILL.md` (append body section)

- [ ] **Step 1: Append Section 4 to `SKILL.md`**

````markdown

## 4. Interpreting Results

A recall result is **what was true at a point in time**, not ground truth _now_. Treat it as a hypothesis. Protocol:

1. **Read the recalled snapshot as a claim, not a fact.** It describes a past session, not the current repo state.
2. **Verify against live state before acting.** If recall says "we decided to use `ServiceX`", check the code for `ServiceX` imports before recommending it. If recall says "the bug was in `foo.rs:42`", read `foo.rs:42` before proposing a fix.
3. **On conflict, prefer current observation.** The recall may be from a session that predated a subsequent decision. Fresh observation wins.
4. **Update or drop the memory if it is wrong.** If a recall result is contradicted by the current state and the contradiction is load-bearing (the user would act on it), save a new `clx_remember` that supersedes the stale entry.
5. **Handle the "memory says X exists" failure mode explicitly.** If recall says a file, function, or flag exists, _grep for it_ before using it as evidence. Memory is cheap; filesystem checks are cheaper.

Example failure mode to avoid:

- Recall returns: *"Decided to use `retry_with_backoff` helper in `utils/retry.rs`."*
- Wrong move: recommend `retry_with_backoff` to the user.
- Right move: `grep -n retry_with_backoff` first. If it does not exist, the helper was removed or renamed after the snapshot; do not cite it.
````

- [ ] **Step 2: Run the validator — expect success**

Run: `./plugin/scripts/validate.sh`
Expected: `OK: ...`

- [ ] **Step 3: Commit**

```bash
git add plugin/skills/using-clx/SKILL.md
git commit -m "docs(plugin): add result interpretation section to using-clx skill"
```

---

## Task 7: Fill SKILL.md Section 5 — Three Persistence Layers

**Files:**
- Modify: `plugin/skills/using-clx/SKILL.md` (append body section)

- [ ] **Step 1: Append Section 5 to `SKILL.md`**

````markdown

## 5. CLX vs. Native Auto-Memory vs. Context Compression

Three persistence layers are active at once. They serve different purposes and must not be confused.

| Layer                          | Location                                     | Lifetime              | Contains                                                               |
| ------------------------------ | -------------------------------------------- | --------------------- | ---------------------------------------------------------------------- |
| **Native auto-memory**         | `~/.claude/projects/<hash>/memory/`          | Long-lived, per-project | User facts, feedback, project facts, external references.            |
| **CLX memory**                 | `~/.clx/clx.db` (SQLite)                     | Long-lived, cross-session | Session transcripts, snapshots, searchable history of past work.   |
| **Context compression**        | In-process, current conversation             | Ephemeral             | Summarized earlier turns of _this_ session.                           |

**Rule of thumb:**

> Facts about the user → auto-memory. Facts about past work or sessions → CLX. Stuff only relevant this session → nothing, let compression handle it.

Worked examples:

- *"I prefer functional style over OOP."* → auto-memory (user fact, applies to every session).
- *"We decided to use exponential backoff with jitter in the retry module last Thursday."* → CLX (past-work fact, useful when retry logic comes up again).
- *"Let me remember to check that the test file is named `test_auth.py` before I run it."* → nothing. It is in the current context; compression will handle it.

**Do not double-save.** If you already saved a user preference to auto-memory, do not also `clx_remember` it — you will get duplicate hits from both layers during future recall.

**Do not double-dip on recall.** Native auto-memory loads automatically at session start; you do not need `clx_recall` to retrieve user facts. Use `clx_recall` only for the CLX layer (past-work facts).
````

- [ ] **Step 2: Run the validator — expect success**

Run: `./plugin/scripts/validate.sh`
Expected: `OK: ...`

- [ ] **Step 3: Check total line count is within the 150–200 target**

Run: `wc -l plugin/skills/using-clx/SKILL.md`
Expected: between roughly 140 and 220 lines. If significantly over (say, >260), stop and flag for review — one or more sections should be moved to `plugin/skills/using-clx/references/` per the spec's §2 escape hatch.

- [ ] **Step 4: Commit**

```bash
git add plugin/skills/using-clx/SKILL.md
git commit -m "docs(plugin): add persistence layer comparison to using-clx skill"
```

---

## Task 8: Write `plugin/README.md`

**Files:**
- Create: `plugin/README.md`

- [ ] **Step 1: Write `plugin/README.md`**

````markdown
# CLX Claude Code Plugin

Teaches Claude Code how to use CLX's persistent memory system effectively. Ships as a single skill (`using-clx`) that loads on demand when CLX-relevant prompts come in.

## What this plugin is (and is not)

**It is:** A knowledge payload. It tells Claude _when_ to call `clx_recall`, `clx_remember`, `clx_checkpoint`, and `clx_rules`, how CLX's memory model works, how to write good recall queries, and how CLX memory relates to Claude's native auto-memory and context compression.

**It is not:** An installer. It does not install CLX binaries, it does not register hooks, and it does not wire up the MCP server. Those are all handled by `clx install` / `install.sh` / Homebrew.

## Hard assumptions

**This plugin does nothing useful unless all of the following are true:**

1. **CLX binaries are installed and on `$PATH`.** Specifically `clx`, `clx-hook`, and `clx-mcp`. Install via `install.sh`, Homebrew (`brew install clx`), or `./target/release/clx install` from a source build. See the top-level `INSTALL.md`.
2. **`clx-mcp` is registered as an MCP server in Claude Code.** The skill references MCP tools (`clx_recall`, `clx_remember`, `clx_checkpoint`, `clx_rules`) that exist only if the MCP server is wired into Claude Code's config. `clx install` handles this automatically; if you installed manually, verify with `clx health`.
3. **Ollama is running** with models `qwen3:1.7b` and `qwen3-embedding:0.6b` pulled.

If any of these is violated, Claude will try to call MCP tools that do not exist and fail with normal "tool not found" errors. That is by design — the plugin does not silently degrade.

## Install

From a `clx` checkout:

```bash
# Symlink (recommended — picks up future updates automatically)
ln -s "$(pwd)/plugin" ~/.claude/plugins/clx

# Or copy
cp -R plugin ~/.claude/plugins/clx
```

Restart Claude Code. Verify with:

```bash
ls ~/.claude/plugins/clx/skills/using-clx/SKILL.md
```

Marketplace publishing (so `/plugin install clx` works out of the box) is planned but not included in this version.

## Smoke test

Run this checklist after installing, after every CLX version bump, and before shipping any skill content change.

Start a Claude Code session with the plugin installed, then issue each of the following prompts. In each case, Claude should load the `using-clx` skill and call the corresponding MCP tool.

1. **Recall test** — prompt: *"We talked about the retry logic earlier — can you remind me what we decided?"*
   - Expected: Claude calls `clx_recall` with a query that mentions retry logic.
2. **Remember test** — prompt: *"From now on I want all errors logged as structured JSON."*
   - Expected: Claude calls `clx_remember` to persist the preference.
3. **Checkpoint test** — prompt: *"I'm about to drop the `snapshots` table to recreate it fresh."*
   - Expected: Claude calls `clx_checkpoint` _before_ any destructive action.

If any step fails, the most likely cause is the skill's frontmatter `description` not matching the prompt. Adjust the description in `plugin/skills/using-clx/SKILL.md` and re-run.

## Static validation

```bash
./plugin/scripts/validate.sh
```

Checks that `plugin.json` parses, `SKILL.md` has valid frontmatter, and the frontmatter contains every required trigger keyword. Run on every change to plugin files. Also runs in CI.

## Version

Plugin version always equals CLX version. Bumping CLX in `Cargo.toml` requires bumping `plugin/plugin.json` in the same commit. See `CONTRIBUTING.md`.
````

- [ ] **Step 2: Run the validator — expect success (README does not affect validation but sanity-check the skill is still good)**

Run: `./plugin/scripts/validate.sh`
Expected: `OK: ...`

- [ ] **Step 3: Commit**

```bash
git add plugin/README.md
git commit -m "docs(plugin): add plugin README with install, assumptions, smoke test"
```

---

## Task 9: Wire `validate.sh` into CI

**Files:**
- Modify: `.github/workflows/ci.yml` — add a new `plugin-validate` job.

- [ ] **Step 1: Open `.github/workflows/ci.yml` and locate the `audit:` job (around line 179)**

The new job is appended after `audit:` at the bottom of the `jobs:` block. It uses `ubuntu-latest` (validator is pure Bash + Python 3), does not need the Rust toolchain, and does not need any caching.

- [ ] **Step 2: Append the new job**

Append these lines at the end of `.github/workflows/ci.yml`:

```yaml

  # ---------------------------------------------------------------------------
  # plugin-validate: static checks for the Claude Code plugin under plugin/.
  # No Rust dependency — just Bash + Python 3 (preinstalled on ubuntu-latest).
  # ---------------------------------------------------------------------------
  plugin-validate:
    name: Validate Claude Code plugin
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run plugin validator
        run: ./plugin/scripts/validate.sh
```

- [ ] **Step 3: Verify the YAML parses**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo OK`
Expected: `OK`

(If `yaml` is not installed: `python3 -c "import json, subprocess; subprocess.check_call(['yq', '.', '.github/workflows/ci.yml'], stdout=subprocess.DEVNULL)" && echo OK`. If neither is available, skip this check — GitHub Actions will validate on push.)

- [ ] **Step 4: Run the validator locally one more time to be sure the CI command works**

Run: `./plugin/scripts/validate.sh`
Expected: `OK: ...`

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(plugin): run plugin validator in CI"
```

---

## Task 10: Update `CONTRIBUTING.md` with the version-lockstep rule

**Files:**
- Modify: `CONTRIBUTING.md` — add a short "Claude Code plugin" section.

- [ ] **Step 1: Read the current `CONTRIBUTING.md` to pick the right insertion point**

Run: `cat CONTRIBUTING.md | head -80`

Look for an existing section on releases, versioning, or the Rust workspace. The new section goes immediately after that — or at the bottom of the file if no logical home exists.

- [ ] **Step 2: Append (or insert) this section**

```markdown
## Claude Code Plugin

The `plugin/` folder at the repo root ships the CLX Claude Code plugin — a skills-only plugin that teaches Claude how to use CLX's persistent memory system. It has two hard rules:

1. **Plugin version equals CLX version.** Bumping the workspace version in `Cargo.toml` requires bumping `plugin/plugin.json` in the same commit. Mismatched versions are a CI failure waiting to happen.
2. **MCP tool surface changes require a plugin skill update in the same PR.** If you rename, add, remove, or change the semantics of any `clx_*` MCP tool exposed by `clx-mcp`, update `plugin/skills/using-clx/SKILL.md` in the same pull request. The plugin's whole value is teaching Claude the tool surface; drift between the skill and the real tools breaks the plugin silently.

Run `./plugin/scripts/validate.sh` before pushing any change to `plugin/`. CI runs it automatically on every PR.
```

- [ ] **Step 3: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs(plugin): document version-lockstep rule in CONTRIBUTING"
```

---

## Task 11: Manual smoke test and wrap-up

**Files:** none (manual verification only)

- [ ] **Step 1: Install the plugin locally**

```bash
ln -sf "$(pwd)/plugin" ~/.claude/plugins/clx
```

- [ ] **Step 2: Verify CLX prerequisites**

Run: `clx health`
Expected: `clx-mcp` is registered, Ollama is reachable, embedding model is available. If anything is red, fix it before running the smoke test — otherwise the smoke test is testing CLX, not the plugin.

- [ ] **Step 3: Restart Claude Code**

Quit and reopen Claude Code so the plugin is picked up.

- [ ] **Step 4: Run smoke test prompt 1 — recall**

In a fresh Claude Code session, paste: *"We talked about the retry logic earlier — can you remind me what we decided?"*

Expected: Claude loads the `using-clx` skill (you should see it surface the skill's guidance) and calls `clx_recall` with a query mentioning retry/backoff. Actual content of the recall result does not matter — what matters is that the tool is called.

- [ ] **Step 5: Run smoke test prompt 2 — remember**

Paste: *"From now on I want all errors logged as structured JSON."*

Expected: Claude calls `clx_remember` with a string describing the preference.

- [ ] **Step 6: Run smoke test prompt 3 — checkpoint**

Paste: *"I'm about to drop the `snapshots` table to recreate it fresh."*

Expected: Claude calls `clx_checkpoint` _before_ suggesting or executing any destructive command.

- [ ] **Step 7: If any step fails**

The most likely cause is the frontmatter `description` not triggering the skill matcher. Do not change the skill body. Instead:

1. Edit `plugin/skills/using-clx/SKILL.md` frontmatter `description` to add or emphasize the missing trigger.
2. Re-run `./plugin/scripts/validate.sh` to confirm required keywords are still present.
3. Restart Claude Code.
4. Re-run the failing smoke test step.
5. Commit the description fix: `git commit -am "fix(plugin): tune using-clx skill trigger for <case>"`.

- [ ] **Step 8: Final git log check**

Run: `git log --oneline -12`
Expected: every commit message follows `<type>(plugin): ...` format, and you see the full task history from scaffold → validator → each skill section → README → CI → CONTRIBUTING.

No final commit needed unless a fix landed in Step 7.

---

## Post-Plan Notes

- **No version bump.** This plan ships the plugin pinned to the _current_ CLX version (0.5.3). The next CLX release bumps both `Cargo.toml` and `plugin/plugin.json` in the same commit — that is outside this plan's scope.
- **No marketplace submission.** Deferred to v2 per the spec. Adding it later is metadata-only.
- **No slash commands, no subagent.** Deferred to v2. If the single skill grows too heavy in practice, revisit and split per the spec's §8 "deferred" list.
