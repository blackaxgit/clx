---
name: clx-doctor
description: >
  Use when CLX recall returns no results, looks empty, or behaves
  unexpectedly; diagnoses provider, embedding, DB, and config issues
  via shell commands (clx health, clx health --json, clx embeddings
  status) and log inspection. Examples: "why isn't recall working", "clx
  returns empty", "diagnose embedding model mismatch", "check provider
  fallback status". Do NOT invoke for normal "no relevant context"
  outcomes; only for outright failures or recall results that look
  structurally wrong (e.g., wrong model id, missing snapshots).
---

# clx-doctor

Diagnose CLX recall, embedding, provider, and DB issues.

## When to use

Trigger phrases:

- "why isn't recall working", "clx is broken", "recall returns empty",
- "diagnose embedding mismatch", "check provider fallback status",
- "did the Stop hook fire", "is my CLX DB corrupt".

Strong invocation signals:

- Multiple recalls in a row return zero hits on a topic that should have
  history.
- Score bands look wrong (everything at 0.0 or 1.0).
- "embedding model changed" error surfaced.
- Provider HTTP 5xx or timeout messages in logs.
- TUI dashboard shows snapshot count is zero despite recent work.

## When NOT to use

- Normal "no relevant context" outcomes on a genuinely new topic.
- First-run UX before any session has saved a snapshot.
- The user is asking a product question, not reporting a failure.

## Diagnostic decision tree

### Branch A: empty recall

1. Check index size: run `clx embeddings status`.
   Expected: snapshot count > 0, last index time recent.
   If 0: nothing has been saved yet; not a bug.
2. If non-zero: try a known-good query (echo a recent fact the user
   just saved via `clx_remember`). If that also misses, escalate to
   Branch B.

### Branch B: embedding model mismatch

1. Run `clx embeddings status` and compare `configured_model` (active route) vs
   `stored_model` (vectors in the index).
2. If different: user changed embedding provider; run
   `clx embeddings rebuild`. Until rebuild completes, recall returns
   empty by design.
3. Verify rebuild progress; report ETA to user.

### Branch C: provider 5xx or timeout

1. Run `clx health` (or `clx health --json` for machine-readable output)
   to check provider reachability and routing for each capability
   (chat, embeddings).
2. Inspect `~/.clx/logs/clx-hook.log` for recent provider errors
   (`tail -n 200`); look for `provider=... status=5xx` lines.
3. If primary is cold and fallback is healthy: CLX is already on
   fallback; the 30s cooldown will retry primary automatically.
4. If both fail: network or auth issue; `clx health` reports the
   secret-source / provider health check (keychain, env var, file).

### Branch D: Stop hook not firing

1. Verify Claude Code hooks config registers `clx-hook` for `Stop`.
2. Tail `~/.clx/logs/clx-hook.log` while the user runs `/exit` or
   ends a session; expect a `received event=Stop` line.
3. If absent: the hook binary may be missing or misconfigured;
   `clx install --check` reports per-hook status.

### Branch E: corrupt or locked DB

1. Run `clx health`; it reports snapshot-DB status as part of the
   overall health check.
2. If healthy: DB is fine; problem is elsewhere.
3. If errors: back up `~/.clx/store.db` first, then
   `clx maintenance rebuild --from-snapshots` if available, or restore
   from a `.bak` and replay recent `events`.
4. "database is locked" usually means a stale `clx-hook` process; check
   `pgrep -fl clx-hook` and end stragglers.

## Tool surface

`clx-doctor` is a Skill, not a single MCP tool. It composes shell
invocations and log reads; Claude orchestrates them and reports findings
back to the user.

- `clx health` (top-level health check) / `clx health --json`
- `clx embeddings status` / `clx embeddings rebuild`
- `tail -n 200 ~/.clx/logs/clx-hook.log`
- `pgrep -fl clx-hook`
- `clx install --check`

## Anti-pattern guard

- Do not run `clx maintenance rebuild` without confirming a backup
  exists; it is destructive on a corrupt DB.
- Do not kill processes blindly; verify they are stale `clx-hook` first.
- Do not invoke this skill for normal "no match" recall outcomes; that
  inflates noise and trains the user to ignore real diagnostics.
- Do not chain every branch; pick the one matching the symptom and
  stop early once the root cause is clear.

## Reporting back

When the diagnosis completes, summarize for the user in three parts:

1. What was checked (commands run, outputs in brief).
2. What was found (root cause, with evidence quote).
3. What to do (specific next command, or "no action needed").

_Last verified: 2026-05-16._
