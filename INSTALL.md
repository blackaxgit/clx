# Installing CLX

## Prerequisites

- **macOS** (Apple Silicon / ARM64 only)
- **Rust** toolchain (edition 2024, rustc 1.85+) — install via [rustup](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **[Ollama](https://ollama.com)** — download from the website or install via Homebrew:
  ```bash
  brew install ollama
  ```

### Host prerequisites (optional, per host)

CLX always installs the Claude Code integration. To also install into Codex CLI
or Cursor, make sure the host meets these requirements before running
`clx install`:

- **Codex CLI** — version **>= 0.23.0** is required (earlier releases are
  affected by CVE-2025-61260). Command-validation hooks were stabilized later,
  so **>= 0.124** is recommended for the PreToolUse guardrail. Install or update
  with:
  ```bash
  npm install -g @openai/codex
  ```
- **Cursor** — hook support requires Cursor **>= 1.7**; the current release is
  recommended. Cursor command gating fires in the IDE agent and cloud agents
  only; the local `cursor-agent` CLI does not run hooks.

## Quick Install

### Option 1: Install via Claude Code

Paste this prompt into Claude Code:

```
Install CLX for me: clone https://github.com/blackaxgit/clx, build with cargo build --release, then run ./target/release/clx install. After that, pull the required Ollama models: ollama pull qwen3:1.7b && ollama pull qwen3-embedding:0.6b. Finally, tell me to restart Claude Code.
```

### Option 2: Build from Source

```bash
git clone https://github.com/blackaxgit/clx.git
cd clx
cargo build --release
./target/release/clx install
```

Then install the Ollama models:

```bash
ollama pull qwen3:1.7b
ollama pull qwen3-embedding:0.6b
```

### Add to PATH

`clx install` copies all binaries to `~/.clx/bin/`. Add this to your `~/.zshrc` (or `~/.bashrc`):

```bash
export PATH="$HOME/.clx/bin:$PATH"
```

Then reload your shell:

```bash
source ~/.zshrc
```

## What `clx install` Does

The install command sets up everything CLX needs to work with Claude Code:

1. **Creates `~/.clx/` directory** with subdirectories for config, data, logs, rules, and prompts
2. **Copies binaries** (`clx`, `clx-hook`, `clx-mcp`) to `~/.clx/bin/`
3. **Initializes SQLite database** for session storage and context persistence
4. **Configures Claude Code hooks** in `~/.claude/settings.json`:
   - `PreToolUse` - validates commands before execution
   - `PostToolUse` - logs command results
   - `PreCompact` - snapshots context before compression
   - `SessionStart` / `SessionEnd` - tracks session lifecycle
   - `SubagentStart` - monitors subagent activity
   - `UserPromptSubmit` - injects context on user prompts
   - `Stop` - opt-in auto-summarize at end of turn
5. **Registers MCP server** (`clx-mcp`) so the host agent can use CLX tools
6. **Injects CLX section** into `~/.claude/CLAUDE.md` with tool documentation

## Choosing which hosts to install (`--target`)

By default `clx install` (and `clx uninstall`) act on every host CLX can detect
on the machine. Claude Code is always treated as present; Codex CLI and Cursor
are included automatically when detected. Override this with `--target`:

```bash
clx install --target claude   # Claude Code only (~/.claude)
clx install --target codex    # Codex CLI only (~/.codex)
clx install --target cursor    # Cursor only (~/.cursor + repo-local rule)
clx install --target all       # all three hosts, unconditionally
clx install --target auto      # every detected host (the default)
```

`clx uninstall` accepts the same `--target` values. What each host receives:

- **Claude Code** — hooks + MCP server in `~/.claude/settings.json`, plus the
  CLX section in `~/.claude/CLAUDE.md`.
- **Codex CLI** — `~/.codex/hooks.json` hook entries, `[mcp_servers.clx]` in
  `~/.codex/config.toml`, and the CLX section in `~/.codex/AGENTS.md` (falling
  back to `AGENTS.override.md` when `AGENTS.md` would exceed Codex's size cap).
- **Cursor** — `mcpServers.clx` in `~/.cursor/mcp.json`, `~/.cursor/hooks.json`
  command/MCP gates with `failClosed: true`, and a project-scoped
  `<repo>/.cursor/rules/clx.mdc` rule.

## After Installation

1. **Restart Claude Code** to load the new hooks and MCP server.
2. **Verify** CLX is working:

```bash
clx dashboard
```

This opens an interactive dashboard showing session history, validation stats, and system status.

You should see:
- Session tracking active (new sessions appear in the dashboard)
- Ollama status: connected
- Hook status: all hooks configured

## Uninstall

```bash
# Remove hooks and MCP config (keeps ~/.clx/ data)
clx uninstall

# Remove everything including data
clx uninstall --purge

# Uninstall from a specific host only
clx uninstall --target codex
```

Uninstall removes the per-host hook and MCP entries and strips the injected
`# CLX Integration` section from each host's instructions file (`CLAUDE.md`,
`AGENTS.md` and its `AGENTS.override.md` fallback); the Cursor
`<repo>/.cursor/rules/clx.mdc` rule file is deleted.

## Troubleshooting

### `clx: command not found`

Ensure `~/.clx/bin` is in your PATH:

```bash
echo 'export PATH="$HOME/.clx/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Ollama not running

```bash
# Start Ollama
ollama serve

# Verify it's running
curl http://127.0.0.1:11434/
```

### Missing models

```bash
ollama pull qwen3:1.7b
ollama pull qwen3-embedding:0.6b
```

### Hooks not working

Check that `~/.claude/settings.json` contains the CLX hooks:

```bash
grep clx ~/.claude/settings.json
```

If not, re-run `clx install`.

### Permission issues

CLX sets `~/.clx/` to owner-only access (700). If you see permission errors:

```bash
chmod -R u+rwX ~/.clx/
```
