# Installing CLX

## Prerequisites

- **macOS** (ARM64/Apple Silicon recommended)
- **Rust** toolchain (edition 2024, rustc 1.85+) - install via [rustup](https://rustup.rs/)
- **[Ollama](https://ollama.com)** with models:
  - `qwen3:1.7b` for risk assessment
  - `qwen3-embedding:0.6b` for embeddings

## Quick Install

### Option 1: Install via Claude Code

Paste this prompt into Claude Code:

```
Install CLX for me: clone https://github.com/blackaxgit/clx, build with cargo build --release, then run ./target/release/clx install. After that, pull the required Ollama models: ollama pull qwen3:1.7b && ollama pull qwen3-embedding:0.6b. Finally, tell me to restart Claude Code.
```

### Option 2: One-Line Install

```bash
curl -fsSL https://raw.githubusercontent.com/blackaxgit/clx/main/install.sh | bash
```

### Option 3: Build from Source

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

## What `clx install` Does

The install command sets up everything CLX needs to work with Claude Code:

1. **Creates `~/.clx/` directory** with subdirectories for config, data, logs, rules, and prompts
2. **Copies binaries** (`clx-hook`, `clx-mcp`) to `~/.clx/bin/`
3. **Initializes SQLite database** for session storage and context persistence
4. **Configures Claude Code hooks** in `~/.claude/settings.json`:
   - `PreToolUse` - validates commands before execution
   - `PostToolUse` - logs command results
   - `PreCompact` - snapshots context before compression
   - `SessionStart` / `SessionEnd` - tracks session lifecycle
   - `SubagentStart` - monitors subagent activity
   - `UserPromptSubmit` - injects context on user prompts
5. **Registers MCP server** (`clx-mcp`) so Claude can use CLX tools
6. **Injects CLX section** into `~/.claude/CLAUDE.md` with tool documentation

## After Installation

Restart Claude Code to load the new hooks and MCP server:

```bash
clx dashboard
```

This opens an interactive dashboard showing session history, validation stats, and system status.

## Uninstall

```bash
# Remove hooks and MCP config (keeps ~/.clx/ data)
clx uninstall

# Remove everything including data
clx uninstall --purge
```

## Troubleshooting

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
cat ~/.claude/settings.json | grep clx
```

If not, re-run `clx install`.

### Permission issues

CLX sets `~/.clx/` to owner-only access (700). If you see permission errors:

```bash
chmod -R u+rwX ~/.clx/
```
