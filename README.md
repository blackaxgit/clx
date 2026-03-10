# CLX - Claude Code Extension

[![CI](https://github.com/blackaxgit/clx/actions/workflows/ci.yml/badge.svg)](https://github.com/blackaxgit/clx/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://mozilla.org/MPL/2.0/)
[![Claude Code Ready](https://img.shields.io/badge/Claude_Code-Auto_Install_Ready-blueviolet?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDE2IDE2Ij48dGV4dCB4PSIwIiB5PSIxMyIgZm9udC1zaXplPSIxNCI+8J+UpTwvdGV4dD48L3N2Zz4=)](#install-with-claude-code)

> **Note:** Currently supports macOS (ARM64/Apple Silicon) only.

Intelligent command validation and context persistence for Claude Code.

## Features

- **Command Validation** - Two-layer validation system:
  - Layer 0: Fast deterministic whitelist/blacklist rules (~1ms)
  - Layer 1: LLM-based risk assessment via Ollama (~100-300ms)

- **Context Persistence** - SQLite-based storage with semantic search:
  - Automatic snapshots before context compression
  - Vector embeddings for semantic recall
  - Session history and analytics

- **User Learning** - Adapts to your workflow:
  - Tracks approved/denied commands
  - Auto-generates rules based on usage patterns

- **MCP Tools** - Claude can access:
  - `clx_recall` - Search historical context
  - `clx_remember` - Explicitly save information
  - `clx_checkpoint` - Create manual snapshots
  - `clx_rules` - Manage validation rules

## Install with Claude Code

> Let Claude handle the entire setup. You just need macOS, [Ollama](https://ollama.com), and [Rust](https://rustup.rs/) installed.

**1.** Make sure Ollama is running:

```bash
ollama serve
```

**2.** Paste this into Claude Code:

```
Install CLX from https://github.com/blackaxgit/clx:
1. Clone the repo and build: git clone https://github.com/blackaxgit/clx.git /tmp/clx && cd /tmp/clx && cargo build --release
2. Run the installer: ./target/release/clx install
3. Pull Ollama models: ollama pull qwen3:1.7b && ollama pull qwen3-embedding:0.6b
4. Add to PATH: echo 'export PATH="$HOME/.clx/bin:$PATH"' >> ~/.zshrc
5. Tell me to restart Claude Code when done
```

**3.** Restart Claude Code.

**Done.** Hooks are validating commands, context is being persisted, and MCP tools are available.

### One-line install (alternative)

```bash
curl -fsSL https://raw.githubusercontent.com/blackaxgit/clx/main/install.sh | bash
```

---

## Manual Install

> Full control over every step. Requires macOS (ARM64), Rust 1.85+, and Ollama.

**1. Install prerequisites:**

```bash
# Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Ollama (if not installed) — or download from https://ollama.com
brew install ollama
ollama serve   # start the server
```

**2. Build and install CLX:**

```bash
git clone https://github.com/blackaxgit/clx.git
cd clx
cargo build --release
./target/release/clx install
```

**3. Pull the required Ollama models:**

```bash
ollama pull qwen3:1.7b
ollama pull qwen3-embedding:0.6b
```

**4. Add CLX to your PATH:**

```bash
echo 'export PATH="$HOME/.clx/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**5. Restart Claude Code**, then verify:

```bash
clx dashboard
```

You should see the interactive dashboard with session history and system status.

See [INSTALL.md](INSTALL.md) for troubleshooting.

## Usage

### CLI Commands

```bash
# Check status
clx dashboard

# Search context
clx recall "authentication bug"

# View/edit configuration
clx config
clx config edit

# Manage rules
clx rules list
clx rules allow "npm install *"
clx rules deny "rm -rf /"

# Generate shell completions (v0.2+)
clx completions bash > ~/.clx-completion.bash
clx completions zsh > ~/.clx-completion.zsh

# Manage embeddings (v0.2+)
clx embeddings status        # Check model and dimensions
clx embeddings rebuild       # Rebuild for model migration

# Uninstall
clx uninstall
clx uninstall --purge  # Also removes ~/.clx
```

### Configuration

Edit `~/.clx/config.yaml`:

```yaml
validator:
  enabled: true
  layer1_enabled: true        # LLM validation
  layer1_timeout_ms: 30000
  default_decision: "ask"     # allow, deny, ask

context:
  enabled: true
  auto_snapshot: true

ollama:
  host: "http://127.0.0.1:11434"
  model: "qwen3:1.7b"
  embedding_model: "qwen3-embedding:0.6b"
  timeout_ms: 60000

user_learning:
  enabled: true
  auto_whitelist_threshold: 3   # Auto-add after N allows
  auto_blacklist_threshold: 2   # Auto-block after N denies

logging:
  level: "info"
  file: "~/.clx/logs/clx.log"
```

### Custom Rules

Edit `~/.clx/rules/default.yaml`:

```yaml
whitelist:
  - pattern: "Bash(npm:test*)"
    description: "Allow npm test commands"
  - pattern: "Bash(cargo:build*)"
    description: "Allow cargo build"

blacklist:
  - pattern: "Bash(rm:-rf /*)"
    description: "Block recursive delete from root"
  - pattern: "Bash(curl:*|bash)"
    description: "Block pipe to shell"
```

### Custom LLM Prompt

Edit `~/.clx/prompts/validator.txt` to customize risk assessment.

## How It Works

### Command Validation Flow

```
Claude requests command
        ↓
PreToolUse hook fires
        ↓
Layer 0: Check whitelist/blacklist
    ├─ Match whitelist → Allow
    ├─ Match blacklist → Deny
    └─ Unknown → Continue
        ↓
Layer 1: Ollama risk assessment
    ├─ Score 1-3 → Allow
    ├─ Score 4-7 → Ask user
    └─ Score 8-10 → Deny
        ↓
User confirms (if Ask)
        ↓
Command executes
        ↓
PostToolUse logs result
```

### Context Persistence Flow

```
PreCompact hook fires (before compression)
        ↓
Read transcript from JSONL file
        ↓
Generate summary via Ollama
        ↓
Store snapshot in SQLite
        ↓
Generate embedding for search
        ↓
Context available via clx_recall
```

## Project Structure

```
clx/
├── crates/
│   ├── clx-core/       # Core library
│   │   └── src/
│   │       ├── config.rs      # Configuration management
│   │       ├── storage/       # SQLite storage (sessions, snapshots, rules)
│   │       ├── policy/        # Command validation (L0 rules + L1 LLM)
│   │       ├── ollama.rs      # Ollama client
│   │       └── embeddings.rs  # Vector search
│   ├── clx-hook/       # Hook handler binary
│   ├── clx-mcp/        # MCP server binary
│   └── clx/            # CLI binary + dashboard
├── scripts/            # Docker compose, service management, packaging
├── install.sh          # Build-from-source installer
├── INSTALL.md          # Installation guide
└── CONTRIBUTING.md     # Contribution guide
```

## Development

```bash
# Build
cargo build

# Test
cargo test

# Run with verbose logging
RUST_LOG=debug ./target/debug/clx dashboard
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MPL-2.0
