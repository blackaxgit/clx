# CLX - Claude Code Extension

[![CI](https://github.com/blackaxgit/clx/actions/workflows/ci.yml/badge.svg)](https://github.com/blackaxgit/clx/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://mozilla.org/MPL/2.0/)

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

## Quick Start

### Prerequisites

1. **macOS** (ARM64/Apple Silicon)
2. **Rust 1.85+** — install via [rustup](https://rustup.rs/): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
3. **[Ollama](https://ollama.com)** — download from website or `brew install ollama`

### Let Claude Code Do It

Copy this prompt into Claude Code — it handles the full setup:

```
Install CLX for me:
1. Clone https://github.com/blackaxgit/clx and build with cargo build --release
2. Run ./target/release/clx install
3. Pull Ollama models: ollama pull qwen3:1.7b && ollama pull qwen3-embedding:0.6b
4. Add ~/.clx/bin to my PATH by appending 'export PATH="$HOME/.clx/bin:$PATH"' to ~/.zshrc
5. Tell me to restart Claude Code when done
```

After restarting Claude Code, CLX is active — hooks validate commands, context is persisted, and MCP tools are available.

### Manual Install

```bash
# Clone and build
git clone https://github.com/blackaxgit/clx.git
cd clx
cargo build --release

# Install CLX (configures hooks, MCP server, copies binaries to ~/.clx/bin/)
./target/release/clx install

# Pull required Ollama models
ollama pull qwen3:1.7b
ollama pull qwen3-embedding:0.6b

# Add CLX to your PATH (add to ~/.zshrc to persist)
export PATH="$HOME/.clx/bin:$PATH"
```

**Restart Claude Code**, then verify:

```bash
clx dashboard    # Interactive dashboard with session history and system status
```

See [INSTALL.md](INSTALL.md) for more options and troubleshooting.

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
