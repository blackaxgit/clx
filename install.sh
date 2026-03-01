#!/bin/bash
#
# CLX Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/user/clx/main/install.sh | bash
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info() { echo -e "${CYAN}$1${NC}"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}!${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; exit 1; }

# Check platform
OS=$(uname -s)
ARCH=$(uname -m)

if [[ "$OS" != "Darwin" ]]; then
    error "CLX currently only supports macOS. Detected: $OS"
fi

if [[ "$ARCH" != "arm64" ]]; then
    warn "CLX is optimized for Apple Silicon (arm64). Detected: $ARCH"
fi

echo ""
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         CLX Installer v0.1.0           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

CLX_DIR="$HOME/.clx"
BIN_DIR="$CLX_DIR/bin"
DATA_DIR="$CLX_DIR/data"

# Check if already installed
if [[ -d "$CLX_DIR" ]]; then
    info "Existing CLX installation found at $CLX_DIR"
    read -p "Reinstall/upgrade? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
fi

# Step 1: Check dependencies
info "Checking dependencies..."

# Check Rust/Cargo
if ! command -v cargo &> /dev/null; then
    warn "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
success "Rust installed"

# Check Ollama (Docker or native)
OLLAMA_INSTALLED=false
OLLAMA_VIA_DOCKER=false

# Check if Docker is available
DOCKER_AVAILABLE=false
if command -v docker &> /dev/null && docker info &> /dev/null 2>&1; then
    DOCKER_AVAILABLE=true
fi

# Check if native Ollama is installed
NATIVE_OLLAMA=false
if command -v ollama &> /dev/null; then
    NATIVE_OLLAMA=true
fi

if [[ "$DOCKER_AVAILABLE" == "true" ]]; then
    if [[ "$NATIVE_OLLAMA" == "true" ]]; then
        success "Native Ollama found"
        read -p "Run Ollama in Docker instead? (recommended for easier management) [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            OLLAMA_VIA_DOCKER=true
        else
            OLLAMA_INSTALLED=true
        fi
    else
        info "Docker is available"
        read -p "Run Ollama in Docker? (recommended) [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            OLLAMA_VIA_DOCKER=true
        fi
    fi
elif [[ "$NATIVE_OLLAMA" == "true" ]]; then
    OLLAMA_INSTALLED=true
    success "Ollama installed"
else
    # Neither Docker nor native Ollama found
    warn "Ollama not found (required for L1 validation and embeddings)"
    echo ""
    echo "  Options:"
    echo "    1. Install Docker (recommended)"
    echo "       macOS: brew install --cask docker"
    echo ""
    echo "    2. Install Ollama natively"
    echo "       brew install ollama"
    echo "       or download from https://ollama.ai"
    echo ""
    read -p "Install Docker now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Installing Docker via Homebrew..."
        brew install --cask docker
        success "Docker installed"
        warn "Please start Docker Desktop, then re-run this script."
        exit 0
    else
        read -p "Continue without Ollama? CLX will work with L0 rules only. [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Please install Docker or Ollama, then re-run this script."
            exit 0
        fi
    fi
fi

# If using Docker Ollama, start it now (before building, so docker-compose.yml is available)
if [[ "$OLLAMA_VIA_DOCKER" == "true" ]]; then
    info "Docker-based Ollama will be set up after installation"
fi

# Step 2: Clone or update repository
info "Getting CLX source..."

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

if [[ -d "./crates/clx" ]]; then
    # Running from clx repo
    info "Using local source"
    SRC_DIR="$(pwd)"
else
    # Clone from GitHub
    info "Cloning from GitHub..."
    git clone --depth 1 https://github.com/user/clx.git "$TEMP_DIR/clx" 2>/dev/null || {
        error "Failed to clone repository. Please check your internet connection."
    }
    SRC_DIR="$TEMP_DIR/clx"
fi

cd "$SRC_DIR"

# Step 3: Build
info "Building CLX (this may take a few minutes)..."

cargo build --release 2>&1 | while read line; do
    if [[ "$line" == *"Compiling"* ]]; then
        echo -ne "\r  Building: ${line##*Compiling }                    "
    fi
done
echo ""

if [[ ! -f "target/release/clx" ]]; then
    error "Build failed. Please check error messages above."
fi

success "Build complete"

# Step 4: Install
info "Installing CLX..."

# Create directories
mkdir -p "$BIN_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$CLX_DIR/logs"
mkdir -p "$CLX_DIR/rules"
mkdir -p "$CLX_DIR/prompts"
mkdir -p "$CLX_DIR/docker"

# Copy binaries
cp "target/release/clx" "$BIN_DIR/"
cp "target/release/clx-hook" "$BIN_DIR/"
cp "target/release/clx-mcp" "$BIN_DIR/"
chmod +x "$BIN_DIR"/*

success "Binaries installed to $BIN_DIR"

# Copy Docker compose file
if [[ -f "scripts/docker-compose.yml" ]]; then
    cp "scripts/docker-compose.yml" "$CLX_DIR/docker/"
    success "Docker compose configuration installed"
fi

# Copy helper scripts
if [[ -f "scripts/clx-services.sh" ]]; then
    cp "scripts/clx-services.sh" "$BIN_DIR/"
    chmod +x "$BIN_DIR/clx-services.sh"
    success "Service management script installed"
fi

# Install sqlite-vec library for semantic search
mkdir -p "$CLX_DIR/lib"
if [[ -f "libs/vec0.dylib" ]]; then
    cp "libs/vec0.dylib" "$CLX_DIR/lib/"
    success "sqlite-vec library installed"
elif [[ -f "$CLX_DIR/lib/vec0.dylib" ]]; then
    success "sqlite-vec library already installed"
else
    warn "sqlite-vec library not found"
    echo "  Semantic search requires vec0.dylib"
    echo "  Download from: https://github.com/asg017/sqlite-vec/releases"
fi

# Step 5: Add to PATH
SHELL_RC=""
if [[ -f "$HOME/.zshrc" ]]; then
    SHELL_RC="$HOME/.zshrc"
elif [[ -f "$HOME/.bashrc" ]]; then
    SHELL_RC="$HOME/.bashrc"
fi

if [[ -n "$SHELL_RC" ]]; then
    if ! grep -q "CLX_PATH" "$SHELL_RC" 2>/dev/null; then
        echo '' >> "$SHELL_RC"
        echo '# CLX' >> "$SHELL_RC"
        echo 'export PATH="$HOME/.clx/bin:$PATH"  # CLX_PATH' >> "$SHELL_RC"
        success "Added to PATH in $SHELL_RC"
    fi
fi

# Export for current session
export PATH="$BIN_DIR:$PATH"

# Step 6: Run clx install to configure Claude Code
info "Configuring Claude Code integration..."
"$BIN_DIR/clx" install

# Step 7: Set up Ollama and pull models
if [[ "$OLLAMA_VIA_DOCKER" == "true" ]]; then
    echo ""
    info "Setting up Docker-based Ollama..."

    # Start Ollama container
    info "Starting Ollama container..."
    docker compose -f "$CLX_DIR/docker/docker-compose.yml" up -d

    # Wait for Ollama to be ready
    info "Waiting for Ollama to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:11434/ > /dev/null 2>&1; then
            success "Ollama is ready"
            break
        fi
        echo -n "."
        sleep 1
    done
    echo ""

    if ! curl -s http://localhost:11434/ > /dev/null 2>&1; then
        warn "Ollama did not start in time. You can start it manually with: clx-services start"
    else
        # Pull models inside Docker container
        read -p "Pull required models now? (qwen3:1.7b ~1.4GB, qwen3-embedding:0.6b ~639MB) [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            info "Pulling qwen3:1.7b..."
            docker exec clx-ollama ollama pull qwen3:1.7b
            success "qwen3:1.7b pulled"

            info "Pulling qwen3-embedding:0.6b..."
            docker exec clx-ollama ollama pull qwen3-embedding:0.6b
            success "qwen3-embedding:0.6b pulled"
        else
            info "You can pull models later with: clx-services pull-models"
        fi
    fi

    OLLAMA_INSTALLED=true

elif [[ "$OLLAMA_INSTALLED" == "true" ]]; then
    echo ""
    info "Checking Ollama models..."

    # Check if models exist (native Ollama)
    MODELS=$(ollama list 2>/dev/null || echo "")

    if ! echo "$MODELS" | grep -q "qwen3:1.7b"; then
        read -p "Pull qwen3:1.7b model (~1.4GB)? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            info "Pulling qwen3:1.7b..."
            ollama pull qwen3:1.7b
        fi
    else
        success "qwen3:1.7b available"
    fi

    if ! echo "$MODELS" | grep -q "qwen3-embedding:0.6b"; then
        read -p "Pull qwen3-embedding:0.6b model (~639MB)? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            info "Pulling qwen3-embedding:0.6b..."
            ollama pull qwen3-embedding:0.6b
        fi
    else
        success "qwen3-embedding:0.6b available"
    fi
fi

# Done
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     CLX Installation Complete!         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo "  Directory: $CLX_DIR"
echo "  Binaries:  $BIN_DIR/clx, clx-hook, clx-mcp"
echo ""
echo "  Next steps:"
echo "    1. Restart your terminal (or run: source $SHELL_RC)"

if [[ "$OLLAMA_VIA_DOCKER" == "true" ]]; then
    echo "    2. Manage Ollama: clx-services [start|stop|status|logs]"
    echo "    3. View logs: docker compose -f ~/.clx/docker/docker-compose.yml logs -f"
    echo "    4. Restart Claude Code"
    echo "    5. Run: clx status"
else
    echo "    2. Start Ollama: ollama serve"
    echo "    3. Restart Claude Code"
    echo "    4. Run: clx status"
fi

echo ""
