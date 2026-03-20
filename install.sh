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

# Model defaults — read from config if available, otherwise use defaults.
# This ensures install.sh and clx-services.sh stay in sync with config.yaml.
CLX_CONFIG="$HOME/.clx/config.yaml"
if [[ -f "$CLX_CONFIG" ]]; then
    VALIDATION_MODEL=$(grep '^\s*model:' "$CLX_CONFIG" | head -1 | sed 's/.*model:\s*//' | tr -d '[:space:]')
    EMBEDDING_MODEL=$(grep '^\s*embedding_model:' "$CLX_CONFIG" | head -1 | sed 's/.*embedding_model:\s*//' | tr -d '[:space:]')
fi
VALIDATION_MODEL="${VALIDATION_MODEL:-qwen3:1.7b}"
EMBEDDING_MODEL="${EMBEDDING_MODEL:-qwen3-embedding:0.6b}"

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

# Step 1: Prerequisite validation
info "Checking prerequisites..."

MISSING=()

# Check Git
if ! command -v git &> /dev/null; then
    MISSING+=("git")
fi

# Check curl
if ! command -v curl &> /dev/null; then
    MISSING+=("curl")
fi

# Check Rust/Cargo
RUST_MISSING=false
if ! command -v cargo &> /dev/null; then
    RUST_MISSING=true
    MISSING+=("cargo (Rust toolchain)")
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing prerequisites:"
    for dep in "${MISSING[@]}"; do
        echo "  - $dep"
    done
    echo ""

    # Provide install instructions for non-Rust dependencies
    if ! command -v git &> /dev/null; then
        echo "  Install git:"
        echo "    macOS: xcode-select --install"
        echo "    Linux: sudo apt-get install git  (or equivalent)"
        echo ""
    fi
    if ! command -v curl &> /dev/null; then
        echo "  Install curl:"
        echo "    macOS: curl should be pre-installed"
        echo "    Linux: sudo apt-get install curl  (or equivalent)"
        echo ""
    fi

    # Offer to install Rust automatically if it's the only (or one of the) missing deps
    if [[ "$RUST_MISSING" == "true" ]]; then
        # If git or curl are missing, we can't proceed (need curl for rustup, git for clone)
        if ! command -v curl &> /dev/null; then
            error "curl is required to install Rust and to run this installer. Please install it first."
        fi
        if ! command -v git &> /dev/null; then
            error "git is required to clone the CLX repository. Please install it first."
        fi

        read -p "Install Rust automatically via rustup? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            info "Installing Rust via rustup..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
            success "Rust installed"
        else
            error "Rust is required to build CLX. Please install it from https://rustup.rs and re-run."
        fi
    else
        # Non-Rust deps are missing
        error "Please install missing prerequisites and re-run the installer."
    fi
else
    # All prerequisites present, but Rust might still need the success message
    success "All prerequisites met (git, curl, cargo)"
fi

# Final cargo check (in case rustup was just installed)
if ! command -v cargo &> /dev/null; then
    error "Rust/Cargo not found. Please install from https://rustup.rs and re-run."
fi

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

# sqlite-vec is statically linked into the binary — no dylib download required.
success "sqlite-vec (vector search) built-in"

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

    # Pull latest Ollama image to avoid stale cached versions
    info "Pulling latest Ollama Docker image..."
    docker pull ollama/ollama:latest

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
        read -p "Pull required models now? ($VALIDATION_MODEL ~1.4GB, $EMBEDDING_MODEL ~639MB) [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            info "Pulling $VALIDATION_MODEL..."
            docker exec clx-ollama ollama pull "$VALIDATION_MODEL"
            success "$VALIDATION_MODEL pulled"

            info "Pulling $EMBEDDING_MODEL..."
            docker exec clx-ollama ollama pull "$EMBEDDING_MODEL"
            success "$EMBEDDING_MODEL pulled"
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

    if ! echo "$MODELS" | grep -q "$VALIDATION_MODEL"; then
        read -p "Pull $VALIDATION_MODEL model (~1.4GB)? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            info "Pulling $VALIDATION_MODEL..."
            ollama pull "$VALIDATION_MODEL"
        fi
    else
        success "$VALIDATION_MODEL available"
    fi

    if ! echo "$MODELS" | grep -q "$EMBEDDING_MODEL"; then
        read -p "Pull $EMBEDDING_MODEL model (~639MB)? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            info "Pulling $EMBEDDING_MODEL..."
            ollama pull "$EMBEDDING_MODEL"
        fi
    else
        success "$EMBEDDING_MODEL available"
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
