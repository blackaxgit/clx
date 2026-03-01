#!/bin/bash
#
# Package CLX binaries for distribution
# Creates a tarball that can be installed without Rust
#
set -e

VERSION="0.1.0"
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
PACKAGE_NAME="clx-${VERSION}-${OS}-${ARCH}"

echo "Building release binaries..."
cargo build --release

echo "Creating package directory..."
DIST_DIR="dist/${PACKAGE_NAME}"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/bin"

echo "Copying binaries..."
cp target/release/clx "$DIST_DIR/bin/"
cp target/release/clx-hook "$DIST_DIR/bin/"
cp target/release/clx-mcp "$DIST_DIR/bin/"

echo "Copying install script..."
cat > "$DIST_DIR/install.sh" << 'INSTALL_SCRIPT'
#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}$1${NC}"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; exit 1; }

echo ""
echo -e "${CYAN}CLX Quick Installer${NC}"
echo ""

CLX_DIR="$HOME/.clx"
BIN_DIR="$CLX_DIR/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create directories
mkdir -p "$BIN_DIR"
mkdir -p "$CLX_DIR/data"
mkdir -p "$CLX_DIR/logs"
mkdir -p "$CLX_DIR/rules"
mkdir -p "$CLX_DIR/prompts"

# Copy binaries
cp "$SCRIPT_DIR/bin/"* "$BIN_DIR/"
chmod +x "$BIN_DIR"/*
success "Binaries installed"

# Add to PATH
SHELL_RC=""
[[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"
[[ -f "$HOME/.bashrc" ]] && SHELL_RC="$HOME/.bashrc"

if [[ -n "$SHELL_RC" ]] && ! grep -q "CLX_PATH" "$SHELL_RC" 2>/dev/null; then
    echo '' >> "$SHELL_RC"
    echo 'export PATH="$HOME/.clx/bin:$PATH"  # CLX_PATH' >> "$SHELL_RC"
    success "Added to PATH"
fi

export PATH="$BIN_DIR:$PATH"

# Configure Claude Code
info "Configuring Claude Code..."
"$BIN_DIR/clx" install

echo ""
echo -e "${GREEN}Done!${NC} Restart terminal and Claude Code."
echo ""
INSTALL_SCRIPT

chmod +x "$DIST_DIR/install.sh"

echo "Creating README..."
cat > "$DIST_DIR/README.txt" << README
CLX - Claude Code Extension
===========================

Quick Install:
  ./install.sh

Manual Install:
  1. Copy bin/* to ~/.clx/bin/
  2. Add to PATH: export PATH="\$HOME/.clx/bin:\$PATH"
  3. Run: clx install
  4. Restart Claude Code

Requirements:
  - macOS (Apple Silicon recommended)
  - Ollama (optional, for L1 validation)
    brew install ollama
    ollama pull qwen3:1.7b
    ollama pull qwen3-embedding:0.6b
README

echo "Creating tarball..."
cd dist
tar -czvf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"
cd ..

echo ""
echo "Package created: dist/${PACKAGE_NAME}.tar.gz"
echo ""
echo "To install on another machine:"
echo "  tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "  cd ${PACKAGE_NAME}"
echo "  ./install.sh"
