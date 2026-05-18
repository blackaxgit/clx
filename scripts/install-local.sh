#!/usr/bin/env bash
#
# install-local.sh -- Build CLX from source and install locally.
#
# Produces the same end-state as `brew install clx && clx install` by
# building with `cargo build --release` and then delegating ALL Claude
# Code wiring (hooks, MCP server, skills, CLAUDE.md) to the freshly
# built `clx install` binary -- the identical code path used by the
# Homebrew formula.
#
# FLOW:
#   1. Preflight  -- verify repo, Cargo, Rust toolchain, platform
#   2. Build      -- cargo build --release (or --debug with --debug flag)
#   3. Place      -- copy clx/clx-hook/clx-mcp to --prefix (user-writable)
#   4. Delegate   -- invoke <prefix>/clx install (never bare `clx`)
#   5. Verify     -- read back version stamp, settings.json, skills
#   6. Next steps -- inform the user what to do next
#
# Usage: bash scripts/install-local.sh [OPTIONS]
#
# Minimum requirements:
#   - Bash 4.x+, macOS (arm64 recommended, other platforms warned)
#   - Rust stable >= 1.85 (rust-toolchain.toml: channel = "stable")
#   - cargo in PATH
#
# Version: reads workspace version from Cargo.toml at runtime.
# No Homebrew is used or required.

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REQUIRED_RUST_MINOR=85   # rustc >= 1.85 (Cargo.toml rust-version)
readonly BINARY_NAMES=(clx clx-hook clx-mcp)
readonly SKILL_NAMES=(clx-recall clx-remember clx-checkpoint clx-rules clx-resume clx-doctor)
readonly VERSION_STAMP_FILE=".clx-version"

# ---------------------------------------------------------------------------
# Colors (same palette as install.sh)
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
info()    { printf "${CYAN}%s${NC}\n"        "$*"; }
success() { printf "${GREEN}%s${NC} %s\n" "✓" "$*"; }
warn()    { printf "${YELLOW}%s${NC} %s\n" "!" "$*"; }
error()   { printf "${RED}%s${NC} %s\n"   "✗" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat <<USAGE
Usage: bash scripts/install-local.sh [OPTIONS]

Build CLX from source and install locally without Homebrew.
Produces the same runtime environment as: brew install clx && clx install

OPTIONS:
  --prefix <dir>   Directory for the user-facing clx/clx-hook/clx-mcp binaries.
                   Must be user-writable. Default: \${HOME}/.local/bin
  --debug          Build without --release (faster compile, slower binary).
  --skip-build     Skip cargo build; use binaries already in target/release
                   (or target/debug when combined with --debug).
  --yes            Non-interactive: assume yes to all prompts.
  --uninstall      Remove Claude Code wiring (via clx uninstall) and the
                   binaries placed by this script in --prefix.
  -h, --help       Show this message and exit.

EXAMPLES:
  bash scripts/install-local.sh
  bash scripts/install-local.sh --prefix ~/.local/bin
  bash scripts/install-local.sh --skip-build
  bash scripts/install-local.sh --uninstall

NOTE: Model setup (Ollama pull) is performed by \`clx install\` automatically
      when Ollama is running. It cannot be skipped from this script because
      \`clx install\` owns that step. See \`clx install --help\` for details.
USAGE
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PREFIX="${HOME}/.local/bin"
BUILD_PROFILE="release"
SKIP_BUILD=false
ASSUME_YES=false
UNINSTALL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || error "--prefix requires an argument"
      PREFIX="$2"
      shift 2
      ;;
    --debug)
      BUILD_PROFILE="debug"
      shift
      ;;
    --skip-build)
      SKIP_BUILD=true
      shift
      ;;
    --yes)
      ASSUME_YES=true
      shift
      ;;
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      error "Unknown option: $1  (run with --help for usage)"
      ;;
  esac
done

readonly PREFIX BUILD_PROFILE SKIP_BUILD ASSUME_YES UNINSTALL

BUILD_DIR="${REPO_DIR}/target/${BUILD_PROFILE}"

# ---------------------------------------------------------------------------
# Preflight helpers
# ---------------------------------------------------------------------------

# Confirm we are inside a CLX workspace checkout.
assert_clx_repo() {
  if [[ ! -f "${REPO_DIR}/Cargo.toml" ]] || [[ ! -d "${REPO_DIR}/crates/clx" ]]; then
    error "Not a CLX workspace checkout. Expected crates/clx/ under: ${REPO_DIR}"
  fi
}

# Read the workspace version from Cargo.toml using grep + sed.
# We do NOT use `cargo metadata` to avoid a network round-trip at preflight;
# the version line in the workspace Cargo.toml is canonical and stable.
read_workspace_version() {
  local cargo_toml="${REPO_DIR}/Cargo.toml"
  local raw
  # Match the first `version = "..."` inside the [workspace.package] block.
  # The block always precedes [workspace.dependencies], so the first hit is right.
  raw="$(grep -m1 '^version\s*=' "${cargo_toml}" | sed 's/.*"\(.*\)".*/\1/')"
  if [[ -z "${raw}" ]]; then
    error "Could not read workspace version from ${cargo_toml}"
  fi
  printf '%s' "${raw}"
}

# Verify cargo is present.
assert_cargo() {
  if ! command -v cargo &>/dev/null; then
    error "cargo not found. Install Rust from https://rustup.rs and re-run."
  fi
}

# Parse rustc minor version from `rustc --version` output (e.g. "rustc 1.85.0 ...").
# Returns the minor component as an integer for numeric comparison.
rustc_minor_version() {
  local ver
  ver="$(rustc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [[ -z "${ver}" ]]; then
    printf '0'
    return
  fi
  # Extract the minor version (middle field).
  printf '%s' "${ver}" | cut -d. -f2
}

assert_toolchain() {
  if ! command -v rustc &>/dev/null; then
    error "rustc not found. Install Rust >= 1.${REQUIRED_RUST_MINOR} from https://rustup.rs"
  fi
  local minor
  minor="$(rustc_minor_version)"
  if [[ "${minor}" -lt "${REQUIRED_RUST_MINOR}" ]]; then
    error "rustc 1.${REQUIRED_RUST_MINOR}+ required (found minor=${minor}). Run: rustup update stable"
  fi
}

assert_prefix_writable() {
  local dir="${PREFIX}"
  # Walk up to the first existing ancestor and check writability.
  while [[ ! -e "${dir}" ]]; do
    dir="$(dirname -- "${dir}")"
  done
  if [[ ! -w "${dir}" ]]; then
    error "Prefix '${PREFIX}' is not writable (ancestor '${dir}' denied). Choose a user-writable --prefix or fix permissions."
  fi
}

check_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  if [[ "${os}" != "Darwin" ]]; then
    warn "CLX is developed and tested on macOS. Detected: ${os}. Proceeding, but expect rough edges."
  fi
  if [[ "${arch}" != "arm64" ]]; then
    warn "CLX is optimized for Apple Silicon (arm64). Detected: ${arch}. Proceeding."
  fi
}

# ---------------------------------------------------------------------------
# Brew-shadow / version-skew detection
# ---------------------------------------------------------------------------
detect_shadowing() {
  local prefix_clx="${PREFIX}/clx"
  local existing_path

  # Check for any `clx` already on PATH before our prefix.
  if existing_path="$(command -v clx 2>/dev/null)"; then
    local existing_ver
    existing_ver="$(clx --version 2>/dev/null | head -1 || true)"
    warn "Existing clx found at: ${existing_path} (${existing_ver})"

    # Determine if the existing one will still shadow the prefixed one.
    if [[ "${existing_path}" != "${prefix_clx}" ]]; then
      warn "After install, PATH may still resolve '${existing_path}' before '${PREFIX}/clx'."
      warn "To use the locally built binary in your shell, ensure '${PREFIX}' appears"
      warn "earlier in PATH than '$(dirname -- "${existing_path}")', or invoke it directly:"
      warn "  ${PREFIX}/clx <command>"
    fi
  fi

  # Version-stamp skew: compare stamp in ~/.clx/bin vs what we are about to build.
  local stamp_path="${HOME}/.clx/bin/${VERSION_STAMP_FILE}"
  if [[ -f "${stamp_path}" ]]; then
    local stamped_ver
    stamped_ver="$(tr -d '[:space:]' <"${stamp_path}")"
    if [[ "${stamped_ver}" != "${CLX_VERSION}" ]]; then
      warn "Version skew: ~/.clx/bin was stamped with CLX ${stamped_ver};"
      warn "  we are about to install CLX ${CLX_VERSION}. This will refresh all binaries."
    fi
  fi
}

# ---------------------------------------------------------------------------
# Prompt helper (respects --yes)
# ---------------------------------------------------------------------------
confirm() {
  local prompt="$1"
  if [[ "${ASSUME_YES}" == true ]]; then
    return 0
  fi
  local reply
  read -r -p "${prompt} [y/N] " reply
  [[ "${reply}" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build_clx() {
  if [[ "${SKIP_BUILD}" == true ]]; then
    info "Skipping build (--skip-build)"
    return
  fi

  local cargo_args=()
  if [[ "${BUILD_PROFILE}" == "release" ]]; then
    cargo_args=(--release)
  fi

  info "Running: cargo build ${cargo_args[*]+${cargo_args[*]}}"
  if ! cargo build "${cargo_args[@]}" 2>&1; then
    error "cargo build failed (exit $?). See output above."
  fi
  success "Build complete (profile: ${BUILD_PROFILE})"
}

# ---------------------------------------------------------------------------
# Binary verification
# ---------------------------------------------------------------------------
assert_binaries_exist() {
  local missing=()
  local name
  for name in "${BINARY_NAMES[@]}"; do
    if [[ ! -f "${BUILD_DIR}/${name}" ]]; then
      missing+=("${name}")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    error "Missing built binaries in ${BUILD_DIR}: ${missing[*]}"
  fi
}

# ---------------------------------------------------------------------------
# Place binaries into prefix
# ---------------------------------------------------------------------------
place_binaries() {
  info "Installing binaries to ${PREFIX} ..."
  mkdir -p -- "${PREFIX}"
  local name
  for name in "${BINARY_NAMES[@]}"; do
    cp -- "${BUILD_DIR}/${name}" "${PREFIX}/${name}"
    chmod 0755 -- "${PREFIX}/${name}"
    success "  ${PREFIX}/${name}"
  done
}

# ---------------------------------------------------------------------------
# Delegate wiring to the freshly built clx install
# ---------------------------------------------------------------------------
run_clx_install() {
  local clx_bin="${PREFIX}/clx"
  info "Delegating Claude Code wiring to: ${clx_bin} install"
  info "(This is the same code path as the Homebrew install -- hooks, MCP, skills)"
  # clx install does not accept --yes / --non-interactive; it is already
  # idempotent and does not prompt for destructive actions during a normal
  # install run, so no flag is passed.
  "${clx_bin}" install
}

# ---------------------------------------------------------------------------
# Verification checklist
# ---------------------------------------------------------------------------
verify_installation() {
  local clx_bin="${PREFIX}/clx"
  local stamp_path="${HOME}/.clx/bin/${VERSION_STAMP_FILE}"
  local settings_path="${HOME}/.claude/settings.json"
  local skills_dir="${HOME}/.claude/skills"
  local all_pass=true

  echo ""
  info "--- Verification checklist ---"

  # 1. Stamp matches built version.
  local stamped_ver=""
  if [[ -f "${stamp_path}" ]]; then
    stamped_ver="$(tr -d '[:space:]' <"${stamp_path}")"
  fi
  if [[ "${stamped_ver}" == "${CLX_VERSION}" ]]; then
    success "Version stamp matches ${CLX_VERSION}"
  else
    warn "FAIL: version stamp '${stamped_ver}' != built '${CLX_VERSION}'"
    all_pass=false
  fi

  # 2. clx --version in prefix matches.
  local prefix_ver=""
  if [[ -x "${clx_bin}" ]]; then
    prefix_ver="$("${clx_bin}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  fi
  if [[ "${prefix_ver}" == "${CLX_VERSION}" ]]; then
    success "${clx_bin} --version == ${CLX_VERSION}"
  else
    warn "FAIL: ${clx_bin} --version reported '${prefix_ver}' (expected ${CLX_VERSION})"
    all_pass=false
  fi

  # 3. ~/.clx/bin/clx-hook exists (clx install copies binaries to its own bin).
  if [[ -x "${HOME}/.clx/bin/clx-hook" ]]; then
    success "~/.clx/bin/clx-hook present"
  else
    warn "FAIL: ~/.clx/bin/clx-hook not found"
    all_pass=false
  fi

  # 4. settings.json has Stop hook.
  if [[ -f "${settings_path}" ]] && grep -q '"Stop"' "${settings_path}" 2>/dev/null; then
    success "~/.claude/settings.json contains Stop hook"
  else
    warn "FAIL: Stop hook not found in ${settings_path}"
    all_pass=false
  fi

  # 5. settings.json has clx MCP server.
  if [[ -f "${settings_path}" ]] && grep -q '"clx-mcp"' "${settings_path}" 2>/dev/null; then
    success "~/.claude/settings.json contains clx MCP server"
  else
    warn "FAIL: clx MCP server not found in ${settings_path}"
    all_pass=false
  fi

  # 6. All 6 skill directories present.
  local missing_skills=()
  local skill
  for skill in "${SKILL_NAMES[@]}"; do
    if [[ ! -f "${skills_dir}/${skill}/SKILL.md" ]]; then
      missing_skills+=("${skill}")
    fi
  done
  if [[ ${#missing_skills[@]} -eq 0 ]]; then
    success "All 6 CLX skills present in ~/.claude/skills/"
  else
    warn "FAIL: Missing skills: ${missing_skills[*]}"
    all_pass=false
  fi

  echo ""
  if [[ "${all_pass}" == true ]]; then
    success "All checks passed."
  else
    printf "${RED}%s${NC} %s\n" "✗" "One or more checks failed. Re-run with --skip-build after fixing, or run:" >&2
    printf "  %s\n" "${clx_bin} install" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Uninstall path
# ---------------------------------------------------------------------------
run_uninstall() {
  local clx_bin="${PREFIX}/clx"

  info "Uninstall: delegating wiring removal to ${clx_bin} uninstall ..."

  if [[ ! -x "${clx_bin}" ]]; then
    warn "${clx_bin} not found; attempting to use clx from PATH for uninstall."
    clx_bin="$(command -v clx 2>/dev/null || true)"
    if [[ -z "${clx_bin}" ]]; then
      error "Cannot find clx binary for uninstall. Was --prefix set correctly?"
    fi
  fi

  "${clx_bin}" uninstall

  # Remove binaries this script placed in --prefix.
  local removed=()
  local name
  for name in "${BINARY_NAMES[@]}"; do
    local target="${PREFIX}/${name}"
    if [[ -f "${target}" ]]; then
      rm -f -- "${target}"
      removed+=("${target}")
    fi
  done

  if [[ ${#removed[@]} -gt 0 ]]; then
    success "Removed from ${PREFIX}: ${BINARY_NAMES[*]}"
  else
    info "No CLX binaries found in ${PREFIX} to remove."
  fi

  echo ""
  success "Uninstall complete. Restart Claude Code to apply changes."
}

# ---------------------------------------------------------------------------
# PATH note helper
# ---------------------------------------------------------------------------
print_path_note() {
  # Check whether PREFIX is already in the effective PATH.
  local in_path=false
  local entry
  while IFS= read -r -d ':' entry; do
    if [[ "${entry}" == "${PREFIX}" ]]; then
      in_path=true
      break
    fi
  done <<<"${PATH}:"

  if [[ "${in_path}" == false ]]; then
    echo ""
    warn "  '${PREFIX}' is not in your current PATH."
    warn "  Add it to your shell profile:"
    warn "    export PATH=\"${PREFIX}:\${PATH}\""
    warn "  Then reload: source ~/.zshrc  (or ~/.bashrc)"
  fi
}

# ---------------------------------------------------------------------------
# Final next-steps message
# ---------------------------------------------------------------------------
print_next_steps() {
  echo ""
  printf "${GREEN}╔════════════════════════════════════════╗${NC}\n"
  printf "${GREEN}║    CLX ${CLX_VERSION} installed from source     ║${NC}\n"
  printf "${GREEN}╚════════════════════════════════════════╝${NC}\n"
  echo ""
  echo "  Binaries (user PATH): ${PREFIX}/clx"
  echo "  Runtime dir:          ~/.clx/"
  echo "  Claude settings:      ~/.claude/settings.json"
  echo ""
  echo "  Next steps:"
  echo "    1. Restart Claude Code to load hooks and the MCP server."
  echo "    2. Verify with: ${PREFIX}/clx dashboard"

  print_path_note

  echo ""
  echo "  Model setup (optional, improves recall ranking):"
  echo "    Run: ollama pull qwen3:1.7b && ollama pull qwen3-embedding:0.6b"
  echo "    Without models, CLX falls back to RRF-only ranking -- not an error."
  echo ""
  echo "  To uninstall:"
  echo "    bash scripts/install-local.sh --uninstall"
  echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  echo ""
  printf "${CYAN}╔════════════════════════════════════════╗${NC}\n"
  printf "${CYAN}║     CLX local build installer          ║${NC}\n"
  printf "${CYAN}╚════════════════════════════════════════╝${NC}\n"
  echo ""

  # Phase 1: Preflight
  assert_clx_repo

  # Read version early so it is available for shadowing detection and messages.
  CLX_VERSION="$(read_workspace_version)"
  readonly CLX_VERSION

  info "Building CLX ${CLX_VERSION} from source (no Homebrew)"

  check_platform
  assert_cargo
  assert_toolchain
  assert_prefix_writable
  detect_shadowing

  if [[ "${UNINSTALL}" == true ]]; then
    run_uninstall
    exit 0
  fi

  # Phase 2: Build
  build_clx

  # Phase 3: Verify built binaries exist, then place them.
  assert_binaries_exist
  place_binaries

  # Phase 4: Delegate all Claude Code wiring to the freshly built binary.
  run_clx_install

  # Phase 5: Verify.
  verify_installation

  # Phase 6: Next steps.
  print_next_steps
}

main "$@"
