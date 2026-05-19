#!/usr/bin/env bash
#
# CLX 0.8.0 local test harness.
#
# One command, zero network, zero real keychain, zero 568 MB model download.
# See docs/testing.md for prerequisites, the published coverage denominator,
# and the exclusion rationale.
#
# Subcommands (spec section 3):
#   fast         cargo nextest run --workspace            (quick inner loop)
#   cov          cargo llvm-cov nextest, instrumented denominator, >= 97%
#   snapshots    cargo insta test --review                (TUI pixel snapshots)
#   mutants      cargo mutants --in-place                 (long; opt-in)
#   all          fast + cov + snapshot-verify             (pre-release gate)
#   pre-release  all + plugin validate --strict + e2e suite
#
# Any tool that is absent is skipped with an actionable hint; siblings still
# run. Only `cov` and `pre-release` carry a hard pass/fail gate.

set -euo pipefail

# --- Locate the workspace root (this script lives in <root>/scripts) --------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# --- The published instrumented coverage denominator ------------------------
# Kept byte-identical with Cargo.toml [workspace.metadata.cargo-llvm-cov] and
# the table in docs/testing.md. Edit all three together.
COV_IGNORE_REGEX='(dashboard/event\.rs|main\.rs|dashboard/runtime\.rs|credentials/keychain_acl\.rs|dashboard/mod\.rs|commands/keychain_trust\.rs)'
COV_FAIL_UNDER=97

# --- Hermetic environment: no network, no keychain, no model download -------
# CLX_MODEL_FETCH_DRYRUN  -> `clx model fetch` stubs artifacts, never downloads
#                            the 568 MB bge-reranker-v2-m3 weights.
# CLX_CREDENTIALS_BACKEND  -> force the default age-encrypted file backend so
#                            nothing touches the real macOS keychain.
# RUST_BACKTRACE           -> actionable failures.
# #[ignore] real-keychain tests stay ignored: we never pass --run-ignored.
export CLX_MODEL_FETCH_DRYRUN=1
export CLX_CREDENTIALS_BACKEND="${CLX_CREDENTIALS_BACKEND:-age}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

# --- Colors (suppressed when not a tty) -------------------------------------
if [ -t 1 ]; then
  C_BOLD=$'\033[1m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'
  C_YEL=$'\033[33m'; C_RST=$'\033[0m'
else
  C_BOLD=''; C_RED=''; C_GRN=''; C_YEL=''; C_RST=''
fi

info()  { printf '%s==>%s %s\n' "${C_BOLD}" "${C_RST}" "$*"; }
ok()    { printf '%s ok %s %s\n' "${C_GRN}" "${C_RST}" "$*"; }
warn()  { printf '%sskip%s %s\n' "${C_YEL}" "${C_RST}" "$*"; }
fail()  { printf '%sFAIL%s %s\n' "${C_RED}" "${C_RST}" "$*" >&2; }

# has_tool <cargo-subcommand> -> 0 if `cargo <sub>` is available.
has_tool() {
  command -v "cargo-$1" >/dev/null 2>&1
}

missing_hint() {
  warn "cargo-$1 not installed; skipping. Install all harness tools with:"
  printf '       cargo install cargo-nextest cargo-llvm-cov cargo-insta cargo-mutants\n'
}

usage() {
  cat <<'EOF'
clx test harness

Usage: scripts/test.sh <subcommand>

Subcommands:
  fast         cargo nextest run --workspace (quick inner loop)
  cov          cargo llvm-cov nextest, instrumented denominator, fail < 97%
  snapshots    cargo insta test --review (TUI pixel snapshots)
  mutants      cargo mutants --in-place (long-running; opt-in)
  all          fast + cov + snapshot verify (the pre-release gate)
  pre-release  all + plugin/scripts/validate.sh --strict + e2e suite
  --help, -h   this message

Prerequisites (graceful skip if absent):
  cargo install cargo-nextest cargo-llvm-cov cargo-insta cargo-mutants

Hermetic: zero network, zero real keychain, zero 568 MB model download.
EOF
}

# --- fast: quick inner loop -------------------------------------------------
run_fast() {
  if ! has_tool nextest; then
    missing_hint nextest
    info "Falling back to: cargo test --workspace"
    cargo test --workspace
    ok "cargo test (fallback) passed"
    return 0
  fi
  info "cargo nextest run --workspace"
  cargo nextest run --workspace
  ok "fast suite passed"
}

# --- LLVM toolchain resolution for cargo-llvm-cov ---------------------------
# cargo-llvm-cov needs llvm-cov + llvm-profdata that match the rustc LLVM. With
# rustup it discovers them via the active toolchain. Without rustup (Homebrew
# rust) the operator otherwise has to export LLVM_COV/LLVM_PROFDATA by hand;
# auto-detect the Homebrew LLVM so `cov` works out of the box.
resolve_llvm_env() {
  if command -v rustup >/dev/null 2>&1; then
    return 0
  fi
  if [ -n "${LLVM_COV:-}" ] && [ -n "${LLVM_PROFDATA:-}" ]; then
    return 0
  fi
  local candidates=()
  if command -v brew >/dev/null 2>&1; then
    candidates+=("$(brew --prefix llvm 2>/dev/null)/bin")
  fi
  candidates+=("/opt/homebrew/opt/llvm/bin" "/usr/local/opt/llvm/bin")
  local dir
  for dir in "${candidates[@]}"; do
    if [ -x "${dir}/llvm-cov" ] && [ -x "${dir}/llvm-profdata" ]; then
      export LLVM_COV="${dir}/llvm-cov"
      export LLVM_PROFDATA="${dir}/llvm-profdata"
      info "auto-resolved LLVM: ${dir} (no rustup; using Homebrew LLVM)"
      return 0
    fi
  done
  fail "rustup absent and no Homebrew LLVM found. Install with:"
  printf '       brew install llvm   # provides llvm-cov + llvm-profdata\n' >&2
  printf '       (or export LLVM_COV / LLVM_PROFDATA to a matching toolchain)\n' >&2
  return 1
}

# --- cov: the instrumented coverage gate ------------------------------------
run_cov() {
  if ! has_tool llvm-cov; then
    missing_hint llvm-cov
    return 0
  fi
  resolve_llvm_env || return 1
  local runner=()
  if has_tool nextest; then
    # The `ci` profile (.config/nextest.toml) sets fail-fast=false and
    # retries=0: a coverage measurement must run EVERY test regardless of
    # individual failures and still emit the summary, not abort on first red.
    runner=(nextest --profile ci)
  else
    warn "cargo-nextest absent; cargo-llvm-cov will use the built-in test runner"
  fi
  info "cargo llvm-cov ${runner[*]:-} --workspace (denominator: ${COV_IGNORE_REGEX})"
  cargo llvm-cov "${runner[@]}" --workspace \
    --ignore-filename-regex "${COV_IGNORE_REGEX}" \
    --fail-under-lines "${COV_FAIL_UNDER}" \
    --summary-only
  ok "coverage >= ${COV_FAIL_UNDER}% on the published instrumented denominator"
}

# --- snapshots: TUI pixel snapshots -----------------------------------------
# `verify` mode (non-interactive, used by `all`/`pre-release`) vs `review`.
run_snapshots() {
  local mode="${1:-review}"
  if ! has_tool insta; then
    missing_hint insta
    return 0
  fi
  if [ "${mode}" = "verify" ]; then
    info "cargo insta test (verify, no pending snapshots allowed)"
    cargo insta test --unreferenced=reject
    ok "snapshots verified"
  else
    info "cargo insta test --review"
    cargo insta test --review
    ok "snapshot review complete"
  fi
}

# --- mutants: long-running mutation gate ------------------------------------
run_mutants() {
  if ! has_tool mutants; then
    missing_hint mutants
    return 0
  fi
  info "cargo mutants --in-place (hot modules per mutants.toml; long-running)"
  cargo mutants --in-place
  ok "mutation run complete"
}

# --- all: the pre-release gate ----------------------------------------------
run_all() {
  run_fast
  run_cov
  run_snapshots verify
  ok "all: fast + cov + snapshot-verify complete"
}

# --- pre-release: full sign-off ---------------------------------------------
run_pre_release() {
  run_all
  local validate="plugin/scripts/validate.sh"
  if [ -x "${validate}" ]; then
    info "${validate} --strict"
    bash "${validate}" --strict
    ok "plugin validate (strict) passed"
  else
    warn "${validate} not found or not executable; skipping plugin validation"
  fi
  info "e2e suite: cargo test --workspace --test '*' (assert_cmd binaries)"
  cargo test --workspace --test '*'
  ok "pre-release sign-off complete"
}

main() {
  local cmd="${1:-}"
  case "${cmd}" in
    fast)        run_fast ;;
    cov)         run_cov ;;
    snapshots)   run_snapshots review ;;
    mutants)     run_mutants ;;
    all)         run_all ;;
    pre-release) run_pre_release ;;
    -h|--help|help|'') usage ;;
    *)
      fail "unknown subcommand: ${cmd}"
      usage
      exit 2
      ;;
  esac
}

main "$@"
