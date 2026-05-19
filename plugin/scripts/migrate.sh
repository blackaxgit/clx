#!/usr/bin/env bash
# Migrate a CLX plugin install from the 2025 layout to the 2026 schema.
#
# 2025 layout:
#   <root>/plugin.json
#   <root>/skills/using-clx/SKILL.md
#
# 2026 layout:
#   <root>/.claude-plugin/plugin.json
#   <root>/.claude-plugin/skills/<name>/SKILL.md   (one per skill)
#
# Usage:
#   plugin/scripts/migrate.sh [--root <dir>] [--dry-run] [--yes] [--rollback]
#
#   --root <dir>   Target a specific plugin root. Default: the CLX source
#                  repo (parent of this script's plugin/ directory).
#                  Typical alt: ~/.claude/plugins/clx
#   --dry-run      Print the plan; do not modify the filesystem.
#   --yes          Skip interactive confirmation (required in CI).
#   --rollback     Reverse a prior migration using .archive/2025 contents.
#
# Exit codes:
#   0  success or clean no-op
#   1  validation error or aborted by user
#   2  unsupported state (mixed layout, conflicting files)

set -euo pipefail
LC_ALL=C
export LC_ALL

DRY_RUN=0
ASSUME_YES=0
ROLLBACK=0
ROOT=""

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
default_root="$(cd "$script_dir/.." && pwd)"

usage() {
    sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

log()  { printf '[migrate] %s\n' "$*"; }
warn() { printf '[migrate] WARN: %s\n' "$*" >&2; }
die()  { printf '[migrate] FAIL: %s\n' "$*" >&2; exit "${2:-1}"; }

# Argument parse.
while [ $# -gt 0 ]; do
    case "$1" in
        --root)     ROOT="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=1; shift ;;
        --yes)      ASSUME_YES=1; shift ;;
        --rollback) ROLLBACK=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) die "unknown arg '$1' (try --help)" 2 ;;
    esac
done

[ -n "$ROOT" ] || ROOT="$default_root"
[ -d "$ROOT" ] || die "root does not exist: $ROOT" 2
ROOT="$(cd "$ROOT" && pwd)"

LEGACY_MANIFEST="$ROOT/plugin.json"
LEGACY_SKILLS="$ROOT/skills"
NEW_DIR="$ROOT/.claude-plugin"
NEW_MANIFEST="$NEW_DIR/plugin.json"
NEW_SKILLS="$NEW_DIR/skills"
ARCHIVE_DIR="$ROOT/.archive/2025"

run() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '  (dry-run) %s\n' "$*"
    else
        eval "$@"
    fi
}

confirm() {
    if [ "$ASSUME_YES" = "1" ] || [ "$DRY_RUN" = "1" ]; then
        return 0
    fi
    printf '%s [y/N]: ' "$1"
    read -r reply || true
    case "$reply" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

rollback() {
    log "rollback mode on root: $ROOT"
    [ -d "$ARCHIVE_DIR" ] || die "no archive found at $ARCHIVE_DIR; nothing to roll back" 1
    log "plan:"
    [ -f "$ARCHIVE_DIR/plugin.json" ] && log "  restore $ARCHIVE_DIR/plugin.json -> $LEGACY_MANIFEST"
    [ -d "$ARCHIVE_DIR/skills" ]      && log "  restore $ARCHIVE_DIR/skills -> $LEGACY_SKILLS"
    log "  remove $NEW_DIR"
    confirm "Proceed with rollback?" || die "aborted by user" 1

    if [ -f "$ARCHIVE_DIR/plugin.json" ]; then
        run "cp '$ARCHIVE_DIR/plugin.json' '$LEGACY_MANIFEST'"
    fi
    if [ -d "$ARCHIVE_DIR/skills" ]; then
        run "cp -R '$ARCHIVE_DIR/skills' '$LEGACY_SKILLS'"
    fi
    run "rm -rf '$NEW_DIR'"
    log "rollback complete."
}

migrate() {
    log "migrate mode on root: $ROOT"

    local has_legacy_manifest=0 has_legacy_skills=0 has_new=0
    [ -f "$LEGACY_MANIFEST" ] && has_legacy_manifest=1
    [ -d "$LEGACY_SKILLS" ]   && has_legacy_skills=1
    [ -d "$NEW_DIR" ]         && has_new=1

    if [ "$has_legacy_manifest" = "0" ] && [ "$has_legacy_skills" = "0" ]; then
        if [ "$has_new" = "1" ]; then
            log "no legacy files present; new layout already in place. Nothing to do."
            return 0
        fi
        die "no plugin files found at $ROOT (looked for plugin.json and .claude-plugin/)" 2
    fi

    if [ "$has_new" = "1" ] && [ "$has_legacy_manifest" = "1" ]; then
        die "both layouts present at $ROOT (plugin.json AND .claude-plugin/); resolve manually" 2
    fi

    log "plan:"
    [ "$has_legacy_manifest" = "1" ] && log "  move    $LEGACY_MANIFEST -> $NEW_MANIFEST"
    [ "$has_legacy_skills" = "1" ]   && {
        log "  archive $LEGACY_SKILLS -> $ARCHIVE_DIR/skills"
        log "  remove  $LEGACY_SKILLS"
    }
    [ "$has_legacy_manifest" = "1" ] && log "  archive copy of plugin.json -> $ARCHIVE_DIR/plugin.json"

    confirm "Proceed with migration?" || die "aborted by user" 1

    run "mkdir -p '$NEW_DIR' '$ARCHIVE_DIR'"

    if [ "$has_legacy_manifest" = "1" ]; then
        run "cp '$LEGACY_MANIFEST' '$ARCHIVE_DIR/plugin.json'"
        run "mv '$LEGACY_MANIFEST' '$NEW_MANIFEST'"
    fi

    if [ "$has_legacy_skills" = "1" ]; then
        # Archive then remove (never rm -rf the original without a copy).
        run "cp -R '$LEGACY_SKILLS' '$ARCHIVE_DIR/skills'"
        run "rm -rf '$LEGACY_SKILLS'"
        # The 2026 layout's skills/ is intentionally NOT auto-populated from
        # the monolithic legacy SKILL.md; users should pull the official
        # 2026 skills via 'clx install' or by copying from the repo. Print a
        # clear note about this.
        warn "legacy single skill archived; install the 0.8.0 plugin to pick up the six named skills."
    fi

    log "migration complete. Run plugin/scripts/validate.sh to verify."
}

if [ "$ROLLBACK" = "1" ]; then
    rollback
else
    migrate
fi
