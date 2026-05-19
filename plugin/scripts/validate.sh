#!/usr/bin/env bash
# Static validator for the CLX Claude Code plugin (2026 schema).
#
# Checks:
#   1. .claude-plugin/plugin.json parses as valid JSON and declares name + version.
#   2. Each SKILL.md under .claude-plugin/skills/<name>/SKILL.md has valid YAML
#      frontmatter with required keys: name, description.
#   3. name is kebab-case, <= 64 chars, matches parent directory.
#   4. description is non-empty, <= 1024 chars.
#   5. No orphan skills: every .claude-plugin/skills/<dir>/ has SKILL.md and
#      every SKILL.md sits in .claude-plugin/skills/<dir>/.
#   6. --strict: description starts with "Use when" (trigger-bleed guard).
#
# Exits non-zero on any failure.

set -euo pipefail

STRICT=0
for arg in "$@"; do
    case "$arg" in
        --strict) STRICT=1 ;;
        --no-strict) STRICT=0 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$PLUGIN_DIR/.claude-plugin/plugin.json"
SKILLS_DIR="$PLUGIN_DIR/.claude-plugin/skills"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# 1. Manifest must exist, parse as JSON, and have name + version.
[ -f "$MANIFEST" ] || fail "plugin.json not found at $MANIFEST"
python3 -m json.tool "$MANIFEST" > /dev/null || fail "plugin.json is not valid JSON"
python3 -c "
import json, sys
m = json.load(open('$MANIFEST'))
for k in ('name', 'version'):
    if k not in m or not m[k]:
        print(f'manifest missing {k}', file=sys.stderr); sys.exit(1)
" || fail "plugin.json missing required name/version"

# 2-6. Validate each SKILL.md.
[ -d "$SKILLS_DIR" ] || fail "skills directory not found at $SKILLS_DIR"

skill_count=0
while IFS= read -r skill; do
    skill_count=$((skill_count + 1))
    parent_dir="$(basename "$(dirname "$skill")")"

    head -1 "$skill" | grep -qx -- '---' \
        || fail "$skill does not start with YAML frontmatter (---)"

    frontmatter="$(awk '/^---$/{c++; next} c==1{print} c==2{exit}' "$skill")"
    [ -n "$frontmatter" ] || fail "$skill frontmatter block is empty"

    name="$(printf '%s\n' "$frontmatter" | awk -F': *' '/^name:/{print $2; exit}' | tr -d '"'\''')"
    desc="$(printf '%s\n' "$frontmatter" \
        | awk '/^description:/{flag=1; sub(/^description: */, ""); print; next}
               flag && /^[a-zA-Z_][a-zA-Z0-9_]*:/{flag=0; exit}
               flag{print}' \
        | sed 's/^[>|][-+]*$//' \
        | tr '\n' ' ' | sed 's/^ *//; s/ *$//; s/  */ /g')"

    [ -n "$name" ] || fail "$skill missing frontmatter key: name"
    [ -n "$desc" ] || fail "$skill missing frontmatter key: description"

    case "$name" in
        [a-z]*) ;;
        *) fail "$skill name '$name' must start with lowercase letter" ;;
    esac
    echo "$name" | grep -qE '^[a-z][a-z0-9-]*$' \
        || fail "$skill name '$name' must be kebab-case (lowercase letters, digits, hyphens)"

    name_len=${#name}
    [ "$name_len" -le 64 ] || fail "$skill name length ($name_len) exceeds 64 chars"

    desc_len=${#desc}
    [ "$desc_len" -le 1024 ] || fail "$skill description length ($desc_len) exceeds 1024 chars"

    [ "$name" = "$parent_dir" ] \
        || fail "$skill name '$name' does not match parent dir '$parent_dir'"

    if [ "$STRICT" -eq 1 ]; then
        case "$desc" in
            "Use when"*) ;;
            *) fail "$skill description must start with 'Use when' under --strict" ;;
        esac
    fi
done < <(find "$SKILLS_DIR" -mindepth 2 -maxdepth 2 -name 'SKILL.md' -type f | sort)

# Orphan check: every subdir must have SKILL.md.
while IFS= read -r dir; do
    [ -f "$dir/SKILL.md" ] || fail "skill dir $dir missing SKILL.md"
done < <(find "$SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d | sort)

[ "$skill_count" -gt 0 ] || fail "no skills found under $SKILLS_DIR"

# Bidirectional orphan check between manifest "skills" array and on-disk dirs.
# Manifest entries look like "./skills/<name>"; on-disk skill dirs sit at
# $SKILLS_DIR/<name>/.
declared_skills="$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
for s in m.get('skills', []):
    name = s.rsplit('/', 1)[-1]
    print(name)
" | sort)"

ondisk_skills="$(find "$SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d \
    -exec basename {} \; | sort)"

# Direction 1: every declared skill must exist on disk.
while IFS= read -r name; do
    [ -z "$name" ] && continue
    [ -d "$SKILLS_DIR/$name" ] \
        || fail "manifest declares skill '$name' but $SKILLS_DIR/$name does not exist"
done <<< "$declared_skills"

# Direction 2: every on-disk skill must be declared in manifest.
while IFS= read -r name; do
    [ -z "$name" ] && continue
    if ! printf '%s\n' "$declared_skills" | grep -qx "$name"; then
        fail "on-disk skill dir '$name' is not declared in $MANIFEST skills array"
    fi
done <<< "$ondisk_skills"

echo "OK: $MANIFEST and $skill_count SKILL.md file(s) valid (strict=$STRICT)."
