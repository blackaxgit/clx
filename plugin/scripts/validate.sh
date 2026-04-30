#!/usr/bin/env bash
# Static validator for the CLX Claude Code plugin.
# Checks:
#   1. plugin.json parses as valid JSON.
#   2. SKILL.md has valid YAML frontmatter.
#   3. Frontmatter description contains every required trigger keyword.
# Exits non-zero on any failure.

set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$PLUGIN_DIR/plugin.json"
SKILL="$PLUGIN_DIR/skills/using-clx/SKILL.md"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# 1. plugin.json must exist and parse as valid JSON.
[ -f "$MANIFEST" ] || fail "plugin.json not found at $MANIFEST"
python3 -m json.tool "$MANIFEST" > /dev/null || fail "plugin.json is not valid JSON"

# 2. SKILL.md must exist and start with YAML frontmatter block.
[ -f "$SKILL" ] || fail "SKILL.md not found at $SKILL"
head -1 "$SKILL" | grep -qx -- '---' || fail "SKILL.md does not start with YAML frontmatter (---)"

# Extract frontmatter block (lines between the first two --- markers) and
# fold all whitespace runs (including newlines) into single spaces. This makes
# keyword matching robust against YAML folded-scalar line wraps, where a
# multi-word keyword like "persistent memory" can otherwise straddle a
# line break.
frontmatter="$(awk '/^---$/{c++; next} c==1{print} c==2{exit}' "$SKILL")"
[ -n "$frontmatter" ] || fail "SKILL.md frontmatter block is empty"
frontmatter_folded="$(printf '%s' "$frontmatter" | tr '\n\t' '  ' | tr -s ' ')"

# 3. Required trigger keywords must appear in the frontmatter.
required=(
    "earlier"
    "we discussed"
    "clx_recall"
    "clx_remember"
    "clx_checkpoint"
    "clx_rules"
    "persistent memory"
)
for kw in "${required[@]}"; do
    printf '%s' "$frontmatter_folded" | grep -qi -- "$kw" \
        || fail "frontmatter missing required trigger keyword: '$kw'"
done

echo "OK: plugin/plugin.json and plugin/skills/using-clx/SKILL.md are valid."
