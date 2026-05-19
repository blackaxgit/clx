#!/usr/bin/env bash
# Shell tests for plugin/scripts/validate.sh
#
# Coverage:
#   1. Happy path: real plugin/.claude-plugin/ tree validates green (exit 0).
#   2. Missing manifest: synthesized tree without plugin.json fails.
#   3. Legacy layout detected: only plugin.json at root, no .claude-plugin/.
#   4. Skill name mismatch: dir renamed but frontmatter name stale.
#   5. Oversize description: synthesized 1100-char description fails.
#   6. Trigger-bleed (strict): description without "Use when" prefix.
#   7. Orphan in manifest: manifest references a missing skill dir.
#   8. Orphan on disk: skill dir exists but is not in manifest.
#
# Runs with plain bash. No bats dependency.

set -uo pipefail
LC_ALL=C
export LC_ALL

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
real_validate="$repo_root/plugin/scripts/validate.sh"

pass=0
fail=0
failures=()

assert_eq() {
    # assert_eq <label> <actual> <expected>
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        pass=$((pass + 1))
        printf '  PASS: %s\n' "$label"
    else
        fail=$((fail + 1))
        failures+=("$label (got '$actual', want '$expected')")
        printf '  FAIL: %s (got "%s", want "%s")\n' "$label" "$actual" "$expected"
    fi
}

run_validate() {
    # run_validate <fake_plugin_dir> [args...]
    # Stages a fake plugin/ tree, invokes the real validate.sh with PLUGIN_DIR
    # relocated by symlinking the script in. Returns the exit code in $?.
    local fake_plugin="$1"; shift
    # Copy validate.sh into the fake tree so the script's $PLUGIN_DIR resolves
    # to the fake root.
    mkdir -p "$fake_plugin/scripts"
    cp "$real_validate" "$fake_plugin/scripts/validate.sh"
    chmod +x "$fake_plugin/scripts/validate.sh"
    bash "$fake_plugin/scripts/validate.sh" "$@" > /dev/null 2>&1
    return $?
}

make_skill() {
    # make_skill <skills_dir> <name> <description>
    local dir="$1" name="$2" desc="$3"
    mkdir -p "$dir/$name"
    cat > "$dir/$name/SKILL.md" <<EOF
---
name: $name
description: >
  $desc
---

# $name

Body.
EOF
}

write_manifest() {
    # write_manifest <path> <skill1> [<skill2> ...]
    local path="$1"; shift
    {
        printf '{\n'
        printf '  "name": "clx",\n'
        printf '  "version": "0.8.0",\n'
        printf '  "description": "test fixture",\n'
        printf '  "skills": ['
        local first=1
        for s in "$@"; do
            if [ "$first" = "1" ]; then
                printf '"./skills/%s"' "$s"
                first=0
            else
                printf ', "./skills/%s"' "$s"
            fi
        done
        printf ']\n'
        printf '}\n'
    } > "$path"
}

# ----- Test 1: real tree validates green ----------------------------------

echo "== Test 1: real plugin tree (happy path) =="
bash "$real_validate" > /dev/null 2>&1
assert_eq "1.real_tree_exit_code" "$?" "0"

# Staging area for synthetic tests.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ----- Test 2: missing manifest -------------------------------------------

echo "== Test 2: missing manifest =="
t2="$work/t2/plugin"
mkdir -p "$t2/.claude-plugin/skills/clx-recall"
make_skill "$t2/.claude-plugin/skills" "clx-recall" "Use when X."
# no plugin.json
run_validate "$t2"
assert_eq "2.missing_manifest_fails" "$?" "1"

# ----- Test 3: legacy layout detected -------------------------------------

echo "== Test 3: legacy layout =="
t3="$work/t3/plugin"
mkdir -p "$t3"
cat > "$t3/plugin.json" <<'EOF'
{"name":"clx","version":"0.5.3","skills":"./skills"}
EOF
run_validate "$t3"
assert_eq "3.legacy_manifest_fails" "$?" "1"

# ----- Test 4: skill name mismatch ----------------------------------------

echo "== Test 4: name mismatch =="
t4="$work/t4/plugin"
mkdir -p "$t4/.claude-plugin/skills"
make_skill "$t4/.claude-plugin/skills" "clx-recall" "Use when X."
# Rename dir but keep frontmatter name=clx-recall.
mv "$t4/.claude-plugin/skills/clx-recall" "$t4/.claude-plugin/skills/clx-recall-renamed"
write_manifest "$t4/.claude-plugin/plugin.json" "clx-recall-renamed"
run_validate "$t4"
assert_eq "4.name_mismatch_fails" "$?" "1"

# ----- Test 5: oversize description ---------------------------------------

echo "== Test 5: oversize description =="
t5="$work/t5/plugin"
mkdir -p "$t5/.claude-plugin/skills"
# 1100 chars of 'x' inside a "Use when ..." sentence.
big="$(python3 -c "print('Use when ' + 'x' * 1100)")"
make_skill "$t5/.claude-plugin/skills" "clx-recall" "$big"
write_manifest "$t5/.claude-plugin/plugin.json" "clx-recall"
run_validate "$t5"
assert_eq "5.oversize_description_fails" "$?" "1"

# ----- Test 6: trigger-bleed prefix ---------------------------------------

echo "== Test 6: trigger-bleed (strict mode) =="
t6="$work/t6/plugin"
mkdir -p "$t6/.claude-plugin/skills"
make_skill "$t6/.claude-plugin/skills" "clx-recall" "For memory operations and stuff."
write_manifest "$t6/.claude-plugin/plugin.json" "clx-recall"
run_validate "$t6" --strict
assert_eq "6a.bleed_strict_fails" "$?" "1"
run_validate "$t6" --no-strict
assert_eq "6b.bleed_nonstrict_passes" "$?" "0"

# ----- Test 7: orphan in manifest -----------------------------------------

echo "== Test 7: orphan in manifest =="
t7="$work/t7/plugin"
mkdir -p "$t7/.claude-plugin/skills"
make_skill "$t7/.claude-plugin/skills" "clx-recall" "Use when X."
write_manifest "$t7/.claude-plugin/plugin.json" "clx-recall" "clx-does-not-exist"
run_validate "$t7"
assert_eq "7.orphan_in_manifest_fails" "$?" "1"

# ----- Test 8: orphan on disk ---------------------------------------------

echo "== Test 8: orphan on disk =="
t8="$work/t8/plugin"
mkdir -p "$t8/.claude-plugin/skills"
make_skill "$t8/.claude-plugin/skills" "clx-recall" "Use when X."
make_skill "$t8/.claude-plugin/skills" "clx-remember" "Use when X."
write_manifest "$t8/.claude-plugin/plugin.json" "clx-recall"
# clx-remember exists but is not in manifest.
run_validate "$t8"
assert_eq "8.orphan_on_disk_fails" "$?" "1"

# ----- Summary -------------------------------------------------------------

echo
echo "Passed: $pass"
echo "Failed: $fail"
if [ "$fail" -gt 0 ]; then
    echo "Failures:"
    for f in "${failures[@]}"; do
        printf '  - %s\n' "$f"
    done
    exit 1
fi
echo "All validate.sh tests passed."
exit 0
