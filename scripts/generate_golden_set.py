#!/usr/bin/env python3
"""Generate a fully synthetic RAGAS-style golden set for CLX recall benchmarking.

Inputs (all PUBLIC):
  - /Users/blackax/Projects/clx/specs/*.md (committed in this repo)
  - Optional --issues-json file (GitHub issues export); skipped if missing

Output:
  - /Users/blackax/Projects/clx/tests/fixtures/recall_golden.yaml

Constraints (enforced before write):
  - No user content. No PHI. No real session IDs.
  - Forbidden tokens are scanned and abort the write on any match:
      /Users/, ~/.clx/, sk-, Bearer , azure_subscription_id, uuid4-shaped IDs.

Determinism:
  - random.seed(0xCAFE)
  - Output is sorted by id; sha256 is reported for reproducibility.

Categories (6, evenly covered):
  recall | skills | config | hook | trust | migration
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path("/Users/blackax/Projects/clx")
SPECS_DIR = REPO_ROOT / "specs"
DEFAULT_OUT = REPO_ROOT / "tests" / "fixtures" / "recall_golden.yaml"

SEED = 0xCAFE

FORBIDDEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("/Users/", re.compile(r"/Users/")),
    ("~/.clx/", re.compile(r"~/\.clx/")),
    ("sk- token", re.compile(r"\bsk-[A-Za-z0-9_-]{6,}")),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{6,}")),
    ("azure_subscription_id", re.compile(r"azure_subscription_id")),
    (
        "uuid4-shaped session id",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
    ),
]

# Hand-curated synthetic question templates per category. Each entry is
# (category, query, expected_snapshot_ids). Snapshot IDs map to a synthetic
# fixture corpus seeded by the criterion bench at runtime, so the IDs are
# semantic only (not tied to any real database).
SYNTHETIC_PAIRS: list[tuple[str, str, list[int]]] = [
    # ---------------- recall (5) ----------------
    (
        "recall",
        "How does the RRF rank fusion stage work in the recall pipeline?",
        [1, 2],
    ),
    (
        "recall",
        "What value of k does Cormack et al. 2009 recommend for reciprocal rank fusion?",
        [1, 3],
    ),
    (
        "recall",
        "How is the cross-encoder reranker integrated after RRF in the recall pipeline?",
        [2, 4],
    ),
    (
        "recall",
        "What is the multiplicative time-decay formula and default half-life applied to recall hits?",
        [5, 6],
    ),
    (
        "recall",
        "Why does the recall pipeline use a percentile gate instead of a fixed score threshold?",
        [6, 7],
    ),
    # ---------------- skills (5) ----------------
    (
        "skills",
        "How does the CLX plugin expose skills to Claude Code via the manifest?",
        [10, 11],
    ),
    (
        "skills",
        "What does the SKILL.md frontmatter schema require for discoverability?",
        [11, 12],
    ),
    (
        "skills",
        "Which directory holds plugin-provided skills and how are they discovered?",
        [10, 13],
    ),
    (
        "skills",
        "How do skills declare their trigger description for progressive disclosure?",
        [12, 14],
    ),
    (
        "skills",
        "What is the relationship between commands, agents, and skills in the CLX plugin?",
        [10, 14],
    ),
    # ---------------- config (5) ----------------
    (
        "config",
        "Where are CLX configuration defaults loaded from and how does figment layer overrides?",
        [20, 21],
    ),
    (
        "config",
        "Which AutoRecallConfig fields control the reranker timeout and enabled flag?",
        [21, 22],
    ),
    (
        "config",
        "How is the rrf_enabled flag wired through RecallEngine::query?",
        [2, 22],
    ),
    (
        "config",
        "What is the default percentile gate value in AutoRecallConfig?",
        [21, 23],
    ),
    (
        "config",
        "How does CLX resolve the model cache directory under the user home?",
        [23, 24],
    ),
    # ---------------- hook (5) ----------------
    (
        "hook",
        "What does the UserPromptSubmit hook do when the reranker model is missing?",
        [30, 31],
    ),
    (
        "hook",
        "How does the PreToolUse hook validate dangerous shell commands before execution?",
        [31, 32],
    ),
    (
        "hook",
        "Which hook fires the background fetch for bge-reranker-v2-m3 on first run?",
        [30, 33],
    ),
    (
        "hook",
        "How does the SessionEnd hook trigger the auto-summary snapshot path?",
        [33, 34],
    ),
    (
        "hook",
        "Which std::sync::Once guard prevents repeated background model fetch spawns?",
        [30, 34],
    ),
    # ---------------- trust (5) ----------------
    (
        "trust",
        "How is the trust mode token stored and expired on disk?",
        [40, 41],
    ),
    (
        "trust",
        "Which lockfile prevents concurrent clx model fetch invocations?",
        [41, 42],
    ),
    (
        "trust",
        "What audit log fields capture an elevated trust operation?",
        [42, 43],
    ),
    (
        "trust",
        "How does CLX redact secrets before writing audit log rows?",
        [43, 44],
    ),
    (
        "trust",
        "Where does CLX persist the SecretString for backend credentials?",
        [40, 44],
    ),
    # ---------------- migration (5) ----------------
    (
        "migration",
        "How does the storage layer apply schema migrations on open?",
        [50, 51],
    ),
    (
        "migration",
        "Which migration introduced the tool_events table in schema v6?",
        [51, 52],
    ),
    (
        "migration",
        "How does the audit_log foreign key constraint cascade on session delete?",
        [52, 53],
    ),
    (
        "migration",
        "What was the schema change that added the snapshots_fts virtual table?",
        [50, 53],
    ),
    (
        "migration",
        "How does CLX guard against running against a newer schema version?",
        [53, 54],
    ),
]

# Per-id summary corpus that the criterion bench will seed into storage.
# Keep summaries short and topical; categories drive content. The bench
# reads this same map (via the YAML output) so that expected_snapshot_ids
# correspond to seeded snapshot rows.
SNAPSHOT_CORPUS: dict[int, dict[str, str]] = {
    # recall (1-9)
    1: {
        "summary": "Reciprocal rank fusion replaces linear hybrid merge in recall.",
        "key_facts": "rrf, fusion, recall, hybrid",
    },
    2: {
        "summary": "RecallEngine::query threads RRF config through the pipeline.",
        "key_facts": "rrf, engine, pipeline, query",
    },
    3: {
        "summary": "Cormack et al. 2009 use k=60 as the literature-standard RRF constant.",
        "key_facts": "cormack, k, sigir, rrf",
    },
    4: {
        "summary": "Cross-encoder bge-reranker-v2-m3 runs after RRF with a 250ms budget.",
        "key_facts": "reranker, cross-encoder, bge, latency",
    },
    5: {
        "summary": "Multiplicative time-decay uses exp(-ln(2)*age_days/30) half-life.",
        "key_facts": "decay, half-life, time, score",
    },
    6: {
        "summary": "Time-decay multiplies score by half-life curve before the gate.",
        "key_facts": "decay, gate, percentile, pipeline",
    },
    7: {
        "summary": "Percentile gate replaces brittle 0.35 fixed similarity threshold.",
        "key_facts": "percentile, gate, threshold, recall",
    },
    # skills (10-14)
    10: {
        "summary": "CLX plugin manifest registers skills under .claude/skills directory.",
        "key_facts": "plugin, manifest, skills, directory",
    },
    11: {
        "summary": "SKILL.md frontmatter schema declares name, description, and triggers.",
        "key_facts": "skill, frontmatter, schema, yaml",
    },
    12: {
        "summary": "Skill descriptions drive progressive disclosure and discovery.",
        "key_facts": "skill, description, discovery, progressive",
    },
    13: {
        "summary": "Plugin skills are auto-discovered from the plugin's skills folder.",
        "key_facts": "plugin, autodiscovery, skills, folder",
    },
    14: {
        "summary": "Plugin components: commands, agents, hooks, and skills compose the manifest.",
        "key_facts": "plugin, commands, agents, skills, hooks",
    },
    # config (20-24)
    20: {
        "summary": "CLX loads defaults via figment with env, file, and CLI layers.",
        "key_facts": "figment, config, defaults, layering",
    },
    21: {
        "summary": "AutoRecallConfig exposes reranker_enabled, reranker_timeout_ms, rrf_k.",
        "key_facts": "autorecall, config, reranker, fields",
    },
    22: {
        "summary": "rrf_enabled boolean lets operators roll back to linear merge.",
        "key_facts": "rrf, rollback, config, flag",
    },
    23: {
        "summary": "Percentile gate default is 70 in AutoRecallConfig.",
        "key_facts": "percentile, gate, default, config",
    },
    24: {
        "summary": "paths::model_cache_dir resolves under the CLX data directory for cached reranker weights.",
        "key_facts": "paths, model, cache, directory",
    },
    # hook (30-34)
    30: {
        "summary": "UserPromptSubmit hook spawns background bge-reranker fetch on miss.",
        "key_facts": "hook, prompt, background, fetch",
    },
    31: {
        "summary": "PreToolUse hook validates shell commands against the deny list.",
        "key_facts": "pretooluse, validation, shell, deny",
    },
    32: {
        "summary": "PreToolUse hook blocks dangerous commands before execution.",
        "key_facts": "block, dangerous, shell, command",
    },
    33: {
        "summary": "SessionEnd hook triggers the final auto-summary snapshot.",
        "key_facts": "sessionend, hook, auto-summary, snapshot",
    },
    34: {
        "summary": "std::sync::Once guard prevents duplicate model fetch spawns.",
        "key_facts": "once, guard, fetch, dedup",
    },
    # trust (40-44)
    40: {
        "summary": "TrustToken stores enabled_at, expires_at, and duration on disk.",
        "key_facts": "trust, token, expiry, disk",
    },
    41: {
        "summary": "clx model fetch acquires a lockfile to prevent concurrent runs.",
        "key_facts": "fetch, lockfile, concurrency, model",
    },
    42: {
        "summary": "Audit log captures actor, operation, and outcome for elevated calls.",
        "key_facts": "audit, log, fields, elevated",
    },
    43: {
        "summary": "Secret redaction strips API key prefixes before audit log persistence.",
        "key_facts": "redaction, secret, audit, persistence",
    },
    44: {
        "summary": "SecretString wraps backend credentials in zeroizing storage.",
        "key_facts": "secretstring, credentials, zeroize, backend",
    },
    # migration (50-54)
    50: {
        "summary": "Storage::open applies schema migrations idempotently at startup.",
        "key_facts": "migration, schema, startup, idempotent",
    },
    51: {
        "summary": "Schema v6 introduces tool_events for hook-driven tool tracking.",
        "key_facts": "schema, v6, tool_events, hook",
    },
    52: {
        "summary": "audit_log foreign key references sessions with ON DELETE CASCADE.",
        "key_facts": "audit, foreign-key, cascade, session",
    },
    53: {
        "summary": "snapshots_fts virtual table enables BM25 full-text search.",
        "key_facts": "fts5, virtual-table, bm25, snapshots",
    },
    54: {
        "summary": "Schema version check refuses downgrade to prevent corruption.",
        "key_facts": "schema, version, downgrade, guard",
    },
}


def _scan_forbidden(text: str) -> list[str]:
    matches: list[str] = []
    for label, pat in FORBIDDEN_PATTERNS:
        m = pat.search(text)
        if m:
            matches.append(f"{label} -> {m.group(0)!r}")
    return matches


def _load_optional_issues(path: str | None) -> list[dict]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def _spec_titles() -> list[str]:
    """Return the section H1 titles of public specs; used only to derive a
    cross-reference list embedded in the YAML header (sanity, not content)."""
    titles: list[str] = []
    if not SPECS_DIR.exists():
        return titles
    for p in sorted(SPECS_DIR.glob("*.md")):
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.startswith("# "):
                    titles.append(line[2:].strip())
                    break
        except Exception:
            continue
    return titles


def _render_yaml(pairs: list[tuple[str, str, list[int]]], spec_titles: list[str]) -> str:
    """Render YAML by hand to avoid runtime PyYAML dependency."""
    lines: list[str] = []
    lines.append("# Auto-generated by scripts/generate_golden_set.py")
    lines.append("# Fully synthetic. No user content. No PHI. No real session IDs.")
    lines.append("# Inputs: public CLX specs under /specs/*.md.")
    lines.append(f"# Seed: {hex(SEED)}")
    lines.append("version: 1")
    lines.append("source: synthetic-public-specs-only")
    lines.append(f"seed: {SEED}")
    lines.append("spec_sources:")
    for title in spec_titles:
        # quote and escape to keep YAML clean
        safe = title.replace('"', '\\"')
        lines.append(f'  - "{safe}"')
    lines.append("snapshot_corpus:")
    for sid in sorted(SNAPSHOT_CORPUS):
        entry = SNAPSHOT_CORPUS[sid]
        s = entry["summary"].replace('"', '\\"')
        kf = entry["key_facts"].replace('"', '\\"')
        lines.append(f"  - snapshot_id: {sid}")
        lines.append(f'    summary: "{s}"')
        lines.append(f'    key_facts: "{kf}"')
    lines.append("pairs:")
    # sort by stable id (q-001, q-002, ...) for determinism
    sorted_pairs = sorted(pairs, key=lambda t: t[1])
    for i, (category, query, expected) in enumerate(sorted_pairs, start=1):
        qid = f"q-{i:03d}"
        safe_query = query.replace('"', '\\"')
        lines.append(f"  - id: {qid}")
        lines.append(f"    category: {category}")
        lines.append(f'    query: "{safe_query}"')
        lines.append(
            "    expected_snapshot_ids: [" + ", ".join(str(x) for x in expected) + "]"
        )
    return "\n".join(lines) + "\n"


def _category_counts(pairs: Iterable[tuple[str, str, list[int]]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for cat, _, _ in pairs:
        counts[cat] = counts.get(cat, 0) + 1
    return counts


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic recall golden set.")
    parser.add_argument(
        "--issues-json",
        default=None,
        help="Optional path to GitHub issues JSON export (ignored if missing).",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUT),
        help="Output YAML path.",
    )
    args = parser.parse_args(argv)

    random.seed(SEED)
    _ = _load_optional_issues(args.issues_json)  # currently unused

    pairs = list(SYNTHETIC_PAIRS)
    if len(pairs) < 30:
        print(
            f"ERROR: synthetic pair count {len(pairs)} is below the 30-pair floor.",
            file=sys.stderr,
        )
        return 2

    spec_titles = _spec_titles()
    rendered = _render_yaml(pairs, spec_titles)

    forbidden = _scan_forbidden(rendered)
    if forbidden:
        print("ERROR: forbidden tokens found in generated YAML:", file=sys.stderr)
        for hit in forbidden:
            print(f"  - {hit}", file=sys.stderr)
        return 3

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")

    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    counts = _category_counts(pairs)
    print(f"Generated {len(pairs)} pairs to {out_path} (sha256: {digest})")
    print("Category counts:")
    for cat in sorted(counts):
        print(f"  {cat}: {counts[cat]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
