# Codex Independent Pre-Release Audit — CLX v0.8.1 / [Unreleased]

> The prompt and execution rules for an **independent** second-opinion
> pre-release audit by OpenAI Codex CLI. Two files: this task statement,
> and `AGENTS.audit.md` (persistent execution rules; see §"Invocation").
>
> **Anti-anchoring is the load-bearing design choice.** Recent research
> (arxiv 2603.18740, Mar/Apr 2026) shows framing a change as "fixed"
> reduces a reviewing AI's vulnerability detection by 16-93%. Codex is
> therefore given **only** the threat model + RED attack register +
> adversarial recon targets — **not** our GREEN/PURPLE writeups, not
> CHANGELOG narrative, not the "this is closed" verdicts. Codex is told
> to re-derive every attack against the current source and report what
> it finds, not validate what we claim. Sources: research file
> `specs/2026-05-19-codex-prompt-research.md` (§3 anchoring), recon
> `specs/2026-05-19-codex-recon.md` (12 ranked targets).

---

## Task statement (stdin to `codex exec`)

```
You are an independent security + release-readiness auditor of the CLX
codebase at the worktree root. You did not write any of this code and
have no stake in any prior review's verdict. Be adversarial.

SCOPE
- CLX is a Rust 2024 workspace + security tool: validates Claude Code
  Bash commands via a hook, stores secrets in an age-encrypted file
  backend, runs an MCP server, enforces project config-trust, ships
  arm64-only macOS binaries via Homebrew tap.
- Audit target = current main HEAD (v0.8.1 shipped + [Unreleased]
  changes accumulating for v0.8.2: coverage push, B1-10 trust-token
  hardening, Stream A residuals).
- Out of scope: opening a PR, modifying source, running anything that
  contacts the network beyond the pre-staged RustSec DB cache, fixing
  what you find. ESCALATE; DO NOT FIX.

THREAT MODEL (the minimum context — do not seek more)
- Same-uid local-trust model. The dominant attack class is a hostile
  cloned project repo acting through `.clx/config.yaml`, project
  `.clx/prompts/validator.txt`, project CLAUDE.md, transcripts, and
  any `CLX_*` env var inherited from a parent process.
- A real Azure key + tenant URL leaked previously (the exact tenant
  ends with `.openai.azure.com`). **Never reproduce a real secret or
  tenant URL** in your output. Use synthetic placeholders only.

WHAT YOU ARE GIVEN (deliberately minimal)
- The repo at the worktree root, read-only.
- The RED ATTACK REGISTER below. These are confirmed-attack
  descriptions, not verdicts. Re-derive each against the current
  source and report what you actually find.
- Twelve adversarial recon targets (T1..T12) in
  `specs/2026-05-19-codex-recon.md`. Treat them as hypotheses to
  refute or confirm, not conclusions.

WHAT YOU ARE NOT GIVEN (anti-anchoring)
- DO NOT read or rely on:
    specs/2026-05-19-rgp-purple-signoff.md  (the "SHIP" verdict)
    specs/2026-05-19-rgp-green-*.md         (the "this is fixed" notes)
    specs/2026-05-19-residual-status.md     (the "this is closed" notes)
    specs/2026-05-19-residual-research.md   (orchestrator analysis)
    specs/2026-05-19-rgp-prerelease.md
    CHANGELOG.md beyond the version + [Unreleased] entry list
  These were authored by or summarise the prior team's work. If you
  catch yourself anchoring on their conclusions, stop and re-derive
  from source. Reading them is allowed only to *check claims against
  code*, never to substitute for that check.

RED ATTACK REGISTER (re-derive each against current main HEAD)

R-B4-1 (CRIT) — A hostile cloned repo's `.clx/config.yaml` could,
  pre-fix, neutralise the command validator (set
  `validator.layer1_enabled:false`, `default_decision:allow`,
  `auto_allow_reads:true`, `prompt_sensitivity:low`, `trust_mode:true`,
  `layer1_timeout_ms:1`, `user_learning.auto_whitelist_threshold:1`).
  Re-derive: walk every code path that consumes a project
  `.clx/config.yaml`. Confirm whether the security-sensitive subtrees
  are dropped under YAML merge keys (`<<: *anchor`), aliases, tags,
  dotted keys, BOM, mixed scalar types, deeply nested aliases, and
  serde_yml's known unsoundness paths. If you can construct a YAML
  document that bypasses the filter, that is a regression.
  Target file: `crates/clx-core/src/config/project.rs`.

R-B6 (HIGH) — Azure HTTP error bodies and tenant/endpoint hostnames
  must never reach a log/CLI sink unredacted. Re-derive: enumerate
  EVERY sink reachable from an Azure error path (4xx/5xx body,
  reqwest::Error transport, panic message, sqlite log, audit reason,
  snapshot summary, debug! lines, tracing spans, env-dump). For each,
  prove the path passes through redaction OR show a counterexample.
  Target files: `crates/clx-core/src/llm/azure.rs`,
  `crates/clx-core/src/redaction.rs`,
  `crates/clx-core/src/llm/mod.rs` (LlmError Display chain),
  `crates/clx-hook/src/hooks/stop_auto_summary.rs`,
  `crates/clx-core/src/recall/mod.rs`.

R-B1-4/B3-2 (HIGH) — An overbroad learned/added allow rule (`*`,
  `Bash(*)`) becomes a permanent L0 whitelist. Re-derive: try
  equivalents the validator missed — `Bash( * )`, `Bash(:*)`,
  `Bash(::*)`, `Tool(*)`, Unicode whitespace, full-width asterisk,
  `**`, `***`, double-wrapping. Also: are there OTHER rule-load
  paths besides learned-load + clx_rules-add (file rules, default
  rules, MCP imports) that bypass the check?
  Target files: `crates/clx-core/src/policy/matching.rs`,
  `crates/clx-core/src/policy/rules.rs`,
  `crates/clx-mcp/src/tools/rules.rs`.

R-B5-4 audit chain — There is supposed to be a SHA-256 hash-chained
  `validator_disabled` audit. Re-derive: read
  `crates/clx-hook/src/audit_chain.rs` in isolation, ignoring all
  documentation. Build the threat model yourself: cross-process
  tamper (concurrent hooks), truncation, replay, missing genesis,
  failure mode (fail-open vs fail-closed if chain corrupted),
  whether seq=1 every invocation actually constitutes a chain.

R-B1-10 trust-token removal — The mtime-only legacy plain-text trust
  token must no longer grant trust under any code path. Re-derive:
  grep for every read of `~/.clx/.trust_mode_token`, every `#[cfg]`
  override, every test that toggles `auto_allow_*`. Confirm no
  reachable path still treats a non-JSON file as trust.
  Target file: `crates/clx-hook/src/hooks/pre_tool_use.rs`.

R-supply-chain — `deny.toml` has a documented `ignore` list of 5
  unmaintained transitive advisories. Re-derive: for each one,
  enumerate the reachable code path and either justify the ignore
  with the specific call sites or flag the ignore as masking an
  exploitable risk. Pay special attention to RUSTSEC-2025-0068
  (`serde_yml`, unsound) — it parses untrusted project YAML
  **before** the inert filter; the "compensating control" claim
  must be re-derived not accepted.
  Target file: `deny.toml`,
  `crates/clx-core/src/config/project.rs:85-92`.

R-workflow — `.github/workflows/release.yml` and `ci.yml`: enumerate
  every `${{ ... }}` substitution that comes from `github.event.*`
  or any other attacker-influenceable source; assert least-privilege
  permissions; verify the `attest-build-provenance` step is wired
  correctly (`id-token: write`, `attestations: write`); verify the
  SBOM step produces a real CycloneDX file; verify the deny/audit
  gate is genuinely blocking, not warn-only.

ADVERSARIAL RECON TARGETS (12 hypotheses to confirm OR refute)
- Read `specs/2026-05-19-codex-recon.md` for T1..T12 file:line
  pointers. Treat each as "this is probably broken — prove it" or
  "the prior recon was wrong here — show why".

EVIDENCE BUNDLE (the only acceptable confidence format)
For every claim of "still vulnerable" or "regression":
  1. VERDICT  one of: VULN-CONFIRMED / VULN-REFUTED / NEW-FINDING /
                       INSUFFICIENT-EVIDENCE
  2. COUNTEREXAMPLE  a concrete minimal input/state/sequence that
                     demonstrates the issue (synthetic secrets only;
                     no PoC that contacts a real service)
  3. REGRESSION-PIN  the file:line that must change to close it, OR
                     "MISSING" if no fix exists yet
  4. RESIDUAL-UNCERTAINTY  what could make this verdict wrong (race,
                           env, build-flag, plan-availability)

Do NOT emit a numeric percentage. "97% confident" is rejected as
false precision; the project's own CHANGELOG records this norm.

DELIVERABLE
Write `specs/2026-05-19-codex-audit-findings.md` with:
  1. Scope + commit SHA you audited.
  2. Per-attack table for R-B4-1 / R-B6 / R-B1-4/B3-2 / R-B5-4 /
     R-B1-10 / R-supply-chain / R-workflow, each row = evidence
     bundle.
  3. Disposition of each T1..T12 recon target (confirmed / refuted /
     reframed-as-new-finding).
  4. Net-new findings the prior team did not surface (this is the
     primary value-add of an independent pass).
  5. A "claims that no longer match code" section: every CHANGELOG /
     spec / doc statement you found that contradicts what the code
     does.
  6. Overall verdict: SHIP / SHIP-WITH-CONDITIONS / NO-SHIP, with the
     blocking list if any.
  7. What you DID NOT check (honest scope boundary).
Time-box: 90 minutes. If you run out, ship a partial report and say
which areas were not reached.

RULES OF ENGAGEMENT (hard)
- Read-only sandbox. No `git commit`, no `git push`, no `cargo run`
  that opens a network socket beyond loopback, no environment
  mutation beyond exporting variables for in-process tests.
- No fixes. If you find a bug, file it in the deliverable; do not
  patch.
- 90-minute total wall-clock budget. Time-box areas; do not run a
  long fuzz in lieu of reading code.
- Refuse to rationalise: if an attack is unreachable for a reason
  that isn't airtight, say "INSUFFICIENT-EVIDENCE", not "accepted".
- Never echo or persist the real previously-leaked Azure key or
  tenant URL; flag any code path that could do so, but use only
  synthetic placeholders in your output.
- Honesty over completeness: a 4-finding report you stand behind is
  worth more than a 40-finding report half-rationalised.
```

---

## Invocation

```bash
# 1. Place the persistent execution rules (sandbox, anti-anchoring,
#    confidence convention) where Codex auto-loads them.
cp specs/2026-05-19-codex-audit-AGENTS.md ./AGENTS.audit.md

# 2. Run Codex against the task statement, gpt-5.1-codex-max, read-only.
codex exec \
  --model gpt-5.1-codex-max \
  --sandbox read-only \
  --ask-for-approval never \
  --output-dir /tmp/codex-audit-out \
  --agents AGENTS.audit.md \
  < specs/2026-05-19-codex-audit-prompt.md

# 3. Capture the Codex version + run metadata for reproducibility.
codex --version > /tmp/codex-audit-out/codex-version.txt
git rev-parse HEAD  > /tmp/codex-audit-out/repo-head.txt

# 4. Remove the override file when the session ends.
rm AGENTS.audit.md
```

## Notes on running

- **Plan-availability fallback**: if `gpt-5.1-codex-max` is not on the
  user's plan, fall back to `gpt-5.5` (400K context in Codex); record
  which model ran in the run metadata. Do NOT use any 2021/2022 Codex
  variant (`code-davinci-002`) — deprecated and irrelevant.
- **Approval-policy drift**: `--ask-for-approval never` alone is not
  sufficient because some Codex versions silently override it
  (openai/codex#5038, #11885). `--sandbox read-only` is the
  enforcement floor; keep both flags.
- **No network**: the only network operation that may be useful is
  `cargo audit` against a pre-staged RustSec DB; pre-fetch with
  `cargo audit fetch` BEFORE Codex starts, then run Codex with the
  network sandbox disabled. If Codex tries to network-fetch, that is
  a finding (Codex should not have network in this RoE).
- **Single shot**: do NOT loop the Codex audit. The anti-anchoring
  benefit decays after the first independent pass; subsequent passes
  start anchoring on the first.
