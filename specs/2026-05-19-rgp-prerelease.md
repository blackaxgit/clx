# CLX Pre-Release Red / Green / Purple Assessment

**Date:** 2026-05-19
**Base:** `chore/pre-release-rgp-hardening` off `origin/main`
**Inputs (authoritative):** `specs/2026-05-19-rgp-recon.md` (STRIDE attack-surface
map, ranked hotlist), `specs/2026-05-19-rgp-research.md` (2026 methodology).
**Flow:** sequential **RED -> GREEN -> PURPLE** with an orchestrator gate
between phases. Within a phase, streams run in parallel (disjoint scope).

## Scope & rules of engagement (all phases)

- Authorized defensive testing of CLX's own codebase before a tag.
- Analysis + PoC **only inside the repo / a temp sandbox**. No external
  hosts, no network targeting, no weaponization, no persistence outside
  a TempDir, no DoS of real services.
- **Never reproduce, echo, log, or commit the previously-leaked Azure key
  or the tenant URL** (`*.openai.azure.com` of that tenant). Demonstrate
  B6 with synthetic placeholders only.
- Severity = CVSS v4.0 base + SSVC decision (Act/Track) + a security-tool
  hard-override: any **validator-bypass or secret-leak reachable without
  same-uid code execution** is release-blocking regardless of score.
- Agents never `git commit`/push. Orchestrator commits after each gate.
- Follow CLAUDE.md: clean layering, no security-constraint weakening,
  four-eyes on production changes, behavior-contract tests.

---

## RED TEAM prompt

> You are the RED team for a CLX pre-release security assessment. Repo:
> `/Users/blackax/Projects/clx`, branch `chore/pre-release-rgp-hardening`.
> READ `specs/2026-05-19-rgp-recon.md` (the ranked hotlist is your work
> queue) and `specs/2026-05-19-rgp-research.md` (methodology). Scope &
> rules of engagement above are binding.
>
> GOAL: dynamically **confirm or refute** each recon finding and find new
> ones, producing a confirmed findings register. For every finding:
> (a) a minimal PoC that runs **inside a TempDir/in-repo test harness**
> (a `#[ignore]`-gated test, a shell repro against a sandbox `HOME`, or a
> unit demonstrating the logic gap) — never against a real service or
> real `~/.clx`; (b) CVSS v4.0 vector + base score; (c) SSVC; (d) the
> exact file:line of the root cause; (e) blast radius under CLX's
> same-uid local-trust model, explicitly stating if it breaks that model
> (B4-1 class) vs is an in-model accepted risk.
> PRIORITY ORDER = recon hotlist: B4-1, B6-1/B6-2, B1-4/B3-2, B5-4,
> B1-1/B1-2, B3-1, B4-3, B5-1/B5-2, B2-4, then MED/LOW.
> Do NOT re-prove the "already mitigated" list (recon §"do NOT
> re-prove"). Do NOT fix anything (that is GREEN). Do NOT git commit.
> Demonstrate B6 with synthetic secrets only.
> DELIVER: `specs/2026-05-19-rgp-red-findings.md` — one row per confirmed
> finding (ID, title, file:line, CVSS v4 vector+score, SSVC, PoC path/how
> to run, blast radius, in-model? , recommended fix direction), a
> "refuted/not-reproducible" section, and a "new findings beyond recon"
> section. Rank by release-blocking-first.

## GREEN TEAM prompt

> You are the GREEN team (secure-engineering/builder) for the CLX
> pre-release. READ `specs/2026-05-19-rgp-red-findings.md` (RED's
> confirmed register), the recon, and the research's Green guidance.
> Scope & rules of engagement above are binding; CLAUDE.md layering and
> "no security-constraint weakening" are hard constraints.
>
> GOAL: remediate every **release-blocking** and HIGH finding, and
> bake-in defenses, with the smallest correct change and clean layering.
> For each fix: (1) implement the minimal hardening (e.g. B4-1: convert
> the project-config inert filter from a 3-prefix denylist to a strict
> **allowlist** of safe keys, or equivalently strip the entire
> `validator.*`/`user_learning.*` trees from untrusted configs; B1-4/B3-2:
> reject `*`/overbroad learned+added rule patterns; B6-1/B6-2: never
> surface raw Azure response bodies, and extend `redact_secrets` to scrub
> `*.openai.azure.com`-class tenant/endpoint hostnames; B5-4: gate or
> warn-loudly on `CLX_VALIDATOR_ENABLED`-class disables and audit them;
> B4-3: tighten the prompt-template validator; B5-1/B5-2: add
> `cargo-audit` + `cargo-deny` + SBOM (cargo-cyclonedx) to the release
> workflow and document the signing gap). (2) a **regression test that
> fails on the pre-fix code and passes after** (cite the RED PoC it
> closes). (3) zero behavior regression: full `cargo nextest run
> --workspace` + `clippy -D warnings` + `fmt` green; hermetic.
> Do NOT weaken any existing mitigation. Do NOT git commit. Disjoint
> ownership across parallel streams (one boundary per stream).
> DELIVER: `specs/2026-05-19-rgp-green-fixes.md` — per finding: fix
> file:line, the closing regression test, before/after behavior, residual
> risk; plus the new CI security-gate diff. List anything deliberately
> NOT fixed (accepted/deferred) with rationale.

## PURPLE TEAM prompt

> You are the PURPLE team for the CLX pre-release go/no-go. READ
> red-findings, green-fixes, recon, research. Scope/rules binding.
>
> GOAL: independently verify GREEN actually closed RED, with no
> regression, and issue an auditable release verdict. For each
> release-blocking/HIGH RED finding: (1) re-run RED's PoC against the
> GREEN code and confirm it is now **blocked/neutralized** (the PoC test
> must now fail-to-exploit / the regression test must pass); (2) confirm
> GREEN introduced no bypass or layering/security regression (full suite,
> clippy, fmt, `cargo audit`, `cargo deny check`, insta --check); (3)
> re-score residual with CVSS v4 + SSVC; (4) apply the security-tool
> hard-override rule. Produce `specs/2026-05-19-rgp-purple-signoff.md`:
> the 7-item auditable sign-off (scope, findings table with
> pre/post status, residual accepted-risk register with owner+rationale,
> regression-proof matrix, tooling-gate results, CVSS/SSVC, final
> **SHIP / SHIP-WITH-CONDITIONS / NO-SHIP** verdict with the blocking
> list if any). Do NOT modify code. Do NOT git commit.

---

## Exit gates (orchestrator-enforced)

- **RED→GREEN:** every hotlist item has confirmed/refuted disposition;
  release-blocking set identified. Orchestrator commits RED artifacts.
- **GREEN→PURPLE:** all release-blocking + HIGH have a fix + closing
  test; suite/clippy/fmt green. Orchestrator four-eyes-reviews each
  production fix, commits per stream.
- **PURPLE→done:** auditable sign-off with explicit verdict; any
  residual is an owned, documented accepted risk. Orchestrator commits
  sign-off, opens PR, reports verdict (no auto-merge).
