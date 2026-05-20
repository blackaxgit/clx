# CLX v0.9.0 Pre-Release Red / Green / Purple

**Date:** 2026-05-20
**Base:** `chore/v0.9.0-rgp-prerelease` off `feat/0.9.0-layer0-toggle`
  (PR #33 head; CI clean).
**Inputs (authoritative):** `2026-05-20-v090-rgp-recon.md` (10 ranked
adversarial targets + 12 test gaps), `2026-05-20-v090-rgp-research.md`
(2026 delta best-practices), `2026-05-19-rgp-prerelease.md` (the v0.8.0
RGP procedure — flow only, not conclusions).
**Flow:** sequential **RED -> GREEN -> PURPLE** with orchestrator gates.
Anti-anchoring re-confirmed by research; the prompts below preserve it.

## Scope & RoE (all phases)
- Authorized defensive testing of CLX's own v0.9.0 candidate before tag.
- Analysis + PoC only inside repo / a temp sandbox. No external hosts.
- **Never reproduce the previously-leaked Azure key or its real tenant URL.**
  Synthetic placeholders only.
- Severity = CVSS v4.0 base + SSVC + the security-tool hard-override
  (any validator bypass or secret leak reachable without same-uid
  code-execution is release-blocking).
- Agents never `git commit` / `git push`. Orchestrator commits after
  each gate.
- Confidence = evidence-bundle 4-tuple (verdict + counterexample +
  regression-pin + residual-uncertainty). Numeric percentages forbidden.

---

## RED prompt

> You are the RED team for the CLX v0.9.0 pre-release. Repo
> `/Users/blackax/Projects/clx`, branch
> `chore/v0.9.0-rgp-prerelease`. READ binding: this file, the recon
> (`2026-05-20-v090-rgp-recon.md`, the ranked top-10 + 12 test gaps is
> your work queue), the scope/RoE above. The codebase delta you are
> auditing = the 4 v0.9.0 commits on top of v0.8.2.
>
> **Anti-anchoring (HARD):** do NOT read or rely on as truth the v0.9.0
> builder-side artefacts (`2026-05-20-layer0-toggle-plan.md`,
> `2026-05-20-layer0-recon.md`, sibling research). v0.8.x PURPLE
> sign-offs are likewise off-limits as verdict sources. You may read
> them only to check specific claims against current code. If you catch
> yourself reasoning "the plan said this is fine, so it is", stop and
> re-derive from source.
>
> GOAL: dynamically confirm or refute each recon target and produce a
> per-finding evidence bundle. For every claim of "still vulnerable" or
> "regression":
>   1. VERDICT  one of: VULN-CONFIRMED / VULN-REFUTED / NEW-FINDING /
>                       INSUFFICIENT-EVIDENCE
>   2. COUNTEREXAMPLE  a concrete minimal input/state/sequence
>                      (synthetic secrets only; PoCs in TempDir / in-repo
>                      `#[ignore]`-gated tests, never a real service)
>   3. REGRESSION-PIN  the exact file:line that must change to close it,
>                      OR "MISSING" if no fix exists
>   4. RESIDUAL-UNCERTAINTY  what could make this verdict wrong
>
> Priority probe order (recon hotlist):
> - **T1** (tamper-evidence claim vs SQLite write-anywhere reality)
> - **T9.2** (L0 off + L1 down + `default_decision=allow` + destructive
>   command → silent allow)
> - **T2** (`load_learned_rules` runs before the L0 gate)
> - **T7** (both-off looks indistinguishable from real validation in the
>   audit DB; no `clx doctor` warning)
> - **T3** (env+config double-audit on a single logical disable)
> - **T8** (CHANGELOG / README over-claim "tamper-evident")
> - The L1 string rename (`"L1 disabled"` -> `"L1-DISABLED"`) — does any
>   downstream consumer break? Research recommends dual-emit one-version
>   window; confirm whether the current impl provides that or not.
> - The ~15 `(0, N)` config_bridge.rs shifts — fuzz with proptest /
>   cargo-mutants if time permits to catch off-by-ones.
> - Carry-over: re-derive that v0.8.2's F1/F2/F3 protections still hold
>   under v0.9.0 changes (esp. F2 overbroad-allow gate, F1 redaction
>   sinks reachable from L0-disabled flow).
>
> Do NOT fix. Do NOT git commit. Leave PoC tests `#[ignore]`-gated so
> the default suite stays green.
>
> DELIVER `specs/2026-05-20-v090-red-findings.md` — one row per confirmed
> finding (ID, title, file:line, CVSS v4 vector+score, SSVC, PoC location
> + run command, blast radius, in-model?, recommended fix direction),
> refuted/not-reproducible section, new findings beyond recon. Ranked
> release-blocking first.

## GREEN prompt

> You are the GREEN team for v0.9.0. READ `red-findings.md` + this file
> + the research. Scope/RoE binding. CLAUDE.md layering + no
> security-constraint weakening + constraint-integrity (don't claim what
> isn't true) are hard constraints.
>
> GOAL: remediate every release-blocking + HIGH finding with the
> smallest correct change and clean layering. For each fix:
> (1) implement the minimal hardening, (2) ship a regression test that
> fails on pre-fix code and passes after (cite the RED PoC it closes),
> (3) zero regression: full `cargo nextest run --workspace` + `clippy
> -D warnings` + `fmt` + `cargo deny check` + `cargo insta test
> --workspace --check` green.
>
> Likely fix surface (subject to RED's actual findings):
> - **T1 / T8 docs honesty** — downgrade "tamper-evident" claims in
>   `CHANGELOG.md`, `README.md`, and any in-code doc that overstates the
>   audit-chain property. The honest statement is the v0.8.2 audit_chain
>   reclassify language: per-event SHA-256 fingerprint emitted to
>   `tracing::warn!`; tamper-evident **only when an external append-only
>   sink captures the anchor**.
> - **T2 cleanup** — move `policy_engine.load_learned_rules` behind the
>   L0 gate so the I/O matches the "L0 disabled = engine doesn't run"
>   property; OR (smaller) document the I/O behaviour and rename the
>   property statement. Pick the smaller correct change; record the
>   rationale.
> - **T3 double-audit** — decide intent: a single logical disable
>   triggered by both env AND config either fires both rows (intentional
>   dual signal) or dedups to one (efficiency). Pick one, document.
> - **T7 clx doctor warning** — surface the both-off + enabled=true
>   pattern with a `clx doctor` warning so a forensic operator can
>   distinguish "validation looks alive" from "no layer is actually
>   running". Mirror the existing CLX_VALIDATOR_* WARN style.
> - **T9.2 silent-allow class** — closing this means hardening the
>   `default_decision=allow` fail-open path so it is loud-and-gated, OR
>   refusing `default_decision=allow` when both layers off. Apply the
>   F7-deferred posture from v0.8.2 here in v0.9.0 since the new toggle
>   creates the exact bypass class F7 was tracking.
> - **L1 string rename** — implement the research-recommended dual-emit
>   one-version window: emit both `"L1 disabled"` AND `"L1-DISABLED"`
>   for v0.9.0 (parallel-change pattern). Plan deprecation removal in
>   v0.10.0 / v0.9.1.
>
> Do NOT git commit. Disjoint ownership across streams (one boundary per
> stream). Evidence-bundle per fix.
>
> DELIVER `specs/2026-05-20-v090-green-fixes.md` — per finding: fix
> file:line, the closing regression test, before/after behaviour,
> residual risk; plus the doc-honesty diffs; plus anything deliberately
> NOT fixed (accept-and-document) with rationale.

## PURPLE prompt

> You are the PURPLE team for the v0.9.0 go/no-go. READ red-findings,
> green-fixes, recon, research. Scope/RoE binding.
>
> GOAL: independently verify GREEN closed RED, no regression, and issue
> an auditable release verdict. For every release-blocking / HIGH RED
> finding:
> (1) re-derive the original attack against the CURRENT post-GREEN code
>     and confirm it is neutralized — not just that a test passes,
> (2) identify any GREEN-introduced regression or layering/security
>     weakening,
> (3) re-score residual with CVSS v4 + SSVC; apply the security-tool
>     hard-override,
> (4) re-run every gate and paste tails: `cargo nextest run
>     --workspace`, `cargo clippy --workspace --all-targets -- -D
>     warnings`, `cargo fmt --all -- --check`, `cargo deny check`,
>     `cargo audit`, `cargo insta test --workspace --check`,
>     workflow YAML parse,
> (5) disposition every accepted residual (T*-Track / accept-DOC) —
>     confirm each is honestly owned with rationale and not a silent
>     drop.
>
> Produce `specs/2026-05-20-v090-purple-signoff.md` — the 7-item
> auditable sign-off (scope+commit SHAs, findings table with pre/post
> status + independent-verification evidence per finding, regression-
> proof matrix linking each GREEN test to its RED PoC, tooling-gate
> tails, residual register with owner+rationale, CVSS/SSVC re-scores,
> final verdict: **SHIP / SHIP-WITH-CONDITIONS / NO-SHIP** with the
> blocking list if any). Adversarial and specific.

---

## Exit gates (orchestrator-enforced)

- **RED -> GREEN**: every recon target has confirmed/refuted disposition;
  release-blocking set identified. Orchestrator commits RED artefacts.
- **GREEN -> PURPLE**: every release-blocking + HIGH has a fix + closing
  test; full gate green. Per-fix four-eyes orchestrator review; commits
  per stream.
- **PURPLE -> tag**: auditable sign-off with explicit verdict; residual
  is documented owned accepted risk. Orchestrator commits sign-off,
  decides whether to ship v0.9.0 or hold for additional GREEN.
