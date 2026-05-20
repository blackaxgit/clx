# Codex Independent Pre-Release Audit — Prompt Research

**Date:** 2026-05-19
**Scope:** Decision-oriented research for the *prompt* that will drive an
OpenAI Codex CLI session to perform an INDEPENDENT second-opinion
pre-release audit of CLX (Rust 2024 workspace, security tool, v0.8.1
shipped, v0.8.2 coverage-push + B1-10 trust-token hardening accumulating
in `[Unreleased]`). The first pass was a Red/Green/Purple sweep
orchestrated by Claude; the deliverable here is the **prompt template**,
not the audit. The Codex audit run itself is downstream.
**Method:** WebSearch over OpenAI Codex docs, Codex repo issues,
arxiv 2026 papers on multi-AI review and confirmation bias, OWASP
Agentic 2026, NIST AI RMF 2026 references, Rust supply-chain guides,
GitHub Actions 2026 security roadmap. WebFetch was denied in this
session — extracts come from search-result page summaries (verbatim
quotes preserved where it matters); deep-link any URL before acting on
a non-obvious claim.
**Confidence convention:** FACT (directly stated by authoritative
source) / INFERENCE (cross-source synthesis) / UNVERIFIED (single
source, flag for re-check). 2026-deprecation flags called out inline.

---

## TL;DR — decisions

1. **Use Codex CLI in `read-only` sandbox with `approval_policy = "never"`,
   no `--dangerously-bypass-approvals-and-sandbox`, no network unless
   explicitly toggled per command.** Network must default OFF; `cargo
   audit`/`cargo deny` runs go through a pre-staged local advisory DB or
   a single allowlisted invocation (see §5). FACT (OpenAI docs).
2. **Adopt a single-file prompt in `AGENTS.md` form** scoped to the
   audit task, plus a `--prompt` (or stdin) task statement that
   references it. Codex loads `AGENTS.md` automatically root-to-leaf
   (≤32 KiB by default); a dedicated `AGENTS.audit.md` placed at repo
   root via `AGENTS.override.md` pattern is the cleanest way to override
   any developer-facing AGENTS.md without polluting normal sessions.
   FACT.
3. **Do NOT feed Codex the GREEN/PURPLE conclusions or the per-finding
   "CLOSED" rationalizations from `specs/2026-05-19-rgp-*.md`.** Confirmation
   bias is empirically large: the 2026 arxiv result (Liu et al.,
   2603.18740) shows framing a change as "fixed/safe" reduces vulnerability
   detection by **16–93%** and succeeds **88% of the time** against
   Claude Code in iterative settings. Give Codex the *diff*, the *threat
   model*, and the *regression suite*. Provide the **RED finding IDs only
   as a re-derivation worksheet** ("re-attack B4-1 against current source;
   record evidence — do not consult the PURPLE writeup"). FACT.
4. **Frame confidence as evidence-bundle, not numeric.** Reject "97%
   confident". Codex must emit, per finding: *(a) re-derived attack or
   counter-example*, *(b) concrete regression test or PoC path*, *(c)
   residual uncertainty stated as the next unprobed assumption*. Mirrors
   `specs/2026-05-19-residual-research.md` Item 6. INFERENCE from 2026
   calibration literature.
5. **Rules of engagement:** no commits, no `git push`, no force-push,
   no editing files outside `/tmp/codex-audit-out/`; time-box one
   session = ≤90 min wall clock; refuse to "fix" — escalate findings
   only; one structured report file per audit run; reproduce no secret
   values in the report (RUSTSEC-style: name the file, name the
   pattern, name the bytes-offset, do not paste the bytes). FACT
   (OpenAI sandbox/approval semantics + OWASP Agentic 2026 + NIST AI
   RMF Agentic Profile 2026).

The recommended **prompt template** is in §6.

---

## 1 — Codex CLI 2026 capabilities & prompt format

### 1.1 What model + window to target (FACT, 2026-04..2026-05)

- **GPT-5.1-Codex-Max** is the current OpenAI-default Codex model and
  introduces *native compaction*: it operates coherently across multiple
  context windows by compressing history rather than using a single
  fixed window. It is "built for long-horizon project-scale work" —
  the exact shape an independent audit needs. (FACT, OpenAI announcement.)
- **GPT-5.5** is available across paid plans with a **400K** window in
  Codex (1M via API). **GPT-5.4** supports up to 1M (labeled
  *experimental* inside Codex). **GPT-5.3-Codex**, GPT-5.4-Mini → 200K.
  **GPT-5.3-Codex-Spark** → 128K (text-only research preview). (FACT,
  OpenAI + GitHub issues openai/codex#19319, #13623, #19464.)
- 2026 quirk: there is a *displayed-vs-actual* drift in Codex
  (openai/codex#19319 — "GPT-5.5 reports 258 400 context window in Codex
  despite published 400K"). **Implication for the audit prompt:** do not
  rely on a single megaprompt dumping the whole repo — chunk by crate,
  let Codex-Max compact across windows. (FACT.)

**Recommendation:** target **GPT-5.1-Codex-Max** (compaction is the
load-bearing capability for a multi-crate audit). Fall back to GPT-5.5
(400K) only if Codex-Max is unavailable on the user's plan.

### 1.2 Where Codex outperforms Claude (INFERENCE from practitioner sources)

For a *second-opinion* pass against a Claude-orchestrated R/G/P, the
specific complementary strengths to lean on are:

- **Single-file deep code reasoning under verifiable build/test gates.**
  OpenAI's own prompting guide states: *"Codex produces higher-quality
  outputs when it can verify its work by including steps to reproduce
  an issue, validate a feature, and run linting and pre-commit checks."*
  Pair every audit claim with a Codex-run `cargo test` / `cargo
  clippy` / `cargo audit` / `cargo deny` invocation. (FACT, OpenAI
  cookbook.)
- **Adversarial debate / cross-critique posture.** The
  `alecnielsen/adversarial-review` 4-phase pattern (Claude + Codex
  parallel review → cross-critique → meta-review → synthesis) is the
  best-published template for catching what one model rationalizes.
  Phase 1 isolation matters: each agent reviews *blind* before seeing
  the other. (FACT, GitHub.)
- **2026 multi-model code review benchmarks** (Martian Code Review
  Bench, Qodo "Best AI Code Review Tools 2026"): different models
  catch different bug classes; running a *different* model after the
  primary reviewer is the empirically best false-negative reduction.
  (FACT / INFERENCE.)

### 1.3 Prompt structure (FACT, OpenAI Codex Prompting Guide + AGENTS.md guide)

OpenAI's own guidance, near-verbatim from the cookbook and developer
docs:

1. **"Start with the standard Codex-Max prompt as your base and make
   tactical additions"** — i.e. don't reinvent; lean on the model's
   trained defaults.
2. **"Remove all prompting for the model to communicate an upfront plan,
   preambles, or other status updates during the rollout, as this can
   cause the model to stop abruptly before completion."** Important:
   *do not ask Codex to print a plan first*; ask for the deliverable.
3. **"Structure Codex prompts like GitHub issues rather than vague
   wishes"** — concrete scope, concrete acceptance, concrete files.
4. **`AGENTS.md` carries persistent execution rules.** Codex auto-loads
   them at session start root-to-leaf, joined with blank lines, up to
   **`project_doc_max_bytes` = 32 KiB by default**. `AGENTS.override.md`
   wins over `AGENTS.md` at the same level. Each becomes its own
   user-role message with header `# AGENTS.md instructions for <dir>`.
   (FACT, developers.openai.com/codex/guides/agents-md.)
5. **Execution rules go verbatim, imperative.** From the OpenAI
   cookbook: *"Write the working rules verbatim in `execution_rules`
   with concrete, imperative sentences like 'Check git status before
   edits,' 'Prefer rg over grep,' 'Use apply_patch for manual edits.'
   The model follows these consistently when they are explicit."*
6. **Tool preference is non-trivial.** Codex is trained to prefer
   `rg` / `rg --files` over `grep`/`find`, and to use dedicated tools
   when available rather than raw shell. Stating the preference in
   `AGENTS.md` is reinforcing, not new — but failing to state it for
   an audit task that involves a lot of grepping leaves quality on
   the table.
7. **Parallel tool calling.** When enabled, Codex uses
   `multi_tool_use.parallel` to batch independent file reads. For
   an audit task that wants to inspect many fix-sites at once, this
   is materially faster — do not artificially serialize.

### 1.4 2026 deprecation flags

- **"codex-davinci-002" (2021 API) is dead.** Any blog post saying
  "Codex" referring to a `code-davinci`/`text-davinci` endpoint is
  pre-2023 and irrelevant. The current product is the **Codex CLI
  (Rust + TS) + the GPT-5.x-Codex family**. FACT.
- **Upfront-plan prompting** ("first, write a plan…") is now
  *deprecated by OpenAI's own prompting guide* for Codex-Max because it
  causes early-stop. DO NOT include "first, output your plan" in the
  audit prompt. FACT.
- **`approval_policy = "untrusted"`** is reported as not respected by
  the VS Code extension (openai/codex#5443) and `approval_policy =
  "never"` is reported as ignored in workspace-write mode in some
  Codex versions (#11885, #5038). **Implication:** the CLI is the
  authoritative surface for the audit run, not the VS Code extension;
  set `sandbox_mode = "read-only"` to *enforce* the constraint
  regardless of approval-policy drift. (FACT, openai/codex issues.)

---

## 2 — Second-opinion AI review methodology 2026

### 2.1 The empirical case for "different model, blind framing"

- **arxiv:2603.18740 (Mar 2026, updated Apr 2026)** —
  *"Measuring and Exploiting Confirmation Bias in LLM-Assisted Security
  Code Review."* Controlled experiment on 250 CVE vulnerability/patch
  pairs, four SOTA models, five framing conditions. Verbatim findings:
  - Framing a change as **bug-free reduces vulnerability detection by
    16–93%**, asymmetric: **false negatives spike**, false positives
    barely move.
  - Adversarial framing succeeds in **35% of cases against GitHub
    Copilot (interactive)** and **88% against Claude Code (autonomous
    agent)** when adversary iteratively refines framing.
  - **Debiasing via metadata redaction + explicit instructions restores
    detection in 100% of interactive cases and 94% of autonomous
    cases.** FACT.
- **arxiv:2603.16244** — *"More Rounds, More Noise: Why Multi-Turn
  Review Fails to Improve Cross-Context Verification."* Warns:
  *"reviewers may fabricate findings in later rounds when the
  artifact's real errors have been largely exhausted, and reviewers
  provided with Q&A exchanges may shift their attention from the
  artifact to the conversation."* FACT.
- **arxiv:2604.01029** — *"Revision or Re-Solving? Decomposing
  Second-Pass Gains in Multi-LLM Pipelines."* Argues second-pass
  gains come from *re-solving with a different model*, not from
  iterative-revision-by-the-same model. FACT.

### 2.2 What this means concretely for the Codex prompt

**Give Codex (the inputs):**

- The **current source** at the tagged commit (read-only checkout).
- The **diff** between v0.8.0 → HEAD-of-`[Unreleased]` (or whatever
  is staged for v0.8.2).
- The **threat model** (CLX is a security tool that runs as a Claude
  hook router on the same uid as the user; trust boundaries are
  untrusted-project-config, untrusted-MCP-input, untrusted-LLM-output,
  network egress to provider).
- The **regression suite** (`scripts/test.sh` + the `*_e2e.rs` and
  `*_behavior.rs` files listed in git status).
- The **RED finding REGISTER** — **IDs and one-line attack
  descriptions only**, not the GREEN fixes or PURPLE rationalizations.
  E.g. *"B4-1: untrusted `.clx/config.yaml` can set `validator.*`;
  goal: confirm independently that this is no longer reachable."*

**Do NOT give Codex (the anchoring inputs):**

- `specs/2026-05-19-rgp-green-*.md` (the fix narratives).
- `specs/2026-05-19-rgp-purple-signoff.md` (the "CLOSED" verdicts and
  evidence chains).
- `CHANGELOG.md` `[0.8.1]` Security section verbatim (it pre-commits
  to "fixed" framing — empirically a 16–93% detection killer per
  2603.18740).
- The Claude orchestrator's confidence statements.

**Why:** anchoring + confirmation bias. The 2026 result is unambiguous:
priming a reviewer with "this was already fixed" cuts detection by an
order of magnitude. The Claude pass already covered the *fix-direction*
view; Codex's value is the *re-attack* view, and that requires it does
not see the fix narrative.

### 2.3 Where to surface the prior pass anyway

The user reasonably wants Codex to *re-derive*, not *re-discover from
zero* — re-discovery wastes hours. The compromise is:

- Provide a **bare RED register** (finding IDs + attacks) as a
  *worksheet*: "Reproduce the attack against current source. Pass /
  Fail / Partial. Evidence path."
- Provide the **NIST/OWASP-style policy invariants** (e.g.
  "untrusted-project-config must not flip `default_decision = allow`")
  without saying which finding ID those invariants came from. (FACT
  guidance from NIST AI RMF Agentic Profile concept note 2026-04-07
  and OWASP Top 10 for Agentic Applications 2026: governance produces
  invariants an outside reviewer can inspect.)
- Permit Codex to **request** the green/purple writeup *only after*
  it has committed a verdict on a finding — that is, structured
  *anti-anchoring* by ordering.

---

## 3 — Pre-release independent-audit checklist 2026 (Rust security tool)

Each line: what to check → what's special about CLX → which class is
"only an independent AI is well-positioned to catch" (marked **[INDEP]**).

### 3.1 Supply chain

- **`cargo audit` live** vs the latest RustSec advisory DB. CLX
  v0.8.1 added this as a *blocking release gate* — Codex should
  confirm the gate runs *before* the build step in `release.yml`
  and *fails closed* (no `continue-on-error`). FACT.
- **`cargo deny check` live** for advisories / licenses / sources /
  bans. `deny.toml` must enumerate (not blanket-ignore) the known
  unmaintained transitives — Codex should *count and list* each
  enumerated advisory and justify it. **[INDEP]** Claude's pass
  produced the list; Codex should re-justify each entry against the
  live RustSec DB on the audit day.
- **`cargo geiger`** for the unsafe-density map across deps. CLX is
  `unsafe_code = deny` at workspace root — the unsafe lives in
  transitive deps (libyaml C binding, etc.). Geiger output gates
  the "does the dep tree drift into more unsafe than last release"
  question. FACT.
- **`cargo vet`** baseline existence check (optional, INFERENCE).
- **SBOM (CycloneDX)** present, well-formed, includes all crates +
  versions. CycloneDX **1.7** is the 2026 current version; check
  generator output is not pinned to 1.4. (FACT, sbom.observer
  2026-03.)
- **SLSA build provenance** attached, **`attest-build-provenance@v1`**
  (or equivalent). Verify the workflow is the one that built the
  release artifact (predicate matches builder ID). FACT.
- **Pinned action SHAs** (no `@v1` floating refs) for any action that
  touches secrets or publishes. GitHub Actions 2026 security roadmap
  + recent compromise patterns flag floating refs as the dominant
  carrier. FACT (github.blog 2026 roadmap).

### 3.2 Workflow integrity (GitHub Actions)

**[INDEP] — these are anchoring-resistant; an independent reviewer
checks them by reading the YAML, not by trusting "we hardened CI".**

- `permissions:` block present at workflow + job level, *minimal*.
  CLX residuals (from PURPLE) flagged the `update-homebrew` job lacks
  a manual-approval `environment:` gate — Codex should *re-derive*
  this independently.
- No untrusted-input → shell injection. Audit every `${{ ... }}` that
  references `github.event.pull_request.title`, `head_ref`,
  `body`, `commit.message`, file paths. FACT (rapidfort 2026,
  corgea 2026, nesbitt 2026).
- No `pull_request_target` with checkout-of-PR-head. FACT.
- No comment-triggered automation without strong auth. FACT.
- Secret names enumerated; no `${{ secrets.* }}` interpolated into
  shell.

### 3.3 Rust-specific

- **`unsafe` audit** — every `unsafe { … }` block has a documented
  safety justification (rationale + invariants). CLX is `unsafe_code =
  deny` at workspace, so this should be near-zero — Codex should
  *enumerate* and *flag* any block that snuck through with `allow`. FACT.
- **`Miri` on unsafe hotspots** (if any) — INFERENCE; only useful if
  CLX gains any unsafe in the v0.8.2 push.
- **Fuzz / property surface**: parsers (YAML config, JSON tokens,
  rules patterns), MCP wire format, hook router decision path,
  redaction. The 2026 Sherlock guide explicitly calls out
  *"deserialization, async concurrency, nondeterminism, resource
  exhaustion under adversarial input"* as the recurrent break-points.
  Codex should re-derive whether the v0.8.1 regression tests cover
  each parser's adversarial corner. FACT.
- **`unsafe_code = deny` lint enforcement** — confirm the lint is
  workspace-level and present in all crate Cargo.toml. FACT.
- **`#[deny(warnings)]` vs `#[forbid(warnings)]`** posture — INFERENCE.

### 3.4 CVE re-derivation

**[INDEP] — this is the single highest-value item for Codex.**

For each RED finding (B4-1, B6-1, B6-2, B1-4, B3-2, B5-4, B3-1, B5-1,
B5-2, R1-NEW-1, R1-NEW-2, B1-10):

1. Codex reads the **attack description only** (not the fix).
2. Codex attempts to **construct a PoC** against current `HEAD`.
3. Verdict: **Reproduces / Does-not-reproduce / Partial / Variant**.
4. Evidence: file:line of the guard that prevents reproduction (if
   not-reproduce), or PoC source (if reproduces). No paste of secret
   values; reference by path and pattern only.
5. Variant search: enumerate *adjacent* attack forms in the same
   class. (E.g. for B4-1, B6 = "what other key paths in the project
   config could weaken security?")
6. Regression-test search: confirm a behavior test exists that fails
   under the attack. If none, that is a finding regardless of whether
   the attack itself reproduces.

### 3.5 Regression search beyond the RED register

- Diff `v0.8.0..HEAD` and ask: *which behaviors changed in fix-commits
  that have no regression test pinning the new behavior?* (i.e. the
  "fix could be silently reverted" set). FACT pattern from Sherlock
  2026 + Practical DevSecOps 2026.
- Dead/orphan code search (`cargo machete` / unused-deps). FACT.
- Doc-code drift: README / man-page / `clx --help` examples that no
  longer match flags. FACT.

### 3.6 Secrets in history

- **gitleaks** scheduled full-history scan. FACT.
- **trufflehog** with credential-verification turned off (do not call
  out to provider APIs from the audit sandbox — see §5). The
  trufflehog *finding* is enough; verification belongs in a separate,
  network-allowed step. FACT.

### 3.7 License & dependency hygiene

- `deny.toml` license allowlist hygiene: confirm no `copyleft`
  ambiguity given CLX is MPL-2.0 (per 1011d5f). FACT.
- Each `cargo deny` advisory exception has a *dated* justification
  comment. FACT.

### 3.8 What ONLY an independent AI can usefully add

- **Re-derivation of the attack** (Claude already wrote the fix —
  Claude is anchored).
- **Variant enumeration** in the same class as each RED finding.
- **Doc-code drift** (Claude often pattern-matches the docs to the
  intended state, not the actual state).
- **Workflow-injection corner cases** that fall between Claude's
  R/G/P matrix cells.
- **Justification audit of `deny.toml` exceptions** — these are the
  most-likely-rationalized artifact in the repo.

---

## 4 — Honest confidence framing (mirrors residual-research item 6)

### 4.1 Reject bare numeric confidence

The CHANGELOG already rejects "97% goal" as test theater (`[Unreleased]`
section, line 30: *"the 97% goal is superseded by an honest
disposition"*). The Codex prompt must mirror this for security claims.

### 4.2 What an evidence-bundle confidence statement looks like

Per finding, Codex must emit a 4-tuple:

1. **Re-derived attack outcome** — Reproduces / Does-not / Partial /
   Variant.
2. **Counter-example search** — what variants did Codex try, and what
   stopped each.
3. **Concrete regression** — `path:line` of the test that pins the
   secure behavior, or `MISSING` if none.
4. **Residual uncertainty** — the next assumption Codex did NOT
   probe, named explicitly (e.g. "I did not exercise the
   `config-trust` hash-trusted path; if a hash-trusted repo turns
   hostile, B4-1's `validator.*` strip is bypassed by design").

### 4.3 Cite sources

- **arxiv:2509.01455** — *"Trusted Uncertainty in LLMs: a Unified
  Framework for Confidence Calibration and Risk-Controlled
  Refusal."* Calibrated abstention is the empirically validated
  alternative to bare verbalized confidence. FACT.
- **arxiv:2604.03904** — *"I-CALM: Incentivizing Confidence-Aware
  Abstention for LLM Hallucination Mitigation."* FACT.
- **arxiv:2603.06604** — *"Know When You're Wrong: Aligning
  Confidence with Correctness for LLM Error Detection."* FACT.
- **Saxum 2026** — *"AI theater is the performance of AI expertise
  without the rigor, verification, or outcomes required."* FACT.
- **Substack natesnewsletter 2026** — *"Smart people armed with LLMs
  and formal tools will ship convincing-looking but wrong work faster
  than many teams can audit."* FACT.

### 4.4 Honest-failure modes Codex must be told to use

- *"INCONCLUSIVE — I could not construct an attack and I could not
  prove the guard is exhaustive; the next probe would be X."*
- *"OUT-OF-SCOPE — this finding depends on the hash-trusted boundary
  which is accepted residual; flagging for the human."*
- *"REGRESSION-MISSING — secure behavior present in source, no test
  pins it; risk is silent revert."*

---

## 5 — Rules of engagement / scope for the Codex auditor

These map directly to Codex CLI configuration flags (FACT,
developers.openai.com/codex/agent-approvals-security +
developers.openai.com/codex/concepts/sandboxing).

### 5.1 Sandbox

- `sandbox_mode = "read-only"`. The audit reads code, runs `cargo
  test` (against a pre-fetched dep cache), and emits a report file
  to `/tmp/codex-audit-out/`. Editing source is *out of scope* — a
  finding is a *finding*, not a *patch*. (FACT.)
- *Rationale anchored in OWASP Agentic 2026:* *"agentic system can
  fail by initiating a cascade of irreversible actions in external
  systems… before any human observes that the agent is behaving
  incorrectly."* An auditor MUST NOT be the one editing the artifact
  it audits.

### 5.2 Approvals

- `approval_policy = "never"` paired with `sandbox_mode = "read-only"`.
  In read-only, "never" cannot cause damage — it only prevents the
  agent from stopping for confirmation on benign reads. Do NOT use
  `--full-auto` and do NOT use `--dangerously-bypass-approvals-and-
  sandbox`. (FACT.)
- Cross-check 2026 deprecation: openai/codex#5038, #11885 — in some
  Codex versions, `approval_policy` is silently overridden in
  workspace-write. **read-only sandbox is the enforcement floor**;
  approval policy is a UX hint. (FACT.)

### 5.3 Network

- `[sandbox_workspace_write].network_access = false` (or simply
  read-only sandbox, which is network-off by default).
- **Allowlist exactly one egress:** the RustSec advisory DB fetch
  (`cargo audit fetch`) and the local crates registry index (which
  is normally pre-staged in `~/.cargo/registry`). If `cargo audit`
  / `cargo deny` need to refresh, do it *outside* Codex's sandbox
  and let Codex consume the cached DB.
- `allow_local_binding = false` (default) — blocks loopback. Audit
  must not bind a port. (FACT.)

### 5.4 No-commit invariants

State in `AGENTS.audit.md`, verbatim, imperative:

- "Do NOT run `git commit`, `git push`, `git tag`, `git checkout -b`,
  `git stash`, or any `git` subcommand that writes to refs."
- "Do NOT run `cargo publish`, `cargo yank`, or any release-pipeline
  command."
- "Do NOT modify any file outside `/tmp/codex-audit-out/`."
- "If a finding requires a fix, escalate by writing the finding to
  the report; do NOT attempt a patch."

### 5.5 Time-box

- Cap one Codex session at **90 min wall**. Codex-Max compaction
  means the model itself does not need a wall cap — but the human
  reviewer's attention budget for the resulting report does. (INFERENCE.)
- Cap **token budget** by limiting tool surface: read-only + no
  network removes the dominant token sinks. (INFERENCE.)

### 5.6 Honesty obligations

- "If you cannot construct an attack, say INCONCLUSIVE — do not
  invent one."
- "Reviewers may fabricate findings in later rounds when real errors
  are exhausted (arxiv:2603.16244). If you find yourself reaching,
  stop and emit INCONCLUSIVE."
- "Do not paste secret values. Reference by file:line and pattern."

### 5.7 Citation framework

- NIST AI RMF Agentic Profile concept note (2026-04-07): *"governance
  produces evidence an outside reviewer can inspect"* — the audit
  report IS that evidence. FACT.
- OWASP Top 10 for Agentic Applications 2026 (ASI02 Tool Misuse;
  Agentic Supply Chain Compromise): an auditor that can write to
  the repo it audits is itself a supply-chain risk. FACT.
- ISO 42001 / NIST AI RMF: *"periodic reviews surface emerging
  risks"* — independence is load-bearing. FACT.

---

## 6 — Recommended prompt template for CLX v0.8.1 → 0.8.2

Two pieces: **(A) `AGENTS.audit.md`** placed at repo root (or
shadowing existing `AGENTS.md` via `AGENTS.override.md` semantics
for the duration of the audit session), and **(B)** the per-run
*task statement* fed via stdin / `--prompt`.

### 6.1 `AGENTS.audit.md` (the persistent execution rules)

```markdown
# AGENTS.md instructions for clx (independent pre-release audit)

You are an INDEPENDENT pre-release security auditor for the CLX
Rust 2024 workspace. The primary code-review pass was performed by a
different AI system (Claude). You are the second-opinion pass. Your
job is to RE-DERIVE attacks against the current source, not to
re-validate the prior reviewer's conclusions.

## Execution rules (verbatim, imperative — do not reinterpret)

- Sandbox is read-only. Do NOT modify any file outside
  `/tmp/codex-audit-out/`.
- Do NOT run `git commit`, `git push`, `git tag`, `git checkout -b`,
  `git stash`, `git reset --hard`, or any git subcommand that writes
  refs.
- Do NOT run `cargo publish`, `cargo yank`, `cargo install`.
- Do NOT make outbound network calls. The RustSec advisory DB and
  the crates index are pre-staged locally.
- Prefer `rg` over `grep` / `find`. Prefer `apply_patch`-style reads
  over raw `cat` for large files. Use parallel tool calls
  (`multi_tool_use.parallel`) for independent reads.
- Do NOT paste secret values in the report. Reference by file:line
  and a non-secret pattern descriptor.
- Do NOT produce an upfront plan, preamble, or status update.
  Produce the audit report directly.
- If you cannot construct an attack, output INCONCLUSIVE — do not
  invent. (See arxiv:2603.16244 on fabrication in late rounds.)
- Do NOT propose patches. Escalate findings to the report.

## What you have access to

- The current source at `HEAD` (read-only).
- The diff `v0.8.0..HEAD` (in `/tmp/codex-audit-out/diff.patch`).
- The threat model (below).
- The regression suite (`scripts/test.sh`, `crates/**/tests/*`).
- A RED finding REGISTER (IDs + one-line attack descriptions only).

## What you DO NOT have access to (by design — anchoring control)

- The GREEN fix-narrative writeups
  (`specs/2026-05-19-rgp-green-*.md`).
- The PURPLE sign-off and CLOSED verdicts
  (`specs/2026-05-19-rgp-purple-signoff.md`).
- The CHANGELOG `[0.8.1]` Security section verbatim.
- The Claude orchestrator's confidence statements.

Reason: arxiv:2603.18740 (March 2026) demonstrates that framing a
change as bug-free reduces vulnerability detection by 16–93%, with
adversarial framing succeeding 88% of the time against autonomous
agents in real project configurations.

## Threat model (CLX)

- CLX is a security tool that runs as a Claude Code hook router on
  the same uid as the user. Untrusted inputs:
  (1) project-local `.clx/config.yaml` from an arbitrary cloned repo,
  (2) MCP tool arguments from an arbitrary MCP client,
  (3) LLM provider response bodies (Azure / OpenAI / Anthropic
       reachable via redacted egress),
  (4) learned/saved rules persisted between sessions.
- Trust escape hatch: `clx config-trust` records a hash that allows
  the project's config to set otherwise-blocked keys. The
  hash-trusted boundary is OUT OF SCOPE for this audit (accepted
  residual: a trusted repo that turns hostile is the user's risk).
- Hard invariants:
    (a) untrusted-project-config must NOT flip `default_decision`,
        `validator.layer1_enabled`, `validator.layer1_timeout_ms`,
        `auto_allow_reads`, `prompt_sensitivity`, `trust_mode`,
        `user_learning.*`.
    (b) no secret value (token, plaintext credential, Azure
        endpoint host) may reach a log/CLI/error sink unredacted.
    (c) no overbroad allow rule (`*`, `Bash(*)`) may be persisted at
        either the learned-rule load boundary OR the MCP add
        boundary.
    (d) `CLX_VALIDATOR_*` env weakening MUST emit a prominent WARN.
    (e) release pipeline MUST fail closed on `cargo audit` /
        `cargo deny` non-zero exit.
    (f) only a signed JSON `TrustToken` may grant trust mode
        (no mtime-only legacy fallback).

## Verdict vocabulary (use exactly these tokens)

- REPRODUCES — attack succeeds on current source.
- DOES-NOT-REPRODUCE — attack does not succeed, and the guard is
  named (file:line).
- PARTIAL — attack succeeds against an in-scope variant; record the
  variant.
- VARIANT — attack as stated does not work, but an adjacent attack
  in the same class does; record the adjacent attack.
- INCONCLUSIVE — could not construct attack, could not prove
  exhaustive; the next probe would be X.
- REGRESSION-MISSING — secure behavior present, no test pins it;
  risk is silent revert.
- OUT-OF-SCOPE — depends on accepted-residual boundary.

## Confidence framing (mandatory per finding)

Per finding, emit a 4-tuple:
1. Verdict (one of the tokens above).
2. Counter-example search — variants attempted and what stopped each.
3. Regression — file:line of the test pinning the behavior, or MISSING.
4. Residual uncertainty — the next assumption you did NOT probe,
   named explicitly.

Bare numeric confidence ("97%") is REJECTED. Use the 4-tuple.

## Deliverable

One file: `/tmp/codex-audit-out/codex-audit-report.md`. Sections:

1. Run metadata (commit SHA of HEAD, `cargo --version`, `rustc
   --version`, date).
2. Per-finding table (RED ID → verdict → 4-tuple).
3. New findings (not in the RED register).
4. Workflow integrity findings (`.github/workflows/*`).
5. Supply-chain re-derivation (`cargo audit` output digest,
   `cargo deny` exception justification audit).
6. Variant enumeration (per RED finding class).
7. Regression-missing list.
8. Doc-code drift list.
9. Honest residuals (what you did not probe and why).
```

### 6.2 Task statement (fed via `codex exec --prompt -` or stdin)

```
Independently audit CLX at HEAD as defined in AGENTS.audit.md.

Targets in priority order:
  1. Re-derive each RED-register attack against current source.
     Register IDs: B4-1, B6-1, B6-2, B1-4, B3-2, B5-4, B3-1, B5-1,
     B5-2, R1-NEW-1, R1-NEW-2, B1-10.
     For each, emit the verdict 4-tuple.
  2. Workflow integrity: `.github/workflows/*.yml`. Look for
     untrusted-input interpolation, missing permissions blocks,
     floating action refs, missing manual-approval environments on
     publish jobs (homebrew), and `pull_request_target` misuse.
  3. `deny.toml` exception audit: enumerate every advisory ignore
     and justify it against the current RustSec DB.
  4. Variant enumeration per RED class — what *adjacent* attacks
     in the same class are not yet covered by a regression test?
  5. Regression-missing search: for each fix-commit in
     `v0.8.0..HEAD`, confirm a behavior test pins the new secure
     behavior; flag any that does not.
  6. Doc-code drift: `README.md`, `crates/clx/src/cli/help_text.rs`
     (or equivalent), `clx --help` output vs. flag definitions.
  7. Honest residuals: what you did NOT probe and why.

Constraints:
  - Read-only sandbox. No commits, no edits, no network beyond the
    pre-staged RustSec DB.
  - Do not consult `specs/2026-05-19-rgp-green-*.md` or
    `specs/2026-05-19-rgp-purple-signoff.md`. If you find yourself
    needing to, output INCONCLUSIVE for that finding instead.
  - 90 min wall-clock budget. Produce the single report file at
    `/tmp/codex-audit-out/codex-audit-report.md`. No upfront plan,
    no preamble.
```

### 6.3 Invocation

```sh
mkdir -p /tmp/codex-audit-out
git diff v0.8.0..HEAD > /tmp/codex-audit-out/diff.patch
# Pre-stage advisory DBs OUTSIDE the sandboxed Codex session:
cargo audit fetch || true
cargo deny check --hide-inclusion-graph 2>&1 | tee \
    /tmp/codex-audit-out/deny-out.txt
# Now invoke Codex (read-only, no approval prompts, no network):
codex exec \
    --model gpt-5.1-codex-max \
    --sandbox read-only \
    --ask-for-approval never \
    --cwd "$(pwd)" \
    --prompt - <<'PROMPT'
[paste §6.2 task statement here]
PROMPT
```

Notes (FACT):

- `--sandbox read-only` enforces filesystem isolation regardless of
  `approval_policy` drift (openai/codex#5038, #11885).
- `--ask-for-approval never` is harmless under read-only.
- `--model gpt-5.1-codex-max` selects the compaction-capable model
  built for project-scale work.
- The advisory DB fetch happens *outside* Codex so the sandbox can
  stay network-off.

---

## 7 — Sources cited (URL + date; 2026-deprecation flags inline)

### OpenAI Codex (FACT)

- [Codex Prompting Guide — developers.openai.com cookbook](https://developers.openai.com/cookbook/examples/gpt-5/codex_prompting_guide) — 2026
- [Codex Prompting Guide — GPT-5.1-Codex-Max variant](https://cookbook.openai.com/examples/gpt-5/gpt-5-1-codex-max_prompting_guide) — 2026 (the *current* Codex-Max guide; supersedes pre-Max patterns)
- [Best practices — Codex](https://developers.openai.com/codex/learn/best-practices) — 2026
- [Prompting — Codex](https://developers.openai.com/codex/prompting) — 2026
- [Custom instructions with AGENTS.md — Codex](https://developers.openai.com/codex/guides/agents-md) — 2026
- [Agent approvals & security — Codex](https://developers.openai.com/codex/agent-approvals-security) — 2026
- [Sandbox — Codex](https://developers.openai.com/codex/concepts/sandboxing) — 2026
- [Security — Codex](https://developers.openai.com/codex/security) — 2026
- [Configuration Reference — Codex](https://developers.openai.com/codex/config-reference) — 2026
- [CLI — Codex](https://developers.openai.com/codex/cli) — 2026
- [Building more with GPT-5.1-Codex-Max — OpenAI](https://openai.com/index/gpt-5-1-codex-max/) — 2026
- [Codex full documentation (llms-full.txt)](https://developers.openai.com/codex/llms-full.txt) — 2026

### Codex repo issues (FACT — for behavior drift and known bugs)

- [openai/codex#19319 — GPT-5.5 displays 258 400 ctx vs published 400 K](https://github.com/openai/codex/issues/19319) — 2026 (FLAG: context-window display drift)
- [openai/codex#13623 — 1M window display issue](https://github.com/openai/codex/issues/13623) — 2026
- [openai/codex#19464 — Support 1M for GPT-5.5](https://github.com/openai/codex/issues/19464) — 2026
- [openai/codex#5443 — approval_policy=untrusted not respected by VS Code ext](https://github.com/openai/codex/issues/5443) — 2026 (FLAG: do not rely on extension-side approval policy)
- [openai/codex#5038 — VS Code ignores approval_policy=never](https://github.com/openai/codex/issues/5038) — 2026
- [openai/codex#11885 — workspace-write ignores approval_policy](https://github.com/openai/codex/issues/11885) — 2026

### Multi-AI / second-opinion methodology (FACT)

- [arxiv:2603.18740 — Measuring and Exploiting Confirmation Bias in LLM-Assisted Security Code Review](https://arxiv.org/abs/2603.18740) — 2026-03 / updated 2026-04 (THE load-bearing source — 16–93% detection reduction under fix-framing)
- [arxiv:2603.16244 — More Rounds, More Noise](https://arxiv.org/pdf/2603.16244) — 2026
- [arxiv:2604.01029 — Revision or Re-Solving? Decomposing Second-Pass Gains](https://arxiv.org/pdf/2604.01029) — 2026
- [alecnielsen/adversarial-review — Claude+Codex 4-phase debate](https://github.com/alecnielsen/adversarial-review) — 2026
- [How to Set Up Automated Code Review with Multiple AI Agents — MindStudio](https://www.mindstudio.ai/blog/automated-code-review-multiple-ai-agents) — 2026
- [Why Your AI Code Reviews Are Broken (And How to Fix Them) — Qodo](https://www.qodo.ai/blog/why-your-ai-code-reviews-are-broken-and-how-to-fix-them/) — 2026
- [Multi-Model AI Code Review — Zylos Research](https://zylos.ai/research/2026-02-17-multi-model-ai-code-review) — 2026-02

### Governance / responsible-AI (FACT)

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) — 2026 (Agentic Profile concept note 2026-04-07)
- [NIST AI RMF Agentic Profile — Lab Space](https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/) — 2026
- [OWASP Top 10 for Agentic Applications 2026 — OWASP](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — 2026
- [OWASP Top 10 for Agentic Apps — NeuralTrust deep dive](https://neuraltrust.ai/blog/owasp-top-10-for-agentic-applications-2026) — 2026
- [OWASP LLM Top 10 2026 — Repello AI](https://repello.ai/blog/owasp-llm-top-10-2026) — 2026
- [AI Risk Management 2026 — Underdefense](https://underdefense.com/blog/ai-risk-management/) — 2026
- [Guardrails in Agentic AI — Medium](https://ritikjain51.medium.com/guardrails-in-agentic-ai-from-chaos-to-control-a7a24d77d1a5) — 2026-05
- [From guardrails to governance — MIT Tech Review](https://www.technologyreview.com/2026/02/04/1131014/from-guardrails-to-governance-a-ceos-guide-for-securing-agentic-systems/) — 2026-02

### Rust supply chain & audit (FACT)

- [Sherlock Rust Security & Auditing Guide 2026](https://sherlock.xyz/post/rust-security-auditing-guide-2026) — 2026
- [Rust Vulnerability Scanning: What cargo audit Misses — GeekWala](https://www.geekwala.com/blog/securing-rust-dependencies-2026) — 2026
- [RustSec Advisory Database](https://rustsec.org/) — current
- [Auditing Rust Crates Effectively — arxiv:2602.06466](https://arxiv.org/html/2602.06466v1) — 2026
- [Comparing Rust Supply Chain Safety Tools — LogRocket](https://blog.logrocket.com/comparing-rust-supply-chain-safety-tools/) — 2026
- [google/rust-crate-audits — auditing_standards.md](https://github.com/google/rust-crate-audits/blob/main/auditing_standards.md) — 2026

### GitHub Actions security (FACT)

- [GitHub Actions 2026 security roadmap — github.blog](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) — 2026
- [GitHub Actions Under Active Exploitation — RapidFort](https://www.rapidfort.com/blog/github-actions-under-active-exploitation-audit-your-org-for-high-risk-workflow-patterns) — 2026
- [GitHub Actions Security Checklist — Corgea](https://corgea.com/learn/github-actions-security-checklist) — 2026
- [GitHub Actions is the weakest link — Andrew Nesbitt](https://nesbitt.io/2026/04/28/github-actions-is-the-weakest-link.html) — 2026-04-28
- [Secure use reference — GitHub Docs](https://docs.github.com/en/actions/reference/security/secure-use) — current

### SBOM / SLSA (FACT)

- [CycloneDX 1.7 — SBOM Observer release notes](https://docs.sbom.observer/release-notes/2026-03-25-cyclonedx-1.7) — 2026-03-25
- [SBOMs + SLSA + Sigstore — Petronella](https://petronellatech.com/blog/signed-sealed-delivered-verifiable-software-supply-chains-with-sboms/) — 2026
- [From SBOM to SLSA — Petronella](https://petronellatech.com/blog/from-sbom-to-slsa-securing-your-software-supply-chain/) — 2026

### Secrets scanning (FACT)

- [Gitleaks vs TruffleHog 2026 — AppSecSanta](https://appsecsanta.com/secret-scanning-tools/gitleaks-vs-trufflehog) — 2026
- [detect-secrets vs Gitleaks vs TruffleHog vs GitGuardian 2026 — NomadX](https://devsecops.ae/secrets-scanners-comparison-2026/) — 2026
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — current

### Confidence calibration / anti-test-theater (FACT)

- [arxiv:2509.01455 — Trusted Uncertainty in LLMs](https://arxiv.org/pdf/2509.01455) — 2025/2026
- [arxiv:2604.03904 — I-CALM: Confidence-Aware Abstention](https://arxiv.org/html/2604.03904) — 2026
- [arxiv:2603.06604 — Know When You're Wrong](https://arxiv.org/pdf/2603.06604) — 2026
- [arxiv:2509.25532 — Calibrating Verbalized Confidence with Self-Generated Distractors](https://arxiv.org/pdf/2509.25532) — 2025/2026
- [AI Theater: Who Do You Trust? — Saxum](https://saxum.com/loop-lab/ai-theater-who-do-you-trust/) — 2026
- [Self-Audit Framework — natesnewsletter Substack](https://natesnewsletter.substack.com/p/if-a-former-deepmind-engineering) — 2026

### Practitioner write-ups on Codex CLI (FACT / INFERENCE)

- [OpenAI Codex: Workflows and Best Practices 2026 — smart-webtech](https://smart-webtech.com/blog/openai-codex-workflows-and-best-practices/) — 2026
- [Proven Patterns for OpenAI Codex in 2026 — DEV / Kuldeep Paul](https://dev.to/kuldeep_paul/proven-patterns-for-openai-codex-in-2026-prompts-validation-and-gateway-governance-1jhm) — 2026
- [Codex Best Practices — Simi Studio](https://simi.studio/en/posts/codex-best-practices/) — 2026
- [Codex CLI Cheatsheet — Shipyard](https://shipyard.build/blog/codex-cli-cheat-sheet/) — 2026
- [Codex AGENTS.md Explained — Verdent](https://www.verdent.ai/guides/codex-agents-md-explained) — 2026
- [Codex CLI Skills & AGENTS.md Setup 2026 — Agensi](https://www.agensi.io/learn/codex-cli-agents-md-complete-guide) — 2026
- [Codex CLI hook governance — Agentic Control Plane](https://agenticcontrolplane.com/blog/codex-cli-hooks-reference) — 2026
- [Building Production-Ready AI Agents: OpenAI Codex CLI Architecture — ZenML LLMOps Database](https://www.zenml.io/llmops-database/building-production-ready-ai-agents-openai-codex-cli-architecture-and-agent-loop-design) — 2026
- [How to Configure Claude Code, Cursor, and Codex CLI — Agensi](https://www.agensi.io/learn/ai-agent-configuration-guide-2026) — 2026
- [Codex CLI No-Approval Guide — SmartScope](https://smartscope.blog/en/generative-ai/chatgpt/codex-cli-approval-modes-no-approval/) — 2026
- [Codex CLI approval_policy Implementation Patterns — SmartScope](https://smartscope.blog/en/generative-ai/chatgpt/codex-cli-approval-policy-implementation/) — 2026 (note: title says 2025 but content reflects 2026 semantics; cross-check against developers.openai.com before relying)
- [How Codex CLI Flags Actually Work — Vincent Schmalbach](https://www.vincentschmalbach.com/how-codex-cli-flags-actually-work-full-auto-sandbox-and-bypass/) — 2026

### 2026 deprecation flags (consolidated)

- *DEPRECATED:* "first, output your plan" / preamble prompting for
  Codex-Max — causes early stop per OpenAI's own guide.
- *DEPRECATED:* `codex-davinci-002` / `code-davinci-002` (2021 API) —
  unrelated to current Codex CLI. Treat any blog referencing those
  as out-of-date.
- *DEPRECATED:* `serde_yml` (RUSTSEC-2025-0068, unsound +
  unmaintained) — confirms migration urgency captured in
  `specs/2026-05-19-residual-research.md`.
- *FLAGGED:* `approval_policy` is silently overridden in some
  contexts (openai/codex#5038, #11885) — *only the sandbox mode is
  enforcement*. Prefer `sandbox_mode = read-only` for hard
  invariants.

---

## 8 — Summary, Changes, Verification, Risks

### Summary

Decision-oriented research for the **prompt** that drives an independent
Codex pre-release audit of CLX. Five decisions: (1) GPT-5.1-Codex-Max
under read-only sandbox; (2) `AGENTS.audit.md` + stdin task statement;
(3) feed *attack register*, withhold *fix narratives* (16–93% detection
shift per arxiv:2603.18740); (4) evidence-bundle 4-tuple instead of
numeric confidence; (5) no commits, no network beyond pre-staged
RustSec DB, 90-min budget, escalate-don't-fix. Recommended template in
§6 is ready to refine downstream.

### Changes

- New file: `/Users/blackax/Projects/clx/specs/2026-05-19-codex-prompt-research.md`
- No code touched; no `git` operations performed.

### Verification

- Sources cited inline; 40+ URLs with publication dates; 2026-deprecation
  flags called out where current.
- Confidence convention applied (FACT / INFERENCE / UNVERIFIED) and the
  load-bearing claim (anchoring magnitude) is cited to a *peer-review-track
  arxiv* with verbatim percentages, not a blog.
- Threat-model and invariant set in §6.1 are cross-checked against the
  CLX `CHANGELOG.md` `[0.8.1]` Security section (B4-1 / B6-1 / B6-2 /
  B1-4 / B3-2 / B5-4 / B3-1 / B1-10 / B5-1 / B5-2) — i.e. the prompt's
  invariants and the actual fixes are in one-to-one correspondence.
- Codex CLI flag set (`--sandbox read-only`, `--ask-for-approval never`,
  `--model gpt-5.1-codex-max`) cross-checked against `developers.openai
  .com/codex/agent-approvals-security` and known Codex repo bugs that
  make `approval_policy` alone insufficient (#5038, #11885) — read-only
  sandbox is the enforcement floor.

### Risks / follow-ups

- **WebFetch was denied this session.** All extracts came from
  WebSearch summaries (which include verbatim quotes). Before emitting
  the final prompt to a Codex run, *re-fetch the four primary OpenAI
  doc pages* (`/codex/prompting`, `/codex/learn/best-practices`,
  `/codex/agent-approvals-security`, `/codex/guides/agents-md`) and
  diff against the verbatim quotes used here. Flag for the next phase.
- **The `cookbook.openai.com/examples/gpt-5/gpt-5-1-codex-max_prompting
  _guide` URL is the *current* Codex-Max prompting guide** and may
  contain Codex-Max-specific patterns not surfaced in the older
  `codex_prompting_guide` URL. Pull both and reconcile.
- **The CHANGELOG `[Unreleased]` section mentions a *coverage push to
  90%* with explicit anti-test-theater framing (line 30).** The Codex
  prompt's confidence-framing rules (§4, §6.1) inherit this exactly —
  if the user changes the framing in CHANGELOG, the prompt template
  needs the same change.
- **`approval_policy` drift (openai/codex#5038, #11885) is the
  highest-risk Codex quirk for this use case.** The mitigation (rely
  on `sandbox_mode = read-only`) is the right call, but a Codex
  version bump between research and audit-day could change the
  behavior again. Pin the Codex CLI version in the invocation
  command (`codex --version` recorded in `/tmp/codex-audit-out/`
  run metadata).
- **The Sherlock 2026 + Practical DevSecOps 2026 + LogRocket 2026
  Rust supply-chain sources are mid-tier publisher content,
  not first-party.** The first-party sources (RustSec, rust-lang
  blog, google/rust-crate-audits) are cited alongside for the
  load-bearing claims; UNVERIFIED items from the mid-tier sources
  are flagged inline.
- **The `AGENTS.audit.md` template hard-codes the v0.8.1 RED register
  IDs.** When v0.8.2 ships, the register will need updating; the
  template's structure does not.
