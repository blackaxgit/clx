# Residual Remediation Research — 2026 Best Practices

**Date:** 2026-05-19
**Scope:** Decision-oriented research for 6 residual remediations on the CLX Rust 2024 workspace
(`clx-core` / `clx-hook` / `clx-mcp` / `clx`), `unsafe_code = deny`, tokio, serde_yml, age,
rusqlite, reqwest, GitHub Actions release.
**Method:** WebSearch over official advisories/docs/maintainer repos (WebFetch unavailable in
this session — denied; findings synthesized from search-result extraction; deep-link any URL
before acting). Codebase grounded against current sources.
**Confidence convention:** FACT (directly stated by authoritative source) / INFERENCE
(cross-source synthesis) / UNVERIFIED (single source, flag for re-check).

Each item: current consensus → recommended approach → rejected alternatives → deprecation flags.
A consolidated per-item seed plan is at the end.

---

## Item 1 — serde_yml RUSTSEC-2025-0068 migration

### Codebase reality
- `Cargo.toml:27` → `serde_yml = "0.0.12"`; consumed by `crates/clx/Cargo.toml:18` and
  `crates/clx-core/Cargo.toml:13` via `serde_yml.workspace = true`.
- This parser handles **untrusted project config** (`.clx/` YAML, project trust files) — it is
  on the attack surface of a security tool, so unsoundness here is materially worse than for a
  build-only tool. (FACT — codebase + threat model.)

### Advisory facts (FACT)
- **RUSTSEC-2025-0068**, published **September 2025**: `serde_yml` is *unsound and unmaintained*.
  The upstream GitHub repo was **archived** after unsoundness reports. Root cause: the fork
  contains AI-generated code that is "complete nonsense or unsound"; docs.rs build was broken by
  a hallucinated rustdoc flag. (rustsec.org/advisories/RUSTSEC-2025-0068.html — 2025-09;
  rustsec/advisory-db#2395.)
- RustSec explicitly recommends two maintained successors:
  - **`serde_norway`** — maintained fork of `serde_yaml` on `unsafe-libyaml-norway`.
  - **`serde_yaml_ng`** — maintained fork of `serde_yaml` (acatton), originally on
    `unsafe-libyaml`, actively migrating to `libyaml-safer`.

### Maintenance signals (FACT / INFERENCE)
- `serde_yaml` (dtolnay): last release **0.9.34+deprecated (March 2024)**, repo **archived**,
  deprecation encoded in the version string. Author no longer uses YAML. **Do not adopt** — it
  is itself flagged unmaintained (rustsec/advisory-db#2132). (FACT.)
- `serde_yaml_ng` v0.10.x: ~988 commits, growing user/issue/PR activity, July 2025 maintainer
  note confirms active maintenance; goal is *maximal API compat with dtolnay serde_yaml* (forked
  at upstream commit 200950); in-progress migration `unsafe-libyaml` → `libyaml-safer` (memory-
  safer). Maintainer caveat: "don't expect professional support." (FACT — repo README.)
- `serde_norway` (cafkafk/Christina Sørensen): ~0.9.42, packaged by distros (Fedora review,
  Repology), adopted by espanso as the serde_yaml replacement; maintainer states *not committed
  to long-term maintenance*. (FACT — crates.io / espanso#1937.)

### API / migration cost vs `serde_yml 0.0.12` (INFERENCE)
- Both successors are line-for-line forks of `dtolnay/serde_yaml`'s public API
  (`from_str`/`to_string`/`Value`/`Mapping`/`Number`). `serde_yml 0.0.12` is *also* a serde_yaml
  fork, so the public surface CLX uses is near-identical. Expected migration: a dependency rename
  + `serde_yml::` → `serde_yaml_ng::` path substitution; **no serde derive changes**. Low cost
  (hours, not days), gated by CLX's actual API usage (only `from_str`/`to_*` per current code).

### RECOMMENDED
**Adopt `serde_yaml_ng` (latest 0.10.x).** It is the most-active fork, has the clearest
API-compat charter, and is moving toward a memory-safer parser (`libyaml-safer`) — the strongest
posture for a security tool parsing untrusted YAML under `unsafe_code = deny` (the unsafe lives
in the C-binding dep, not CLX). Pin exact version; add a `cargo-deny` advisory gate so any future
RUSTSEC on the successor fails CI.

### Rejected alternatives
- **`serde_norway`** — viable and distro-blessed, but maintainer explicitly disclaims long-term
  commitment; equal API but weaker continuity signal than `serde_yaml_ng`. Acceptable fallback.
- **`serde_yaml` (dtolnay)** — REJECTED: archived/deprecated, separately RUSTSEC-flagged.
- **`saphyr` / `yaml-rust2`** — pure-Rust (no C `libyaml`), attractive for `unsafe_code = deny`
  purity, but they are *low-level YAML event/AST* libraries, **not serde-integrated**. Adopting
  would require writing a serde bridge → high migration cost, more new code on the security-
  critical path. REJECTED for this remediation; revisit only if a fully-pure-Rust serde YAML
  stack matures. (`saphyr` is the actively-developed successor to `yaml-rust2`.)
- **Drop YAML / switch to TOML+serde** — largest blast radius (breaks existing user config
  files); out of scope for a security remediation.

### Deprecation flags (2026)
- `serde_yml` — unsound + unmaintained (RUSTSEC-2025-0068). MUST remove.
- `serde_yaml` — unmaintained/deprecated (rustsec/advisory-db#2132). MUST NOT adopt.
- `unsafe-libyaml` — itself unmaintained; prefer the successor's `libyaml-safer` path when stable.

---

## Item 2 — GitHub Actions manual-approval release gate

### Consensus (FACT — GitHub Docs, 2026)
- The 2026-correct mechanism is a **deployment environment with protection rules**, not a
  third-party "manual approval" action. Put the auto-publish job (Homebrew tap push) in a job
  with `environment: release-publish`; the job **pauses** until a required reviewer approves.
- **Required reviewers:** up to 6 users/teams; only **one** must approve.
- **Prevent self-review:** enable so the release initiator cannot approve their own publish —
  enforces two-person control. (docs.github.com/.../deployments-and-environments — 2026.)
- **Wait timer:** optional 1–43,200 min delay (defense-in-depth "cool-off" before publish).
- **Environment secrets gate:** secrets scoped to the environment (e.g. `HOMEBREW_TAP_TOKEN`
  from the existing homebrew-distribution prep) are **inaccessible until approval** — the token
  literally cannot be used by an unapproved run. This is the key security property.
- Max 6 protection rules per environment.

### CRITICAL plan availability constraint (FACT — flag this)
On **GitHub Free / Pro / Team**, required-reviewer and wait-timer protection rules are available
**only for public repositories**. Private repos need GitHub Enterprise/Team-with-private. CLX's
release repo must be **public** for this gate to work on a non-Enterprise plan — verify before
relying on it. (docs.github.com — 2026.)

### Composition with `actions/attest-build-provenance` keyless signing (FACT / INFERENCE)
- `actions/attest-build-provenance` uses **Sigstore keyless** signing: the workflow's OIDC
  identity *is* the signing credential; a short-lived Sigstore cert signs the attestation and the
  proof is written to a public transparency log + the GH attestations API. Public repo → public-
  good Sigstore; private → GitHub private Sigstore instance. This satisfies **SLSA Build L3**.
- **Correct composition (recommended ordering):**
  1. `build` job: compile + `actions/attest-build-provenance` over the release artifacts
     (binaries / formula). Provenance is bound to the *build*, requires `id-token: write` +
     `attestations: write`, **no environment** (so it always runs, unattended).
  2. `publish` job: `needs: [build]`, `environment: release-publish` → **human approval gate
     here**, then Homebrew tap push using the environment-scoped token.
  - Rationale: attestation must cover the exact artifact bytes regardless of approval; approval
    gates *distribution*, not *provenance generation*. Gating the build would let an approver
    sign-off on something never attested. (INFERENCE from SLSA + GitHub docs; consistent across
    sources.)
- Consumers verify with `gh attestation verify` / `slsa-verifier` against the published artifact.

### RECOMMENDED
Two-job release workflow: unattended `build`+attest job → approval-gated `publish` environment
(`release-publish`) with **required reviewers + prevent-self-review + environment-scoped tap
token**, optional short wait timer. Keep keyless attestation in the build job. Verify the release
repo is public (or on Enterprise) so the gate is enforceable.

### Rejected alternatives
- **Third-party "manual approval" issue-comment actions** (e.g. trstringer/manual-approval) —
  REJECTED: not native, no secret-gating (token still reachable by the run), weaker audit trail
  than environment deployments, supply-chain surface.
- **Gating the build/attest job behind approval** — REJECTED: breaks provenance-covers-artifact
  invariant; an approver could authorize an unattested artifact.
- **Branch-protection / required PR review as the release gate** — REJECTED: protects source,
  not the publish action; does not gate the tap token.
- **`workflow_dispatch` manual trigger only** — insufficient: a single actor can both trigger
  and publish; no two-person control, no self-review prevention.

### Deprecation flags
- None. Environment protection rules + keyless `attest-build-provenance` are the current
  GitHub-recommended 2026 stack. (Note: the older `slsa-github-generator` reusable workflow
  still works but `actions/attest-build-provenance` is the simpler GitHub-native path.)

---

## Item 3 — Forensic audit logging of a security-control bypass

### Codebase reality
- `crates/clx-core/src/storage/audit.rs` — `audit_log` table: `session_id, timestamp, command,
  working_dir, layer, decision, risk_score, reasoning, user_decision`. No integrity column, no
  hash chain, ordinary mutable SQLite rows, retention via `cleanup_old_audit_logs`. The
  validator-disabled-via-env event has no representation today.

### Consensus (FACT — Crosby/Wallach USENIX'09; OWASP; 2026 practitioner sources)
- **Pattern: append-only structured event + SHA-256 hash chain.** Each row stores
  `prev_hash` and `entry_hash = SHA256(canonical(fields) || prev_hash)`. Altering or deleting
  any row breaks every subsequent hash → *tamper-evident* (detectable), the achievable property
  for a local single-binary tool. Same construction as git/Certificate Transparency.
- **Tamper-evident ≠ tamper-proof:** a local attacker with write access can recompute the whole
  chain. Mitigations that *do* apply locally: (a) anchor — periodically log the head hash to an
  append-only sink the process cannot rewrite cheaply (stderr/syslog/`tracing` at WARN, file
  with `O_APPEND`); (b) genesis hash pinned at install; (c) verify-chain command. (FACT —
  Crosby & Wallach; INFERENCE for the local-tool mapping.)

### Recommended event schema for "validator disabled via env" (no PII)
A dedicated `security_control_event` (or a typed `decision = "control_bypass"` audit row) with:

| Field | Value / note |
|---|---|
| `event_type` | `"validator_disabled"` (enum, not free text) |
| `control` | stable id of the disabled control (e.g. `"command_validator_L1"`) |
| `mechanism` | `"env_var"` |
| `trigger_key` | the env var **name only** (e.g. `CLX_DISABLE_VALIDATOR`) — never its value |
| `effective` | bool: did the bypass actually take effect |
| `timestamp` | RFC3339 UTC (matches existing `to_rfc3339()` convention) |
| `process` | pid + binary name + version (which binary observed it) |
| `session_id` | existing correlation key |
| `prev_hash` / `entry_hash` | hex SHA-256 chain columns |
| `schema_version` | integer, for forward-compat of the audit format |

**No-PII rules:** never store env *values*, full argv, user home paths, hostnames, or the
project path verbatim. `working_dir` (already stored) should be hashed or basename-only for
control events. Reasoning/justification fields must pass redaction (Item 5) before insert.

**Integrity considerations:** compute the hash over a *canonical* serialization (stable key
order, fixed numeric/string encoding) so verification is deterministic; write the row inside the
same SQLite transaction; treat a chain-verify mismatch as a hard alert, not a warning.

### RECOMMENDED
Add a typed, append-only, hash-chained control-bypass event (schema above), genesis-anchored at
install, head-hash periodically emitted to the existing `tracing` WARN sink, plus a
`clx audit verify` command. Reuse the existing `Storage` transaction + RFC3339 convention; add
`prev_hash`/`entry_hash`/`schema_version` columns via migration.

### Rejected alternatives
- **Plain `tracing::warn!` log line only** — REJECTED: not queryable, not integrity-protected,
  trivially lost; acceptable only as the *anchor* sink, not the system of record.
- **Full Merkle tree / external transparency log** — REJECTED as over-engineering for a
  single-user local tool; hash chain gives the needed property at far lower complexity (revisit
  if multi-tenant/server mode appears).
- **Signing each row with an embedded key** — REJECTED: a local-only key offers no real
  assurance against a local attacker and adds key-management burden; chain + external anchor is
  the honest model.
- **Storing the env value "for forensics"** — REJECTED: violates no-PII/no-secret rule; the
  key name + effect is sufficient and safe.

### Deprecation flags
- None technically deprecated; flag that *mutable, unchained* audit rows (current state) are
  below 2026 forensic baseline for a security-control event.

---

## Item 4 — SSRF allowlist hardening (`CLX_ALLOW_AZURE_HOSTS` class)

### Codebase reality
- `crates/clx-core/src/llm/azure.rs:99-125` `validate_host`: string-compares the URL **hostname**
  against `CLX_ALLOW_AZURE_HOSTS` entries and `ALLOWED_HOST_SUFFIXES`. **It never resolves DNS
  and never inspects the connected IP** → classic DNS-rebinding gap: `evil-allowed-host.example`
  can be allowlisted by name yet resolve to `169.254.169.254` / `127.0.0.1` / RFC1918 at connect
  time. reqwest follows redirects by default unless disabled.

### Consensus (FACT — OWASP SSRF Cheat Sheet; 2025–2026 SSRF research)
- Name-only allowlisting is **insufficient**: the TOCTOU between resolve-for-validation and
  resolve-for-connect is the canonical DNS-rebinding bypass (OWASP; windshock 2025-06;
  craftcms GHSA-gp2f-7wcm-5fhx; thingsboard#15253).
- Mandatory layered controls for an env-provided host allowlist:
  1. **Scheme allowlist:** `https` only (block `http`, `file`, `gopher`, etc.).
  2. **Host allowlist (exact):** keep exact-host/suffix match; treat env entries as hostnames,
     not regexes.
  3. **Resolve, then re-block:** resolve the host to all A/AAAA, and **reject if any resolved
     IP** is loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10` —
     covers `169.254.169.254` IMDS and IPv6 `[fd00:ec2::254]`), RFC1918 / ULA `fc00::/7`,
     CGNAT `100.64.0.0/10`, `0.0.0.0/8`, multicast, or unspecified. Allowlist membership does
     **not** exempt an internal IP — re-block runs *after* the allowlist.
  4. **Pin the connection to the validated IP** (connect to the exact IP that passed checks, or
     use a custom resolver/connector) to close the rebind gap — *the* fix, not just re-checking.
  5. **Disable HTTP redirects** on the reqwest client (or re-run full validation per hop).
  6. Defense-in-depth: on cloud, IMDSv2 hop-limit 1 / egress firewall — out of CLX's control but
     document as operator guidance.

### Rust-specific implementation note (INFERENCE)
The DNS-rebind-safe approach in reqwest is a **custom DNS resolver / `connect`-time check**:
resolve once, validate every returned `IpAddr` with `std::net::IpAddr` classification
(`is_loopback`, `is_link_local`, `is_private`, plus explicit IMDS/ULA/CGNAT ranges since std
doesn't cover all), then connect to that exact validated socket address. Apply the same guard
uniformly across `azure.rs`, `ollama.rs`, `fallback.rs` (all three reference the allow-host env
class) — currently only `azure.rs` validates.

### RECOMMENDED
Replace name-only `validate_host` with a shared egress guard: `https`-only + exact host
allowlist + **post-resolution IP re-block of all loopback/link-local/RFC1918/ULA/CGNAT/IMDS
ranges (allowlist cannot exempt these)** + connection pinned to the validated IP +
redirects disabled. Centralize in `clx-core` and apply to every LLM backend, not just Azure.

### Rejected alternatives
- **Keep name-only allowlist, add IP check at validation only (not at connect)** — REJECTED:
  still TOCTOU-vulnerable to DNS rebinding (resolve twice → second answer differs).
- **Blocklist of bad IPs instead of allowlist + re-block** — REJECTED: blocklists are
  incomplete by construction (IPv6 forms, decimal/octal/0x IP encodings, NAT64); OWASP favors
  allowlist + structural re-block.
- **Trust env allowlist as fully authoritative (current behavior)** — REJECTED: an operator-set
  allowlist must still not be able to authorize the metadata endpoint; the re-block is a
  non-overridable backstop.
- **Egress proxy only** — good defense-in-depth but external to the binary; not a substitute for
  in-process validation in a distributable CLI.

### Deprecation flags
- The name-only `validate_host` (current code) is the deprecated pattern per 2026 OWASP
  guidance — explicitly insufficient against DNS rebinding.

---

## Item 5 — Secret/PII redaction in logs & audit trails (2026)

### Codebase reality
- `crates/clx-core/src/redaction.rs`: prefix/keyword + URL-authority-suffix scrubbing (no regex),
  plus `redact_json_value` walking `serde_json::Value` by sensitive **key name** and string-leaf
  patterns. This is the right *shape* but is pattern-based for free-text reasoning fields.

### Consensus (FACT — 2026 Rust/observability + PII-detection literature)
- **Three-tier architecture is the 2026 best practice** (Axum/Rust PII article, May 2026;
  Sentry Rust docs):
  1. **Data-model tier:** wrap secrets in types whose `Debug`/`Display` redact by construction
     so leakage is a *compile-time-shaped* error, not a runtime grep. CLX already uses
     `secrecy::SecretString` for keys — extend this discipline to all credential/PII-bearing
     fields. **This is the strongest control and should be primary.**
  2. **Transport tier:** sanitize request/response bodies at the boundary before any sink.
  3. **Observability tier:** install a `tracing` field visitor that redacts structured fields
     **by key name** before formatting (works because CLX emits structured `tracing` events).
- **Why regex alone is now considered insufficient for free-text** (Protecto/Private-AI/rehydra,
  2025–2026): regex matches strings, not meaning — misses contextual PII ("daughter Emily at
  Ridgewood Elementary" has no token pattern), is brittle to format variance/concatenation, and
  widening patterns explodes false positives. For *free-text reasoning/audit* fields, structural
  + typed handling beats regex; pure regex is acceptable only for *low-risk structured* fields
  with known formats (e.g. an `api_key=` token).

### Recommended Rust patterns / crates
- Keep & expand `secrecy::SecretString` (already a dep) for typed redaction — primary control.
- Structured `tracing` redaction layer that drops/masks fields by key (no regex on free text).
- The `redaction` crate (sformisano/redaction) — purpose-built "redact before leaving trusted
  context (logs/telemetry/responses)"; evaluate as the field-level wrapper. (UNVERIFIED depth —
  single source; spike before adopting.)
- For free-text reasoning/audit envelopes: **structural minimization first** — don't log the
  free text at all, or log a typed/enumerated summary; treat regex scrubbing as a last-resort
  net, never the only layer. Apply redaction *before* the Item 3 hash is computed (so the
  immutable record never contained the secret).
- Debug-logged JSON envelopes: extend `redact_json_value` to deny-by-default unknown keys in
  sensitive envelopes rather than allow-by-default + pattern match.

### RECOMMENDED
Adopt the three-tier model: (1) typed `SecretString`/redacting-wrapper fields as the primary
guarantee, (2) a `tracing` key-name redaction layer for structured events, (3) keep the existing
prefix/URL scrubber as a defense-in-depth net **only**. For free-text reasoning/audit fields,
minimize/enumerate rather than rely on regex; redact before hashing/persisting.

### Rejected alternatives
- **Regex-only redaction of free-text reasoning fields** — REJECTED as 2026-insufficient
  (context-blind, brittle, false-positive-prone per Protecto/Private-AI).
- **Allow-by-default JSON logging + post-hoc scrub** — REJECTED: any new sensitive key leaks
  until a pattern is added; prefer deny-by-default field allowlists for sensitive envelopes.
- **ML/NER PII detector in-process** — REJECTED for a local CLI: heavy dependency, latency,
  model-supply-chain surface; the typed-field approach removes the need. Revisit only if CLX
  ever ingests arbitrary user free-text it must publish.
- **Logging then redacting at the aggregator** — REJECTED: secret already left the process /
  hit disk; redaction must be at/inside the boundary.

### Deprecation flags
- Pure-regex free-text PII redaction is explicitly called out as insufficient in 2026 sources —
  flag CLX's reliance on pattern matching for *reasoning* fields as below current best practice
  (the URL/keyword scrubber is fine as a *secondary* net).

---

## Item 6 — Defensible ">97% confidence a fix is correct"

### Consensus (FACT — DevSecOps/Precursor/Invicti 2026; Rust testing literature; arXiv 2603.10072)
- A bare numeric confidence ("97%") with no underlying statistical model is **false precision /
  test theater** — 2026 guidance is to *replace the number with a named evidence bundle*, or
  bound it with an actual pass/fail statistical model. The defensible artifact is the
  methodology, not the percentage.
- **Proof-of-Vulnerability (PoV) / fail-before-pass is the load-bearing control:** a regression
  test that **fails on the pre-fix code and passes on the post-fix code**. A fix without a test
  that demonstrably failed before it is unverified. (Precursor; USPTO 11301367; arXiv 2603.10072.)
- Layered verification ladder (apply by risk):
  1. **Fail-before / pass-after** regression test committed alongside the fix (mandatory).
  2. **Adversarial re-derivation:** independently re-attack the fixed path (bypass attempts:
     for Item 4, DNS-rebind/redirect/encoding variants; for Item 1, malicious YAML corpora).
  3. **Property / fuzz** where input is adversarial and structured — `proptest` for in-suite
     invariants (no tooling), `cargo-fuzz` (libFuzzer, coverage-guided) for parser/egress paths.
     Pattern: fuzz interactively to find deep bugs → freeze findings as `proptest`/unit
     regressions so CI keeps them. Property tests are weaker than coverage-guided fuzzing —
     state which you used.
  4. **Mutation testing** (`cargo-mutants`) on the changed module to prove the new tests
     actually kill the relevant mutants (guards against assertion-free "test theater").
  5. **CI gating:** fast PoV/property tests on PR, slower fuzz/mutation on merge gate; advisory
     scan (`cargo-deny`/`audit`) for dependency fixes (Item 1).

### How to express the confidence statement (RECOMMENDED form)
Do **not** ship "~97% confident." Ship an evidence statement, e.g.:

> "Fix verified by: (a) PoV regression `test_x` — fails at parent commit, passes at fix
> commit (CI link); (b) adversarial re-derivation of N bypass variants, all blocked;
> (c) `proptest`/`cargo-fuzz` over the affected parser/egress path, M iterations, no
> counterexample; (d) `cargo-mutants` on the changed module — K/K relevant mutants killed.
> Residual risk: <enumerated unknowns>."

If a number is contractually required, derive it from the pass/fail reliability model
(observed passes/failures → reliability at a stated confidence, per the pass/fail statistical
literature) and **state the model and sample size** — never an unmodeled gut number.

### RECOMMENDED
Mandate per security fix: a fail-before/pass-after PoV regression test (commit-linked),
adversarial re-derivation of the bypass class, `proptest` and/or `cargo-fuzz` on
parser/egress/crypto-adjacent paths, `cargo-mutants` on the changed module to validate the
tests, advisory scan for dependency fixes. Replace "% confidence" with the evidence bundle above
(or a modeled, sample-sized figure). This is the verification contract for Items 1–5.

### Rejected alternatives
- **Unmodeled "~97%" assertion** — REJECTED: false precision, no statistical basis (2026
  consensus, arXiv 2603.10072).
- **Coverage % as the confidence proxy** — REJECTED: high coverage with weak assertions passes
  mutation-naive; coverage is necessary, not sufficient.
- **Fuzzing-only, no regression test** — REJECTED: a found bug not frozen as a fail-before test
  regresses silently.
- **Manual review sign-off only** — REJECTED: not reproducible, not CI-enforced; acceptable
  only *in addition to* the automated bundle.

### Deprecation flags
- None deprecated; flag the *practice* of stating bare numeric confidence without a statistical
  model or evidence bundle as below 2026 standard.

---

## Consolidated per-item seed plan (for multi-agent remediation)

| # | Remediation | Recommended approach (one line) | Key constraint to honor |
|---|---|---|---|
| 1 | serde_yml RUSTSEC-2025-0068 | Swap `serde_yml 0.0.12` → **`serde_yaml_ng` 0.10.x** workspace-wide; add `cargo-deny` advisory gate. API-compatible, hours of work. | Reject serde_yaml (deprecated) & saphyr (no serde). |
| 2 | Release approval gate | Two jobs: unattended `build`+`actions/attest-build-provenance`; approval-gated `publish` **environment** (required reviewers + prevent-self-review + env-scoped tap token). | Release repo MUST be public (or Enterprise) for the gate to exist on non-Enterprise plans. |
| 3 | Bypass audit logging | Typed append-only **hash-chained** `validator_disabled` event (enum fields, key-name-only, no PII), genesis-anchored, head-hash to `tracing` WARN, `clx audit verify`. | Env value/argv/paths never stored; redact (Item 5) before hashing. |
| 4 | SSRF hardening | Shared egress guard: https-only + exact host allowlist + **post-DNS re-block of loopback/link-local/RFC1918/ULA/CGNAT/IMDS (non-overridable)** + connect pinned to validated IP + redirects off; apply to all LLM backends. | Allowlist must NOT be able to exempt internal/metadata IPs. |
| 5 | Redaction | Three-tier: typed `SecretString`/redacting wrappers (primary) + `tracing` key-name redaction layer + existing scrubber as net only; minimize/enumerate free-text reasoning instead of regex. | Redact before persist/hash; deny-by-default sensitive JSON keys. |
| 6 | Fix-confidence methodology | Per fix: fail-before/pass-after PoV test + adversarial re-derivation + proptest/cargo-fuzz on parser/egress + cargo-mutants on changed module; replace "~97%" with evidence bundle. | No unmodeled numeric confidence; tests must demonstrably fail pre-fix. |

**Cross-cutting:** Items 1, 3, 4, 5 each require an Item-6 evidence bundle. Items 3 and 5 are
coupled (redact-before-hash ordering). Item 2 is independent and can run in parallel. File
ownership for parallel agents is naturally disjoint: (1) `Cargo.toml`+`*/Cargo.toml`+yaml call
sites; (2) `.github/workflows/`; (3) `clx-core/src/storage/`; (4) `clx-core/src/llm/`;
(5) `clx-core/src/redaction.rs`+`tracing` setup; (6) test/CI harness across crates.

---

## Sources (URL + observed date)

**Item 1**
- RUSTSEC-2025-0068 advisory (2025-09): https://rustsec.org/advisories/RUSTSEC-2025-0068.html
- advisory-db serde_yml issue: https://github.com/rustsec/advisory-db/issues/2395
- advisory-db serde_yaml unmaintained #2132: https://github.com/rustsec/advisory-db/issues/2132
- serde-yaml-ng (maintainer repo, July 2025 status): https://github.com/acatton/serde-yaml-ng
- serde_norway crates.io: https://crates.io/crates/serde_norway/versions
- espanso replacement discussion: https://github.com/espanso/espanso/issues/1937
- serde-yaml deprecation thread: https://users.rust-lang.org/t/serde-yaml-deprecation-alternatives/108868

**Item 2**
- GitHub Docs — Deployments and environments (2026): https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
- GitHub Docs — Reviewing deployments: https://docs.github.com/actions/managing-workflow-runs/reviewing-deployments
- actions/attest-build-provenance: https://github.com/actions/attest-build-provenance
- SLSA BYO builder on GitHub Actions: https://slsa.dev/blog/2023/08/bring-your-own-builder-github
- SLSA L3 build provenance (2026-02): https://oneuptime.com/blog/post/2026-02-09-slsa-level3-build-provenance/view
- OneUptime — environment protection rules (2026-01-25): https://oneuptime.com/blog/post/2026-01-25-github-actions-environment-protection-rules/view

**Item 3**
- Crosby & Wallach, Efficient Data Structures for Tamper-Evident Logging (USENIX Security '09): https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf
- SHA-256 hash-chain audit log (DEV, 2025/26): https://dev.to/veritaschain/building-a-tamper-evident-audit-log-with-sha-256-hash-chains-zero-dependencies-h0b
- Tamper-proof audit log architecture (DEV): https://dev.to/robertatkinson3570/the-architecture-behind-tamper-proof-audit-logs-56ek
- Audit logging best practices (Sonar): https://www.sonarsource.com/resources/library/audit-logging/

**Item 4**
- OWASP SSRF Prevention Cheat Sheet (current): https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Limitations of "secure" SSRF patches, defense-in-depth (2025-06): https://windshock.github.io/en/post/2025-06-25-ssrf-defense/
- Craft CMS metadata SSRF via DNS rebinding (GHSA): https://github.com/craftcms/cms/security/advisories/GHSA-gp2f-7wcm-5fhx
- ThingsBoard SSRF DNS-rebinding fix + allowlist: https://github.com/thingsboard/thingsboard/pull/15253
- DNS rebinding vs SSRF protections: https://behradtaher.dev/DNS-Rebinding-Attacks-Against-SSRF-Protections/

**Item 5**
- Axum/Rust PII leak architecture (2026-05): https://medium.com/@abhinav.dobhal/your-axum-service-is-leaking-pii-heres-the-architecture-to-stop-it-fffc4b28b57d
- Sentry Rust — scrubbing sensitive data: https://docs.sentry.io/platforms/rust/data-management/sensitive-data/
- redaction crate: https://github.com/sformisano/redaction
- Why regex fails PII detection (Protecto, 2025-12): https://www.protecto.ai/blog/why-regex-fails-pii-detection-in-unstructured-text/
- Private-AI — hidden PII detection crisis: https://www.private-ai.com/en/blog/hidden-pii-detection
- Semantic vs regex redaction (rehydra): https://www.rehydra.ai/blog/semantic-redaction-vs-regex-why-context-matters-for-pii
- Rust structured logs with tracing (2026-01): https://oneuptime.com/blog/post/2026-01-07-rust-tracing-structured-logs/view

**Item 6**
- Security regression tests guide (DevSecOps School, 2026): https://devsecopsschool.com/blog/security-regression-tests/
- Vulnerability remediation + regression testing (Precursor): https://www.precursorsecurity.com/blog/vulnerability-remediation-do-not-forget-regression-testing
- Are you sure that vulnerability is fixed (Invicti): https://www.invicti.com/blog/web-security/are-you-sure-that-vulnerability-is-fixed-continuous-security-testing
- Automated fix verification from PoCs (USPTO 11301367): https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11301367
- Why LLMs fail at security patch generation (arXiv 2603.10072): https://arxiv.org/pdf/2603.10072
- proptest property-based testing (Rust patterns): https://softwarepatternslexicon.com/patterns-rust/22/4/
- cargo-fuzz testing guide: https://softwarepatternslexicon.com/rust/testing-and-quality-assurance/fuzz-testing-with-cargo-fuzz/
- Rust testing or verifying: why not both (Alastair Reid): https://alastairreid.github.io/why-not-both/
- Reliability/confidence from pass/fail data: https://khuston.github.io/statistics/2021/01/25/reliability-and-confidence-for-pass-fail-data.html

*Note: WebFetch was denied in this session; advisory/doc content was extracted via WebSearch
result synthesis. Before implementation, deep-link RUSTSEC-2025-0068, the GitHub Docs
environments page, and the OWASP SSRF cheat sheet to confirm verbatim details (esp. plan-
availability of environment protection rules and exact recommended-alternative wording).*
