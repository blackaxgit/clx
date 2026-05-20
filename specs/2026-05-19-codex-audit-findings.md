# Codex Independent Pre-Release Audit Findings

Codex version: `codex-cli 0.130.0` (`codex --version` also emitted a PATH warning)
Repo HEAD: `0ca37b5af941f2aa55e9dcffd42fd8b4ef10a33b`
Model: `gpt-5.5`
Timestamp: `2026-05-19T23:36:05Z`
Overall verdict: `NO-SHIP`

## Scope

Audited the current worktree at `/Users/blackax/Projects/clx` against the requested CLX pre-release security scope. I read the audit prompt, recon targets, execution rules, and source/workflow files directly. I did not read the forbidden signoff/status files named in the task.

Validation commands run:

- `cargo audit` failed initially because it tried to fetch and lock a read-only advisory DB path.
- `cargo audit --no-fetch` completed and reported 8 allowed warnings.
- `cargo test --workspace --no-run` passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` passed.
- `cargo deny check` failed before policy evaluation because it tried to lock `/Users/blackax/.cargo/advisory-dbs/db.lock` in the read-only sandbox.
- `cargo test --workspace -- --ignored --list` completed and listed 9 ignored tests.

## Per-Attack Evidence Bundles

| Attack | Verdict | Severity | Evidence bundle | Recommendation |
|---|---|---:|---|---|
| R-B4-1 project config filter | VULN-REFUTED | Low | COUNTEREXAMPLE tested: merge-key YAML parses as `validator: {"<<": ...}` and `filter_value` drops the entire top-level `validator` subtree at `crates/clx-core/src/config/project.rs:161`; scalar `validator: false` is also dropped because the key matches before value traversal. REGRESSION-PIN: add missing adversarial tests at `project.rs:374`. RESIDUAL-UNCERTAINTY: `serde_yml` itself remains unsound before filtering. | Keep the whole-subtree filter, add merge/alias/tagged-scalar tests, and migrate off `serde_yml`. |
| R-B6 Azure redaction | VULN-CONFIRMED | High | COUNTEREXAMPLE: a synthetic Azure connection error can enter `LlmError::Connection(e.to_string())` unredacted at `crates/clx-core/src/llm/azure.rs:280` and `:303`; `LlmError` displays it verbatim at `llm/mod.rs:33`. Additional unredacted sinks exist at `crates/clx-hook/src/transcript.rs:285`, `:339`, `crates/clx/src/commands/embeddings.rs:99`, `:108`, `:360`, `:370`, `:484`, `:489`, and `crates/clx/src/commands/recall.rs:153` via error Display chains. REGRESSION-PIN: redact at the error construction boundary and enforce redacted display wrappers at all CLI/log sinks. RESIDUAL-UNCERTAINTY: exact `reqwest::Error` text varies by transport failure. | Make Azure backend construct redacted `LlmError` strings, and ban raw `{e}` / `e.to_string()` for LLM errors outside redaction helpers. |
| R-B1-4/B3-2 overbroad allow | VULN-CONFIRMED | High | COUNTEREXAMPLE: file-loaded `whitelist: ["Bash(*)"]` is accepted at `crates/clx-core/src/policy/rules.rs:216` with no overbroad gate. Probe also showed `is_overbroad_allow_pattern("Bash(*)x") == false`, but `PolicyEngine` evaluates `Bash(*)x` as `Allow` because `parse_pattern` uses `rfind(')')` and ignores trailing text (`matching.rs:10`, `policy/mod.rs:181`). REGRESSION-PIN: `rules.rs:216`, `matching.rs:10`. RESIDUAL-UNCERTAINTY: learned/MCP paths wrap `Bash(*)x` before load, making that specific variant inert there; file config remains exploitable. | Apply the overbroad gate to file rules and make `parse_pattern` require the closing `)` to end the string. |
| R-B5-4 audit chain | VULN-CONFIRMED | High | COUNTEREXAMPLE: every hook invocation calls `build_record(1, ..., GENESIS_HASH)` at `crates/clx-hook/src/hooks/pre_tool_use.rs:47`; no prior head is read or persisted. `audit_chain.rs:10` says process-local, but comments at `audit_chain.rs:14` claim deletion breaks subsequent hashes. REGRESSION-PIN: `pre_tool_use.rs:44-64` plus missing persistent chain-head storage. RESIDUAL-UNCERTAINTY: an external log aggregator could preserve individual WARN anchors, but that is not an in-repo chain. | Reclassify as per-event fingerprinting or persist a chain head with concurrency-safe update semantics. |
| R-B1-10 trust-token removal | VULN-REFUTED | Low | COUNTEREXAMPLE attempted: fresh non-JSON `.trust_mode_token` now falls through because JSON parse failure returns `false` at `crates/clx-hook/src/hooks/pre_tool_use.rs:166-175`; only JSON `TrustToken` path can return early at `:129-163`. REGRESSION-PIN: none. RESIDUAL-UNCERTAINTY: future JSON leniency or clock rollback could affect expiry semantics. | Remove the dead legacy-token branch at `pre_tool_use.rs:180-196` for clarity. |
| R-supply-chain | VULN-CONFIRMED | High | COUNTEREXAMPLE: `cargo audit --no-fetch` reports `serde_yml 0.0.12` (`RUSTSEC-2025-0068`) and `libyml 0.0.5` (`RUSTSEC-2025-0067`) as unsound on the path used for untrusted project YAML at `project.rs:96`. `deny.toml:15-17` calls the inert filter a compensating control, but the parse happens before the filter. New `rand` `RUSTSEC-2026-0097` warnings also appear. REGRESSION-PIN: `Cargo.toml:27`, `deny.toml:18-24`, `project.rs:96`. RESIDUAL-UNCERTAINTY: I did not develop a memory-corruption PoC. | Block release on YAML parser migration or isolate untrusted YAML parsing out of the trusted process. Reconcile deny/audit policy with the 8 current warnings. |
| R-workflow | VULN-CONFIRMED | Medium | COUNTEREXAMPLE: `.github/workflows/ci.yml` has no explicit top-level `permissions`, so least privilege depends on repo defaults. `.github/workflows/release.yml:24-27` grants `contents: write`, `id-token: write`, and `attestations: write` workflow-wide; `update-homebrew` at `release.yml:243` has no `environment:` gate and inherits broad permissions while using `secrets.HOMEBREW_TAP_TOKEN` at `:255`. Attestation wiring itself is present at `:153-156`, and SBOM generation copies `crates/clx/clx.cdx.xml` at `:145-146`. REGRESSION-PIN: `ci.yml:22`, `release.yml:243`. RESIDUAL-UNCERTAINTY: GitHub repository-level workflow permission settings were not inspected. | Add explicit read-only CI permissions, narrow release job permissions per job, and put Homebrew publishing behind a protected environment. |

## Recon Target Disposition

| ID | Title | Verdict | Severity | Evidence | Recommendation |
|---|---|---:|---:|---|---|
| T1 | Audit chain is not actually chained | VULN-CONFIRMED | High | `pre_tool_use.rs:47` hard-codes `seq=1` and `GENESIS_HASH`; `audit_chain.rs` has no I/O. | Persist and verify cross-process chain state, or rename the property. |
| T2 | Azure connection errors leak tenant host | VULN-CONFIRMED | High | Raw `reqwest::Error` is stored in `LlmError::Connection` at `azure.rs:284`, `:307`; several sinks display LLM errors without redaction. | Redact at source and at every LLM error sink. |
| T3 | File-loaded allow rules bypass overbroad gate | VULN-CONFIRMED | High | `rules.rs:216-219` pushes config whitelist patterns directly; dynamic probe showed `Bash(*)x` evades the gate but matches all commands in direct config rules. | Gate file rules and fix `parse_pattern` trailing-junk acceptance. |
| T4 | Auto-summary snapshot path lacks redaction | VULN-CONFIRMED | High | `stop_auto_summary.rs:124-145` persists LLM-produced `summary` verbatim; `snapshot.rs:23`, `:87` insert it; `recall/mod.rs:222` only escapes `<` and `>`. | Apply `redact_secrets` before snapshot persistence and before recall formatting. |
| T5 | YAML merge/alias filter bypass | VULN-REFUTED | Low | Probe showed merge keys remain under top-level `validator`, which `filter_value` drops; scalar `validator` is also dropped. | Add regression tests for merge keys, aliases, BOM, and tagged scalars. |
| T6 | `redact_azure_hosts` boundary set incomplete | VULN-CONFIRMED | Medium | Probe: `tenant.openai.azure.com:443`, `tenant.openai.azure.com;`, and `host=tenant.openai.azure.com&port=443` survive `redact_secrets`; boundary set is at `redaction.rs:110-112`. | Treat `:`, `;`, `<`, `>`, `=`, `&`, `?`, and `\` as boundaries or parse hosts structurally. |
| T7 | `serde_yml` unsoundness and ignore list | VULN-CONFIRMED | High | `deny.toml` ignores `RUSTSEC-2025-0068`; `cargo audit --no-fetch` also reports `libyml` unsoundness and `rand` warnings. | Migrate parser and update deny policy to fail on newly observed advisories. |
| T8 | Trust-token mtime fallback removal | VULN-REFUTED | Low | Non-JSON token path returns `false` at `pre_tool_use.rs:166-175`; tests exist at `pre_tool_use.rs:727` and `validation_e2e.rs:344`. | Delete unreachable legacy log/allow branch. |
| T9 | Accepted residuals / Azure DNS rebind | NEW-FINDING | Medium | Azure host validation is string suffix only (`azure.rs:117-121`); there is no resolved-IP private/link-local recheck before `reqwest` sends. | Resolve and reject loopback/private/link-local targets after DNS, with explicit opt-in for local tests. |
| T10 | Multi-agent rationalisation traces | VULN-CONFIRMED | Medium | L0 shell escape coverage exists for some forms (`policy/tests.rs:1155`), but unknown/evasive forms fall to L1; if global config sets `default_decision=allow`, `pre_tool_use.rs:335-358`, `:381-405`, `:427-452`, and `:458-481` fail open on provider errors/timeouts. | Treat global `default_decision=allow` as privileged, loudly gated, or disallowed outside trusted configs. |
| T11 | Homebrew release gate / workflow posture | VULN-CONFIRMED | Medium | `release.yml:243-255` publishes to the tap with a PAT and no protected `environment`; CI has no explicit permissions. | Add environment approval and job-scoped permissions. |
| T12 | Ignored keychain tests | VULN-REFUTED | Low | `cargo test --workspace -- --ignored --list` lists 9 ignored tests; 8 are keychain tests in `credentials.rs:1137-1273`, 1 is `clx-mcp` credential-cycle. They compile under `cargo test --no-run`. | Add a scheduled/manual macOS job that runs ignored keychain tests explicitly. |

## Net-New Findings

1. `Bash(*)x` / `Bash(*)*` parser-gate mismatch: the overbroad detector returns false, while direct config-file rules match all Bash commands because `parse_pattern` ignores trailing text after `)`.
2. Additional unredacted LLM error sinks exist outside the Azure target files, especially transcript summarization, embeddings, and recall CLI output.
3. Current RustSec state is not the documented 5-warning set: `cargo audit --no-fetch` showed 8 allowed warnings, including `libyml` and `rand` advisories.
4. CI lacks explicit `permissions`, so least privilege is not asserted in code.

## Claims That No Longer Match Code

- `crates/clx-hook/src/audit_chain.rs:14-18` describes deletion breaking subsequent hashes, but production creates only one-record chains per hook process.
- `deny.toml:15-17` says the inert filter and hash-trust gate compensate for `serde_yml`; they do not compensate for parse-time memory unsafety at `project.rs:96`.
- `.github/workflows/ci.yml:7` says coverage fails below 70%, while `ci.yml:113-115` still says below 80%; the actual gate at `ci.yml:172-174` is 70%.
- The recon expectation of 9 skipped keychain tests is imprecise: I found 9 ignored tests total, 8 keychain tests plus 1 MCP credential-cycle test.

## Overall Release Recommendation

`NO-SHIP` for v0.8.2 until the following blockers are addressed:

1. Close the Azure/LLM redaction gaps at source and sinks.
2. Fix direct file-rule overbroad allow handling and parser trailing-junk acceptance.
3. Stop parsing untrusted project YAML with `serde_yml`/`libyml`, or isolate that parser from trusted control flow.
4. Correct the audit-chain claim by implementing persistent chaining or downgrading the guarantee.
5. Add explicit least-privilege workflow permissions and a protected Homebrew publish gate.

The code compiles cleanly, but the remaining issues affect the central security promises of CLX: command validation, secret/tenant redaction, forensic auditability, and supply-chain posture.

## What I Did Not Check

- I did not run the full test suite, only `--no-run` plus ignored-test listing.
- I did not fuzz YAML or redaction parsers.
- I did not contact Azure or any external service.
- I did not inspect GitHub repository settings, secrets, branch protections, or environments.
- I did not read the forbidden signoff/status files named in the task.
- I did not validate Homebrew tap contents outside this repository.

## Verdict Summary

- VULN-CONFIRMED: 8
- NEW-FINDING: 1
- VULN-REFUTED: 3
- NEEDS-INVESTIGATION: 0
