# CLX 0.8.0 Pre-Release Spec: Credentials and Configuration

Domain: credential backends, credential resolution, layered config, config-trust,
provider routing and fallback.

Branch verified: `feat/0.8.0-memory-skills-coverage` (HEAD `1b8515a`).
All claims cite `file:line` against that tree. Behavior is described from real
code, not from docs or intent.

---

## 1. Overview

### 1.1 Where things live

| Artifact | Path | Mode (Unix) | Source |
|---|---|---|---|
| CLX base dir | `~/.clx` | 0700 (forced) | `crates/clx-core/src/paths.rs:10`; backend ensure_dir `credentials/backend.rs:142-153` |
| Global config | `~/.clx/config.yaml` | (not enforced) | `config/mod.rs:1134`, `config/mod.rs:1203-1209` |
| Project config | `<repo>/.clx/config.yaml` | (not enforced) | `config/project.rs:30-64` |
| Encrypted credentials (DEFAULT) | `~/.clx/credentials.age` | 0600 | `credentials/backend.rs:129`, `:209-230` |
| Age identity keyfile | `~/.clx/cred.key` | 0600 | `credentials/backend.rs:130`, `:171-197` |
| Inter-process lock sidecar | `~/.clx/credentials.age.lock` | 0600 | `credentials/backend.rs:131`, `:340-374` |
| Config trustlist | `~/.clx/trusted_configs.json` | 0600 | `config/trust.rs:91-95`, `:138-176` |
| Logs dir | `~/.clx/logs` | (created) | `config/mod.rs:1131-1132` |

`~/.clx` resolves from `dirs::home_dir()` then `.join(".clx")`
(`paths.rs:10-14`). There is no `CLX_HOME` override; tests override `HOME`.

### 1.2 Credential resolution precedence (Azure provider key)

`resolve_azure_credential` (`config/mod.rs:1786-1833`), in strict order:

1. **Env var** named in `providers.<name>.api_key_env`, if set and non-empty
   (`config/mod.rs:1794-1799`). Zero prompts.
2. **Selected credential backend**, key `"<provider_name>-api-key"`
   (`config/mod.rs:1802-1803`). Default backend is the age file; keychain is
   reached here ONLY if the user opted in. On `Ok(None)` it falls through; on
   backend `Err` it logs a WARN and falls through (it never silently retries a
   different store) (`config/mod.rs:1804-1818`).
3. **`providers.<name>.api_key_file`** (Unix: file must be mode 0600)
   (`config/mod.rs:1821-1823`, reader `:1842-1861`).
4. **Hard error** with an actionable message naming the backend, the exact
   key, and the `clx credentials set` / `clx credentials migrate` remedy
   (`config/mod.rs:1825-1832`).

Keychain is NEVER step 2 under the default (`file`) backend. Proven by unit
tests `default_backend_store_and_index_never_touch_keychain`
(`credentials.rs:1645`) and `resolve_order_file_backend_serves_before_api_key_file`
(`credentials.rs:1803-1815`).

### 1.3 Backend model

`CredentialBackend` trait (`credentials/backend.rs:39-50`): `get` (Ok(None)
for missing, never error, never fall back to another store), `set`, `delete`
(idempotent), `list_keys`, `label`.

- **AgeFileBackend** (DEFAULT, `serde` default of `CredentialBackendKind::File`,
  `credentials.rs:148-157`): age v1 (X25519 + ChaCha20-Poly1305) encrypted file.
  Pure local file IO. NEVER prompts. Identical on every OS.
- **KeyringBackend** (OPT-IN only, `credentials/backend.rs:443-542`): the
  system keychain. Constructed only when `credentials.backend: keychain` or
  `CLX_CREDENTIALS_BACKEND=keychain`.

Scoping, key validation, the legacy JSON index, the session cache, and the
relaxed-ACL notice all live ABOVE the trait and are backend-agnostic
(`credentials/backend.rs:3-7`, `credentials.rs:101-123`).

### 1.4 Layered config model

`Config::load` (`config/mod.rs:1124-1184`) builds a Figment with:

- Layer 1 (lowest): global `~/.clx/config.yaml` if it is a file
  (`config/mod.rs:1138-1141`).
- Layer 2: project `<repo>/.clx/config.yaml`, read raw then passed through
  `apply_project_layer` (trust-gated inert filter) before merge
  (`config/mod.rs:1143-1162`).
- Layer 3 (highest): `Env::prefixed("CLX_")` figment provider, additive safety
  net only (`config/mod.rs:1164-1170`).

After extraction: `translate_legacy_in_place` converts a legacy `ollama:`
block into `providers:`+`llm:` in memory (`config/mod.rs:1176-1177`,
`:1633-1665`); then `apply_env_overrides` applies the authoritative,
range-validated env-var logic (`config/mod.rs:1179-1181`, `:1238+`).
Effective precedence: validated env override > project (trust/inert filtered)
> global > struct defaults.

---

## 2. Feature / config inventory (REAL defaults)

### 2.1 Credentials and provider sections

| Section.key | Env var | Default | file:line |
|---|---|---|---|
| `credentials.backend` | `CLX_CREDENTIALS_BACKEND` | `file` | struct `config/mod.rs:276-281`; default `:283-291`; env resolve `:300-310`; enum default `credentials.rs:148-157` |
| `providers.<name>` (map) | (none) | empty `BTreeMap` | `config/mod.rs:217-219`, `:1080-1085` |
| `providers.<name>` Ollama: `host` | `CLX_OLLAMA_HOST` (legacy block only) | `http://127.0.0.1:11434` | `config/mod.rs:651-652`, default `:812-814` |
| Ollama `model` | `CLX_OLLAMA_MODEL` | `qwen3:1.7b` | `config/mod.rs:655-656`, `:817-819` |
| Ollama `embedding_model` | `CLX_OLLAMA_EMBEDDING_MODEL` | `qwen3-embedding:0.6b` | `config/mod.rs:659-660`, `:804-806` |
| Ollama `embedding_dim` | `CLX_EMBEDDING_DIM` | `1024` | `config/mod.rs:663-664`, `:808-810` |
| Ollama `timeout_ms` | `CLX_OLLAMA_TIMEOUT_MS` | `60000` | `config/mod.rs:667-668`, `:821-823` |
| Ollama `max_retries` | (none) | `3` | `config/mod.rs:671-672`, `:825-827` |
| Ollama `retry_delay_ms` | (none) | `100` | `config/mod.rs:675-676`, `:829-831` |
| Ollama `retry_backoff` | (none) | `2.0` | `config/mod.rs:679-680`, `:833-835` |
| Azure `endpoint` | (none) | required (no default) | `config/mod.rs:1038-1040` |
| Azure `api_key_env` | (none) | `None` | `config/mod.rs:1042-1043` |
| Azure `api_key_file` | (none) | `None` | `config/mod.rs:1045-1046` |
| Azure `api_version` | (none) | `None` (=> `/openai/v1/...`) | `config/mod.rs:1048-1049`; URL shape `llm/azure.rs:76-110` |
| Azure `timeout_ms` | (none) | `30000` | `config/mod.rs:1051-1052`, `:1058-1060` |
| Azure `retry` | (none) | `RetryConfig::default()` | `config/mod.rs:1054-1055` |
| `llm.chat` route | (none) | `None` until set/legacy-translated | `config/mod.rs:222-223`, `:1089-1108` |
| `llm.embeddings` route | (none) | `None` until set/legacy-translated | `config/mod.rs:1091` |
| `<route>.fallback` | (none) | `None` | `config/mod.rs:1106-1108` |
| Azure host allowlist | `CLX_ALLOW_AZURE_HOSTS` | empty (all non-allowlisted hosts rejected) | `llm/azure.rs:54-72` |

### 2.2 Retention / logging / other sections (defaults)

| Section.key | Env var | Default | file:line |
|---|---|---|---|
| `retention.tool_events_days` | (none) | `30` | `config/mod.rs:338-339`, `:350-352` |
| `retention.events_days` | (none) | `7` | `config/mod.rs:342-343`, `:353-355` |
| `retention.snapshots_days` | (none) | `0` (keep forever) | `config/mod.rs:346-347`, `:362` |
| `logging.level` | `CLX_LOGGING_LEVEL` | `info` | `config/mod.rs:703-704`, `:845-847` |
| `logging.file` | `CLX_LOGGING_FILE` | `~/.clx/logs/clx.log` | `config/mod.rs:707-708`, `:849-851` |
| `logging.max_size_mb` | `CLX_LOGGING_MAX_SIZE_MB` | `10` | `config/mod.rs:711-712`, `:853-855` |
| `logging.max_files` | `CLX_LOGGING_MAX_FILES` | `5` | `config/mod.rs:715-716`, `:857-859` |
| `validator.enabled` | `CLX_VALIDATOR_ENABLED` | `true` | `config/mod.rs:580-581`, `:779-781`, env `:1240-1242` |
| `validator.layer1_timeout_ms` | `CLX_VALIDATOR_LAYER1_TIMEOUT_MS` | `30000` | `config/mod.rs:588-589`, `:783-785` |

(Other non-credential sections exist; out of scope for this domain.)

---

## 3. Behavior spec

### 3.1 Credential resolution order (Azure key)

**Normal:** env var present and non-empty wins immediately, zero prompts,
backend never touched (`config/mod.rs:1794-1799`).

**Edge - env set but empty:** `!v.is_empty()` guard fails so the empty value
is skipped; resolution proceeds to the backend (`config/mod.rs:1796`).

**Normal - backend hit:** with the default file backend, `store.get(key)`
returns `Ok(Some(v))` from `~/.clx/credentials.age` and resolution returns it.
The keychain is never constructed (`config/mod.rs:1802-1805`).

**Edge - backend miss:** `Ok(None)` falls through to `api_key_file`; it does
NOT fall to the keychain (`config/mod.rs:1806`).

**Failure - backend IO error:** logged at WARN
(`credential backend unavailable, falling back to api_key_file`) then falls
through to `api_key_file` (`config/mod.rs:1807-1818`). It never retries a
different store.

**Failure - nothing anywhere:** actionable error string naming env, the
labeled backend, the literal key `<provider>-api-key`, and the remedy
commands (`config/mod.rs:1825-1832`).

**Keychain never reached under default:** the only `KeyringBackend`
construction sites are `with_kind(Keychain, ...)` (`credentials.rs:199`),
`with_service*` (`:242`, `:276`), and the explicit
`from_config(CredentialBackendKind::Keychain)` in `migrate`
(`commands/credentials.rs:209`) and `keychain-trust`
(`commands/keychain_trust.rs:36-37`). `resolve_azure_credential` calls
`from_config(backend_kind)` where `backend_kind` is the user's selection
(`config/mod.rs:1802`, `:1742-1745`). Default `backend_kind` is `File`
(`config/mod.rs:300-310`, `credentials.rs:148-157`). Regression test
`default_backend_store_and_index_never_touch_keychain` asserts a `KeychainSpy`
counter stays zero across store/get/list/delete (`credentials.rs:1645`,
spy `:819-881`).

### 3.2 AgeFileBackend (default)

**Locations / modes:** `credentials.age` and `cred.key` written 0600 via
`write_private` (`backend.rs:209-230`); `~/.clx` forced 0700 by `ensure_dir`
(`backend.rs:142-153`). Lock sidecar opened 0600 (`backend.rs:344-351`).

**Encryption at rest:** map serialized JSON, age-encrypted with the X25519
recipient derived from `cred.key`; ciphertext is NOT plaintext
(`backend.rs:293-326`; test `age_backend_blob_is_ciphertext_not_plaintext`
`credentials.rs:1351`).

**Identity generation:** first use generates a random X25519 identity,
written to a unique temp then published via `hard_link` + unlink so racing
first-runs converge (loser adopts the winner's keyfile)
(`backend.rs:158-197`, `:235-243`). No machine-id-derived material
(`backend.rs:62`).

**Atomic write:** every `set`/`delete` re-encrypts the whole map, writes a
unique temp file (`.<stem>.<pid>.<nanos>.tmp`), `fsync`s, then `fs::rename`
over the destination on the same filesystem; temp removed on rename failure
(`backend.rs:199-206`, `:292-326`). Test
`age_backend_concurrent_set_does_not_corrupt` (`credentials.rs:1381`).

**Zero-byte / corrupt-file behavior:**
- File ABSENT => legitimate empty store, `Ok(BTreeMap::new())`, zero prompts
  (`backend.rs:262-264`; test `age_backend_keyfile_present_but_blob_absent_is_empty`
  `credentials.rs:1581`).
- File present, ZERO bytes => treated as CORRUPTION, returns an actionable
  `Storage` error, does NOT overwrite (would otherwise destroy credentials).
  Recovery requires the user to delete the empty file deliberately
  (`backend.rs:267-278`; test `ss2_zero_byte_blob_is_corruption_not_empty_and_no_wipe`
  `credentials.rs:1505`).
- File present, non-zero garbage => age decoder errors with a
  `corrupt credentials.age?` context (`backend.rs:279-283`; test
  `ss2_nonzero_garbage_blob_still_errors` `credentials.rs:1564`).
- Missing/wrong keyfile => decrypt fails `wrong/lost keyfile?`
  (`backend.rs:282-283`; test `age_backend_decrypt_fails_without_keyfile`
  `credentials.rs:1366`).

**Inter-process lock + bounded wait:** the full read-modify-write is wrapped
by an in-process `Mutex` then an advisory exclusive `flock` on the dedicated
`credentials.age.lock` sidecar (never the renamed data file)
(`backend.rs:328-395`). Poll every 25 ms (`LOCK_POLL_INTERVAL`,
`backend.rs:101`) up to a 10 s deadline (`LOCK_TIMEOUT`, `backend.rs:98`); on
timeout it returns a `Storage` error stating it aborts WITHOUT writing so no
credential is lost (`backend.rs:357-366`). RAII guard unlocks on every exit
path including panic; kernel releases on process death (`backend.rs:103-117`).

**Concurrent writers keep distinct keys:** the lock serializes the entire RMW
so two hook processes cannot read the same snapshot and drop each other's
write. Tests `age_backend_concurrent_set_does_not_corrupt`
(`credentials.rs:1381`) and `ss1_concurrent_independent_instances_lose_no_writes`
(`credentials.rs:1419`).

**List derived from backend:** for the age-file backend `list_scoped` returns
keys derived from `backend.list_keys()` (the single source of truth), filtered
by scoped prefix, de-scoped, sorted, deduped; the separate JSON index is no
longer authoritative there because it is maintained outside the locked RMW and
can drop entries under concurrency (`credentials.rs:529-562`; test
`list_derived_from_backend_loses_no_entries_under_concurrent_stores`
`credentials.rs:1709`).

### 3.3 KeyringBackend (opt-in)

**Opt in:** set `credentials.backend: keychain` in config, or
`CLX_CREDENTIALS_BACKEND=keychain` (env wins; unknown value is a hard error,
never a silent fallback) (`config/mod.rs:300-310`,
`credentials.rs:159-171`). Test `keychain_kind_selects_keychain_backend`
(`credentials.rs:1613`).

**Behavior:** `get` maps `NoEntry` to `Ok(None)`; `set` writes then calls
`relax_item_access` (macOS only) and the store layer emits a one-time
relaxed-ACL stderr+info notice; `delete` is idempotent; `list_keys` returns
empty (no portable enumeration), so `list_scoped` uses the JSON index for the
keychain backend (`credentials/backend.rs:503-542`,
`credentials.rs:529-535`, notice `credentials.rs:677-699`).

**Adhoc-binary caveat (honest):** no macOS keychain API serves an
unsigned/adhoc-signed binary prompt-free. The data-protection keychain
rejects unsigned binaries (`errSecMissingEntitlement -34018`); the legacy
keychain prompts on every read and "Always Allow" never persists for an
adhoc cdhash. This is why the keychain CANNOT be the default
(`credentials/backend.rs:9-19`). The opt-in path mitigates with a
creation-time permissive `SecAccess` (`keychain_acl.rs`), but it remains
best-effort for adhoc binaries.

**`clx keychain-trust`:** repairs pre-0.8.0 items with a SINGLE
`/usr/bin/security set-generic-password-partition-list` call that relaxes
EVERY CLX item at once (`commands/keychain_trust.rs:24-101`,
`keychain_acl.rs:159-185`, `:480+`). It prints a one-prompt heads-up
(human output only, never on `--json`) (`keychain_trust.rs:42-45`). When no
CLX items exist it short-circuits with zero prompts and prints "no password
prompt needed" (`keychain_trust.rs:79-84`,
`credentials.rs:719-733`). Non-macOS: `KeychainTrustReport { macos:false }`,
prints a no-op message, exits 0 (`keychain_acl.rs:186-208`,
`keychain_trust.rs:51-66`).

**`clx credentials migrate <key>`:** if the key is already resolvable in the
configured (file) backend it does NOT read the keychain
(`commands/credentials.rs:181-204`). Otherwise it does ONE explicit opt-in
keychain read (the only place a single macOS prompt may appear), writes the
value into the file backend, and reports success; `Ok(None)` => error telling
the user to `clx credentials set`; `Err` => surfaced
(`commands/credentials.rs:206-244`).

### 3.4 `clx credentials` set/get/list/delete and the MCP tool

CLI handler loads config to pick the backend (default `file`), never touching
the keychain (`commands/credentials.rs:56-63`):

- **set**: `store.store(key, value)`; success line / JSON `{action:set,
  success:true}` (`commands/credentials.rs:66-87`).
- **get**: prints only the value for piping; `Ok(None)` => bail
  `Credential '<key>' not found` (or JSON `value:null,error`); `Err` => bail
  (`commands/credentials.rs:89-133`).
- **list**: keys from `store.list()`; annotates a key as `(ollama)` /
  `(azure_openai)` only when it ends with `:api-key` AND that provider name is
  in config (`commands/credentials.rs:135-179`).
- **delete**: idempotent; success line / JSON (`commands/credentials.rs:247-266`).

**Scoping:** global keys are `clx:global:<key>`; project keys are
`clx:project:<project>:<key>` (`credentials.rs:47-50`, `:621-626`).
`get_with_fallback` tries project then global (`credentials.rs:449-459`).
Key validation: non-empty, no NUL, <=255 chars, charset
`[A-Za-z0-9_.-]`, no `..` (`credentials.rs:580-618`).

**`clx_credentials` MCP tool** (`clx-mcp/src/tools/credentials.rs:14-144`):
actions `get|set|delete|list`. `key` <= `MAX_KEY_LEN`, `value` <=
`MAX_CONTENT_LEN`, optional `project` (`:17-67`). `get` ALWAYS masks the
value: >6 chars => `abc...xyz (N chars)`, else `**** (N chars)`
(`:38-50`, mask fn `:151-160`). `set` returns a note recommending the
terminal `clx credentials set` because MCP values appear in the transcript
(`:78-85`). The store is the cached store
(`config.credential_store_cached`, `config/mod.rs:323-327`).

### 3.5 Provider config, capability routing, fallback

`ProviderConfig` is a `kind:`-tagged enum: `ollama` | `azure_openai`
(`config/mod.rs:1080-1085`). `LlmRouting` has `chat` and `embeddings`
`CapabilityRoute`s, each `{provider, model, fallback?}`
(`config/mod.rs:1088-1108`).

`create_llm_client(capability)` resolves the route, builds the primary
client, and if `fallback` is set wraps both in a `FallbackClient` with the
fallback's own model substituted (`config/mod.rs:1695-1708`).

`build_client_for_provider`: Ollama => `OllamaBackend`; Azure => resolve
`credential_backend_kind()` then `resolve_azure_credential` then
`AzureOpenAIBackend` (`config/mod.rs:1726-1752`). So the chat path and the
embeddings path each resolve the key for THEIR provider via §3.1; Ollama
needs no credential.

**Azure URL shape:** `api_version` unset => `/openai/v1/{chat completions |
embeddings | models}`; set => dated deployment shape
`/openai/deployments/<deployment>/...?api-version=<v>`
(`llm/azure.rs:76-110`; tests `dated_url_shape_when_api_version_set`
`azure.rs:557`, `v1_url_shape_when_api_version_unset` `azure.rs:586`).
Azure host must be in `CLX_ALLOW_AZURE_HOSTS` or the backend rejects it
(`llm/azure.rs:54-72`).

**Fallback + 30 s cooldown** (`llm/fallback.rs`): on a TRANSIENT primary
error the wrapper logs a WARN `primary failed; falling back`, records the
failure instant, and delegates to the fallback (with the fallback's model)
(`fallback.rs:75-89`, `:91-110`). A non-transient error is returned as-is, no
fallback (`fallback.rs:87`; test `fallback_not_used_on_terminal_error`
`:189-212`). For 30 s after a failure (`COOLDOWN`, `fallback.rs:14`) the
primary is skipped entirely (`use_fallback_directly`, `:40-49`, `:71-74`;
test `cooldown_skips_primary_after_failure` `:214-242`). Cooldown is
in-process only (a `Mutex<Option<Instant>>`), not persisted.

### 3.6 Config layering and the project inert-key gate

Project config discovery: `CLX_CONFIG_PROJECT` (empty/`none`/`off` disables;
otherwise an explicit path), else walk up from CWD for `.clx/config.yaml`,
bounded by `$HOME` (the parent of `config_dir()`); if CWD is not under that
boundary, discovery is skipped entirely (`config/project.rs:30-64`,
`config/mod.rs:1149-1151`).

Non-inert key patterns (dropped from untrusted project configs):
`providers` (drops the entire `providers:` block), `logging.file`,
`validator.enabled` (`config/project.rs:75-79`). A path matches if it equals
or is prefixed by a pattern (`config/project.rs:167-171`). Each dropped key
logs one WARN (`config/project.rs:151-158`). Invalid YAML => empty string =>
the project layer is a no-op and the global layer wins
(`config/project.rs:85-92`).

`apply_project_layer`: compute `sha256:<hex>` of the raw file
(`config/trust.rs:248-251`); if the trustlist contains that exact hash, the
raw YAML is honored (non-inert keys take effect); otherwise
`filter_inert_only` strips them. Trustlist load error => log WARN, fail
closed to the inert filter; missing trustlist => empty list => filtered
(`config/project.rs:108-135`). Tests
`trusted_hash_returns_raw_config_with_providers` (`project.rs:252`),
`untrusted_hash_applies_inert_filter` (`:269`),
`edit_after_trust_invalidates_match` (`:284`),
`missing_trustlist_file_falls_back_to_filter` (`:306`).

Precedence (effective): validated env override (`apply_env_overrides`,
`config/mod.rs:1238+`) > project layer (after trust/inert filter) > global
`~/.clx/config.yaml` > struct serde defaults. The figment `Env::prefixed`
layer is an additive safety net; `apply_env_overrides` is authoritative for
range-checked vars (`config/mod.rs:1164-1181`).

### 3.7 config-trust (file-hash trustlist)

`~/.clx/trusted_configs.json`, schema version 1, written atomically
(temp + 0600 + rename), missing file => empty list, malformed JSON =>
error (refuses silent reset), unsupported version => error
(`config/trust.rs:42-176`). `is_trusted` requires an EXACT hash match;
truncated/prefix hashes are not trusted (`config/trust.rs:178-182`; test
`is_trusted_requires_exact_match` `:369`). Per-machine, per-user,
per-file-hash; never committed, never propagates via git
(`config/trust.rs:6-21`).

CLI (`clx config-trust`, `commands/trust.rs:300-468`):
- **add `<path>` [-y]**: canonicalize path, read contents, compute hash; if
  already trusted, report and exit; else (unless `-y`/`--json`) print an
  interactive confirmation explaining the non-inert grant and the
  edit-invalidates-trust property, then add + save
  (`trust.rs:332-405`).
- **list**: table or JSON of `short_hash`, `added_at`, `path`, plus the
  trustlist path (`trust.rs:407-447`).
- **remove `<hash>`**: full hash or unambiguous prefix (>=6 chars);
  ambiguous prefix => error; no match => `not_found`
  (`trust.rs:449-468`, `config/trust.rs:202-224`).

Hash invalidation on edit: any byte change changes the SHA-256, so a
previously trusted file falls back to the inert filter automatically
(`config/trust.rs:13-16`, `:248-251`; test
`compute_file_hash_changes_on_edit` `:273`,
`edit_after_trust_invalidates_match` `project.rs:284`).

### 3.8 Retention and logging behavior

`RetentionConfig`: a `0` for any field disables trimming for that table;
positive = retention window in days; consumed by `clx maintenance trim`
(`config/mod.rs:330-365`). Defaults: tool_events 30, events 7, snapshots 0
(keep forever).

`LoggingConfig`: `file` supports `~/` expansion via `expand_tilde` =>
`log_file_path()` (`config/mod.rs:1212-1227`). Defaults: level `info`, file
`~/.clx/logs/clx.log`, max_size 10 MB, max_files 5
(`config/mod.rs:845-859`). `logging.file` is non-inert: a project config
cannot redirect the log path unless its hash is trusted
(`config/project.rs:75-79`).

---

## 4. Edge / failure matrix

| # | Scenario | Expected behavior | file:line |
|---|---|---|---|
| E1 | No credential anywhere (Azure) | Hard error naming env, labeled backend, key `<p>-api-key`, remedy commands | `config/mod.rs:1825-1832` |
| E2 | `api_key_env` set but empty string | Empty value skipped, resolution continues to backend | `config/mod.rs:1796` |
| E3 | `api_key_file` wrong mode (not 0600) | Refuses to read: `file mode ... is <m>; refusing to read (must be 0600)` | `config/mod.rs:1842-1853` |
| E4 | `credentials.age` zero bytes | `Storage` corruption error, file NOT overwritten, manual delete required | `backend.rs:267-278`; test `credentials.rs:1505` |
| E5 | `credentials.age` non-zero garbage | age decoder error `corrupt credentials.age?` | `backend.rs:279-283`; test `credentials.rs:1564` |
| E6 | `credentials.age` absent (fresh install) | Empty store, zero prompts | `backend.rs:262-264`; test `credentials.rs:1581` |
| E7 | Lost / wrong `cred.key` | decrypt error `wrong/lost keyfile?` | `backend.rs:282-283`; test `credentials.rs:1366` |
| E8 | Lock held > 10 s by another process | `Storage` error, aborts WITHOUT writing, advises retry | `backend.rs:357-366` |
| E9 | Concurrent writers, distinct keys | No lost writes (locked RMW + backend-derived list) | tests `credentials.rs:1419`, `:1709` |
| E10 | Untrusted project config with `providers:` | `providers:` block dropped, WARN per key, global/default providers used | `config/project.rs:75-79`, `:151-158`; test `project.rs:269` |
| E11 | Trusted project config (hash matches) | Raw YAML honored, non-inert keys take effect | `config/project.rs:119-126`; test `project.rs:252` |
| E12 | Trusted file then edited | Hash mismatch => inert filter reapplied, edits do not bypass | test `project.rs:284` |
| E13 | `backend=keychain` on non-macOS | KeyringBackend used (Secret Service / Cred Mgr); keychain-trust is a no-op exit 0 | `keychain_acl.rs:186-208`, `keychain_trust.rs:51-66` |
| E14 | `migrate` when keychain has nothing | Error: nothing to migrate, advises `clx credentials set` | `commands/credentials.rs:234-240` |
| E15 | `migrate` when key already in file backend | No keychain read; reports "already in <backend>" | `commands/credentials.rs:181-204` |
| E16 | Azure primary transient down | WARN `primary failed; falling back`, fallback used, 30 s cooldown | `fallback.rs:75-89`; test `:214-242` |
| E17 | Azure primary terminal (401) | Error returned, fallback NOT used | `fallback.rs:87`; test `:189-212` |
| E18 | Malformed global `config.yaml` | `Config::load` => `Error::Config("figment merge failed: ...")` | `config/mod.rs:1172-1174` |
| E19 | Malformed project `config.yaml` | `filter_inert_only` returns "", project layer is a no-op, global wins | `config/project.rs:85-92` |
| E20 | `CLX_CREDENTIALS_BACKEND=bogus` | Hard `Error::Config` (`unknown credentials backend ...`), never silent file/keychain | `config/mod.rs:303-308`, `credentials.rs:162-169` |
| E21 | Malformed `trusted_configs.json` | Load error (refuses silent reset); `apply_project_layer` logs WARN, fails closed to inert filter | `config/trust.rs:106-128`, `config/project.rs:109-118` |

---

## 5. Verification steps (copy-pasteable)

Use a throwaway `HOME` so production credentials are untouched.

### 5.1 Default backend never prompts; set/list/get/delete

```bash
export HOME=$(mktemp -d)
cd /Users/blackax/Projects/clx
cargo run -q -p clx -- credentials set azure-prod-api-key 'sk-test-123456'
cargo run -q -p clx -- credentials list          # shows azure-prod-api-key
cargo run -q -p clx -- credentials get azure-prod-api-key   # prints sk-test-123456
file "$HOME/.clx/credentials.age"                # age encrypted, not JSON
stat -f '%Sp' "$HOME/.clx/credentials.age"       # -rw------- (0600)
stat -f '%Sp' "$HOME/.clx"                       # drwx------ (0700)
cargo run -q -p clx -- credentials delete azure-prod-api-key
# Observe: zero macOS keychain dialogs at any point.
```

### 5.2 Opt into keychain and verify selection

```bash
export CLX_CREDENTIALS_BACKEND=keychain
cargo run -q -p clx -- credentials list   # now uses KeyringBackend (macOS may prompt)
unset CLX_CREDENTIALS_BACKEND
# Negative: a typo must hard-fail, never silently use file:
CLX_CREDENTIALS_BACKEND=bogus cargo run -q -p clx -- credentials list  # exits with Config error
```

### 5.3 Config layering + config-trust

```bash
export HOME=$(mktemp -d)
mkdir -p "$HOME/work/.clx" && cd "$HOME/work"
cat > .clx/config.yaml <<'YAML'
logging:
  level: debug
  file: /tmp/exfil.log
providers:
  rogue:
    kind: azure_openai
    endpoint: https://evil.example.com
YAML
# Untrusted: providers + logging.file dropped, logging.level kept (check WARN logs).
cargo run -q -p clx -- config-trust list      # empty
cargo run -q -p clx -- config-trust add "$HOME/work/.clx/config.yaml" -y
cargo run -q -p clx -- config-trust list      # one entry, sha256:...
# Now the raw YAML (incl. providers/logging.file) is honored.
# Edit the file (add a space) -> hash changes -> inert filter reapplies.
cargo run -q -p clx -- config-trust remove sha256:<prefix>
```

### 5.4 Provider fallback (broken primary -> WARN -> fallback)

Drive the unit tests that mock a 503 primary and assert the fallback fires
plus the 30 s cooldown sticks:

```bash
cargo test -p clx-core --lib llm::fallback
# fallback_on_primary_503_succeeds, fallback_not_used_on_terminal_error,
# cooldown_skips_primary_after_failure
```

### 5.5 Automated test suites to run before tagging

```bash
cargo test -p clx-core --lib credentials          # backend, cache, corruption, lock, resolution
cargo test -p clx-core --lib config::project      # inert filter + trust gate
cargo test -p clx-core --lib config::trust        # trustlist hash/version/atomic save
cargo test -p clx-core --lib llm::azure           # URL shape, host allowlist, transient classify
cargo test -p clx-core --lib llm::fallback        # primary->fallback + cooldown
cargo test -p clx-core --lib config               # defaults, env overrides, yaml roundtrip
```

Key behavior-anchor tests: `default_backend_store_and_index_never_touch_keychain`
(`credentials.rs:1645`), `resolve_order_file_backend_serves_before_api_key_file`
(`:1803`), `ss2_zero_byte_blob_is_corruption_not_empty_and_no_wipe` (`:1505`),
`ss1_concurrent_independent_instances_lose_no_writes` (`:1419`),
`list_derived_from_backend_loses_no_entries_under_concurrent_stores` (`:1709`),
`keychain_kind_selects_keychain_backend` (`:1613`),
`backend_kind_parses_and_defaults` (`:1594`).

---

## 6. Known limitations / out of scope for 0.8.0

- **Developer-ID signing is a separate-repo concern.** CLX ships
  adhoc/unsigned via Homebrew; no macOS keychain API serves an adhoc binary
  prompt-free (`credentials/backend.rs:9-19`). The file backend is the
  default precisely to avoid this. Signing/notarization is NOT in this repo
  or this release.
- **Opt-in keychain remains best-effort for adhoc binaries.** Creation-time
  `SecAccess` and `clx keychain-trust` reduce re-prompting but cannot fully
  eliminate it for an unsigned cdhash. This is documented honestly to the
  user via the one-time relaxed-ACL notice (`credentials.rs:677-699`) and the
  trust-tradeoff notice (`commands/keychain_trust.rs:86-97`).
- **Session read cache is process-scoped only** (`Arc<Mutex<...>>`, zeroized
  on drop, never persisted) (`credentials.rs:89-99`, `:248-269`); a fresh
  process re-reads the backend.
- **Fallback cooldown is in-process only**; it does not persist across hook
  invocations (each hook is a new process) (`llm/fallback.rs:24-26`).

---

## RISKS / SUSPECTED GAPS

1. **`credentials list` annotation suffix mismatch (likely bug).** The
   resolver and `clx credentials set`/`migrate` use the key form
   `"<provider>-api-key"` (HYPHEN) (`config/mod.rs:1803`, `:1828`;
   `commands/credentials.rs:50`). But the list annotation strips the suffix
   `":api-key"` (COLON) before looking the provider up
   (`commands/credentials.rs:159-160`). A real Azure key stored as
   `azure-prod-api-key` will therefore never receive the `(azure_openai)`
   annotation. Cosmetic only (does not affect resolution) but the annotation
   feature is effectively dead for the canonical key naming. Note also
   `validate_key` rejects colons in user keys (`credentials.rs:600-608`), so
   a `:api-key` key cannot even be stored, making the colon-suffix branch
   unreachable for normal credentials.

2. **Figment env layer vs `apply_env_overrides` double-application.**
   `Config::load` merges `Env::prefixed("CLX_")` into figment
   (`config/mod.rs:1170`) AND then runs `apply_env_overrides`
   (`:1181`). For flat top-level keys the figment layer may set a raw value
   that the validated override then re-validates; for out-of-range values the
   validated path keeps the default while figment may have already coerced a
   parseable-but-unintended value into a different field. Comments call the
   figment layer an "additive safety net" but the precedence interaction is
   not asserted by a test for conflicting values. Recommend a QA test that
   sets, e.g., `CLX_VALIDATOR_LAYER1_TIMEOUT_MS=99999999` and asserts the
   final value is the validated default, not the figment-merged raw value
   (`config/mod.rs:1164-1181`, `:1250-1258`).

3. **`api_key_file` plaintext + 0600 race.** `read_file_credential` checks
   mode then reads in two syscalls (TOCTOU) and logs a WARN that the key is
   in plaintext (`config/mod.rs:1842-1860`). Low severity (local file, same
   user) but worth noting for the threat model: the mode is enforced, not the
   ownership.

4. **`load_from_file_only` skips the project layer and trust gate.** The
   dashboard Settings path uses raw `serde_yml::from_str` of the GLOBAL file
   only (`config/mod.rs:1190-1200`); it does not apply the inert filter or
   env overrides. This is intentional (raw editing view) but means the
   dashboard can display/round-trip a config that differs from the effective
   runtime config. Confirm QA does not treat the Settings tab as the source
   of truth for effective behavior.

5. **`AgeFileBackend::get`/`list_keys` take NO inter-process lock.** Only the
   write path (`with_map`) acquires the sidecar lock (`backend.rs:376-395`);
   `get`/`list_keys` call `load_map` directly (`backend.rs:399-423`). Because
   writes are atomic rename, a concurrent reader sees either the old or new
   complete file (never a partial), so this is believed safe. Flagged for
   explicit QA acknowledgement: there is no test asserting a read concurrent
   with a rename never observes a transient `NotFound`/zero-byte if a reader
   opens the path between unlink and rename completion. The rename is atomic
   on the same filesystem so the window should not exist, but it is
   unverified by an automated test.

6. **`CLX_CONFIG_PROJECT` accepts an arbitrary absolute path with no inert
   filter exemption.** An attacker controlling the environment can point CLX
   at any `config.yaml`; that file still goes through `apply_project_layer`
   so non-inert keys are filtered unless trusted (`config/project.rs:31-36`,
   `config/mod.rs:1150-1162`). Behavior is safe but the env-var override of
   project discovery is a powerful knob worth calling out in the threat
   model (env-controlled config source selection).
