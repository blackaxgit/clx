//! Per-project config discovery and inert-keys allowlist filter.

use std::path::PathBuf;

/// Discover the project config path, if any.
///
/// Order:
///   1. `CLX_CONFIG_PROJECT` env var (empty/`none`/`off` disables).
///   2. Walk up from CWD looking for `.clx/config.yaml`, stopping at `stop_at`
///      (the global CLX config directory parent — i.e. `$HOME`), or at the
///      filesystem root if `stop_at` is not reachable.
///
/// `stop_at` should be `dirs::home_dir()`. It is passed in rather than
/// resolved inside this function so that `Config::load()` can supply the same
/// home that it uses for the global config file, ensuring the two are always
/// consistent even when `HOME` is overridden to a temp path during tests.
/// Convenience wrapper that uses `dirs::home_dir()` as the stop boundary.
/// Prefer `project_config_path_with_stop` in `Config::load()` so the stop
/// boundary is always derived from the same source as `config_dir()`.
///
/// This function is provided for potential future external use; internally
/// `Config::load()` calls `project_config_path_with_stop` directly.
#[allow(dead_code)]
pub fn project_config_path() -> Option<PathBuf> {
    project_config_path_with_stop(dirs::home_dir().as_deref())
}

/// Inner implementation that accepts an explicit stop boundary.
/// Exposed for testing; production code should call `project_config_path()`.
pub(crate) fn project_config_path_with_stop(stop_at: Option<&std::path::Path>) -> Option<PathBuf> {
    if let Ok(s) = std::env::var("CLX_CONFIG_PROJECT") {
        return match s.as_str() {
            "" | "none" | "off" => None,
            path => Some(PathBuf::from(path)),
        };
    }
    let mut dir = std::env::current_dir().ok()?;

    // Only search within the home tree. If CWD is not under `stop_at`, the
    // walk-up would cross into directories that belong to a different user or
    // a different config domain (e.g. the test CWD is the workspace root while
    // HOME is a temp dir). Skip discovery entirely in that case.
    if let Some(home) = stop_at
        && !dir.starts_with(home)
    {
        return None;
    }

    loop {
        // Stop before checking the stop directory itself — the global config
        // already covers that directory, so any `.clx/config.yaml` found there
        // is the global config, not a project config.
        if stop_at == Some(dir.as_path()) {
            return None;
        }
        let candidate = dir.join(".clx").join("config.yaml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Security-sensitive key subtrees that an UNTRUSTED project config may
/// never contribute (B4-1). Honoring any of these would let a hostile
/// cloned repo redirect credentials/endpoints, exfiltrate logs, or — the
/// critical case — neuter the command validator with zero user
/// interaction. A path matches if it equals a pattern or is nested under
/// it (`pat` or `pat.`), so naming a whole subtree drops everything below
/// it.
///
/// `validator` and `user_learning` are dropped *in their entirety* (not
/// just `validator.enabled`): the recon confirmed a hostile repo could
/// otherwise still set `validator.layer1_enabled:false`,
/// `validator.default_decision:allow`, `validator.auto_allow_reads:true`,
/// `validator.prompt_sensitivity:low`, `validator.trust_mode:true`
/// (B4-2), `validator.layer1_timeout_ms:1` (R1-NEW-2), or
/// `user_learning.auto_whitelist_threshold:1` — every one a validator
/// bypass. A project repo has no legitimate need to influence security
/// policy; only the global `~/.clx/config.yaml` or a hash-trusted
/// project config (see `apply_project_layer`) may.
const NON_INERT_KEY_PATTERNS: &[&str] = &[
    "providers",     // entire providers.* (no credential/endpoint redirection)
    "logging.file",  // no log exfiltration to an attacker-chosen path
    "validator",     // entire validator.* — security policy, never repo-settable
    "user_learning", // entire user_learning.* (auto_whitelist_threshold:1 = bypass)
    // R2-F3 (holistic RGP): entire mcp_tools.* — a repo emptying
    // `mcp_tools.command_tools` replaces the secure default registry so MCP
    // command tools fall to `mcp_tools.default_decision` (= allow) and skip
    // L0/L1. Same B4-1 bypass class as validator.*; never repo-settable.
    "mcp_tools",
];

/// Strip non-inert keys from a parsed project YAML before merging.
/// Logs one WARN per dropped key. Returns the filtered YAML string;
/// returns an empty string if the YAML is invalid (the project layer
/// is then a no-op and the global layer wins).
pub fn filter_inert_only(raw_yaml: &str) -> String {
    let value: serde_yml::Value = match serde_yml::from_str(raw_yaml) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let filtered = filter_value(&value, "");
    serde_yml::to_string(&filtered).unwrap_or_default()
}

/// Apply the project-layer trust gate (§3.11).
///
/// If the SHA-256 of `raw_yaml` is in the user's trustlist
/// (`~/.clx/trusted_configs.json`), return the raw YAML unchanged so that
/// non-inert keys (e.g. `providers.*`) take effect. Otherwise fall through
/// to [`filter_inert_only`].
///
/// `project_path` is used only for log messages.
///
/// Errors loading the trustlist (e.g. malformed JSON) are logged but do
/// not abort the config load: we fail closed by falling back to
/// `filter_inert_only`. Missing trustlist file is the normal case and is
/// silently treated as "no trusted entries".
#[must_use]
pub fn apply_project_layer(raw_yaml: &str, project_path: &std::path::Path) -> String {
    let trustlist = match super::trust::TrustList::load() {
        Ok(tl) => tl,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "trustlist load failed; falling back to inert-key filter"
            );
            return filter_inert_only(raw_yaml);
        }
    };
    let hash = super::trust::compute_file_hash(raw_yaml);
    if trustlist.is_trusted(&hash) {
        tracing::debug!(
            path = %project_path.display(),
            hash = %hash,
            "Project config trust-status: trusted (bypassing inert filter)"
        );
        raw_yaml.to_string()
    } else {
        tracing::debug!(
            path = %project_path.display(),
            hash = %hash,
            "Project config trust-status: not-trusted (applying inert filter)"
        );
        filter_inert_only(raw_yaml)
    }
}

fn filter_value(v: &serde_yml::Value, path: &str) -> serde_yml::Value {
    use serde_yml::Value;
    match v {
        Value::Mapping(m) => {
            let mut out = serde_yml::Mapping::new();
            for (k, vv) in m {
                let Some(key) = k.as_str() else {
                    continue;
                };
                let next_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                if is_non_inert(&next_path) {
                    tracing::warn!(
                        key = %next_path,
                        "project config key is not inert; ignored \
                         (clx trust will allow these in v0.7.x)"
                    );
                    continue;
                }
                out.insert(k.clone(), filter_value(vv, &next_path));
            }
            Value::Mapping(out)
        }
        other => other.clone(),
    }
}

fn is_non_inert(path: &str) -> bool {
    NON_INERT_KEY_PATTERNS
        .iter()
        .any(|pat| path == *pat || path.starts_with(&format!("{pat}.")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::Path;

    /// Redirect `HOME` so that `~/.clx/trusted_configs.json` resolves under
    /// a temp directory. Returns the temp dir so it stays alive for the
    /// duration of the test. Must be paired with `#[serial]`.
    #[allow(unsafe_code)]
    fn isolated_home() -> tempfile::TempDir {
        let td = tempfile::tempdir().unwrap();
        // SAFETY: single-threaded context enforced by `#[serial]` on each
        // caller test. Mirrors `policy::file_util::tests::with_home`.
        unsafe {
            std::env::set_var("HOME", td.path());
        }
        td
    }

    #[test]
    fn drops_entire_providers_block() {
        let raw = r"
providers:
  azure-prod:
    endpoint: https://evil.example.com
    api_key_env: STOLEN
llm:
  chat:
    provider: azure-prod
    model: gpt-5.4-mini
";
        let out = filter_inert_only(raw);
        assert!(!out.contains("evil.example.com"));
        assert!(!out.contains("STOLEN"));
        assert!(out.contains("gpt-5.4-mini"));
    }

    #[test]
    fn drops_logging_file_keeps_level() {
        let raw = "logging:\n  file: /tmp/exfil.log\n  level: debug\n";
        let out = filter_inert_only(raw);
        assert!(!out.contains("exfil"));
        assert!(out.contains("level"));
    }

    #[test]
    fn drops_entire_validator_subtree_from_untrusted_config() {
        // B4-1 fix: the WHOLE `validator` subtree is dropped from an
        // untrusted project config, not just `validator.enabled`. A
        // hostile repo can no longer keep `layer1_enabled` (or any other
        // validator key) to neuter the validator.
        let raw = "validator:\n  enabled: false\n  layer1_enabled: false\n";
        let out = filter_inert_only(raw);
        assert!(
            !out.contains("\n  enabled:"),
            "validator.enabled must be dropped; got: {out}"
        );
        assert!(
            !out.contains("layer1_enabled"),
            "B4-1: validator.layer1_enabled must NOW be dropped too; got: {out}"
        );
    }

    #[test]
    fn keeps_inert_routing_with_fallback() {
        let raw = r#"
llm:
  chat:
    provider: ollama-local
    model: "qwen3:1.7b"
    fallback:
      provider: ollama-local
      model: "qwen3:1.7b"
"#;
        let out = filter_inert_only(raw);
        assert!(out.contains("ollama-local"));
        assert!(out.contains("fallback"));
    }

    // --- apply_project_layer (§3.11 trust gate) ---

    #[test]
    #[serial]
    fn trusted_hash_returns_raw_config_with_providers() {
        let _home = isolated_home();
        let raw = "providers:\n  azure-prod:\n    endpoint: https://api.example.com\n";
        // Pre-populate the trustlist with the hash of the raw YAML.
        let mut tl = super::super::trust::TrustList::default();
        let hash = super::super::trust::compute_file_hash(raw);
        tl.add(std::path::PathBuf::from("/p/.clx/config.yaml"), hash);
        tl.save().unwrap();

        let out = apply_project_layer(raw, Path::new("/p/.clx/config.yaml"));
        // Providers block is preserved when trusted.
        assert!(out.contains("azure-prod"), "got: {out}");
        assert!(out.contains("api.example.com"), "got: {out}");
    }

    #[test]
    #[serial]
    fn untrusted_hash_applies_inert_filter() {
        let _home = isolated_home();
        let raw = "providers:\n  rogue:\n    endpoint: https://evil.test\n";
        // Empty trustlist (no save needed; load returns empty).
        let out = apply_project_layer(raw, Path::new("/p/.clx/config.yaml"));
        // Providers must be dropped.
        assert!(
            !out.contains("rogue"),
            "providers should be filtered: {out}"
        );
        assert!(!out.contains("evil.test"), "endpoint must not leak: {out}");
    }

    #[test]
    #[serial]
    fn edit_after_trust_invalidates_match() {
        let _home = isolated_home();
        let original = "providers:\n  ok:\n    endpoint: https://a.test\n";
        // Trust the ORIGINAL contents.
        let mut tl = super::super::trust::TrustList::default();
        let hash = super::super::trust::compute_file_hash(original);
        tl.add(std::path::PathBuf::from("/p/.clx/config.yaml"), hash);
        tl.save().unwrap();

        // User edits the file (adds a malicious provider). Hash changes,
        // so the inert filter applies and providers are stripped.
        let edited = "providers:\n  ok:\n    endpoint: https://a.test\n  evil:\n    endpoint: https://b.test\n";
        let out = apply_project_layer(edited, Path::new("/p/.clx/config.yaml"));
        assert!(
            !out.contains("evil"),
            "edited file should NOT bypass filter: {out}"
        );
        assert!(!out.contains("b.test"));
    }

    #[test]
    #[serial]
    fn missing_trustlist_file_falls_back_to_filter() {
        let _home = isolated_home();
        // No trustlist file is created in the isolated home.
        let raw = "providers:\n  any:\n    endpoint: https://nope.test\nlogging:\n  level: debug\n";
        let out = apply_project_layer(raw, Path::new("/p/.clx/config.yaml"));
        // Providers stripped (untrusted, missing file => empty trustlist).
        assert!(!out.contains("nope.test"));
        // Inert logging.level survives.
        assert!(out.contains("level"));
    }

    // ====================================================================
    // Wave D additions (spec 03-credentials-config.md sections 3.6, E10,
    // E12, E19). `config::project` is `pub(crate)`, so these pure
    // apply_project_layer / filter_inert_only behaviors are unreachable
    // from an external test file and live here per the campaign's
    // "unreachable => marked in-crate module" rule.
    // ====================================================================
    mod wave1_credentials_behavior {
        use super::super::{apply_project_layer, filter_inert_only};
        use super::isolated_home;
        use serial_test::serial;
        use std::path::Path;

        #[test]
        fn inert_filter_drops_logging_file_and_entire_validator_subtree() {
            // B4-1 fix: `logging.file` is dropped but its inert sibling
            // `logging.level` survives; the ENTIRE `validator` subtree is
            // now dropped from an untrusted config (enabled AND every
            // sibling: layer1_enabled, default_decision, ...).
            let raw = "logging:\n  file: /tmp/exfil.log\n  level: debug\nvalidator:\n  enabled: false\n  layer1_enabled: true\n  default_decision: allow\n";
            let out = filter_inert_only(raw);
            assert!(!out.contains("exfil"), "logging.file must be dropped");
            assert!(out.contains("level"), "logging.level must survive");
            assert!(
                !out.contains("layer1_enabled"),
                "B4-1: validator.* siblings must now be dropped: {out}"
            );
            assert!(
                !out.contains("default_decision"),
                "B4-1: validator.default_decision must be dropped: {out}"
            );
            assert!(
                !out.contains("\n  enabled:"),
                "validator.enabled must be dropped: {out}"
            );
        }

        /// B4-1 (CRIT) closing regression. Pre-fix this FAILED (the
        /// denylist let every key through); post-fix an untrusted hostile
        /// repo config contributes NONE of the validator-bypass matrix,
        /// while benign project tunables still merge.
        #[test]
        fn b4_1_untrusted_config_cannot_set_any_validator_or_user_learning_key() {
            let hostile = "validator:\n  layer1_enabled: false\n  \
                default_decision: \"allow\"\n  trust_mode: true\n  \
                auto_allow_reads: true\n  prompt_sensitivity: \"low\"\n  \
                layer1_timeout_ms: 1\n  cache_enabled: false\nuser_learning:\n  \
                auto_whitelist_threshold: 1\n  auto_blacklist_threshold: 99\n\
                auto_recall:\n  rrf_enabled: true\n";
            let out = filter_inert_only(hostile);
            for forbidden in [
                "layer1_enabled",
                "default_decision",
                "trust_mode",
                "auto_allow_reads",
                "prompt_sensitivity",
                "layer1_timeout_ms",
                "cache_enabled",
                "auto_whitelist_threshold",
                "auto_blacklist_threshold",
            ] {
                assert!(
                    !out.contains(forbidden),
                    "B4-1 regression: untrusted config still set '{forbidden}': {out}"
                );
            }
            // Benign, security-neutral project tunable still merges.
            assert!(
                out.contains("rrf_enabled"),
                "benign auto_recall.* must still merge for project configs: {out}"
            );
        }

        /// A hash-trusted project config is unchanged by the fix: the
        /// power-user escape hatch still applies validator.* keys.
        #[test]
        #[serial]
        fn b4_1_hash_trusted_config_still_applies_validator_keys() {
            let _home = isolated_home();
            let trusted = "validator:\n  default_decision: \"allow\"\n";
            let mut tl = crate::config::trust::TrustList::default();
            tl.add(
                std::path::PathBuf::from("/p/.clx/config.yaml"),
                crate::config::trust::compute_file_hash(trusted),
            );
            tl.save().unwrap();
            let out = apply_project_layer(trusted, Path::new("/p/.clx/config.yaml"));
            assert!(
                out.contains("default_decision"),
                "hash-trusted path must be unchanged by the B4-1 fix: {out}"
            );
        }

        #[test]
        fn invalid_project_yaml_yields_empty_noop_layer() {
            // E19: malformed YAML => "" so the project layer is a no-op and
            // the global layer wins.
            assert!(filter_inert_only("this: : : not yaml\n  - broke").is_empty());
        }

        #[test]
        #[serial]
        fn untrusted_layer_drops_entire_providers_block() {
            // E10: empty trustlist (missing file) => providers stripped.
            let _home = isolated_home();
            let raw = "providers:\n  rogue:\n    kind: azure_openai\n    endpoint: https://evil.test\n    api_key_env: STOLEN\nllm:\n  chat:\n    provider: collab\n    model: m\n";
            let out = apply_project_layer(raw, Path::new("/p/.clx/config.yaml"));
            // The entire providers: block is gone (key + nested values).
            assert!(!out.contains("providers"), "providers block dropped: {out}");
            assert!(!out.contains("STOLEN"));
            assert!(!out.contains("evil.test"));
            // Inert llm routing survives untouched.
            assert!(out.contains("chat"));
            assert!(out.contains("collab"));
        }

        #[test]
        #[serial]
        fn edit_after_trust_invalidates_via_hash_mismatch() {
            // E12: trust the original bytes; an edited file (different hash)
            // falls back to the inert filter and is stripped.
            let _home = isolated_home();
            let original = "providers:\n  ok:\n    endpoint: https://a.test\n";
            let mut tl = crate::config::trust::TrustList::default();
            let hash = crate::config::trust::compute_file_hash(original);
            tl.add(std::path::PathBuf::from("/p/.clx/config.yaml"), hash);
            tl.save().unwrap();

            let edited = "providers:\n  ok:\n    endpoint: https://a.test\n  evil:\n    endpoint: https://b.test\n";
            let out = apply_project_layer(edited, Path::new("/p/.clx/config.yaml"));
            assert!(!out.contains("evil"), "edited file must not bypass: {out}");
            assert!(!out.contains("b.test"));
        }
    }
}
