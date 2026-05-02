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

/// Patterns of keys NOT allowed from a project config (security gate).
/// Honoring these keys would let a hostile repo redirect credentials,
/// log paths, or HTTP endpoints.
///
/// A path matches if it equals or starts with any pattern. The
/// `providers.` prefix matches any nested `providers.<name>.endpoint`,
/// `providers.<name>.api_key_env`, etc. — i.e., we drop the entire
/// `providers:` section from project configs (provider definitions
/// stay global-only).
const NON_INERT_KEY_PATTERNS: &[&str] = &[
    "providers", // drops providers.* entirely
    "logging.file",
    "validator.enabled",
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
    fn drops_validator_enabled_keeps_layer1() {
        let raw = "validator:\n  enabled: false\n  layer1_enabled: false\n";
        let out = filter_inert_only(raw);
        // validator.enabled must be dropped — the key "enabled:" at validator depth is gone
        assert!(
            !out.contains("\n  enabled:"),
            "validator.enabled must be dropped; got: {out}"
        );
        // layer1_enabled should survive (only validator.enabled is non-inert)
        assert!(out.contains("layer1_enabled"));
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
}
