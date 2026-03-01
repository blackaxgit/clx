//! Input validation helpers for MCP tool parameters.
//!
//! Provides typed extraction and bounds-checking for JSON-RPC tool arguments.
//! All validators return `Result<T, (i32, String)>` matching the JSON-RPC error
//! tuple convention used by `handle_tools_call`.

use serde_json::Value;

use crate::protocol::types::INVALID_PARAMS;

/// Maximum length for short string parameters (queries, keys, actions, tags).
pub const MAX_QUERY_LEN: usize = 10_000;

/// Maximum length for content/text parameters (remembered text, notes).
pub const MAX_CONTENT_LEN: usize = 100_000;

/// Maximum length for short identifiers (keys, action names, categories).
pub const MAX_KEY_LEN: usize = 1_000;

/// Extract and validate a required string parameter.
///
/// Returns an error if the parameter is missing, not a string, or exceeds `max_len`.
pub fn validate_string_param(
    args: &Value,
    name: &str,
    max_len: usize,
) -> Result<String, (i32, String)> {
    let value = args.get(name).and_then(|v| v.as_str()).ok_or((
        INVALID_PARAMS,
        format!("Missing or invalid parameter: {name}"),
    ))?;

    if value.len() > max_len {
        return Err((
            INVALID_PARAMS,
            format!(
                "Parameter '{}' exceeds max length of {} (got {})",
                name,
                max_len,
                value.len()
            ),
        ));
    }

    Ok(value.to_string())
}

/// Extract and validate an optional string parameter.
///
/// Returns `Ok(None)` if the parameter is absent or null.
/// Returns an error if present but not a string, or if it exceeds `max_len`.
pub fn validate_optional_string_param(
    args: &Value,
    name: &str,
    max_len: usize,
) -> Result<Option<String>, (i32, String)> {
    match args.get(name) {
        Some(Value::String(s)) => {
            if s.len() > max_len {
                return Err((
                    INVALID_PARAMS,
                    format!(
                        "Parameter '{}' exceeds max length of {} (got {})",
                        name,
                        max_len,
                        s.len()
                    ),
                ));
            }
            Ok(Some(s.clone()))
        }
        Some(Value::Null) | None => Ok(None),
        _ => Err((
            INVALID_PARAMS,
            format!("Parameter '{name}' must be a string"),
        )),
    }
}

/// Extract and validate an optional integer parameter within a range.
///
/// Accepts JSON numbers that can be represented as `i64`.
/// Returns `Ok(None)` if the parameter is absent or null.
/// Returns an error if the value is not a number or falls outside `[min, max]`.
pub fn validate_optional_i64_param(
    args: &Value,
    name: &str,
    min: i64,
    max: i64,
) -> Result<Option<i64>, (i32, String)> {
    match args.get(name) {
        Some(v) if v.is_number() => {
            let n = v.as_i64().ok_or((
                INVALID_PARAMS,
                format!("Parameter '{name}' must be an integer"),
            ))?;
            if n < min || n > max {
                return Err((
                    INVALID_PARAMS,
                    format!("Parameter '{name}' must be between {min} and {max} (got {n})"),
                ));
            }
            Ok(Some(n))
        }
        Some(Value::Null) | None => Ok(None),
        _ => Err((
            INVALID_PARAMS,
            format!("Parameter '{name}' must be a number"),
        )),
    }
}

/// Extract and validate an optional array of strings parameter.
///
/// Returns `Ok(Vec::new())` if absent or null.
/// Returns an error if present but not an array, or if any element is not a string.
/// Each element is bounded by `max_element_len`; the array itself by `max_count`.
pub fn validate_optional_string_array(
    args: &Value,
    name: &str,
    max_count: usize,
    max_element_len: usize,
) -> Result<Vec<String>, (i32, String)> {
    match args.get(name) {
        Some(Value::Array(arr)) => {
            if arr.len() > max_count {
                return Err((
                    INVALID_PARAMS,
                    format!("Parameter '{name}' has too many elements (max {max_count})"),
                ));
            }
            let mut result = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                let s = v.as_str().ok_or((
                    INVALID_PARAMS,
                    format!("Parameter '{name}[{i}]' must be a string"),
                ))?;
                if s.len() > max_element_len {
                    return Err((
                        INVALID_PARAMS,
                        format!("Parameter '{name}[{i}]' exceeds max length of {max_element_len}"),
                    ));
                }
                result.push(s.to_string());
            }
            Ok(result)
        }
        Some(Value::Null) | None => Ok(Vec::new()),
        _ => Err((
            INVALID_PARAMS,
            format!("Parameter '{name}' must be an array"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // =========================================================================
    // validate_string_param
    // =========================================================================

    #[test]
    fn test_validate_string_param_valid() {
        let args = json!({"query": "hello"});
        let result = validate_string_param(&args, "query", 100);
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn test_validate_string_param_missing() {
        let args = json!({});
        let result = validate_string_param(&args, "query", 100);
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, INVALID_PARAMS);
        assert!(msg.contains("Missing or invalid parameter: query"));
    }

    #[test]
    fn test_validate_string_param_wrong_type() {
        let args = json!({"query": 42});
        let result = validate_string_param(&args, "query", 100);
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, INVALID_PARAMS);
        assert!(msg.contains("Missing or invalid parameter: query"));
    }

    #[test]
    fn test_validate_string_param_too_long() {
        let args = json!({"query": "x".repeat(101)});
        let result = validate_string_param(&args, "query", 100);
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, INVALID_PARAMS);
        assert!(msg.contains("exceeds max length"));
    }

    #[test]
    fn test_validate_string_param_at_limit() {
        let args = json!({"query": "x".repeat(100)});
        let result = validate_string_param(&args, "query", 100);
        assert!(result.is_ok());
    }

    // =========================================================================
    // validate_optional_string_param
    // =========================================================================

    #[test]
    fn test_validate_optional_string_present() {
        let args = json!({"note": "hello"});
        let result = validate_optional_string_param(&args, "note", 100);
        assert_eq!(result.unwrap(), Some("hello".to_string()));
    }

    #[test]
    fn test_validate_optional_string_missing() {
        let args = json!({});
        let result = validate_optional_string_param(&args, "note", 100);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_validate_optional_string_null() {
        let args = json!({"note": null});
        let result = validate_optional_string_param(&args, "note", 100);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_validate_optional_string_wrong_type() {
        let args = json!({"note": 42});
        let result = validate_optional_string_param(&args, "note", 100);
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, INVALID_PARAMS);
        assert!(msg.contains("must be a string"));
    }

    #[test]
    fn test_validate_optional_string_too_long() {
        let args = json!({"note": "x".repeat(101)});
        let result = validate_optional_string_param(&args, "note", 100);
        assert!(result.is_err());
        let (_, msg) = result.unwrap_err();
        assert!(msg.contains("exceeds max length"));
    }

    // =========================================================================
    // validate_optional_i64_param
    // =========================================================================

    #[test]
    fn test_validate_optional_i64_valid() {
        let args = json!({"days": 7});
        let result = validate_optional_i64_param(&args, "days", 1, 365);
        assert_eq!(result.unwrap(), Some(7));
    }

    #[test]
    fn test_validate_optional_i64_missing() {
        let args = json!({});
        let result = validate_optional_i64_param(&args, "days", 1, 365);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_validate_optional_i64_null() {
        let args = json!({"days": null});
        let result = validate_optional_i64_param(&args, "days", 1, 365);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_validate_optional_i64_below_min() {
        let args = json!({"days": 0});
        let result = validate_optional_i64_param(&args, "days", 1, 365);
        assert!(result.is_err());
        let (_, msg) = result.unwrap_err();
        assert!(msg.contains("must be between"));
    }

    #[test]
    fn test_validate_optional_i64_above_max() {
        let args = json!({"days": 400});
        let result = validate_optional_i64_param(&args, "days", 1, 365);
        assert!(result.is_err());
        let (_, msg) = result.unwrap_err();
        assert!(msg.contains("must be between"));
    }

    #[test]
    fn test_validate_optional_i64_wrong_type() {
        let args = json!({"days": "seven"});
        let result = validate_optional_i64_param(&args, "days", 1, 365);
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, INVALID_PARAMS);
        assert!(msg.contains("must be a number"));
    }

    #[test]
    fn test_validate_optional_i64_at_bounds() {
        let args_min = json!({"val": 1});
        assert_eq!(
            validate_optional_i64_param(&args_min, "val", 1, 100).unwrap(),
            Some(1)
        );
        let args_max = json!({"val": 100});
        assert_eq!(
            validate_optional_i64_param(&args_max, "val", 1, 100).unwrap(),
            Some(100)
        );
    }

    // =========================================================================
    // validate_optional_string_array
    // =========================================================================

    #[test]
    fn test_validate_string_array_valid() {
        let args = json!({"tags": ["a", "b", "c"]});
        let result = validate_optional_string_array(&args, "tags", 10, 100);
        assert_eq!(result.unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_validate_string_array_missing() {
        let args = json!({});
        let result = validate_optional_string_array(&args, "tags", 10, 100);
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_validate_string_array_null() {
        let args = json!({"tags": null});
        let result = validate_optional_string_array(&args, "tags", 10, 100);
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_validate_string_array_too_many() {
        let args = json!({"tags": ["a", "b", "c", "d"]});
        let result = validate_optional_string_array(&args, "tags", 3, 100);
        assert!(result.is_err());
        let (_, msg) = result.unwrap_err();
        assert!(msg.contains("too many elements"));
    }

    #[test]
    fn test_validate_string_array_element_too_long() {
        let args = json!({"tags": ["short", "x".repeat(101)]});
        let result = validate_optional_string_array(&args, "tags", 10, 100);
        assert!(result.is_err());
        let (_, msg) = result.unwrap_err();
        assert!(msg.contains("exceeds max length"));
    }

    #[test]
    fn test_validate_string_array_non_string_element() {
        let args = json!({"tags": ["ok", 42]});
        let result = validate_optional_string_array(&args, "tags", 10, 100);
        assert!(result.is_err());
        let (_, msg) = result.unwrap_err();
        assert!(msg.contains("must be a string"));
    }

    #[test]
    fn test_validate_string_array_wrong_type() {
        let args = json!({"tags": "not-an-array"});
        let result = validate_optional_string_array(&args, "tags", 10, 100);
        assert!(result.is_err());
        let (_, msg) = result.unwrap_err();
        assert!(msg.contains("must be an array"));
    }
}
