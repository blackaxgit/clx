//! Shared OpenAI-compatible chat wire types.
//!
//! Both the Azure `OpenAI` backend ([`crate::llm::azure`]) and the `OpenRouter`
//! backend consume the same `/chat/completions` wire shape, so the request
//! and response types live here once instead of being duplicated (and
//! risking drift) per backend.
//!
//! The types are generalized to the union of what each backend needs:
//! - `ChatRequest::max_tokens` and `ChatRequest::max_completion_tokens` are
//!   both optional and `skip_serializing_if = "Option::is_none"` — Azure
//!   sends only `max_completion_tokens`, `OpenRouter` sends only `max_tokens`,
//!   and the field neither backend uses is omitted from the wire body
//!   entirely (not serialized as `null`).
//! - `ChatRequest::provider` carries `OpenRouter`'s provider-routing
//!   preferences ([`ProviderPrefs`]); Azure always sets it to `None`, which
//!   is skipped on serialization, so Azure's request body is unaffected by
//!   this field's existence.
//! - `ChatChoiceMessage::content` is `Option<String>` (not the bare
//!   `String` Azure originally declared) because a provider may return a
//!   response with the content field absent or explicitly `null` — callers
//!   must treat that as a failure rather than silently substituting an
//!   empty string.
//! - `ChatResponse::error` models the `OpenAI`/`OpenRouter` "HTTP 200 with a
//!   top-level `error` envelope" shape, which callers must check before
//!   trusting `choices`.
//!
//! All types are `pub(crate)`: this module is an internal implementation
//! detail of `crate::llm`, not part of the crate's public API.

use crate::llm::LlmError;
use crate::redaction::redact_secrets;
use serde::{Deserialize, Serialize};

/// A single chat message in the `messages` array of a [`ChatRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ChatMessage {
    pub(crate) role: String,
    pub(crate) content: String,
}

/// `OpenRouter` provider-routing preferences.
///
/// Azure never sends this (`ChatRequest::provider` is `None`, which is
/// skipped on serialization). `OpenRouter` uses it to opt out of upstream
/// data collection by default (`data_collection: "deny"`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub(crate) struct ProviderPrefs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data_collection: Option<String>,
}

/// Request body for `POST .../chat/completions`.
///
/// Field order is significant for the Azure byte-identical regression test:
/// `serde_json` serializes struct fields in declaration order, and Azure's
/// pre-refactor wire format was `{"model", "messages", "max_completion_tokens"}`.
/// Keeping `max_tokens` and `provider` `skip_serializing_if`-gated and placed
/// after `messages` preserves that exact byte sequence for Azure (which sets
/// both to `None`/omitted).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ChatRequest {
    pub(crate) model: String,
    pub(crate) messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<ProviderPrefs>,
}

/// Top-level `OpenAI`/`OpenRouter` error envelope.
///
/// `OpenRouter` can return HTTP 200 with this shape embedded in the body to
/// signal an underlying provider failure (C3) — callers must check
/// [`ChatResponse::error`] before reading [`ChatResponse::choices`].
/// `code` is tolerant of both numeric (`429`) and string (`"invalid_request"`)
/// shapes seen across providers, so it is left as a raw [`serde_json::Value`].
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(crate) struct ApiError {
    #[serde(default)]
    pub(crate) code: Option<serde_json::Value>,
    pub(crate) message: String,
    #[serde(default)]
    pub(crate) metadata: Option<serde_json::Value>,
}

/// A single entry in `ChatResponse::choices`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(crate) struct ChatChoice {
    pub(crate) message: ChatChoiceMessage,
}

/// The `message` object nested in a [`ChatChoice`].
///
/// `content` is `Option<String>` — a provider may omit it or return `null`
/// (e.g. a refusal or a tool-call-only response). Callers must map the
/// `None`/empty case to a explicit failure rather than defaulting to an
/// empty string, so silent empty completions are not mistaken for real
/// (if vacuous) model output.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub(crate) struct ChatChoiceMessage {
    #[serde(default)]
    pub(crate) content: Option<String>,
}

/// Response body for `POST .../chat/completions`.
///
/// Both fields default so that either an error-only body (`{"error": {...}}`)
/// or a success-only body (`{"choices": [...]}`) deserializes without a
/// missing-field error.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub(crate) struct ChatResponse {
    #[serde(default)]
    pub(crate) choices: Vec<ChatChoice>,
    #[serde(default)]
    pub(crate) error: Option<ApiError>,
}

/// Extract an inline HTTP-status-shaped value from [`ApiError::code`], if
/// any. `code` is tolerant of both a numeric (`429`) and a string
/// (`"429"`/`"invalid_request"`) shape across providers; a non-numeric
/// string (e.g. `"invalid_request"`) yields `None` rather than an error.
fn inline_error_status(err: &ApiError) -> Option<u16> {
    match &err.code {
        Some(serde_json::Value::Number(n)) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
        Some(serde_json::Value::String(s)) => s.parse::<u16>().ok(),
        _ => None,
    }
}

/// Map a top-level `error` envelope (C3 — present on an HTTP-200-with-error
/// body, or embedded alongside a non-2xx status) to the provider-neutral
/// [`LlmError`].
///
/// `http_status` is the outer HTTP status when known (e.g. `200` for the
/// 200-with-inline-error case); it is used as a fallback when `err.code`
/// does not carry a recognisable numeric status. The inline code always
/// takes precedence, since it reflects the *actual* upstream failure even
/// when the outer transport status was 200.
///
/// `err.message` is passed through [`redact_secrets`] before it can reach
/// any `LlmError::Display` sink (C1).
#[must_use]
pub(crate) fn map_api_error(err: &ApiError, http_status: Option<u16>) -> LlmError {
    let message = redact_secrets(err.message.trim());
    let status = inline_error_status(err).or(http_status);
    match status {
        // Inline/outer 429 always maps to RateLimit — the caller has no
        // `Retry-After` header to attach here (that only exists on the
        // outer non-2xx HTTP response, handled separately by each backend's
        // status-code match), so `retry_after` is `None`.
        Some(429) => LlmError::RateLimit { retry_after: None },
        // AC4: an inline 401/403 is an auth failure, not a generic server
        // error — mirrors the outer-HTTP-status 401/403 -> Auth mapping each
        // backend already applies in its non-2xx branch.
        Some(401 | 403) => LlmError::Auth(message),
        Some(s) => LlmError::Server {
            status: s,
            body: message,
        },
        None => LlmError::InvalidResponse(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: Option<serde_json::Value>, message: &str) -> ApiError {
        ApiError {
            code,
            message: message.to_string(),
            metadata: None,
        }
    }

    #[test]
    fn map_api_error_numeric_code_429_is_rate_limit() {
        let e = err(Some(serde_json::json!(429)), "rate limited");
        assert!(matches!(
            map_api_error(&e, Some(200)),
            LlmError::RateLimit { retry_after: None }
        ));
    }

    #[test]
    fn map_api_error_string_code_429_is_rate_limit() {
        let e = err(Some(serde_json::json!("429")), "rate limited");
        assert!(matches!(
            map_api_error(&e, Some(200)),
            LlmError::RateLimit { retry_after: None }
        ));
    }

    #[test]
    fn map_api_error_numeric_code_503_is_transient_server() {
        let e = err(Some(serde_json::json!(503)), "unavailable");
        let mapped = map_api_error(&e, Some(200));
        match &mapped {
            LlmError::Server { status: 503, .. } => assert!(mapped.is_transient()),
            other => panic!("expected Server{{503}}, got {other:?}"),
        }
    }

    #[test]
    fn map_api_error_code_402_is_non_transient_server() {
        let e = err(Some(serde_json::json!(402)), "payment required");
        let mapped = map_api_error(&e, Some(200));
        match &mapped {
            LlmError::Server { status: 402, .. } => assert!(!mapped.is_transient()),
            other => panic!("expected Server{{402}}, got {other:?}"),
        }
    }

    #[test]
    fn map_api_error_numeric_code_401_is_auth() {
        let e = err(Some(serde_json::json!(401)), "invalid credentials");
        assert!(
            matches!(map_api_error(&e, Some(200)), LlmError::Auth(_)),
            "F-c: inline 401 must map to LlmError::Auth"
        );
    }

    #[test]
    fn map_api_error_numeric_code_403_is_auth() {
        let e = err(Some(serde_json::json!(403)), "forbidden");
        assert!(
            matches!(map_api_error(&e, Some(200)), LlmError::Auth(_)),
            "F-c: inline 403 must map to LlmError::Auth"
        );
    }

    #[test]
    fn map_api_error_falls_back_to_http_status_when_code_not_numeric() {
        let e = err(Some(serde_json::json!("invalid_request")), "bad request");
        let mapped = map_api_error(&e, Some(400));
        assert!(matches!(mapped, LlmError::Server { status: 400, .. }));
    }

    #[test]
    fn map_api_error_no_code_no_status_is_invalid_response() {
        let e = err(None, "unknown failure");
        assert!(matches!(
            map_api_error(&e, None),
            LlmError::InvalidResponse(_)
        ));
    }

    #[test]
    fn map_api_error_redacts_secret_in_message() {
        let e = err(
            Some(serde_json::json!(401)),
            "invalid key sk-abcdefghijklmnopqrstuvwxyz1234567890",
        );
        let mapped = map_api_error(&e, Some(401));
        let display = mapped.to_string();
        assert!(
            !display.contains("abcdefghijklmnopqrstuvwxyz1234567890"),
            "secret leaked into mapped LlmError Display: {display}"
        );
    }
}
