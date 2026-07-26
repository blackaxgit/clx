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
