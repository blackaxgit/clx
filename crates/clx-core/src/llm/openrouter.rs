//! `OpenRouter` (openrouter.ai) backend — a generic OpenAI-compatible
//! CHAT-ONLY backend (hand-rolled `reqwest`, no dedicated crate; C6).
//!
//! Reuses the shared wire types in [`crate::llm::openai_wire`]. Construction
//! hard-fails on any SSRF-shaped endpoint (C2/AC6): non-HTTPS remote host,
//! a host outside the allowlist, or an endpoint carrying userinfo/query/
//! fragment. The HTTP client is built with `redirect::Policy::none()` so a
//! malicious/misconfigured redirect can never re-send the bearer credential
//! and prompt text to another host (`AC6b`).
//!
//! `embed()` is intentionally unimplemented — `OpenRouter` is chat-only
//! (R2/AC7) — and issues no network call.
//!
//! WP3 owns `OpenRouterConfig` and `build_client_for_provider`; this module
//! only needs the individual fields threaded through [`OpenRouterBackend::new`]
//! so it compiles and is fully testable standalone.

use crate::llm::openai_wire::{
    ChatMessage, ChatRequest, ChatResponse, ProviderPrefs, map_api_error,
};
use crate::llm::retry::{RetryConfig, with_backoff};
use crate::llm::{LlmError, LocalLlmBackend};
use crate::redaction::redact_secrets;
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;
use url::{Host, Url};

/// Maximum number of bytes of the raw provider response body to include in a
/// structured error summary (mirrors `azure::MAX_BODY_EXCERPT_BYTES`). Keeps
/// unbounded bodies from flowing verbatim into `LlmError` and its `Display`
/// path; the excerpt is additionally redacted before being embedded.
const MAX_BODY_EXCERPT_BYTES: usize = 80;

/// Per-request timeout for the `is_available` health probe (E7 — must stay
/// well under `validator.layer1_timeout_ms`).
const HEALTH_CHECK_TIMEOUT_MS: u64 = 2_000;

/// `max_tokens` sent on every chat request (R2/AC12 — fixed, not configurable
/// from `generate()`'s signature since it receives no schema/budget).
const MAX_TOKENS: u32 = 2048;

/// Model id used when the caller passes `model: None` to `generate()`.
/// `openrouter/auto` is `OpenRouter`'s own model-router alias, so an
/// unspecified model still resolves to *something* runnable rather than
/// failing construction of the request body.
const DEFAULT_CHAT_MODEL: &str = "openrouter/auto";

/// Hosts allowed without the `CLX_ALLOW_OPENROUTER_HOSTS` override: the
/// apex domain and any subdomain of `openrouter.ai`.
const ALLOWED_APEX_HOST: &str = "openrouter.ai";
const ALLOWED_HOST_SUFFIX: &str = ".openrouter.ai";

// `pub` (not `pub(crate)`) to match `AzureOpenAIBackend`/`OllamaBackend`/
// `FallbackClient`: all four are variant payloads of the `pub enum
// LlmClient`, so each backend type must be at least as visible as the enum
// itself — a `pub(crate)` field type there trips rustc's
// `private_interfaces` lint (promoted to a hard error under this crate's
// `-D warnings` gate).
#[derive(Debug, Clone)]
pub struct OpenRouterBackend {
    endpoint: Url,
    api_key: SecretString,
    retry: RetryConfig,
    http: reqwest::Client,
    referer: Option<String>,
    title: Option<String>,
}

impl OpenRouterBackend {
    /// Construct a backend from individual config fields.
    ///
    /// WP3's `OpenRouterConfig` (config surface, R4) does not exist yet in
    /// this work package, so `new` takes the exact fields it needs rather
    /// than a config struct. WP3's `build_client_for_provider` arm is
    /// expected to call this as:
    ///
    /// ```ignore
    /// OpenRouterBackend::new(
    ///     &cfg.endpoint,
    ///     cfg.timeout_ms,
    ///     cfg.retry,
    ///     cfg.referer.clone(),
    ///     cfg.title.clone(),
    ///     api_key,
    /// )?
    /// ```
    ///
    /// # Errors
    /// Returns `Err(LlmError::Connection(_))` (hard-fail, C2/AC6) when:
    /// - `endpoint` fails to parse as a URL.
    /// - `endpoint` carries userinfo, a query string, or a fragment.
    /// - the scheme is not `https` and the host is not loopback.
    /// - the host is not loopback, not `openrouter.ai`/`*.openrouter.ai`,
    ///   and not listed in `CLX_ALLOW_OPENROUTER_HOSTS`.
    /// - a non-loopback host carries an explicit non-default port.
    /// - the underlying `reqwest::Client` fails to build.
    pub fn new(
        endpoint: &str,
        timeout_ms: u64,
        retry: RetryConfig,
        referer: Option<String>,
        title: Option<String>,
        api_key: SecretString,
    ) -> Result<Self, LlmError> {
        let url = Url::parse(endpoint)
            .map_err(|e| LlmError::Connection(format!("invalid endpoint URL: {e}")))?;
        Self::validate(&url)?;

        let http = reqwest::Client::builder()
            // AC6b: never follow a redirect — it could re-send the bearer
            // credential and prompt text to an attacker-controlled host.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .map_err(|e| LlmError::Connection(format!("http client init: {e}")))?;

        Ok(Self {
            endpoint: url,
            api_key,
            retry,
            http,
            referer,
            title,
        })
    }

    /// SSRF-pinning construction guard (C2/AC6). See [`Self::new`] doc for
    /// the exact rejection conditions.
    fn validate(url: &Url) -> Result<(), LlmError> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(LlmError::Connection(
                "endpoint URL must not contain userinfo".into(),
            ));
        }
        if url.query().is_some() {
            return Err(LlmError::Connection(
                "endpoint URL must not contain a query string".into(),
            ));
        }
        if url.fragment().is_some() {
            return Err(LlmError::Connection(
                "endpoint URL must not contain a fragment".into(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| LlmError::Connection("endpoint URL has no host".into()))?;

        // F-b: decide loopback-ness from the parsed `url::Host` enum, not by
        // string-comparing `host_str()`. For `http://[::1]:PORT`, `host_str()`
        // returns the bracketed form `"[::1]"`, which never equals the bare
        // `"::1"` a naive string check compares against — that mismatch
        // wrongly rejected a legitimate IPv6 loopback endpoint (C2/AC6).
        //
        // F-e: a `Host::Domain` may carry a single trailing `.` (FQDN
        // notation, e.g. `openrouter.ai.`). It is normalized away here,
        // before it can affect either the loopback check or the allowlist
        // match below.
        let (loopback, allowlist_host): (bool, String) = match url.host() {
            Some(Host::Ipv4(ip)) => (ip.is_loopback(), host.to_string()),
            Some(Host::Ipv6(ip)) => (ip.is_loopback(), host.to_string()),
            Some(Host::Domain(d)) => {
                let normalized = d.strip_suffix('.').unwrap_or(d);
                (
                    normalized.eq_ignore_ascii_case("localhost"),
                    normalized.to_string(),
                )
            }
            None => (false, host.to_string()),
        };

        if url.scheme() != "https" && !loopback {
            return Err(LlmError::Connection(format!(
                "scheme must be https for non-loopback host '{host}' (loopback may use http)"
            )));
        }
        // `Url::port()` returns `None` both when no port was given and when
        // the given port equals the scheme's default (443 for https), so a
        // remote host reaches this branch only for a genuinely non-default
        // explicit port.
        if !loopback && url.port().is_some() {
            return Err(LlmError::Connection(format!(
                "explicit non-default port not allowed for remote host '{host}'"
            )));
        }
        if !is_host_allowed(&allowlist_host, loopback) {
            return Err(LlmError::Connection(format!(
                "host '{host}' not in openrouter allowlist (set CLX_ALLOW_OPENROUTER_HOSTS to override)"
            )));
        }
        Ok(())
    }

    /// Strip a trailing `/`, `/api/v1`, or `/api` from the endpoint path so
    /// [`Self::chat_url`]/[`Self::models_url`] can append the canonical
    /// suffix exactly once (R6/AC11).
    fn normalized_base_path(&self) -> &str {
        let path = self.endpoint.path().trim_end_matches('/');
        path.strip_suffix("/api/v1")
            .or_else(|| path.strip_suffix("/api"))
            .unwrap_or(path)
    }

    fn chat_url(&self) -> Url {
        let mut u = self.endpoint.clone();
        u.set_path(&format!(
            "{}/api/v1/chat/completions",
            self.normalized_base_path()
        ));
        u.set_query(None);
        u
    }

    fn models_url(&self) -> Url {
        let mut u = self.endpoint.clone();
        u.set_path(&format!("{}/api/v1/models", self.normalized_base_path()));
        u.set_query(None);
        u
    }
}

fn is_host_allowed(host: &str, loopback: bool) -> bool {
    if loopback {
        return true;
    }
    if host == ALLOWED_APEX_HOST || host.ends_with(ALLOWED_HOST_SUFFIX) {
        return true;
    }
    std::env::var("CLX_ALLOW_OPENROUTER_HOSTS").is_ok_and(|allowlist| {
        allowlist
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(|h| h == host)
    })
}

// --- Helpers ---------------------------------------------------------------

/// Truncate a string to at most `max_bytes` bytes without splitting a UTF-8
/// multi-byte character. Mirrors `azure::truncate_utf8`.
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Build a bounded, redacted error summary from a raw non-2xx response body
/// (C1). The raw body is discarded after excerpt extraction.
fn build_error_summary(status: u16, body: &str) -> String {
    let redacted_body = redact_secrets(body.trim());
    let excerpt = truncate_utf8(&redacted_body, MAX_BODY_EXCERPT_BYTES);
    format!("status={status} body={excerpt:?}")
}

/// Redact a raw `reqwest::Error` before it enters an `LlmError` (mirrors
/// `azure::redact_connection_error` — errors can embed the request URL).
fn redact_connection_error(e: &reqwest::Error) -> LlmError {
    if e.is_timeout() {
        return LlmError::Timeout;
    }
    LlmError::Connection(redact_secrets(&e.to_string()))
}

fn retry_after_for(e: &LlmError) -> Option<Duration> {
    match e {
        LlmError::RateLimit { retry_after } => *retry_after,
        _ => None,
    }
}

/// Map an HTTP response into a [`ChatResponse`] or the appropriate
/// [`LlmError`] (C3/AC3/AC4).
///
/// On a 2xx status, the top-level `error` envelope is checked FIRST (C3) —
/// an inline `429`/`503`/etc. is mapped via [`map_api_error`] before
/// `choices` is ever read, so a 200-with-error body is never mistaken for an
/// empty/successful completion.
async fn map_response(resp: reqwest::Response) -> Result<ChatResponse, LlmError> {
    let status = resp.status();
    if status.is_success() {
        let txt = resp
            .text()
            .await
            .map_err(|e| LlmError::InvalidResponse(redact_secrets(&e.to_string())))?;
        let parsed: ChatResponse = serde_json::from_str(&txt).map_err(|e| {
            LlmError::InvalidResponse(format!(
                "malformed response body: {}",
                redact_secrets(&e.to_string())
            ))
        })?;
        if let Some(err) = &parsed.error {
            // C3: an inline error takes precedence over any `choices` the
            // body might also carry.
            //
            // F-a: pass `None`, not `Some(status.as_u16())`, as the HTTP-status
            // fallback. `map_api_error` already prefers a numeric `err.code`
            // when present; the only case where the fallback is consulted is
            // when `err.code` is absent or non-numeric (e.g. a string like
            // `"invalid_request"`). Falling back to the outer `200` there
            // would synthesize `LlmError::Server { status: 200, .. }` — an
            // effective-200 error response, which C3 forbids. With `None`,
            // that case instead maps to `LlmError::InvalidResponse`.
            return Err(map_api_error(err, None));
        }
        Ok(parsed)
    } else {
        let status_u16 = status.as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs);
        let body = resp.text().await.unwrap_or_default();
        let summary = build_error_summary(status_u16, &body);
        match status_u16 {
            401 | 403 => Err(LlmError::Auth(summary)),
            // AC4: 402/404 are non-transient — OpenRouter 404 means an
            // unknown model/route (not an Azure-specific deployment), and
            // 402 is a billing error; neither should churn retries/fallback.
            402 | 404 => Err(LlmError::Server {
                status: status_u16,
                body: summary,
            }),
            429 => Err(LlmError::RateLimit { retry_after }),
            s => Err(LlmError::Server {
                status: s,
                body: summary,
            }),
        }
    }
}

async fn post_chat(
    backend: &OpenRouterBackend,
    url: &Url,
    body: &ChatRequest,
) -> Result<ChatResponse, LlmError> {
    let mut req = backend
        .http
        .post(url.clone())
        .header(
            "Authorization",
            format!("Bearer {}", backend.api_key.expose_secret()),
        )
        .header("Content-Type", "application/json");
    if let Some(referer) = &backend.referer {
        req = req.header("HTTP-Referer", referer);
    }
    if let Some(title) = &backend.title {
        req = req.header("X-Title", title);
    }
    let resp = req
        .json(body)
        .send()
        .await
        .map_err(|e| redact_connection_error(&e))?;
    map_response(resp).await
}

impl LocalLlmBackend for OpenRouterBackend {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        let url = self.chat_url();
        let body = ChatRequest {
            model: model.unwrap_or(DEFAULT_CHAT_MODEL).to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens: Some(MAX_TOKENS),
            max_completion_tokens: None,
            // C4: privacy default; deliberately no `response_format` /
            // `require_parameters` — `generate()` receives no schema.
            provider: Some(ProviderPrefs {
                data_collection: Some("deny".to_string()),
            }),
        };
        let resp = with_backoff(
            self.retry,
            || post_chat(self, &url, &body),
            LlmError::is_transient,
            retry_after_for,
        )
        .await?;

        match resp.choices.into_iter().next() {
            None => Err(LlmError::InvalidResponse("no choices returned".into())),
            Some(choice) => match choice.message.content {
                Some(c) if !c.is_empty() => Ok(c),
                Some(_) => Err(LlmError::InvalidResponse(
                    "chat response choice had empty content".into(),
                )),
                None => Err(LlmError::InvalidResponse(
                    "chat response choice had no content".into(),
                )),
            },
        }
    }

    async fn embed(&self, _text: &str, _model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        // R2/AC7: OpenRouter is chat-only. No network call is made — the
        // error is returned before any request is constructed.
        Err(LlmError::InvalidResponse(
            "OpenRouter backend is chat-only; embeddings are not supported".into(),
        ))
    }

    async fn is_available(&self) -> bool {
        let url = self.models_url();
        let resp = self
            .http
            .get(url)
            .header(
                "Authorization",
                format!("Bearer {}", self.api_key.expose_secret()),
            )
            .timeout(Duration::from_millis(HEALTH_CHECK_TIMEOUT_MS))
            .send()
            .await;
        matches!(resp, Ok(r) if r.status().is_success())
    }
}

// --- Tests -------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)] // env::set_var/remove_var in the AC6 override tests below.
mod tests {
    use super::*;
    use serial_test::serial;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    fn no_retry() -> RetryConfig {
        RetryConfig {
            max_retries: 0,
            ..Default::default()
        }
    }

    fn key(s: &str) -> SecretString {
        SecretString::new(s.to_string().into())
    }

    fn backend(endpoint: &str) -> OpenRouterBackend {
        OpenRouterBackend::new(endpoint, 5_000, no_retry(), None, None, key("test-key")).unwrap()
    }

    // -- AC2: happy path ----------------------------------------------------

    #[tokio::test]
    async fn generate_happy_path_posts_expected_request() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .and(matchers::header("Authorization", "Bearer test-key"))
            .and(matchers::body_partial_json(serde_json::json!({
                "model": "anthropic/claude-3.5-sonnet",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 2048
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "hello back" } }]
            })))
            .mount(&mock)
            .await;

        let backend = backend(&mock.uri());
        let out = backend
            .generate("hello", Some("anthropic/claude-3.5-sonnet"))
            .await
            .unwrap();
        assert_eq!(out, "hello back");
    }

    // AC10/AC12/E4: provider.data_collection == "deny", max_tokens present,
    // and NO response_format/require_parameters field is sent.
    #[tokio::test]
    async fn generate_body_has_privacy_default_and_no_response_format() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "ok" } }]
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        backend
            .generate("hi", Some("openai/gpt-4o-mini"))
            .await
            .unwrap();

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["max_tokens"], serde_json::json!(2048));
        assert_eq!(
            body["provider"]["data_collection"],
            serde_json::json!("deny")
        );
        assert!(body.get("max_completion_tokens").is_none());
        assert!(body.get("response_format").is_none());
        assert!(body.get("require_parameters").is_none());
        assert_eq!(
            body["messages"],
            serde_json::json!([{"role": "user", "content": "hi"}])
        );
    }

    #[tokio::test]
    async fn generate_model_verbatim_including_slash_and_free_suffix() {
        // E1: model slug with `/` and `:free` suffix passed verbatim.
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .and(matchers::body_partial_json(
                serde_json::json!({ "model": "meta-llama/llama-3.1-8b-instruct:free" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "ok" } }]
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        backend
            .generate("hi", Some("meta-llama/llama-3.1-8b-instruct:free"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn generate_uses_default_model_when_none_given() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .and(matchers::body_partial_json(
                serde_json::json!({ "model": DEFAULT_CHAT_MODEL }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "ok" } }]
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        backend.generate("hi", None).await.unwrap();
    }

    // -- AC3: HTTP-200-with-error body ---------------------------------------

    #[tokio::test]
    async fn inline_error_200_code_429_maps_to_rate_limit() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": { "code": 429, "message": "rate limited upstream" }
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(
            matches!(r, Err(LlmError::RateLimit { .. })),
            "expected RateLimit, got {r:?}"
        );
    }

    #[tokio::test]
    async fn inline_error_200_code_503_maps_to_transient_server() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": { "code": 503, "message": "upstream unavailable" }
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        match &r {
            Err(e @ LlmError::Server { status: 503, .. }) => {
                assert!(e.is_transient(), "503 must be transient");
            }
            other => panic!("expected Server{{503}}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inline_error_200_is_not_parsed_as_empty_choices() {
        // The mock body has NO `choices` key at all — a regression that read
        // `choices` before `error` would see an empty vec and return
        // InvalidResponse("no choices returned") instead of the mapped error.
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": { "code": "invalid_request", "message": "bad request shape" }
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(
            !matches!(r, Err(LlmError::InvalidResponse(ref m)) if m.contains("no choices")),
            "inline error must not be masked as an empty-choices InvalidResponse: {r:?}"
        );
        assert!(r.is_err());
    }

    // F-a: a 2xx body whose inline `error.code` is absent/non-numeric must
    // never fall back to the outer 200 status (C3 forbids ever leaving an
    // effective 200 on an error path).
    #[tokio::test]
    async fn inline_error_200_non_numeric_code_is_invalid_response_not_server_200() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": { "message": "invalid_request" }
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(
            matches!(r, Err(LlmError::InvalidResponse(_))),
            "F-a REGRESSION: expected InvalidResponse, got {r:?}"
        );
        assert!(
            !matches!(r, Err(LlmError::Server { status: 200, .. })),
            "F-a REGRESSION: C3 violated — inline error mapped to Server{{200}}: {r:?}"
        );
    }

    // F-d verification: OpenRouter's `map_response` (which checks `error`
    // before `choices`) runs inside `post_chat`, which is itself the closure
    // `with_backoff` retries — so an inline-transient error (e.g. inline 503)
    // must already be retried exactly like an HTTP-level transient failure,
    // with no code change required on this side of the fix.
    #[tokio::test]
    async fn inline_transient_error_is_retried_by_with_backoff() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": { "code": 503, "message": "upstream unavailable" }
            })))
            .up_to_n_times(2)
            .mount(&mock)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "hello back" } }]
            })))
            .mount(&mock)
            .await;

        let retry = RetryConfig {
            max_retries: 3,
            base_delay: Duration::from_millis(5),
            backoff_factor: 2.0,
            max_delay: Duration::from_millis(50),
        };
        let backend =
            OpenRouterBackend::new(&mock.uri(), 5_000, retry, None, None, key("test-key")).unwrap();
        let out = backend.generate("hi", Some("m")).await.unwrap();
        assert_eq!(out, "hello back");

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            3,
            "expected 2 inline-transient failures + 1 success to be retried"
        );
    }

    // -- AC4: status mapping --------------------------------------------------

    #[tokio::test]
    async fn status_401_maps_to_auth() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::Auth(_))));
    }

    #[tokio::test]
    async fn status_403_maps_to_auth() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::Auth(_))));
    }

    #[tokio::test]
    async fn status_402_maps_to_non_transient_server() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(402).set_body_string("payment required"))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        match &r {
            Err(e @ LlmError::Server { status: 402, .. }) => {
                assert!(!e.is_transient(), "402 must be non-transient");
            }
            other => panic!("expected Server{{402}}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn status_404_maps_to_non_transient_server() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown model"))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        match &r {
            Err(e @ LlmError::Server { status: 404, .. }) => {
                assert!(!e.is_transient(), "404 must be non-transient");
            }
            other => panic!("expected Server{{404}}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn status_429_with_retry_after() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "7")
                    .set_body_string("too many"),
            )
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        match r {
            Err(LlmError::RateLimit { retry_after }) => {
                assert_eq!(retry_after, Some(Duration::from_secs(7)));
            }
            other => panic!("expected RateLimit, got {other:?}"),
        }
    }

    // E6: 429 without Retry-After ⇒ retry_after: None.
    #[tokio::test]
    async fn status_429_without_retry_after() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(429).set_body_string("too many"))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        match r {
            Err(LlmError::RateLimit { retry_after }) => {
                assert_eq!(retry_after, None);
            }
            other => panic!("expected RateLimit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn status_500_maps_to_server() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::Server { status: 500, .. })));
    }

    #[tokio::test]
    async fn status_503_is_transient() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        match &r {
            Err(e @ LlmError::Server { status: 503, .. }) => assert!(e.is_transient()),
            other => panic!("expected Server{{503}}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_2xx_json_yields_invalid_response() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not valid json"))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::InvalidResponse(_))), "{r:?}");
    }

    // -- AC5: secret redaction (host redaction is WP4) -----------------------

    #[tokio::test]
    async fn error_body_with_sk_key_is_redacted_in_display() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_string(
                r#"{"error":{"message":"invalid key sk-abcdefghijklmnopqrstuvwxyz1234567890"}}"#,
            ))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let err = backend.generate("hi", Some("m")).await.unwrap_err();
        let display = err.to_string();
        assert!(
            !display.contains("abcdefghijklmnopqrstuvwxyz1234567890"),
            "AC5 REGRESSION: sk- key leaked into LlmError Display: {display}"
        );
    }

    // AC5 host-redaction portion (deferred from WP2 — `redact_secrets` did not
    // scrub `openrouter.ai` until WP4's redaction extension landed). Drives
    // the REAL backend error path (`build_error_summary` -> `redact_secrets`)
    // with an error body embedding the production `openrouter.ai` endpoint
    // host, and asserts the resulting `LlmError`'s `Display` contains neither
    // the host nor the synthetic key.
    #[tokio::test]
    async fn error_body_with_endpoint_host_is_redacted_in_display() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_string(
                r#"{"error":{"message":"invalid key sk-abcdefghijklmnopqrstuvwxyz1234567890 for host https://openrouter.ai/api/v1/chat/completions"}}"#,
            ))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let err = backend.generate("hi", Some("m")).await.unwrap_err();
        let display = err.to_string();
        assert!(
            !display.contains("openrouter.ai"),
            "AC5 REGRESSION: openrouter.ai endpoint host leaked into LlmError Display: {display}"
        );
        assert!(
            !display.contains("abcdefghijklmnopqrstuvwxyz1234567890"),
            "AC5 REGRESSION: sk- key leaked into LlmError Display: {display}"
        );
        // Note: the redaction MARKER itself is not asserted here — the error
        // summary bounds the body to `MAX_BODY_EXCERPT_BYTES` (80) *after*
        // redaction, so a long marker can be partially truncated in the
        // Display output. What matters (and is asserted above) is that
        // neither raw secret ever appears, truncated or not.
    }

    // -- AC6: construction hard-fail -----------------------------------------

    #[test]
    fn construction_rejects_non_https_remote_host() {
        let r = OpenRouterBackend::new(
            "http://openrouter.ai/api",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(matches!(r, Err(LlmError::Connection(_))));
    }

    #[tokio::test]
    #[serial(env_openrouter_hosts)]
    async fn construction_rejects_host_outside_allowlist() {
        // SAFETY: `serial` guarantees no concurrent env access in this test binary.
        unsafe { std::env::remove_var("CLX_ALLOW_OPENROUTER_HOSTS") };
        let r = OpenRouterBackend::new(
            "https://evil.example.com",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(matches!(r, Err(LlmError::Connection(_))));
    }

    #[test]
    fn construction_rejects_userinfo() {
        let r = OpenRouterBackend::new(
            "https://user:pass@openrouter.ai/api",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(matches!(r, Err(LlmError::Connection(_))));
    }

    #[test]
    fn construction_rejects_query_string() {
        let r = OpenRouterBackend::new(
            "https://openrouter.ai/api?foo=bar",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(matches!(r, Err(LlmError::Connection(_))));
    }

    #[test]
    fn construction_rejects_fragment() {
        let r = OpenRouterBackend::new(
            "https://openrouter.ai/api#frag",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(matches!(r, Err(LlmError::Connection(_))));
    }

    #[test]
    fn construction_rejects_non_default_port_on_remote_host() {
        let r = OpenRouterBackend::new(
            "https://openrouter.ai:8443/api",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(matches!(r, Err(LlmError::Connection(_))));
    }

    #[tokio::test]
    #[serial(env_openrouter_hosts)]
    async fn construction_allows_custom_host_with_env_override() {
        // SAFETY: `serial` guarantees no concurrent env access in this test binary.
        unsafe { std::env::set_var("CLX_ALLOW_OPENROUTER_HOSTS", "my-proxy.internal.example") };
        let r = OpenRouterBackend::new(
            "https://my-proxy.internal.example",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(r.is_ok(), "override host should construct OK: {r:?}");
        // SAFETY: `serial` guarantees no concurrent env access in this test binary.
        unsafe { std::env::remove_var("CLX_ALLOW_OPENROUTER_HOSTS") };
    }

    #[test]
    fn construction_allows_loopback_http() {
        let r = OpenRouterBackend::new(
            "http://127.0.0.1:9999",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(r.is_ok(), "loopback http should construct OK: {r:?}");
    }

    #[test]
    fn construction_allows_localhost_http() {
        let r = OpenRouterBackend::new(
            "http://localhost:9999",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(r.is_ok(), "localhost http should construct OK: {r:?}");
    }

    // F-b: `http://[::1]:PORT` must be recognized as loopback. `host_str()`
    // returns the bracketed form `"[::1]"` for this URL, which never equals
    // the bare `"::1"` a naive string comparison checks against; the fix
    // decides loopback-ness from the parsed `url::Host` enum instead.
    #[test]
    fn construction_allows_ipv6_loopback_http() {
        let r = OpenRouterBackend::new(
            "http://[::1]:8080/api",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(
            r.is_ok(),
            "F-b: IPv6 loopback http should construct OK: {r:?}"
        );
    }

    // F-e: a single trailing `.` on an otherwise-allowlisted domain (FQDN
    // notation) must not change the allowlist decision.
    #[test]
    fn construction_allows_trailing_dot_fqdn() {
        let r = OpenRouterBackend::new(
            "https://openrouter.ai./api",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(
            r.is_ok(),
            "F-e: trailing-dot FQDN should normalize and construct OK: {r:?}"
        );
    }

    #[test]
    fn construction_allows_openrouter_subdomain() {
        let r = OpenRouterBackend::new(
            "https://gateway.openrouter.ai/api",
            5_000,
            no_retry(),
            None,
            None,
            key("k"),
        );
        assert!(
            r.is_ok(),
            "*.openrouter.ai subdomain should be allowed: {r:?}"
        );
    }

    // -- AC6b: redirect safety ------------------------------------------------

    #[tokio::test]
    async fn redirect_to_other_host_is_not_followed() {
        let mock = MockServer::start().await;
        let other = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/steal", other.uri())),
            )
            .mount(&mock)
            .await;
        // The redirect target has no mock registered at all — if the client
        // ever followed the redirect it would 404 there (and be observed by
        // `received_requests`), rather than surfacing the 302 itself.
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(r.is_err(), "a 30x response must surface as an error");
        let other_requests = other.received_requests().await.unwrap();
        assert!(
            other_requests.is_empty(),
            "AC6b REGRESSION: client followed the redirect to another host: {other_requests:?}"
        );
    }

    // -- AC7: embed is chat-only, no network ----------------------------------

    #[tokio::test]
    async fn embed_returns_invalid_response_without_network_call() {
        let mock = MockServer::start().await;
        // No mocks registered at all — any network call would be unmatched.
        let backend = backend(&mock.uri());
        let r = backend.embed("text", Some("m")).await;
        assert!(matches!(r, Err(LlmError::InvalidResponse(_))));
        let requests = mock.received_requests().await.unwrap();
        assert!(
            requests.is_empty(),
            "AC7 REGRESSION: embed() issued a network call: {requests:?}"
        );
    }

    // -- AC11: URL normalization ----------------------------------------------

    #[test]
    fn url_normalization_variants_resolve_to_canonical_paths() {
        for suffix in ["/api", "/api/", "/api/v1", "/api/v1/", ""] {
            let endpoint = format!("https://openrouter.ai{suffix}");
            let backend =
                OpenRouterBackend::new(&endpoint, 5_000, no_retry(), None, None, key("k")).unwrap();
            assert_eq!(
                backend.chat_url().path(),
                "/api/v1/chat/completions",
                "chat_url mismatch for endpoint {endpoint:?}"
            );
            assert_eq!(
                backend.models_url().path(),
                "/api/v1/models",
                "models_url mismatch for endpoint {endpoint:?}"
            );
        }
    }

    // -- E5: absent/null/empty content -----------------------------------------

    #[tokio::test]
    async fn generate_null_content_yields_invalid_response() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": null } }]
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::InvalidResponse(_))));
    }

    #[tokio::test]
    async fn generate_absent_content_field_yields_invalid_response() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": {} }]
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::InvalidResponse(_))));
    }

    #[tokio::test]
    async fn generate_empty_string_content_yields_invalid_response() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "" } }]
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::InvalidResponse(_))));
    }

    #[tokio::test]
    async fn generate_empty_choices_yields_invalid_response() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": []
            })))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let r = backend.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::InvalidResponse(_))));
    }

    // -- E7: is_available bounded probe ---------------------------------------

    #[tokio::test]
    async fn is_available_true_on_2xx() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        assert!(backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_false_on_5xx() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/v1/models"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        assert!(!backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_false_when_probe_exceeds_budget() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/v1/models"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(4_500))
                    .set_body_json(serde_json::json!({"data": []})),
            )
            .mount(&mock)
            .await;
        let backend = backend(&mock.uri());
        let start = std::time::Instant::now();
        let available = backend.is_available().await;
        let elapsed = start.elapsed();
        assert!(!available, "slow probe must report unavailable");
        assert!(
            elapsed < Duration::from_millis(3_500),
            "probe should bail at ~{HEALTH_CHECK_TIMEOUT_MS}ms, took {elapsed:?}"
        );
    }

    // -- referer/title headers -------------------------------------------------

    #[tokio::test]
    async fn generate_sends_optional_referer_and_title_headers() {
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chat/completions"))
            .and(matchers::header("HTTP-Referer", "https://example.com/clx"))
            .and(matchers::header("X-Title", "CLX"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "ok" } }]
            })))
            .mount(&mock)
            .await;
        let backend = OpenRouterBackend::new(
            &mock.uri(),
            5_000,
            no_retry(),
            Some("https://example.com/clx".to_string()),
            Some("CLX".to_string()),
            key("test-key"),
        )
        .unwrap();
        backend.generate("hi", Some("m")).await.unwrap();
    }
}
