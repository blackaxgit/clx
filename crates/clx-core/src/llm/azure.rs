//! Azure OpenAI backend (hand-rolled reqwest client).
//!
//! Targets the v1 OpenAI-compatible path by default
//! (`/openai/v1/chat/completions`, `/openai/v1/embeddings`,
//! `/openai/v1/models`). If the user sets `api_version` in the provider
//! config, switches to the dated URL shape
//! (`/openai/deployments/<deployment>/...?api-version=<v>`).

use crate::config::AzureOpenAIConfig;
use crate::llm::retry::{RetryConfig, with_backoff};
use crate::llm::{LlmError, LocalLlmBackend};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct AzureOpenAIBackend {
    endpoint: Url,
    api_key: SecretString,
    api_version: Option<String>,
    retry: RetryConfig,
    http: reqwest::Client,
}

const ALLOWED_HOST_SUFFIXES: &[&str] = &[".openai.azure.com", ".azure-api.net"];

impl AzureOpenAIBackend {
    pub fn new(cfg: &AzureOpenAIConfig, api_key: SecretString) -> Result<Self, LlmError> {
        let endpoint = Url::parse(&cfg.endpoint)
            .map_err(|e| LlmError::Connection(format!("invalid endpoint URL: {e}")))?;
        Self::validate_host(&endpoint)?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()
            .map_err(|e| LlmError::Connection(format!("http client init: {e}")))?;

        Ok(Self {
            endpoint,
            api_key,
            api_version: cfg.api_version.clone().filter(|s| !s.is_empty()),
            retry: cfg.retry,
            http,
        })
    }

    fn validate_host(url: &Url) -> Result<(), LlmError> {
        let host = url
            .host_str()
            .ok_or_else(|| LlmError::Connection("endpoint URL has no host".into()))?;

        // Allow override for dev tenants / emulators / wiremock tests.
        if let Ok(allowlist) = std::env::var("CLX_ALLOW_AZURE_HOSTS") {
            for h in allowlist
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if host == h {
                    return Ok(());
                }
            }
        }

        for suffix in ALLOWED_HOST_SUFFIXES {
            if host.ends_with(suffix) {
                return Ok(());
            }
        }
        Err(LlmError::Connection(format!(
            "host '{host}' not in azure allowlist (set CLX_ALLOW_AZURE_HOSTS to override)"
        )))
    }

    fn chat_url(&self, deployment: &str) -> Url {
        let mut u = self.endpoint.clone();
        match &self.api_version {
            Some(v) => {
                u.set_path(&format!(
                    "/openai/deployments/{deployment}/chat/completions"
                ));
                u.query_pairs_mut().clear().append_pair("api-version", v);
            }
            None => u.set_path("/openai/v1/chat/completions"),
        }
        u
    }

    fn embeddings_url(&self, deployment: &str) -> Url {
        let mut u = self.endpoint.clone();
        match &self.api_version {
            Some(v) => {
                u.set_path(&format!("/openai/deployments/{deployment}/embeddings"));
                u.query_pairs_mut().clear().append_pair("api-version", v);
            }
            None => u.set_path("/openai/v1/embeddings"),
        }
        u
    }

    fn models_url(&self) -> Url {
        let mut u = self.endpoint.clone();
        match &self.api_version {
            Some(v) => {
                u.set_path("/openai/models");
                u.query_pairs_mut().clear().append_pair("api-version", v);
            }
            None => u.set_path("/openai/v1/models"),
        }
        u
    }
}

// --- Wire types ----------------------------------------------------------

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    content: String,
}

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<u32>,
}

#[derive(Deserialize)]
struct EmbedResponse {
    data: Vec<EmbedDatum>,
}

#[derive(Deserialize)]
struct EmbedDatum {
    embedding: Vec<f32>,
}

// --- Helpers -------------------------------------------------------------

fn is_transient(e: &LlmError) -> bool {
    matches!(
        e,
        LlmError::Timeout | LlmError::RateLimit { .. } | LlmError::Connection(_)
    ) || matches!(
        e,
        LlmError::Server { status, .. } if (500..=599).contains(status) || *status == 408
    )
}

fn retry_after_for(e: &LlmError) -> Option<Duration> {
    match e {
        LlmError::RateLimit { retry_after } => *retry_after,
        _ => None,
    }
}

async fn map_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, LlmError> {
    let status = resp.status();
    let request_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if status.is_success() {
        let txt = resp
            .text()
            .await
            .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;
        serde_json::from_str(&txt).map_err(LlmError::Serialization)
    } else {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs);
        let body = resp.text().await.unwrap_or_default();
        let body_with_id = if request_id.is_empty() {
            body.clone()
        } else {
            format!("{body} (x-request-id: {request_id})")
        };
        match status.as_u16() {
            401 | 403 => Err(LlmError::Auth(body_with_id)),
            404 => Err(LlmError::DeploymentNotFound(body_with_id)),
            408 => Err(LlmError::Timeout),
            429 => Err(LlmError::RateLimit { retry_after }),
            400 if body.contains("content_filter") => Err(LlmError::ContentFilter(body_with_id)),
            s => Err(LlmError::Server {
                status: s,
                body: body_with_id,
            }),
        }
    }
}

async fn post_chat(
    backend: &AzureOpenAIBackend,
    url: &Url,
    body: &ChatRequest<'_>,
) -> Result<ChatResponse, LlmError> {
    let resp = backend
        .http
        .post(url.clone())
        .header("api-key", backend.api_key.expose_secret())
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                LlmError::Timeout
            } else {
                LlmError::Connection(e.to_string())
            }
        })?;
    map_response(resp).await
}

async fn post_embed(
    backend: &AzureOpenAIBackend,
    url: &Url,
    body: &EmbedRequest<'_>,
) -> Result<EmbedResponse, LlmError> {
    let resp = backend
        .http
        .post(url.clone())
        .header("api-key", backend.api_key.expose_secret())
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                LlmError::Timeout
            } else {
                LlmError::Connection(e.to_string())
            }
        })?;
    map_response(resp).await
}

// --- Trait impl ----------------------------------------------------------

impl LocalLlmBackend for AzureOpenAIBackend {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        let deployment = model.ok_or_else(|| {
            LlmError::DeploymentNotFound("no model/deployment specified for chat".into())
        })?;
        let url = self.chat_url(deployment);
        let body = ChatRequest {
            model: deployment,
            messages: vec![ChatMessage {
                role: "user",
                content: prompt,
            }],
            max_completion_tokens: Some(2048),
        };
        let resp = with_backoff(
            self.retry,
            || post_chat(self, &url, &body),
            is_transient,
            retry_after_for,
        )
        .await?;
        resp.choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| LlmError::InvalidResponse("no choices returned".into()))
    }

    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        let deployment = model.ok_or_else(|| {
            LlmError::DeploymentNotFound("no model/deployment specified for embeddings".into())
        })?;
        let url = self.embeddings_url(deployment);
        let body = EmbedRequest {
            model: deployment,
            input: text,
            dimensions: Some(1024),
        };
        let resp = with_backoff(
            self.retry,
            || post_embed(self, &url, &body),
            is_transient,
            retry_after_for,
        )
        .await?;
        resp.data
            .into_iter()
            .next()
            .map(|d| d.embedding)
            .ok_or_else(|| LlmError::InvalidResponse("no embeddings returned".into()))
    }

    async fn is_available(&self) -> bool {
        let url = self.models_url();
        let resp = self
            .http
            .get(url)
            .header("api-key", self.api_key.expose_secret())
            .send()
            .await;
        matches!(resp, Ok(r) if r.status().is_success())
    }
}

// --- Tests ---------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    fn cfg(endpoint: String) -> AzureOpenAIConfig {
        AzureOpenAIConfig {
            endpoint,
            api_key_env: None,
            api_key_file: None,
            api_version: None,
            timeout_ms: 5_000,
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
        }
    }

    fn allow_local() {
        // SAFETY: tests run in separate processes; no other threads read this var
        // concurrently at the point it is set.
        unsafe {
            std::env::set_var("CLX_ALLOW_AZURE_HOSTS", "127.0.0.1,localhost");
        }
    }

    #[tokio::test]
    async fn chat_happy_path() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .and(matchers::header("api-key", "test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "hello back" } }]
            })))
            .mount(&mock)
            .await;
        let backend = AzureOpenAIBackend::new(
            &cfg(mock.uri()),
            SecretString::new("test-key".to_string().into()),
        )
        .unwrap();
        let out = backend
            .generate("hello", Some("gpt-5.4-mini"))
            .await
            .unwrap();
        assert_eq!(out, "hello back");
    }

    #[tokio::test]
    async fn embed_happy_path() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{ "embedding": vec![0.1f32; 1024] }]
            })))
            .mount(&mock)
            .await;
        let backend = AzureOpenAIBackend::new(
            &cfg(mock.uri()),
            SecretString::new("test-key".to_string().into()),
        )
        .unwrap();
        let v = backend
            .embed("text", Some("text-embedding-3-large"))
            .await
            .unwrap();
        assert_eq!(v.len(), 1024);
    }

    #[tokio::test]
    async fn host_outside_allowlist_rejected() {
        // SAFETY: single-threaded at this point in the test; no concurrent readers.
        unsafe { std::env::remove_var("CLX_ALLOW_AZURE_HOSTS") };
        let r = AzureOpenAIBackend::new(
            &cfg("https://evil.example.com".into()),
            SecretString::new("k".to_string().into()),
        );
        assert!(matches!(r, Err(LlmError::Connection(_))));
    }

    #[tokio::test]
    async fn auth_401_maps_to_auth_error() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&mock)
            .await;
        let backend = AzureOpenAIBackend::new(
            &cfg(mock.uri()),
            SecretString::new("bad-key".to_string().into()),
        )
        .unwrap();
        let r = backend.generate("hi", Some("gpt-5.4-mini")).await;
        assert!(matches!(r, Err(LlmError::Auth(_))));
    }

    #[tokio::test]
    async fn deployment_not_found_404() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(404).set_body_string("deployment not found"))
            .mount(&mock)
            .await;
        let backend =
            AzureOpenAIBackend::new(&cfg(mock.uri()), SecretString::new("k".to_string().into()))
                .unwrap();
        let r = backend.generate("hi", Some("does-not-exist")).await;
        assert!(matches!(r, Err(LlmError::DeploymentNotFound(_))));
    }

    #[tokio::test]
    async fn rate_limit_with_retry_after() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "2")
                    .set_body_string("too many"),
            )
            .mount(&mock)
            .await;
        let backend =
            AzureOpenAIBackend::new(&cfg(mock.uri()), SecretString::new("k".to_string().into()))
                .unwrap();
        let r = backend.generate("hi", Some("gpt-5.4-mini")).await;
        match r {
            Err(LlmError::RateLimit { retry_after }) => {
                assert_eq!(retry_after, Some(Duration::from_secs(2)));
            }
            other => panic!("expected RateLimit, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn content_filter_400() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                r#"{"error":{"code":"content_filter","message":"hate detected"}}"#,
            ))
            .mount(&mock)
            .await;
        let backend =
            AzureOpenAIBackend::new(&cfg(mock.uri()), SecretString::new("k".to_string().into()))
                .unwrap();
        let r = backend.generate("hi", Some("gpt-5.4-mini")).await;
        assert!(matches!(r, Err(LlmError::ContentFilter(_))));
    }

    #[tokio::test]
    async fn server_500_after_no_retries_surfaced() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
            .mount(&mock)
            .await;
        let backend =
            AzureOpenAIBackend::new(&cfg(mock.uri()), SecretString::new("k".to_string().into()))
                .unwrap();
        let r = backend.generate("hi", Some("gpt-5.4-mini")).await;
        assert!(matches!(r, Err(LlmError::Server { status: 500, .. })));
    }

    #[tokio::test]
    async fn is_available_true_on_2xx() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data":[]})))
            .mount(&mock)
            .await;
        let backend =
            AzureOpenAIBackend::new(&cfg(mock.uri()), SecretString::new("k".to_string().into()))
                .unwrap();
        assert!(backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_false_on_5xx() {
        allow_local();
        let mock = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;
        let backend =
            AzureOpenAIBackend::new(&cfg(mock.uri()), SecretString::new("k".to_string().into()))
                .unwrap();
        assert!(!backend.is_available().await);
    }
}
