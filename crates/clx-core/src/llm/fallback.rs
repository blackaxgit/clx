//! Primary→secondary LLM provider fallback wrapper.
//!
//! Wraps two `LlmClient` instances. On a transient error from the primary,
//! falls back to the secondary. After a fallback event, a 30-second cooldown
//! skips the primary entirely so a sustained outage does not pay the latency
//! penalty of always hitting the dead primary first.
//!
//! The cooldown is enforced at two scopes (FIX-7):
//! 1. an in-process `Mutex<Option<Instant>>` fast path, and
//! 2. a cross-process file marker in [`crate::llm_health`], so that a recent
//!    primary failure recorded by a *prior* hook process (CLX runs
//!    one-process-per-event) still short-circuits to the fallback.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::llm::{LlmClient, LlmError, LocalLlmBackend};
use crate::llm_health;

/// Sticky-fallback duration after a primary failure.
const COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct FallbackClient {
    primary: Box<LlmClient>,
    fallback: Box<LlmClient>,
    /// If set, overrides the caller's `model` arg when delegating to the
    /// fallback. Necessary because providers don't share model names
    /// (e.g. `gpt-5.4-mini` only exists on Azure).
    fallback_model: Option<String>,
    /// `Some(t)` means primary failed at instant `t`; skip primary until
    /// `t.elapsed() >= COOLDOWN`. In-process fast path.
    last_primary_failure: Mutex<Option<Instant>>,
    /// Optional override for the cross-process marker's base directory. `None`
    /// uses the real CLX data dir; tests point this at a temp dir.
    health_base: Option<PathBuf>,
}

impl FallbackClient {
    #[must_use]
    pub fn new(primary: LlmClient, fallback: LlmClient, fallback_model: Option<String>) -> Self {
        Self {
            primary: Box::new(primary),
            fallback: Box::new(fallback),
            fallback_model,
            last_primary_failure: Mutex::new(None),
            health_base: None,
        }
    }

    /// Test-only constructor that routes the cross-process failure marker
    /// through `base` instead of the real CLX data dir.
    #[cfg(test)]
    fn new_with_health_base(
        primary: LlmClient,
        fallback: LlmClient,
        fallback_model: Option<String>,
        base: PathBuf,
    ) -> Self {
        Self {
            primary: Box::new(primary),
            fallback: Box::new(fallback),
            fallback_model,
            last_primary_failure: Mutex::new(None),
            health_base: Some(base),
        }
    }

    /// Cross-process check: did a prior (or this) process record a primary
    /// failure within the cooldown window? Bounded, non-blocking file read.
    fn cross_process_failure_active(&self) -> bool {
        match &self.health_base {
            Some(base) => llm_health::primary_failure_active_in(base, COOLDOWN),
            None => llm_health::primary_failure_active(COOLDOWN),
        }
    }

    fn use_fallback_directly(&self) -> bool {
        // Fast path: in-process cooldown.
        let in_process_active = matches!(
            *self
                .last_primary_failure
                .lock()
                .expect("poisoned cooldown lock"),
            Some(t) if t.elapsed() < COOLDOWN
        );
        // Cross-process path: a prior hook process may have recorded a failure.
        in_process_active || self.cross_process_failure_active()
    }

    fn record_primary_failure(&self) {
        *self
            .last_primary_failure
            .lock()
            .expect("poisoned cooldown lock") = Some(Instant::now());
        // Seed the cross-process marker so the next per-event process skips
        // the dead primary too. Best-effort; never blocks the LLM path.
        match &self.health_base {
            Some(base) => llm_health::record_primary_failure_in(base),
            None => llm_health::record_primary_failure(),
        }
    }

    fn fb_model<'a>(&'a self, caller: Option<&'a str>) -> Option<&'a str> {
        self.fallback_model.as_deref().or(caller)
    }

    /// Test-only accessor — exposes whether cooldown is currently active.
    #[cfg(test)]
    pub(crate) fn cooldown_active(&self) -> bool {
        self.use_fallback_directly()
    }
}

impl LocalLlmBackend for FallbackClient {
    async fn generate(&self, prompt: &str, model: Option<&str>) -> Result<String, LlmError> {
        if self.use_fallback_directly() {
            let fb_model = self.fb_model(model).map(str::to_owned);
            return Box::pin(self.fallback.generate(prompt, fb_model.as_deref())).await;
        }
        match Box::pin(self.primary.generate(prompt, model)).await {
            Ok(v) => Ok(v),
            Err(e) if e.is_transient() => {
                tracing::warn!(
                    op = "generate",
                    error.kind = %e.kind_str(),
                    "primary failed; falling back"
                );
                self.record_primary_failure();
                let fb_model = self.fb_model(model).map(str::to_owned);
                Box::pin(self.fallback.generate(prompt, fb_model.as_deref())).await
            }
            Err(e) => Err(e),
        }
    }

    async fn embed(&self, text: &str, model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        if self.use_fallback_directly() {
            let fb_model = self.fb_model(model).map(str::to_owned);
            return Box::pin(self.fallback.embed(text, fb_model.as_deref())).await;
        }
        match Box::pin(self.primary.embed(text, model)).await {
            Ok(v) => Ok(v),
            Err(e) if e.is_transient() => {
                tracing::warn!(
                    op = "embed",
                    error.kind = %e.kind_str(),
                    "primary failed; falling back"
                );
                self.record_primary_failure();
                let fb_model = self.fb_model(model).map(str::to_owned);
                Box::pin(self.fallback.embed(text, fb_model.as_deref())).await
            }
            Err(e) => Err(e),
        }
    }

    async fn is_available(&self) -> bool {
        // Either backend healthy means "fallback path is alive." When the
        // cross-process cooldown is active (a recent primary failure), probe the
        // fallback FIRST so a one-shot hook process does not pay the dead
        // primary's probe latency before checking the live fallback.
        if self.use_fallback_directly() {
            return Box::pin(self.fallback.is_available()).await
                || Box::pin(self.primary.is_available()).await;
        }
        Box::pin(self.primary.is_available()).await || Box::pin(self.fallback.is_available()).await
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::config::AzureOpenAIConfig;
    use crate::llm::AzureOpenAIBackend;
    use crate::llm::retry::RetryConfig;
    use secrecy::SecretString;
    use serial_test::serial;
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
        // SAFETY: test-only env var manipulation
        unsafe {
            std::env::set_var("CLX_ALLOW_AZURE_HOSTS", "127.0.0.1,localhost");
        }
    }

    fn azure(uri: String) -> LlmClient {
        let backend =
            AzureOpenAIBackend::new(&cfg(uri), SecretString::new("k".to_string().into())).unwrap();
        LlmClient::Azure(backend)
    }

    /// Counter for unique isolated health-cache base dirs across tests.
    static FC_BASE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Build a `FallbackClient` whose cross-process failure marker lives in a
    /// fresh, unique temp dir, so no test touches the real CLX data dir or
    /// observes another test's marker.
    fn fc_isolated(
        primary: LlmClient,
        fallback: LlmClient,
        fallback_model: Option<String>,
    ) -> FallbackClient {
        let n = FC_BASE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "clx-fallback-iso-{}-{:?}-{n}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&base);
        FallbackClient::new_with_health_base(primary, fallback, fallback_model, base)
    }

    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn fallback_on_primary_503_succeeds() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503).set_body_string("overloaded"))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "from fallback" } }]
            })))
            .expect(1)
            .mount(&fallback_mock)
            .await;

        let fc = fc_isolated(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            Some("fallback-model".into()),
        );

        let out = fc.generate("hi", Some("primary-model")).await.unwrap();
        assert_eq!(out, "from fallback");
    }

    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn fallback_not_used_on_terminal_error() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("should not fire"))
            .expect(0)
            .mount(&fallback_mock)
            .await;

        let fc = fc_isolated(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);

        let r = fc.generate("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::Auth(_))));
    }

    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn cooldown_skips_primary_after_failure() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "ok" } }]
            })))
            .expect(2)
            .mount(&fallback_mock)
            .await;

        let fc = fc_isolated(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);

        let _ = fc.generate("hi", Some("m")).await.unwrap();
        assert!(fc.cooldown_active());

        let out = fc.generate("hi again", Some("m")).await.unwrap();
        assert_eq!(out, "ok");
    }

    // Branch: embed() primary transient failure -> fallback succeeds.
    // Mirrors the generate() path but exercises the separate embed arm.
    // Kills a mutant that drops the embed fallback (would surface the 503)
    // or that forwards to the primary a second time.
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn embed_falls_back_on_primary_transient() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(503).set_body_string("overloaded"))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{ "embedding": vec![0.25f32; 8] }]
            })))
            .expect(1)
            .mount(&fallback_mock)
            .await;

        let fc = fc_isolated(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            Some("fb-embed-model".into()),
        );

        let v = fc
            .embed("hi", Some("primary-embed-model"))
            .await
            .expect("embed should fall back to secondary");
        assert_eq!(v.len(), 8);
        assert!(fc.cooldown_active(), "embed failure must arm the cooldown");
    }

    // Branch: embed() primary terminal (401) error -> NO fallback, error surfaces.
    // Kills a mutant that treats every embed error as transient and falls back.
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn embed_terminal_error_does_not_fall_back() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&primary_mock)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&fallback_mock)
            .await;

        let fc = fc_isolated(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);

        let r = fc.embed("hi", Some("m")).await;
        assert!(matches!(r, Err(LlmError::Auth(_))));
        assert!(
            !fc.cooldown_active(),
            "a terminal error must NOT arm the fallback cooldown"
        );
    }

    // Branch: fb_model() returns the caller's model when fallback_model is None.
    // We prove this by mounting the fallback to only succeed for the caller's
    // model arg. Kills a mutant that hard-codes the fallback model to None or
    // drops the `.or(caller)` fallback in `fb_model`.
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn fallback_uses_caller_model_when_no_override() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&primary_mock)
            .await;

        // Fallback only matches when the request carries the caller's model.
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .and(matchers::body_partial_json(serde_json::json!({
                "model": "caller-model"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "via-caller-model" } }]
            })))
            .expect(1)
            .mount(&fallback_mock)
            .await;

        // fallback_model = None -> fb_model must reuse the caller's model arg.
        let fc = fc_isolated(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);

        let out = fc.generate("hi", Some("caller-model")).await.unwrap();
        assert_eq!(out, "via-caller-model");
    }

    /// Unique temp base dir for the cross-process failure marker.
    fn temp_health_base(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "clx-fallback-health-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    // FIX-7: a primary failure recorded by a PRIOR process (file marker) must
    // make a freshly-constructed FallbackClient (clean in-process state) skip
    // the primary entirely. Before the fix the cooldown lived only in an
    // in-process Mutex, so a new process always re-hit the dead primary.
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn cross_process_recorded_failure_skips_primary() {
        allow_local();
        let base = temp_health_base("recent");
        // Simulate a prior process recording a recent primary failure.
        crate::llm_health::record_primary_failure_in(&base);

        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        // Primary must NOT be contacted at all.
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "should-not-happen" } }]
            })))
            .expect(0)
            .mount(&primary_mock)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "from fallback" } }]
            })))
            .expect(1)
            .mount(&fallback_mock)
            .await;

        // Fresh client: in-process cooldown is empty, only the file marker is set.
        let fc = FallbackClient::new_with_health_base(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            None,
            base.clone(),
        );
        assert!(
            fc.cooldown_active(),
            "recent cross-process failure must arm the cooldown"
        );
        let out = fc.generate("hi", Some("m")).await.unwrap();
        assert_eq!(out, "from fallback");

        let _ = std::fs::remove_dir_all(&base);
    }

    // FIX-7: an ABSENT cross-process marker must NOT short-circuit; the primary
    // is contacted normally.
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn absent_cross_process_marker_uses_primary() {
        allow_local();
        let base = temp_health_base("absent");
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::create_dir_all(&base);

        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "from primary" } }]
            })))
            .expect(1)
            .mount(&primary_mock)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new_with_health_base(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            None,
            base.clone(),
        );
        assert!(
            !fc.cooldown_active(),
            "no recorded failure => cooldown inactive"
        );
        let out = fc.generate("hi", Some("m")).await.unwrap();
        assert_eq!(out, "from primary");

        let _ = std::fs::remove_dir_all(&base);
    }

    // FIX-7: an EXPIRED marker (older than COOLDOWN) must NOT short-circuit.
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn expired_cross_process_marker_uses_primary() {
        allow_local();
        let base = temp_health_base("expired");
        crate::llm_health::record_primary_failure_in(&base);

        // Backdate the marker well beyond COOLDOWN (30s).
        let marker = base.join("primary_llm_failure");
        let past = std::time::SystemTime::now() - Duration::from_mins(2);
        let times = std::fs::FileTimes::new().set_modified(past);
        let f = std::fs::File::options().write(true).open(&marker).unwrap();
        f.set_times(times).unwrap();
        drop(f);

        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": "from primary" } }]
            })))
            .expect(1)
            .mount(&primary_mock)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/openai/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&fallback_mock)
            .await;

        let fc = FallbackClient::new_with_health_base(
            azure(primary_mock.uri()),
            azure(fallback_mock.uri()),
            None,
            base.clone(),
        );
        assert!(
            !fc.cooldown_active(),
            "expired marker must NOT arm the cooldown"
        );
        let out = fc.generate("hi", Some("m")).await.unwrap();
        assert_eq!(out, "from primary");

        let _ = std::fs::remove_dir_all(&base);
    }

    // Branch: is_available() short-circuits true when the PRIMARY is healthy.
    // Kills a mutant that flips the `||` to `&&` (would require both up) or one
    // that always returns false.
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn is_available_true_when_primary_healthy() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&primary_mock)
            .await;
        // Fallback would 500 if consulted; primary's 200 must short-circuit.
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&fallback_mock)
            .await;

        let fc = fc_isolated(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);
        assert!(fc.is_available().await, "primary healthy => available");
    }

    // Branch: is_available() falls through to the FALLBACK when primary is down.
    // Kills a mutant that only checks the primary (would return false here).
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn is_available_true_when_only_fallback_healthy() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&primary_mock)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&fallback_mock)
            .await;

        let fc = fc_isolated(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);
        assert!(
            fc.is_available().await,
            "primary down but fallback healthy => still available"
        );
    }

    // Branch: is_available() returns false only when BOTH backends are down.
    // Kills a mutant that returns true unconditionally.
    #[tokio::test]
    #[serial(env_azure_hosts)]
    async fn is_available_false_when_both_down() {
        allow_local();
        let primary_mock = MockServer::start().await;
        let fallback_mock = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&primary_mock)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openai/v1/models"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&fallback_mock)
            .await;

        let fc = fc_isolated(azure(primary_mock.uri()), azure(fallback_mock.uri()), None);
        assert!(
            !fc.is_available().await,
            "both backends down => not available"
        );
    }
}
