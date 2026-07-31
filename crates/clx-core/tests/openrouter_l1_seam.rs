//! AC8 (mandatory) — `OpenRouter` L1 policy-seam integration test.
//!
//! Proves the `OpenRouter` backend plugs into the existing L1 command-risk
//! validator with ZERO changes to the validator itself: the seam is
//!
//!   config (`providers.openrouter` + `llm.chat`)
//!     -> `Config::create_llm_client(Capability::Chat)`
//!     -> `LlmClient::OpenRouter::generate` (wiremock, HTTP loopback)
//!     -> `PolicyEngine::evaluate_with_llm`
//!     -> `PolicyDecision`
//!
//! `policy/llm.rs` and `pre_tool_use.rs` are untouched by the `OpenRouter`
//! feature (R7) — this test exercises the real `evaluate_with_llm` code path
//! against a real (mocked-at-the-wire) `LlmClient::OpenRouter`, not a stub.
//!
//! Two contracts are proven:
//! - Happy path: a valid validator-shaped JSON verdict maps to the expected
//!   `PolicyDecision` via the existing `risk_score_to_decision` bands
//!   (1-3 Allow, 8-10 Deny) — unchanged by which backend produced the text.
//! - Fail-closed: a malformed/garbage 200 body is unparseable, so
//!   `evaluate_with_llm` returns `Ask` (C5 — a remote low-risk verdict is
//!   never the sole gate; unparseable output must never silently Allow).

use clx_core::config::{
    Capability, CapabilityRoute, Config, LlmRouting, OpenRouterConfig, ProviderConfig,
};
use clx_core::policy::{PolicyDecision, PolicyEngine};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a `Config` routing `llm.chat` to a single `openrouter` provider
/// pointed at the given wiremock loopback URI. `api_key_env` names a
/// per-test-unique env var (set by the caller) so credential resolution
/// never touches the local credential store.
fn config_for(endpoint: &str, api_key_env: &str) -> Config {
    let mut cfg = Config {
        providers: std::collections::BTreeMap::new(),
        ..Config::default()
    };
    cfg.providers.insert(
        "openrouter".to_string(),
        ProviderConfig::OpenRouter(OpenRouterConfig {
            endpoint: endpoint.to_string(),
            api_key_env: Some(api_key_env.to_string()),
            api_key_file: None,
            timeout_ms: 5_000,
            retry: clx_core::llm::RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            referer: None,
            title: None,
        }),
    );
    let route = CapabilityRoute {
        provider: "openrouter".to_string(),
        model: "anthropic/claude-3.5-sonnet".to_string(),
        fallback: None,
        dimension: None,
    };
    cfg.llm = Some(LlmRouting {
        chat: route.clone(),
        // Not exercised by this test (only Capability::Chat is requested),
        // but `LlmRouting` requires both fields.
        embeddings: route,
    });
    cfg
}

/// Mount a `/api/v1/chat/completions` response whose `choices[0].message.content`
/// is the given raw string (the validator JSON verdict, or garbage).
async fn mount_chat_completion(server: &MockServer, content: &str) {
    Mock::given(method("POST"))
        .and(path("/api/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "content": content } }]
        })))
        .mount(server)
        .await;
}

async fn run_seam(server: &MockServer, api_key_env: &str) -> PolicyDecision {
    let cfg = config_for(&server.uri(), api_key_env);
    let client = cfg
        .create_llm_client(Capability::Chat)
        .expect("openrouter chat client must construct (loopback http, valid config)");

    let engine = PolicyEngine::new();
    engine
        .evaluate_with_llm(
            "Bash",
            "rm -rf /tmp/some-dir",
            "/tmp/project",
            &client,
            "anthropic/claude-3.5-sonnet",
            None,
            &clx_core::config::PromptSensitivity::Standard,
        )
        .await
}

#[tokio::test]
async fn ac8_seam_high_risk_score_maps_to_deny() {
    // SAFETY: this env var name is unique to this test function and read
    // only by the credential-resolution path exercised here.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("CLX_TEST_OR_SEAM_KEY_DENY", "dummy-seam-key");
    }

    let server = MockServer::start().await;
    mount_chat_completion(
        &server,
        r#"{"risk_score": 9, "reasoning": "recursive delete of a directory", "category": "dangerous"}"#,
    )
    .await;

    let decision = run_seam(&server, "CLX_TEST_OR_SEAM_KEY_DENY").await;

    #[allow(unsafe_code)]
    unsafe {
        std::env::remove_var("CLX_TEST_OR_SEAM_KEY_DENY");
    }

    match decision {
        PolicyDecision::Deny { reason } => {
            assert!(
                reason.contains("dangerous"),
                "expected the category in the deny reason: {reason}"
            );
        }
        other => panic!("AC8 REGRESSION: expected Deny for risk_score=9, got {other:?}"),
    }
}

#[tokio::test]
async fn ac8_seam_low_risk_score_maps_to_allow() {
    // SAFETY: unique env var name for this test function.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("CLX_TEST_OR_SEAM_KEY_ALLOW", "dummy-seam-key");
    }

    let server = MockServer::start().await;
    mount_chat_completion(
        &server,
        r#"{"risk_score": 2, "reasoning": "read-only listing", "category": "safe"}"#,
    )
    .await;

    let decision = run_seam(&server, "CLX_TEST_OR_SEAM_KEY_ALLOW").await;

    #[allow(unsafe_code)]
    unsafe {
        std::env::remove_var("CLX_TEST_OR_SEAM_KEY_ALLOW");
    }

    assert!(
        matches!(decision, PolicyDecision::Allow),
        "AC8 REGRESSION: expected Allow for risk_score=2, got {decision:?}"
    );
}

/// C5/AC8 fail-closed contract: a malformed/garbage 200 body from the
/// OpenRouter-routed L1 call must never silently Allow — `evaluate_with_llm`
/// must fall back to `Ask` when the response cannot be parsed as the
/// validator JSON shape. Proves the zero-change validator integration holds
/// on the failure path too, not just the happy path.
#[tokio::test]
async fn ac8_seam_malformed_response_yields_ask() {
    // SAFETY: unique env var name for this test function.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("CLX_TEST_OR_SEAM_KEY_ASK", "dummy-seam-key");
    }

    let server = MockServer::start().await;
    // Not JSON at all — no `risk_score`/`reasoning`/`category` shape.
    mount_chat_completion(&server, "this is not json, just garbage prose").await;

    let decision = run_seam(&server, "CLX_TEST_OR_SEAM_KEY_ASK").await;

    #[allow(unsafe_code)]
    unsafe {
        std::env::remove_var("CLX_TEST_OR_SEAM_KEY_ASK");
    }

    assert!(
        matches!(decision, PolicyDecision::Ask { .. }),
        "AC8/C5 REGRESSION: malformed OpenRouter response must fail-closed to Ask, got {decision:?}"
    );
}
