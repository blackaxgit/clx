//! Holistic RED-R1 PoC tests: redaction pipeline + credential store surfaces.
//!
//! All tests are `#[ignore]`-gated so the default suite stays green. Run with:
//!   cargo nextest run -p clx-core --test holistic_red_r1_poc -- --ignored
//!
//! Synthetic placeholders ONLY. Hermetic: pure functions + tempdir; no network,
//! no real keychain, no real model.

#![allow(
    clippy::pedantic,
    clippy::restriction,
    clippy::nursery,
    clippy::doc_markdown
)]

use clx_core::redaction::{redact_json_value, redact_secrets};

// =============================================================================
// SURFACE 1 - Redaction pipeline (free-text + JSON)
// =============================================================================

/// R1-RED-A (CONFIRMED gap): `redact_secrets` only redacts the FIRST `Bearer`
/// and the FIRST `Basic` token in a string. A second credential of the same
/// scheme in the same blob survives verbatim.
#[test]
#[ignore = "RED PoC: proves second Bearer token leaks"]
fn red_a_second_bearer_token_leaks() {
    // Realistic repeated header form (HTTP debug dump of two requests).
    let text = "req1 Authorization: Bearer AAAAAAAAAAAAAAAAAAAA \
                req2 Authorization: Bearer SECONDLEAK999999999999";
    let out = redact_secrets(text);
    assert!(
        !out.contains("AAAAAAAAAAAAAAAAAAAA"),
        "first bearer should be redacted: {out}"
    );
    assert!(
        out.contains("SECONDLEAK999999999999"),
        "RED-A: expected second bearer to leak (single-find bug); got: {out}"
    );
}

/// R1-RED-B (CONFIRMED gap): a short keyword value (<= 4 chars after the
/// separator) is NOT redacted by the tolerant keyword scan
/// (`value_end > value_start + 4`).
#[test]
#[ignore = "RED PoC: proves short keyword value leaks"]
fn red_b_short_keyword_value_leaks() {
    let text = "the password = 1234 was used";
    let out = redact_secrets(text);
    assert!(
        out.contains("1234"),
        "RED-B: expected 4-char password value to leak; got: {out}"
    );
}

/// R1-RED-D (CONFIRMED gap): newline-separated keyword value. The tolerant
/// keyword scan stops the separator-skip at `\n`, so `api_key:\n<secret>`
/// (value on the next line, common in YAML / pretty-printed error bodies) is
/// NOT redacted by free-text `redact_secrets`.
#[test]
#[ignore = "RED PoC: proves newline-separated keyword value leaks"]
fn red_d_newline_separated_value_leaks() {
    let text = "config error:\napi_key:\nSUPERSECRETVALUE1234567890";
    let out = redact_secrets(text);
    assert!(
        out.contains("SUPERSECRETVALUE1234567890"),
        "RED-D: expected newline-separated api_key value to leak; got: {out}"
    );
}

/// R1-RED-E (CONFIRMED gap): base64 / opaque high-entropy secrets with NO
/// recognised prefix and NO `keyword=` context pass through verbatim.
#[test]
#[ignore = "RED PoC: proves bare high-entropy token is not redacted"]
fn red_e_bare_high_entropy_token_leaks() {
    let text = "the value is dGhpc2lzYXNlY3JldHRoYXRzaG91bGRiZXJlZGFjdGVk";
    let out = redact_secrets(text);
    assert!(
        out.contains("dGhpc2lzYXNlY3JldHRoYXRzaG91bGRiZXJlZGFjdGVk"),
        "RED-E: bare high-entropy token survives (no entropy heuristic); got: {out}"
    );
}

/// R1-RED-F (REFUTED): structured JSON secret under a sensitive key IS scrubbed.
#[test]
#[ignore = "RED PoC (refuted): redact_json_value scrubs structured secret"]
fn red_f_json_value_path_is_safe() {
    let v = serde_json::json!({"deeply": {"client_secret": "plainsecretvalue123"}});
    let out = redact_json_value(&v);
    assert_eq!(
        out["deeply"]["client_secret"],
        serde_json::json!("***REDACTED***")
    );
}

// =============================================================================
// SURFACE 2 - Credential store
// =============================================================================

/// R1-RED-G (CONFIRMED, info): `CredentialError` Display propagates inner text
/// to MCP/log sinks (`tool_credentials` returns `format!("...: {e}")`).
#[test]
#[ignore = "RED PoC: credential error Display surfaces inner platform text"]
fn red_g_credential_error_display_surfaces_inner_text() {
    use clx_core::credentials::CredentialError;
    let e = CredentialError::ServiceUnavailable(
        "Keychain service error: synthetic-inner-detail-LEAKMARKER".to_string(),
    );
    let rendered = format!("{e}");
    assert!(
        rendered.contains("LEAKMARKER"),
        "credential error Display propagates inner text to MCP/log sinks: {rendered}"
    );
}

/// R1-RED-H (REFUTED): the age-encrypted file blob never contains plaintext.
#[test]
#[ignore = "RED PoC (refuted): age blob is ciphertext"]
fn red_h_age_blob_is_ciphertext() {
    use clx_core::credentials::{AgeFileBackend, CredentialBackend};
    let tmp = tempfile::tempdir().unwrap();
    let b = AgeFileBackend::with_dir(tmp.path()).unwrap();
    b.set("clx:global:k", "PLAINTEXT-SENTINEL-REDR1").unwrap();
    let bytes = std::fs::read(tmp.path().join("credentials.age")).unwrap();
    let hay = String::from_utf8_lossy(&bytes);
    assert!(
        !hay.contains("PLAINTEXT-SENTINEL-REDR1"),
        "age blob must be ciphertext"
    );
}
