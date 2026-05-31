//! Fixed-vector regression tests for the security redaction + config-trust
//! boundaries.
//!
//! Public boundary: `clx_core::redaction::redact_secrets` / `redact_json_value`
//! for connection strings, PEM private-key material, shell `export` secrets,
//! and Bearer tokens embedded in JSON leaves.
//!
//! NOTE on config-trust: the brief also asked for a config-trust filter
//! invariant "if a public API exists". It does NOT: the untrusted-config filter
//! lives in `clx_core::config::project::filter_inert_only`, but the `project`
//! module is `pub(crate)` with no re-export, so it is unreachable from an
//! integration test. That invariant is already covered by the crate-internal
//! `#[cfg(test)]` suite in `config/project.rs` (see `b4_1_*`,
//! `drops_entire_validator_subtree_from_untrusted_config`).
//!
//! ALL secrets are synthetic (fake passwords, EXAMPLE keys, fake PEM blocks).
//! No real tenant URL or credential appears.
//!
//! Fault model targeted: a regression that stops scrubbing the password inside
//! a connection string, lets PEM key bytes through, drops the export-pattern
//! floor, or leaks a Bearer token in a JSON leaf would re-fail these vectors.

use clx_core::redaction::{redact_json_value, redact_secrets};

// ---------------------------------------------------------------------------
// Connection-string vectors
// ---------------------------------------------------------------------------

/// A SQL-Server-style connection string with an inline `Password=` field must
/// have the password value scrubbed to the stable `***REDACTED***` floor while
/// the surrounding non-secret fields remain.
#[test]
fn connection_string_password_field_is_redacted() {
    let secret = "Sup3rSecretPw_fake";
    let text = format!("Server=tcp:db.internal,1433;Database=app;User ID=svc;Password={secret};");
    let out = redact_secrets(&text);
    assert!(
        !out.contains(secret),
        "connection-string password leaked: {out}"
    );
    assert!(
        out.contains("Password=***REDACTED***"),
        "password field must collapse to the redaction floor: {out}"
    );
    // Non-secret context preserved.
    assert!(out.contains("Server=tcp:db.internal,1433"), "out={out}");
    assert!(out.contains("Database=app"), "out={out}");
}

/// Lowercase `password=` in a URL-ish/query form must also be scrubbed (the
/// keyword match is case-insensitive).
#[test]
fn connection_string_lowercase_password_is_redacted() {
    let secret = "anotherFakePw99";
    let text = format!("postgres host=db user=svc password={secret} sslmode=require");
    let out = redact_secrets(&text);
    assert!(!out.contains(secret), "lowercase password leaked: {out}");
    assert!(out.contains("***REDACTED***"), "out={out}");
}

// ---------------------------------------------------------------------------
// PEM private-key vectors
// ---------------------------------------------------------------------------

/// A PEM private key embedded under a sensitive JSON key must be fully replaced
/// by the redaction floor (the whole value, not a partial scrub), so no base64
/// key material survives.
#[test]
fn pem_private_key_under_sensitive_json_key_is_fully_redacted() {
    // Synthetic, non-functional PEM block. The base64 body is fake.
    let fake_pem = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIBOwIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
KUpRKfFLfRYC9AIFAKE0FAKEbase64bodyAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n\
-----END RSA PRIVATE KEY-----";
    let v = serde_json::json!({ "private_key": fake_pem, "name": "svc-account" });
    let r = redact_json_value(&v);
    // The whole sensitive value collapses to the floor.
    assert_eq!(
        r["private_key"],
        serde_json::json!("***REDACTED***"),
        "private_key value must be fully redacted: {r}"
    );
    // None of the (fake) base64 body may survive anywhere in the output.
    let serialized = r.to_string();
    assert!(
        !serialized.contains("FAKE0FAKEbase64body"),
        "PEM key material leaked in serialized output: {serialized}"
    );
    assert!(
        !serialized.contains("BEGIN RSA PRIVATE KEY"),
        "PEM header leaked: {serialized}"
    );
    // Non-sensitive sibling preserved.
    assert_eq!(r["name"], serde_json::json!("svc-account"));
}

/// A sensitive JSON key carrying a structured credential object must redact the
/// entire object, never recursing into and partially exposing nested fields.
#[test]
fn sensitive_key_redacts_whole_credential_object() {
    let v = serde_json::json!({
        "credentials": { "user": "alice", "password": "hunter2fake", "private_key": "abc" }
    });
    let r = redact_json_value(&v);
    assert_eq!(r["credentials"], serde_json::json!("***REDACTED***"));
    let serialized = r.to_string();
    assert!(
        !serialized.contains("hunter2fake"),
        "nested pw leaked: {serialized}"
    );
    assert!(
        !serialized.contains("alice"),
        "nested user leaked: {serialized}"
    );
}

// ---------------------------------------------------------------------------
// Additional fixed-vector redaction floors (export + bearer in JSON leaves)
// ---------------------------------------------------------------------------

/// Shell `export AWS_SECRET_ACCESS_KEY=...` style line: the value must be
/// scrubbed because the variable name contains a sensitive keyword (KEY/SECRET).
/// Pins the export-pattern floor against a realistic AWS-shaped synthetic value.
#[test]
fn export_aws_secret_access_key_is_redacted() {
    // AKIA... is the documented AWS EXAMPLE access-key id; the secret below is
    // a synthetic 40-char placeholder, never a real credential.
    let secret = "wJalrXUtnFEMIfakeKEYfakefakefakefakefake1";
    let text = format!("export AWS_SECRET_ACCESS_KEY={secret}");
    let out = redact_secrets(&text);
    assert!(!out.contains(secret), "export secret value leaked: {out}");
    assert!(out.contains("***REDACTED***"), "out={out}");
}

/// A Bearer token sitting in a plain (non-sensitive-keyed) JSON string leaf
/// must still be scrubbed via the string-level `redact_secrets` pass, so token
/// material never survives even when the key name looks innocent.
#[test]
fn bearer_token_in_plain_json_leaf_is_redacted() {
    let token = "eyJfakeheaderFAKE.eyJfakepayloadFAKE.sigFAKEsigFAKE";
    let v = serde_json::json!({
        "log_line": format!("upstream replied 401 for Authorization: Bearer {token}"),
        "request_id": "req-123"
    });
    let r = redact_json_value(&v);
    let serialized = r.to_string();
    assert!(
        !serialized.contains(token),
        "bearer token in JSON leaf leaked: {serialized}"
    );
    assert!(
        serialized.contains("Bearer ***REDACTED***"),
        "bearer floor must appear: {serialized}"
    );
    // Non-secret sibling preserved.
    assert_eq!(r["request_id"], serde_json::json!("req-123"));
}
