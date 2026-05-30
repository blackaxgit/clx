//! RED-R1 delta pre-release PoCs (redaction surface, surface 2).
//!
//! ALL tests here are `#[ignore]`-gated so the default suite stays green.
//! Run explicitly with:
//!   cargo test -p clx-core --test delta_red_r1_poc -- --ignored
//!
//! Every input is SYNTHETIC. No real secret, key, or tenant URL appears here.
//! These probe the `redact_secrets` Bearer/Basic + keyword paths as they stand
//! at base `main` @ 63ec0d3. A PoC that asserts a secret SURVIVED proves a
//! no-code-exec leak; when GREEN closes it, that assertion flips and the test
//! must be updated to assert absence.
#![allow(clippy::doc_markdown)]

use clx_core::redaction::redact_secrets;

/// R1-DELTA-A (leak probe): short credential after a bare `Bearer` scheme word.
/// The scheme path requires `token_end - token_start >= 6` (redaction.rs:276),
/// so a <=5-char token after `Bearer ` is NOT redacted. R1-B dropped the length
/// floor for the keyword path but the scheme path kept it.
#[test]
#[ignore = "RED-R1 delta PoC; run with --ignored"]
fn r1_delta_short_bearer_token_leaks() {
    let out = redact_secrets("Bearer ab123"); // 5-char token, was under the >=6 floor
    println!("R1-DELTA-A out={out:?}");
    // CLOSED (post-GREEN): scheme path now redacts any non-empty token.
    assert!(
        !out.contains("ab123"),
        "CLOSURE: short bearer token must be redacted; got {out}"
    );
}

/// R1-DELTA-A2: confirm a >=6 token after the same scheme IS redacted (control).
#[test]
#[ignore = "RED-R1 delta PoC; run with --ignored"]
fn r1_delta_long_bearer_token_redacts_control() {
    let out = redact_secrets("Bearer abc123def");
    println!("R1-DELTA-A2 out={out:?}");
    assert!(
        !out.contains("abc123def"),
        "control: long token must redact: {out}"
    );
}

/// R1-DELTA-B (CRLF probe): CR/LF after the scheme word. `is_ascii_whitespace`
/// covers `\r` and `\n`, so this should redact (refutation control).
#[test]
#[ignore = "RED-R1 delta PoC; run with --ignored"]
fn r1_delta_crlf_after_bearer_redacts() {
    let out = redact_secrets("Authorization: Bearer\r\nSYNTHETICTOKEN1234567");
    println!("R1-DELTA-B out={out:?}");
    assert!(
        !out.contains("SYNTHETICTOKEN1234567"),
        "control: CRLF-after-Bearer must redact: {out}"
    );
}

/// R1-DELTA-C (keyword newline-value, R1-D): `password:\n<secret>` must redact.
#[test]
#[ignore = "RED-R1 delta PoC; run with --ignored"]
fn r1_delta_newline_separated_value_redacts() {
    let out = redact_secrets("password:\nSYNTHSECRET99");
    println!("R1-DELTA-C out={out:?}");
    assert!(
        !out.contains("SYNTHSECRET99"),
        "newline-value must redact: {out}"
    );
}

/// R1-DELTA-D (short keyword value, R1-B): any non-empty value after a keyword.
#[test]
#[ignore = "RED-R1 delta PoC; run with --ignored"]
fn r1_delta_short_keyword_value_redacts() {
    let out = redact_secrets("password:1234");
    println!("R1-DELTA-D out={out:?}");
    assert!(
        !out.contains("1234"),
        "short keyword value must redact: {out}"
    );
}

/// R1-DELTA-E (multi-Bearer all-occurrences): both tokens must redact.
#[test]
#[ignore = "RED-R1 delta PoC; run with --ignored"]
fn r1_delta_multi_bearer_all_redact() {
    let out = redact_secrets("Bearer firsttoken111111 and Bearer secondtoken222222");
    println!("R1-DELTA-E out={out:?}");
    assert!(!out.contains("firsttoken111111"), "first leaked: {out}");
    assert!(!out.contains("secondtoken222222"), "second leaked: {out}");
}

/// R1-DELTA-F (interplay probe): keyword `authorization:` followed by `Bearer`
/// then a SHORT token. Section 3 (scheme) sees `Bearer ` + short token (<6 ->
/// not redacted); section 2b skips the scheme word. Does the short token leak
/// even WITH the keyword present? Probes the cross-section gap.
#[test]
#[ignore = "RED-R1 delta PoC; run with --ignored"]
fn r1_delta_keyword_then_short_bearer_token() {
    let out = redact_secrets("authorization: Bearer ab12");
    println!("R1-DELTA-F out={out:?}");
    // CLOSED (post-GREEN): the compound leak is closed. Pre-fix NEITHER path
    // redacted the short token (keyword path defers to scheme on `Bearer`; the
    // scheme path declined under the >=6 floor). GREEN's floor fix closes it.
    assert!(
        !out.contains("ab12"),
        "CLOSURE: keyword+short-scheme token must be redacted; got {out}"
    );
}
