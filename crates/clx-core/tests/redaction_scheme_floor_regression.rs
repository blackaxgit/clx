//! R1-DELTA-A regression: Bearer/Basic scheme-path redaction floor.
//!
//! The scheme branch in `redact_secrets` previously kept a `token_end -
//! token_start >= 6` minimum-length floor, so a token of <=5 chars after a
//! bare `Bearer `/`Basic ` scheme word survived unredacted. The keyword path
//! had already dropped its floor (R1-B: redact ANY non-empty value); this pins
//! the scheme path to the same contract.
//!
//! These assertions FAIL pre-fix (short token leaks) and PASS post-fix.
//! All strings are SYNTHETIC.

use clx_core::redaction::redact_secrets;

#[test]
fn short_bearer_token_is_redacted() {
    // 5-char token: under the old >=6 floor, so it leaked pre-fix.
    let r = redact_secrets("Bearer ab123");
    assert!(
        !r.contains("ab123"),
        "short Bearer token must be redacted: {r}"
    );
    assert!(
        r.contains("***REDACTED***"),
        "redaction marker must appear: {r}"
    );
}

#[test]
fn short_bearer_token_via_authorization_header_is_redacted() {
    // The keyword path defers to the scheme path on the `Bearer` first word;
    // pre-fix the scheme path declined under the floor, leaving this FULLY
    // unredacted (no marker at all).
    let r = redact_secrets("authorization: Bearer ab12");
    assert!(
        !r.contains("ab12"),
        "short token in Authorization header must be redacted: {r}"
    );
    assert!(
        r.contains("***REDACTED***"),
        "redaction marker must appear: {r}"
    );
}

#[test]
fn one_char_bearer_token_is_redacted() {
    let r = redact_secrets("Bearer x");
    assert!(
        !r.contains(" x"),
        "1-char Bearer token must be redacted: {r}"
    );
    assert!(
        r.contains("Bearer ***REDACTED***"),
        "marker must replace the 1-char token: {r}"
    );
}

#[test]
fn short_basic_token_is_redacted() {
    let r = redact_secrets("Basic abc");
    assert!(
        !r.contains("abc"),
        "short Basic token must be redacted: {r}"
    );
    assert!(
        r.contains("***REDACTED***"),
        "redaction marker must appear: {r}"
    );
}

// ---------------------------------------------------------------------------
// Non-regression: existing correct behavior must be preserved.
// ---------------------------------------------------------------------------

#[test]
fn long_bearer_token_still_redacted() {
    let r = redact_secrets("Bearer longsecrettokenvalue123456");
    assert!(
        !r.contains("longsecrettokenvalue123456"),
        "long token must still redact: {r}"
    );
    assert!(r.contains("Bearer ***REDACTED***"), "got: {r}");
}

#[test]
fn multiple_short_and_long_occurrences_all_redacted() {
    let r = redact_secrets("Bearer ab12 and Bearer longertoken99 then Bearer z");
    assert!(!r.contains("ab12"), "first short token leaked: {r}");
    assert!(!r.contains("longertoken99"), "middle token leaked: {r}");
    assert!(!r.contains(" z"), "trailing 1-char token leaked: {r}");
}

#[test]
fn tab_and_newline_separator_still_redacted() {
    let r = redact_secrets("Authorization:\nBearer\tSECRETVALUE123456");
    assert!(
        !r.contains("SECRETVALUE123456"),
        "tab-after-Bearer must still redact: {r}"
    );
    // A short token with a tab separator must redact too (floor removal +
    // whitespace tolerance combined).
    let r2 = redact_secrets("Bearer\tab12");
    assert!(
        !r2.contains("ab12"),
        "short token after tab must redact: {r2}"
    );
}

// ---------------------------------------------------------------------------
// Edge: a bare scheme word with no following token must not panic and must
// not produce a spurious marker (there is nothing to redact).
// ---------------------------------------------------------------------------

#[test]
fn bare_scheme_word_no_token_is_inert() {
    let bare = redact_secrets("Bearer");
    assert_eq!(bare, "Bearer", "bare `Bearer` must pass through unchanged");

    let trailing_space = redact_secrets("Bearer ");
    assert_eq!(
        trailing_space, "Bearer ",
        "`Bearer ` (whitespace-only after scheme) must not produce a marker"
    );

    let trailing_newline = redact_secrets("Bearer\n");
    assert_eq!(
        trailing_newline, "Bearer\n",
        "`Bearer\\n` (whitespace-only after scheme) must not produce a marker"
    );
}
