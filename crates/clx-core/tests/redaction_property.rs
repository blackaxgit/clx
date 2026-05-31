//! Property-based tests for `clx_core::redaction::redact_secrets`.
//!
//! Public boundary: `redact_secrets(&str) -> String`. These properties pin
//! invariants that fixed-vector tests cannot: idempotence, total/never-panic
//! behavior over arbitrary input, no-leak for generated secret shapes, and
//! preservation of inert text.
//!
//! ALL secrets here are synthetic. No real tenant URL or key appears.
//!
//! Fault model targeted: a regression that makes redaction non-idempotent
//! (double-redacting or re-exposing), panics on adversarial input, leaks a
//! generated secret tail, or starts mangling inert prose.

use clx_core::redaction::redact_secrets;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Idempotence: redacting an already-redacted string is a fixed point.
    /// A second pass must not change the output (no double-marker growth,
    /// no re-detection of the `***REDACTED***` marker as a fresh secret).
    #[test]
    fn redact_is_idempotent(s in ".{0,300}") {
        let once = redact_secrets(&s);
        let twice = redact_secrets(&once);
        prop_assert_eq!(&twice, &once, "redact_secrets must be idempotent");
    }

    /// Totality: never panics on arbitrary input, including control chars,
    /// unbalanced quotes, and embedded keyword fragments. (The test body
    /// completing without unwinding is the assertion.)
    #[test]
    fn redact_never_panics_on_arbitrary_input(s in any::<String>()) {
        let _ = redact_secrets(&s);
    }

    /// No-leak for `sk-` prefixed keys: a generated OpenAI-style key with a
    /// sufficiently long tail must never survive verbatim in the output.
    #[test]
    fn redact_scrubs_sk_prefixed_keys(tail in "[A-Za-z0-9]{8,40}") {
        let secret = format!("sk-{tail}");
        let text = format!("authorization header was {secret} end");
        let out = redact_secrets(&text);
        prop_assert!(
            !out.contains(&secret),
            "sk- key leaked: secret={secret} out={out}"
        );
        prop_assert!(out.contains("sk-***REDACTED***"), "out={out}");
    }

    /// No-leak for keyword=value secrets: the value after a sensitive keyword
    /// separator must never survive, regardless of value content.
    #[test]
    fn redact_scrubs_keyword_value_pairs(
        kw in prop::sample::select(vec!["api_key", "token", "password", "secret"]),
        sep in prop::sample::select(vec!["=", ":"]),
        val in "[A-Za-z0-9_]{4,40}",
    ) {
        let text = format!("{kw}{sep}{val} trailing");
        let out = redact_secrets(&text);
        prop_assert!(
            !out.contains(&val),
            "keyword value leaked: kw={kw} sep={sep} val={val} out={out}"
        );
    }

    /// No-leak for Bearer tokens: any non-empty token after a `Bearer ` scheme
    /// word must be scrubbed.
    #[test]
    fn redact_scrubs_bearer_tokens(tok in "[A-Za-z0-9._-]{6,60}") {
        let text = format!("Authorization: Bearer {tok}");
        let out = redact_secrets(&text);
        prop_assert!(!out.contains(&tok), "bearer token leaked: tok={tok} out={out}");
    }

    /// Inert text preservation: strings drawn from a safe alphabet that contain
    /// no secret prefix, no sensitive keyword, and no `://` must round-trip
    /// UNCHANGED. This guards against over-redaction of ordinary prose/commands.
    #[test]
    fn redact_preserves_inert_text(words in prop::collection::vec("[a-z]{1,8}", 1..12)) {
        let text = words.join(" ");
        // Reject any accidental sensitive substring so the property is sound.
        let lower = text.to_lowercase();
        prop_assume!(!["sk-", "pk-", "ghp_", "gho_", "xoxb-", "xoxp-",
                       "key", "token", "password", "secret", "auth",
                       "bearer", "basic", "export", "credential", "api",
                       "://"]
            .iter()
            .any(|p| lower.contains(p)));
        let out = redact_secrets(&text);
        prop_assert_eq!(&out, &text, "inert text was modified: {}", text);
    }
}
