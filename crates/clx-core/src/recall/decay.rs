//! Time-decay and percentile-gate stages for the recall pipeline.
//!
//! Both functions are pure (no IO, no global state) and deterministic given
//! their inputs. They are intended to be chained after the RRF fusion step
//! inside `RecallEngine::query`.
//!
//! ## Time-decay (multiplicative half-life)
//!
//! ```text
//! final_score = base_score * 0.5_f64.powf(age_days / half_life_days)
//! ```
//!
//! At `age_days == half_life_days` the score is halved. At `age_days == 0`
//! the score is unchanged. Negative ages (clock-skew between snapshot
//! creation and recall time) are clamped to zero so we never amplify a score.
//!
//! ## Percentile gate
//!
//! Compute the `p_th` percentile of hit scores, then drop hits below that
//! threshold. With `percentile == 0` the filter is a passthrough. With one
//! or zero input hits we return the input unchanged (a percentile is not
//! meaningfully defined on a single element).
//!
//! ## Layering
//!
//! Domain layer: both functions take owned inputs, return owned outputs,
//! and depend only on `chrono` for parsing the snapshot timestamp.

use chrono::{DateTime, Utc};

use super::RecallHit;

/// Apply multiplicative time-decay to each hit's score, in place.
///
/// * `hits` - the slice to mutate.
/// * `half_life_days` - the half-life of the decay curve in days. A value
///   of `30.0` means a 30-day-old hit retains half of its base score. A
///   value of `0.0` or below disables decay (treated as passthrough to
///   avoid divide-by-zero or unbounded decay).
/// * `now` - the reference time. Injected (rather than calling `Utc::now()`
///   internally) so tests are deterministic.
///
/// Hits whose `created_at` field fails to parse as RFC-3339 are left
/// unchanged (no panic; the recall pipeline should never collapse on a
/// malformed timestamp).
pub fn apply_time_decay(hits: &mut [RecallHit], half_life_days: f64, now: DateTime<Utc>) {
    if half_life_days <= 0.0 {
        // Disabled by config: no-op.
        return;
    }

    for hit in hits.iter_mut() {
        let Ok(created) = DateTime::parse_from_rfc3339(&hit.created_at) else {
            // Malformed timestamp: leave the score untouched.
            continue;
        };

        let created_utc: DateTime<Utc> = created.with_timezone(&Utc);
        let age_seconds = now
            .signed_duration_since(created_utc)
            .num_seconds();

        // Convert to fractional days. Clamp negative ages (clock skew) to 0
        // so we never multiply by a value greater than 1.0.
        let age_days = (age_seconds as f64 / 86_400.0).max(0.0);

        // Multiplicative half-life: score *= 0.5 ^ (age_days / half_life_days).
        let decay = 0.5_f64.powf(age_days / half_life_days);
        hit.score *= decay;
    }
}

/// Drop hits with a score strictly below the `p_th` percentile.
///
/// * `hits` - the input list. Returned unchanged if `percentile == 0`,
///   `hits.len() <= 1`, or if `percentile > 100`.
/// * `percentile` - the cutoff percentile in `[0, 100]`. Common values:
///   `70` keeps the top ~30%, `50` keeps the top half, `90` keeps the
///   top ~10%.
///
/// Ties at the percentile threshold are kept (`>= threshold`, not `>`), so
/// behaviour is stable when many hits share the same score.
#[must_use]
pub fn apply_percentile_gate(hits: Vec<RecallHit>, percentile: u32) -> Vec<RecallHit> {
    if percentile == 0 || hits.len() <= 1 || percentile > 100 {
        return hits;
    }

    // Collect the score distribution.
    let mut scores: Vec<f64> = hits.iter().map(|h| h.score).collect();
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // Linear-interpolation percentile (NIST method R6): for n samples,
    // the p-th percentile index is `(p/100) * (n - 1)` zero-based.
    // We use the nearest-rank variant via index clamping to keep the math
    // straightforward; for our use case (top-K filtering) this is sufficient.
    let n = scores.len();
    let rank = (f64::from(percentile) / 100.0) * (n as f64 - 1.0);
    let idx = rank.round() as usize;
    let idx = idx.min(n - 1);
    let threshold = scores[idx];

    hits.into_iter().filter(|h| h.score >= threshold).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recall::RecallSearchType;
    use chrono::Duration;

    fn hit_with_score_and_age(snapshot_id: i64, score: f64, age_days: f64, now: DateTime<Utc>) -> RecallHit {
        let created = now - Duration::seconds((age_days * 86_400.0) as i64);
        RecallHit {
            snapshot_id,
            session_id: format!("session-{snapshot_id}"),
            created_at: created.to_rfc3339(),
            summary: Some(format!("Summary {snapshot_id}")),
            key_facts: Some(format!("Facts {snapshot_id}")),
            score,
            search_type: RecallSearchType::Semantic,
        }
    }

    fn fixed_now() -> DateTime<Utc> {
        "2026-05-16T12:00:00+00:00"
            .parse::<DateTime<Utc>>()
            .expect("static rfc3339 must parse")
    }

    #[test]
    fn decay_at_half_life_halves_score() {
        let now = fixed_now();
        let mut hits = vec![hit_with_score_and_age(1, 1.0, 30.0, now)];
        apply_time_decay(&mut hits, 30.0, now);
        assert!(
            (hits[0].score - 0.5).abs() < 1e-6,
            "at one half-life, score should halve; got {}",
            hits[0].score
        );
    }

    #[test]
    fn decay_at_zero_age_unchanged() {
        let now = fixed_now();
        let mut hits = vec![hit_with_score_and_age(1, 0.8, 0.0, now)];
        apply_time_decay(&mut hits, 30.0, now);
        assert!(
            (hits[0].score - 0.8).abs() < 1e-6,
            "score at age=0 must be unchanged; got {}",
            hits[0].score
        );
    }

    #[test]
    fn decay_at_two_half_lives_quarters_score() {
        let now = fixed_now();
        let mut hits = vec![hit_with_score_and_age(1, 1.0, 60.0, now)];
        apply_time_decay(&mut hits, 30.0, now);
        assert!(
            (hits[0].score - 0.25).abs() < 1e-6,
            "at two half-lives, score should be quartered; got {}",
            hits[0].score
        );
    }

    #[test]
    fn decay_clamps_negative_age_to_zero() {
        // Future-dated snapshot (clock skew). Age becomes negative; clamped
        // to 0 means the score stays at the base value.
        let now = fixed_now();
        let mut hits = vec![hit_with_score_and_age(1, 0.7, -10.0, now)];
        apply_time_decay(&mut hits, 30.0, now);
        assert!(
            (hits[0].score - 0.7).abs() < 1e-6,
            "future-dated hit must not amplify; got {}",
            hits[0].score
        );
        assert!(
            hits[0].score <= 0.7,
            "decayed score must never exceed base; got {}",
            hits[0].score
        );
    }

    #[test]
    fn decay_empty_input_is_a_noop() {
        let now = fixed_now();
        let mut hits: Vec<RecallHit> = Vec::new();
        apply_time_decay(&mut hits, 30.0, now);
        assert!(hits.is_empty());
    }

    #[test]
    fn decay_half_life_zero_is_passthrough() {
        // half_life_days <= 0.0 disables decay (no divide-by-zero, no NaN).
        let now = fixed_now();
        let mut hits = vec![hit_with_score_and_age(1, 0.6, 90.0, now)];
        apply_time_decay(&mut hits, 0.0, now);
        assert!((hits[0].score - 0.6).abs() < 1e-12);
    }

    #[test]
    fn decay_fractional_half_life() {
        // Half-life 7.5 days, age 15 days => two half-lives => 0.25.
        let now = fixed_now();
        let mut hits = vec![hit_with_score_and_age(1, 1.0, 15.0, now)];
        apply_time_decay(&mut hits, 7.5, now);
        assert!(
            (hits[0].score - 0.25).abs() < 1e-6,
            "two fractional half-lives should quarter score; got {}",
            hits[0].score
        );
    }

    #[test]
    fn decay_malformed_timestamp_leaves_score_untouched() {
        let now = fixed_now();
        let mut hits = vec![RecallHit {
            snapshot_id: 1,
            session_id: "s".into(),
            created_at: "not-a-real-timestamp".into(),
            summary: None,
            key_facts: None,
            score: 0.9,
            search_type: RecallSearchType::Semantic,
        }];
        apply_time_decay(&mut hits, 30.0, now);
        assert!((hits[0].score - 0.9).abs() < 1e-12);
    }

    #[test]
    fn gate_percentile_zero_keeps_all() {
        let now = fixed_now();
        let hits: Vec<RecallHit> = (1..=5)
            .map(|i| hit_with_score_and_age(i as i64, f64::from(i as u32) * 0.1, 0.0, now))
            .collect();
        let filtered = apply_percentile_gate(hits.clone(), 0);
        assert_eq!(filtered.len(), hits.len());
    }

    #[test]
    fn gate_single_hit_returned_unchanged() {
        let now = fixed_now();
        let hits = vec![hit_with_score_and_age(1, 0.1, 0.0, now)];
        let filtered = apply_percentile_gate(hits, 70);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn gate_empty_input_returns_empty() {
        let filtered = apply_percentile_gate(Vec::<RecallHit>::new(), 70);
        assert!(filtered.is_empty());
    }

    #[test]
    fn gate_p70_keeps_top_30_percent() {
        // 10 hits with scores 0.1, 0.2, ..., 1.0.
        // p70 across (0..=9) gives rank index round(0.7 * 9) = round(6.3) = 6,
        // threshold = scores[6] = 0.7. Hits with score >= 0.7 are kept: 0.7..1.0.
        let now = fixed_now();
        let hits: Vec<RecallHit> = (1..=10)
            .map(|i| hit_with_score_and_age(i as i64, f64::from(i as u32) * 0.1, 0.0, now))
            .collect();
        let filtered = apply_percentile_gate(hits, 70);
        assert_eq!(filtered.len(), 4, "p70 of 10 hits should keep 4");
        for h in &filtered {
            assert!(h.score >= 0.7 - 1e-9, "kept score {} below threshold", h.score);
        }
    }

    #[test]
    fn gate_p50_keeps_top_half() {
        // 10 hits, p50 keeps roughly top half (>= median).
        let now = fixed_now();
        let hits: Vec<RecallHit> = (1..=10)
            .map(|i| hit_with_score_and_age(i as i64, f64::from(i as u32) * 0.1, 0.0, now))
            .collect();
        let filtered = apply_percentile_gate(hits, 50);
        // rank = round(0.5 * 9) = 5; threshold = scores[5] = 0.6.
        // Hits 0.6..1.0 = 5 hits kept.
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn gate_p100_keeps_only_max_scoring_hit() {
        let now = fixed_now();
        let hits: Vec<RecallHit> = (1..=5)
            .map(|i| hit_with_score_and_age(i as i64, f64::from(i as u32) * 0.1, 0.0, now))
            .collect();
        let filtered = apply_percentile_gate(hits, 100);
        assert_eq!(filtered.len(), 1, "p100 should keep only top hit");
        assert!((filtered[0].score - 0.5).abs() < 1e-9);
    }

    #[test]
    fn gate_all_same_score_keeps_everything() {
        let now = fixed_now();
        let hits: Vec<RecallHit> = (1..=5)
            .map(|i| hit_with_score_and_age(i as i64, 0.5, 0.0, now))
            .collect();
        let filtered = apply_percentile_gate(hits, 70);
        assert_eq!(filtered.len(), 5, "ties at threshold must all survive");
    }

    #[test]
    fn gate_out_of_range_percentile_is_passthrough() {
        // percentile > 100 is a config error; be lenient and return input.
        let now = fixed_now();
        let hits: Vec<RecallHit> = (1..=5)
            .map(|i| hit_with_score_and_age(i as i64, f64::from(i as u32) * 0.1, 0.0, now))
            .collect();
        let filtered = apply_percentile_gate(hits.clone(), 200);
        assert_eq!(filtered.len(), hits.len());
    }
}
