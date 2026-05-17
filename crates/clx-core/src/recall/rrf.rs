//! Reciprocal Rank Fusion (RRF) for combining multiple ranked recall result
//! lists into a single fused ranking.
//!
//! Implementation of Cormack, Clarke, and Buettcher (2009),
//! "Reciprocal Rank Fusion outperforms Condorcet and individual rank learning
//! methods" (SIGIR 2009). The literature-standard constant is `k = 60`.
//!
//! ## Algorithm
//!
//! For each ranker `r` and each candidate document `d`:
//!
//! ```text
//! rrf_score(d) = sum_r [ 1.0 / (k + rank_r(d)) ]
//! ```
//!
//! where `rank_r(d)` is the **1-indexed** rank of `d` in ranker `r`'s output.
//! Documents missing from a ranker contribute `0` to the sum.
//!
//! RRF is parameter-free relative to score scales: only the rank position
//! matters, so the previous linear-weighting tuning of 0.6 / 0.4 becomes
//! obsolete.
//!
//! ## Layering
//!
//! This module is **domain layer**: a pure function over input vectors,
//! no IO, no global state.

use std::collections::HashMap;

use super::{RecallHit, RecallSearchType};

/// Fuse multiple ranked lists of recall hits into a single ranking using
/// Reciprocal Rank Fusion.
///
/// * `rankings` - one or more ranked lists, each pre-sorted descending by
///   the ranker's own score. Each input list is treated as authoritative for
///   its own rank ordering (the function only looks at vector position, not
///   the underlying score values).
/// * `k` - the RRF constant (literature default: `60`). Larger `k` flattens
///   the contribution differences between rank 1 and rank N.
/// * `max_results` - truncate the fused result to at most this many hits.
///
/// ## Deduplication
///
/// Hits are merged by `snapshot_id`. When a hit appears in multiple input
/// rankings, its RRF score contributions are **summed**, and the resulting
/// hit retains the metadata of the first occurrence encountered, with
/// `search_type` promoted to `RecallSearchType::Hybrid`.
///
/// ## Determinism
///
/// Ties in fused score are broken by `snapshot_id` descending (stable,
/// deterministic). Empty input returns an empty vec.
#[must_use]
pub fn rrf_fuse(
    rankings: &[Vec<RecallHit>],
    k: u32,
    max_results: usize,
) -> Vec<RecallHit> {
    // Use f64 because k can be 0 (edge case test) and we want full precision
    // when many small reciprocal contributions are summed across many rankers.
    let k_f = f64::from(k);

    // snapshot_id -> (fused_score, representative_hit, contributing_ranker_count)
    let mut fused: HashMap<i64, (f64, RecallHit, u32)> = HashMap::new();

    for list in rankings {
        for (rank_zero, hit) in list.iter().enumerate() {
            // RRF uses 1-indexed ranks (Cormack et al. 2009).
            let rank = (rank_zero + 1) as f64;
            let contribution = 1.0 / (k_f + rank);

            fused
                .entry(hit.snapshot_id)
                .and_modify(|(score, _existing, count)| {
                    *score += contribution;
                    *count += 1;
                })
                .or_insert_with(|| (contribution, hit.clone(), 1));
        }
    }

    // Promote search_type to Hybrid when a hit appeared in more than one ranker.
    // For single-ranker hits, preserve the original search_type (Semantic/Fts5/Text).
    let mut results: Vec<RecallHit> = fused
        .into_iter()
        .map(|(_id, (score, mut hit, count))| {
            hit.score = score;
            if count > 1 {
                hit.search_type = RecallSearchType::Hybrid;
            }
            hit
        })
        .collect();

    // Sort by fused score descending, breaking ties by snapshot_id descending
    // for deterministic ordering.
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.snapshot_id.cmp(&a.snapshot_id))
    });

    results.truncate(max_results);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(snapshot_id: i64, score: f64, search_type: RecallSearchType) -> RecallHit {
        RecallHit {
            snapshot_id,
            session_id: format!("session-{snapshot_id}"),
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            summary: Some(format!("Summary {snapshot_id}")),
            key_facts: Some(format!("Facts {snapshot_id}")),
            score,
            search_type,
        }
    }

    #[test]
    fn rrf_full_agreement_top_doc_wins() {
        // Both rankers rank doc 1 first; expected score = 2 * 1/(60 + 1) = 2/61.
        let semantic = vec![
            hit(1, 0.99, RecallSearchType::Semantic),
            hit(2, 0.80, RecallSearchType::Semantic),
        ];
        let fts = vec![
            hit(1, 5.0, RecallSearchType::Fts5),
            hit(2, 3.0, RecallSearchType::Fts5),
        ];

        let fused = rrf_fuse(&[semantic, fts], 60, 10);

        assert_eq!(fused[0].snapshot_id, 1);
        let expected = 2.0 / 61.0;
        assert!(
            (fused[0].score - expected).abs() < 1e-12,
            "expected {expected}, got {}",
            fused[0].score
        );
        assert_eq!(fused[0].search_type, RecallSearchType::Hybrid);
    }

    #[test]
    fn rrf_full_disagreement_returns_all_with_partial_contributions() {
        // Semantic: [A, B, C], FTS: [C, B, A]
        // RRF(A) = 1/(60+1) + 1/(60+3) = 1/61 + 1/63 = 124/3843
        // RRF(B) = 1/(60+2) + 1/(60+2) = 2/62      = 124/3844
        // RRF(C) = 1/(60+3) + 1/(60+1) = 1/63 + 1/61 = 124/3843
        //
        // A and C are tied at 124/3843 and are both higher than B at 124/3844
        // (smaller denominator wins). Tie-break by `snapshot_id` descending
        // puts C (30) before A (10) per the contract documented at the top
        // of this module.
        let semantic = vec![
            hit(10, 0.9, RecallSearchType::Semantic), // A
            hit(20, 0.8, RecallSearchType::Semantic), // B
            hit(30, 0.7, RecallSearchType::Semantic), // C
        ];
        let fts = vec![
            hit(30, 5.0, RecallSearchType::Fts5), // C
            hit(20, 4.0, RecallSearchType::Fts5), // B
            hit(10, 3.0, RecallSearchType::Fts5), // A
        ];
        let fused = rrf_fuse(&[semantic, fts], 60, 10);

        let score_a: f64 = 1.0 / 61.0 + 1.0 / 63.0;
        let score_b: f64 = 2.0 / 62.0;
        let score_c: f64 = 1.0 / 63.0 + 1.0 / 61.0;

        assert_eq!(fused.len(), 3);

        // C wins on snapshot_id tie-break ahead of A.
        assert_eq!(fused[0].snapshot_id, 30, "C wins the descending-id tiebreak");
        assert!((fused[0].score - score_c).abs() < 1e-12_f64);
        assert_eq!(fused[1].snapshot_id, 10, "A follows the descending-id tiebreak");
        assert!((fused[1].score - score_a).abs() < 1e-12_f64);
        assert_eq!(fused[2].snapshot_id, 20, "B is last with the smaller score");
        assert!((fused[2].score - score_b).abs() < 1e-12_f64);
    }

    #[test]
    fn rrf_single_source_only_uses_that_ranker() {
        let semantic = vec![
            hit(1, 0.9, RecallSearchType::Semantic),
            hit(2, 0.8, RecallSearchType::Semantic),
        ];
        let fused = rrf_fuse(&[semantic, Vec::new()], 60, 10);
        assert_eq!(fused.len(), 2);
        assert_eq!(fused[0].snapshot_id, 1);
        // Single-source hit: search_type preserved as Semantic, NOT Hybrid.
        assert_eq!(fused[0].search_type, RecallSearchType::Semantic);
        assert!((fused[0].score - 1.0 / 61.0).abs() < 1e-12);
    }

    #[test]
    fn rrf_fts_only_preserves_fts_search_type() {
        let fts = vec![
            hit(7, 5.0, RecallSearchType::Fts5),
            hit(8, 4.0, RecallSearchType::Fts5),
        ];
        let fused = rrf_fuse(&[Vec::new(), fts], 60, 10);
        assert_eq!(fused.len(), 2);
        assert_eq!(fused[0].snapshot_id, 7);
        assert_eq!(fused[0].search_type, RecallSearchType::Fts5);
    }

    #[test]
    fn rrf_both_empty_returns_empty() {
        let fused = rrf_fuse(&[Vec::<RecallHit>::new(), Vec::new()], 60, 10);
        assert!(fused.is_empty());
    }

    #[test]
    fn rrf_no_rankings_returns_empty() {
        let fused = rrf_fuse(&[], 60, 10);
        assert!(fused.is_empty());
    }

    #[test]
    fn rrf_respects_max_results() {
        // 20 docs in, expect only 3 out, sorted descending.
        let semantic: Vec<RecallHit> = (1..=20)
            .map(|i| hit(i, 1.0 / f64::from(i as u32), RecallSearchType::Semantic))
            .collect();
        let fused = rrf_fuse(&[semantic], 60, 3);
        assert_eq!(fused.len(), 3);
        assert_eq!(fused[0].snapshot_id, 1);
        assert_eq!(fused[1].snapshot_id, 2);
        assert_eq!(fused[2].snapshot_id, 3);
    }

    #[test]
    fn rrf_k_60_matches_literature_worked_example() {
        // Cormack et al. 2009 example: doc at rank 1 with k=60 contributes 1/61.
        // doc at rank 1 from two rankers => 2/61 ~ 0.03278...
        let semantic = vec![hit(1, 0.9, RecallSearchType::Semantic)];
        let fts = vec![hit(1, 5.0, RecallSearchType::Fts5)];
        let fused = rrf_fuse(&[semantic, fts], 60, 1);
        assert_eq!(fused.len(), 1);
        assert!((fused[0].score - (2.0 / 61.0)).abs() < 1e-12);
    }

    #[test]
    fn rrf_k_zero_edge_case_does_not_divide_by_zero_at_rank_1() {
        // k = 0 means rank 1 contributes 1/1 = 1.0; safe because rank starts at 1.
        let semantic = vec![hit(1, 0.9, RecallSearchType::Semantic)];
        let fused = rrf_fuse(&[semantic], 0, 1);
        assert!((fused[0].score - 1.0).abs() < 1e-12);
    }

    #[test]
    fn rrf_search_type_promoted_to_hybrid_when_in_multiple_rankers() {
        let semantic = vec![hit(42, 0.9, RecallSearchType::Semantic)];
        let fts = vec![hit(42, 4.0, RecallSearchType::Fts5)];
        let fused = rrf_fuse(&[semantic, fts], 60, 10);
        assert_eq!(fused.len(), 1);
        assert_eq!(fused[0].search_type, RecallSearchType::Hybrid);
    }

    #[test]
    fn rrf_truncation_at_zero_returns_empty() {
        let semantic = vec![hit(1, 0.9, RecallSearchType::Semantic)];
        let fused = rrf_fuse(&[semantic], 60, 0);
        assert!(fused.is_empty());
    }

    #[test]
    fn rrf_three_rankers_sum_contributions() {
        // Doc 1 at rank 1 in all three rankers.
        let r1 = vec![hit(1, 0.9, RecallSearchType::Semantic)];
        let r2 = vec![hit(1, 5.0, RecallSearchType::Fts5)];
        let r3 = vec![hit(1, 0.5, RecallSearchType::Text)];
        let fused = rrf_fuse(&[r1, r2, r3], 60, 10);
        assert_eq!(fused.len(), 1);
        let expected = 3.0 / 61.0;
        assert!((fused[0].score - expected).abs() < 1e-12);
        assert_eq!(fused[0].search_type, RecallSearchType::Hybrid);
    }

    #[test]
    fn rrf_deterministic_tie_break_by_snapshot_id() {
        // Two hits with identical rank in identical single ranker -> identical
        // score. Tie-break: higher snapshot_id first.
        let semantic = vec![
            hit(1, 0.5, RecallSearchType::Semantic),
            hit(2, 0.5, RecallSearchType::Semantic),
        ];
        // Both at distinct ranks in the same list, so they actually differ;
        // craft two equal-rank cases using two parallel rankers.
        let r1 = vec![hit(1, 0.9, RecallSearchType::Semantic)];
        let r2 = vec![hit(2, 0.9, RecallSearchType::Fts5)];
        let fused = rrf_fuse(&[r1, r2], 60, 10);
        assert_eq!(fused.len(), 2);
        // Both at rank 1 in their respective rankers => identical score.
        assert!((fused[0].score - fused[1].score).abs() < 1e-12);
        // Tie-break: snapshot_id 2 comes before 1.
        assert_eq!(fused[0].snapshot_id, 2);
        assert_eq!(fused[1].snapshot_id, 1);

        // Silence unused-variable warning in stable check.
        let _ = semantic;
    }
}
