//! RAGAS-style synthetic recall accuracy bench.
//!
//! How to run:
//!   cargo bench --bench recall_accuracy
//!
//! What it reports per configuration:
//!   - context_precision@10 = mean over queries of |retrieved ∩ expected| / K
//!   - context_recall@10    = mean over queries of |retrieved ∩ expected| / |expected|
//!   - p50 + p95 over per-query precision and recall
//!
//! Configurations benchmarked (A/B sanity):
//!   - rrf_enabled = true  (0.8.0 default)
//!   - rrf_enabled = false (0.7.x linear-weight rollback path)
//!
//! Golden set sourcing:
//!   - Fully synthetic. No user content. No PHI. Generator script:
//!     `scripts/generate_golden_set.py` reads only public CLX specs.
//!
//! Target (warn-only CI gate; NOT enforced in 0.8.0):
//!   - context_precision >= 0.85
//!
//! The bench seeds an in-memory `Storage` with the snapshot corpus
//! embedded in the YAML and runs `RecallEngine::query` for every pair.

#![allow(clippy::doc_markdown)]

use std::collections::HashSet;
use std::path::PathBuf;

use chrono::Utc;
use clx_core::recall::{RecallEngine, RecallQueryConfig};
use clx_core::storage::{Storage, StorageSnapshotRepo};
use clx_core::types::{Session, SessionId, Snapshot, SnapshotTrigger};
use criterion::{Criterion, criterion_group, criterion_main};

/// One golden pair: a synthetic query plus the snapshot ids a perfect
/// recall pipeline should surface.
#[derive(Debug, Clone)]
struct GoldenPair {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    category: String,
    query: String,
    expected: HashSet<i64>,
}

/// One row of the synthetic snapshot corpus seeded into storage.
#[derive(Debug, Clone)]
struct CorpusRow {
    snapshot_id: i64,
    summary: String,
    key_facts: String,
}

/// Parsed golden set: corpus + pairs.
#[derive(Debug)]
struct GoldenSet {
    corpus: Vec<CorpusRow>,
    pairs: Vec<GoldenPair>,
}

/// Minimal hand-rolled YAML reader for the strict format produced by
/// `scripts/generate_golden_set.py`. We avoid a YAML crate dependency to
/// keep the bench's dev-dep footprint small and deterministic.
fn load_golden_set(path: &PathBuf) -> GoldenSet {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let mut corpus: Vec<CorpusRow> = Vec::new();
    let mut pairs: Vec<GoldenPair> = Vec::new();

    enum Section {
        None,
        Corpus,
        Pairs,
    }
    let mut section = Section::None;

    // Per-row accumulators.
    let mut cur_snapshot_id: Option<i64> = None;
    let mut cur_summary: Option<String> = None;
    let mut cur_key_facts: Option<String> = None;

    let mut cur_id: Option<String> = None;
    let mut cur_category: Option<String> = None;
    let mut cur_query: Option<String> = None;
    let mut cur_expected: Option<HashSet<i64>> = None;

    fn flush_corpus(
        corpus: &mut Vec<CorpusRow>,
        sid: &mut Option<i64>,
        summary: &mut Option<String>,
        kf: &mut Option<String>,
    ) {
        if let (Some(s), Some(sum), Some(k)) = (sid.take(), summary.take(), kf.take()) {
            corpus.push(CorpusRow {
                snapshot_id: s,
                summary: sum,
                key_facts: k,
            });
        }
    }

    fn flush_pair(
        pairs: &mut Vec<GoldenPair>,
        id: &mut Option<String>,
        cat: &mut Option<String>,
        q: &mut Option<String>,
        exp: &mut Option<HashSet<i64>>,
    ) {
        if let (Some(i), Some(c), Some(query), Some(e)) =
            (id.take(), cat.take(), q.take(), exp.take())
        {
            pairs.push(GoldenPair {
                id: i,
                category: c,
                query,
                expected: e,
            });
        }
    }

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "snapshot_corpus:" {
            // Flush in case we were inside another section earlier (shouldn't happen with this format).
            flush_corpus(
                &mut corpus,
                &mut cur_snapshot_id,
                &mut cur_summary,
                &mut cur_key_facts,
            );
            section = Section::Corpus;
            continue;
        }
        if line == "pairs:" {
            flush_corpus(
                &mut corpus,
                &mut cur_snapshot_id,
                &mut cur_summary,
                &mut cur_key_facts,
            );
            flush_pair(
                &mut pairs,
                &mut cur_id,
                &mut cur_category,
                &mut cur_query,
                &mut cur_expected,
            );
            section = Section::Pairs;
            continue;
        }

        match section {
            Section::None => {}
            Section::Corpus => {
                let stripped = line.trim_start();
                if let Some(rest) = stripped.strip_prefix("- snapshot_id:") {
                    // new row
                    flush_corpus(
                        &mut corpus,
                        &mut cur_snapshot_id,
                        &mut cur_summary,
                        &mut cur_key_facts,
                    );
                    let v = rest.trim();
                    cur_snapshot_id = Some(v.parse().expect("snapshot_id parse"));
                } else if let Some(rest) = stripped.strip_prefix("summary:") {
                    cur_summary = Some(unquote(rest.trim()));
                } else if let Some(rest) = stripped.strip_prefix("key_facts:") {
                    cur_key_facts = Some(unquote(rest.trim()));
                }
            }
            Section::Pairs => {
                let stripped = line.trim_start();
                if let Some(rest) = stripped.strip_prefix("- id:") {
                    flush_pair(
                        &mut pairs,
                        &mut cur_id,
                        &mut cur_category,
                        &mut cur_query,
                        &mut cur_expected,
                    );
                    cur_id = Some(rest.trim().to_string());
                } else if let Some(rest) = stripped.strip_prefix("category:") {
                    cur_category = Some(rest.trim().to_string());
                } else if let Some(rest) = stripped.strip_prefix("query:") {
                    cur_query = Some(unquote(rest.trim()));
                } else if let Some(rest) = stripped.strip_prefix("expected_snapshot_ids:") {
                    let v = rest.trim();
                    // Format: [1, 2, 3]
                    let inner = v.trim_start_matches('[').trim_end_matches(']').trim();
                    let mut set = HashSet::new();
                    for part in inner.split(',') {
                        let p = part.trim();
                        if p.is_empty() {
                            continue;
                        }
                        set.insert(p.parse::<i64>().expect("expected_snapshot_ids parse"));
                    }
                    cur_expected = Some(set);
                }
            }
        }
    }

    // Final flushes.
    flush_corpus(
        &mut corpus,
        &mut cur_snapshot_id,
        &mut cur_summary,
        &mut cur_key_facts,
    );
    flush_pair(
        &mut pairs,
        &mut cur_id,
        &mut cur_category,
        &mut cur_query,
        &mut cur_expected,
    );

    assert!(!corpus.is_empty(), "golden set: empty corpus");
    assert!(!pairs.is_empty(), "golden set: empty pairs");
    GoldenSet { corpus, pairs }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].replace("\\\"", "\"")
    } else {
        s.to_string()
    }
}

/// Seed an in-memory storage with one session and N snapshots whose
/// `id` values match the corpus rows by INSERT order. To guarantee the
/// snapshot ids land where we want them, we insert in ascending order
/// and assume `rowid` allocation starts at 1; we then translate the
/// reported ids through a remap so the bench's expected sets stay valid
/// even if SQLite ever changes that contract.
struct SeededStorage {
    storage: Storage,
    /// Maps `corpus.snapshot_id` (logical id from YAML) ->
    /// `storage row id` (actual SQLite rowid).
    id_map: std::collections::HashMap<i64, i64>,
}

fn seed_storage(corpus: &[CorpusRow]) -> SeededStorage {
    let storage = Storage::open_in_memory().expect("open in-memory storage");

    let session = Session::new(
        SessionId::new("bench-session"),
        "synthetic-bench".to_string(),
    );
    storage.create_session(&session).expect("create session");

    let mut id_map = std::collections::HashMap::new();
    // Sort by snapshot_id ascending so the rowid order matches the
    // logical order, which keeps the mapping intuitive.
    let mut rows = corpus.to_vec();
    rows.sort_by_key(|r| r.snapshot_id);
    for row in &rows {
        let mut snap = Snapshot::new(SessionId::new("bench-session"), SnapshotTrigger::Auto);
        snap.summary = Some(row.summary.clone());
        snap.key_facts = Some(row.key_facts.clone());
        // created_at defaults to Utc::now(); keep at "now" so time-decay
        // does not down-weight bench hits.
        snap.created_at = Utc::now();
        let actual = storage.create_snapshot(&snap).expect("create snapshot");
        id_map.insert(row.snapshot_id, actual);
    }

    SeededStorage { storage, id_map }
}

/// Aggregate metrics across all pairs for a single configuration.
struct Metrics {
    mean_precision: f64,
    mean_recall: f64,
    p50_precision: f64,
    p95_precision: f64,
    p50_recall: f64,
    p95_recall: f64,
    n: usize,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

async fn evaluate(
    seeded: &SeededStorage,
    pairs: &[GoldenPair],
    config: &RecallQueryConfig,
) -> Metrics {
    let repo = StorageSnapshotRepo::new(&seeded.storage, None);
    let engine = RecallEngine::new(&repo);
    let k = config.max_results as f64;

    let mut precisions = Vec::with_capacity(pairs.len());
    let mut recalls = Vec::with_capacity(pairs.len());

    for pair in pairs {
        // Translate logical expected ids -> actual storage rowids.
        let expected_actual: HashSet<i64> = pair
            .expected
            .iter()
            .filter_map(|logical| seeded.id_map.get(logical).copied())
            .collect();

        let hits = engine.query(&pair.query, config).await.hits;
        let retrieved: HashSet<i64> = hits.iter().map(|h| h.snapshot_id).collect();

        let inter = retrieved.intersection(&expected_actual).count() as f64;
        let precision = if hits.is_empty() { 0.0 } else { inter / k };
        let recall = if expected_actual.is_empty() {
            0.0
        } else {
            inter / expected_actual.len() as f64
        };
        precisions.push(precision);
        recalls.push(recall);
    }

    let mut p_sorted = precisions.clone();
    let mut r_sorted = recalls.clone();
    p_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    r_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = pairs.len();
    let mean_precision = precisions.iter().sum::<f64>() / n as f64;
    let mean_recall = recalls.iter().sum::<f64>() / n as f64;

    Metrics {
        mean_precision,
        mean_recall,
        p50_precision: percentile(&p_sorted, 0.50),
        p95_precision: percentile(&p_sorted, 0.95),
        p50_recall: percentile(&r_sorted, 0.50),
        p95_recall: percentile(&r_sorted, 0.95),
        n,
    }
}

fn golden_set_path() -> PathBuf {
    // CARGO_MANIFEST_DIR points to crates/clx-core during bench compilation.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // repo root
    p.push("tests");
    p.push("fixtures");
    p.push("recall_golden.yaml");
    p
}

fn bench_recall_accuracy(c: &mut Criterion) {
    let path = golden_set_path();
    let golden = load_golden_set(&path);
    let seeded = seed_storage(&golden.corpus);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    // Config A: 0.8.0 default (RRF on)
    let cfg_rrf_on = RecallQueryConfig {
        max_results: 10,
        similarity_threshold: 0.0,
        fallback_to_fts: true,
        include_key_facts: true,
        rrf_enabled: true,
        rrf_k: 60,
        // Disable time-decay + percentile gate inside the bench so the
        // measurement isolates fusion behavior. Decay/gate have their own
        // unit tests; the goal here is to compare RRF vs linear fusion.
        time_decay_half_life_days: 0.0,
        percentile_gate: 0,
        reranker_enabled: false,
        reranker_timeout_ms: 250,
    };

    // Config B: rollback path (linear 0.6/0.4 hybrid merge)
    let cfg_rrf_off = RecallQueryConfig {
        rrf_enabled: false,
        ..cfg_rrf_on.clone()
    };

    let mut group = c.benchmark_group("recall_accuracy");
    group.sample_size(10);

    group.bench_function("rrf_enabled_true", |b| {
        b.iter(|| {
            let m = rt.block_on(evaluate(&seeded, &golden.pairs, &cfg_rrf_on));
            assert!(m.mean_precision.is_finite());
        });
    });
    group.bench_function("rrf_enabled_false", |b| {
        b.iter(|| {
            let m = rt.block_on(evaluate(&seeded, &golden.pairs, &cfg_rrf_off));
            assert!(m.mean_precision.is_finite());
        });
    });

    group.finish();

    // One-shot summary print (criterion captures it on stdout).
    let m_on = rt.block_on(evaluate(&seeded, &golden.pairs, &cfg_rrf_on));
    let m_off = rt.block_on(evaluate(&seeded, &golden.pairs, &cfg_rrf_off));

    println!();
    println!("RAGAS-style synthetic golden set ({} pairs)", m_on.n);
    println!("  config=rrf_enabled=true");
    println!(
        "    context_precision@10 mean={:.3} p50={:.3} p95={:.3}",
        m_on.mean_precision, m_on.p50_precision, m_on.p95_precision
    );
    println!(
        "    context_recall@10    mean={:.3} p50={:.3} p95={:.3}",
        m_on.mean_recall, m_on.p50_recall, m_on.p95_recall
    );
    println!("  config=rrf_enabled=false");
    println!(
        "    context_precision@10 mean={:.3} p50={:.3} p95={:.3}",
        m_off.mean_precision, m_off.p50_precision, m_off.p95_precision
    );
    println!(
        "    context_recall@10    mean={:.3} p50={:.3} p95={:.3}",
        m_off.mean_recall, m_off.p50_recall, m_off.p95_recall
    );

    if m_on.mean_precision < 0.85 {
        eprintln!(
            "::warning::context_precision {:.3} below 0.85 target (warn-only in 0.8.0)",
            m_on.mean_precision
        );
    }
}

criterion_group!(benches, bench_recall_accuracy);
criterion_main!(benches);
