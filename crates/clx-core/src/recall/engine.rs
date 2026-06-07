//! The recall engine, expressed purely in terms of Domain ports.
//!
//! The engine holds `&dyn SnapshotRepo` and `Option<&dyn QueryEmbedder>`
//! plus an optional cross-encoder reranker. It does not import `Storage`,
//! `LlmClient`, or `EmbeddingStore`; those are wired in at the call site
//! through the adapters in `storage::recall_repo` and `recall::adapters`.

use tracing::{debug, error, warn};

use super::ports::{QueryEmbedder, SnapshotRepo};
use super::{
    RecallHit, RecallQueryConfig, RecallQueryResult, RecallSearchType, decay, hybrid_merge, rerank,
    rrf, score_from_distance,
};

/// Outcome of a single candidate-generation stage.
///
/// Distinguishes "the stage ran and found nothing" (`errored == false`) from
/// "the stage failed" (`errored == true`) so the engine can mark the overall
/// result degraded rather than folding both into an empty vec. See
/// [`RecallQueryResult`].
struct StageOutcome {
    hits: Vec<RecallHit>,
    errored: bool,
}

impl StageOutcome {
    fn ok(hits: Vec<RecallHit>) -> Self {
        Self {
            hits,
            errored: false,
        }
    }

    fn failed() -> Self {
        Self {
            hits: Vec::new(),
            errored: true,
        }
    }
}

/// Engine that performs hybrid search across stored snapshots.
///
/// Constructed via [`RecallEngine::new`] and configured with the builder
/// methods. The engine never owns its collaborators; all references are
/// borrowed for the lifetime of the engine.
pub struct RecallEngine<'a> {
    repo: &'a dyn SnapshotRepo,
    embedder: Option<&'a dyn QueryEmbedder>,
    /// The model identifier (`"<provider>:<model>"`) that the current
    /// config would use for new embeddings. When `Some`, mismatch
    /// detection is active: `check_model_mismatch` returns the stored vs.
    /// configured pair when they differ.
    configured_model_ident: Option<String>,
    /// Optional cross-encoder rerank backend (D2). When `Some` AND
    /// `config.reranker_enabled == true` AND `backend.is_ready()`, the
    /// pipeline runs `apply_reranker` between RRF fusion and time-decay.
    reranker: Option<&'a dyn rerank::Reranker>,
}

impl<'a> RecallEngine<'a> {
    /// Create a new recall engine bound to the given snapshot repository.
    ///
    /// The engine has no embedder and no reranker by default; attach them
    /// with the builder methods before calling [`Self::query`].
    #[must_use]
    pub fn new(repo: &'a dyn SnapshotRepo) -> Self {
        Self {
            repo,
            embedder: None,
            configured_model_ident: None,
            reranker: None,
        }
    }

    /// Attach a query embedder. Without one the engine skips the semantic
    /// stage and only runs FTS5 / substring search.
    #[must_use]
    pub fn with_embedder(mut self, embedder: &'a dyn QueryEmbedder) -> Self {
        self.embedder = Some(embedder);
        self
    }

    /// Attach a cross-encoder rerank backend. When attached AND the
    /// per-query config has `reranker_enabled = true` AND the backend
    /// reports `is_ready() == true`, the recall pipeline will run the
    /// rerank stage between RRF fusion and time-decay.
    #[must_use]
    pub fn with_reranker(mut self, backend: &'a dyn rerank::Reranker) -> Self {
        self.reranker = Some(backend);
        self
    }

    /// Attach the configured embedding model identifier so that mismatch
    /// detection works. The identifier should be `"<provider>:<model>"`.
    #[must_use]
    pub fn with_model_ident(mut self, ident: impl Into<String>) -> Self {
        self.configured_model_ident = Some(ident.into());
        self
    }

    /// Check whether the stored model identifier differs from the
    /// configured one.
    ///
    /// Returns `Some((stored, configured))` when a mismatch is detected.
    /// Returns `None` when:
    /// - `configured_model_ident` was not set,
    /// - the repository reports no stored model (empty DB / sentinel rows),
    /// - the identifiers match, or
    /// - the repo lookup errored.
    #[must_use]
    pub fn check_model_mismatch(&self) -> Option<(String, String)> {
        let configured = self.configured_model_ident.as_deref()?;
        let stored = self.repo.current_embedding_model().ok().flatten()?;
        if stored == configured {
            None
        } else {
            Some((stored, configured.to_string()))
        }
    }

    /// Run hybrid search: FTS5 first (fast), then semantic if available.
    ///
    /// FTS5 runs first because it completes in <10ms, guaranteeing baseline
    /// results even if the embedding call consumes most of the timeout.
    ///
    /// Returns a [`RecallQueryResult`] whose `degraded` flag is set when any
    /// candidate-generation stage (semantic embedding, vector search, FTS5,
    /// session listing) errored. A degraded result with hits still carries
    /// those hits (partial failure); a degraded result with no hits is
    /// distinct from a healthy empty result — callers must not present it as
    /// "no relevant context". When *every* attempted generator fails a single
    /// distinct `error!` is emitted.
    pub async fn query(&self, query: &str, config: &RecallQueryConfig) -> RecallQueryResult {
        let mut fts_hits = Vec::new();
        let mut semantic_hits = Vec::new();
        // Track candidate-generation health: how many stages we attempted and
        // how many of those errored. `degraded` is true when any attempted
        // stage errored; ALL-failed (count == errored, count > 0) escalates to
        // a distinct error! below.
        let mut stages_attempted = 0usize;
        let mut stages_errored = 0usize;

        // FTS5 first — always fast (<10ms), provides baseline results
        if config.fallback_to_fts {
            let outcome = self.try_fts(query, config);
            stages_attempted += 1;
            stages_errored += usize::from(outcome.errored);
            fts_hits = outcome.hits;
        }

        // Then try semantic search (may be slow due to remote embedding call)
        if let Some(embedder) = self.embedder
            && self.repo.semantic_enabled()
        {
            let outcome = self.try_semantic(query, embedder, config).await;
            stages_attempted += 1;
            stages_errored += usize::from(outcome.errored);
            semantic_hits = outcome.hits;
        }

        // If FTS5 was skipped and semantic found nothing, try FTS5 as last resort
        if !config.fallback_to_fts && semantic_hits.is_empty() {
            let outcome = self.try_fts(query, config);
            stages_attempted += 1;
            stages_errored += usize::from(outcome.errored);
            fts_hits = outcome.hits;
        }

        let degraded = stages_errored > 0;
        if stages_attempted > 0 && stages_errored == stages_attempted {
            error!(
                "Recall degraded: all {stages_attempted} candidate-generation stage(s) failed; \
                 results are unavailable (distinct from an empty match set)"
            );
        }

        let mut fused = if config.rrf_enabled {
            rrf::rrf_fuse(&[semantic_hits, fts_hits], config.rrf_k, config.max_results)
        } else {
            hybrid_merge(semantic_hits, fts_hits, config.max_results)
        };

        // Stage 3: cross-encoder rerank (D2). Only runs when (a) a backend
        // is attached AND (b) config opts in AND (c) we have at least one
        // candidate. On timeout or any error, `apply_reranker` returns its
        // input unchanged so we keep the RRF ordering.
        if config.reranker_enabled
            && let Some(backend) = self.reranker
            && !fused.is_empty()
        {
            let timeout = std::time::Duration::from_millis(config.reranker_timeout_ms);
            fused = rerank::apply_reranker(fused, query, backend, timeout).await;
        }

        if config.time_decay_half_life_days > 0.0 {
            decay::apply_time_decay(
                &mut fused,
                config.time_decay_half_life_days,
                chrono::Utc::now(),
            );
        }

        if config.percentile_gate > 0 {
            fused = decay::apply_percentile_gate(fused, config.percentile_gate);
        }

        RecallQueryResult {
            hits: fused,
            degraded,
        }
    }

    /// Attempt embedding-based semantic search.
    ///
    /// Returns a [`StageOutcome`] whose `errored` flag is set when the
    /// embedding call or the vector search failed (each logged as a warning).
    /// A successful call that simply found nothing returns `errored == false`.
    async fn try_semantic(
        &self,
        query: &str,
        embedder: &dyn QueryEmbedder,
        config: &RecallQueryConfig,
    ) -> StageOutcome {
        let embedding = match embedder.embed_query(query).await {
            Ok(emb) => emb,
            Err(e) => {
                warn!("Recall semantic embedding failed: {e}");
                return StageOutcome::failed();
            }
        };

        debug!(
            "Generated recall query embedding with {} dimensions",
            embedding.len()
        );

        // Fetch extra candidates for filtering
        let fetch_limit = config.max_results * 2;
        let similar = match self.repo.semantic_similar(&embedding, fetch_limit) {
            Ok(results) => results,
            Err(e) => {
                warn!("Recall vector search failed: {e}");
                return StageOutcome::failed();
            }
        };

        if similar.is_empty() {
            debug!("No similar embeddings found for recall");
            return StageOutcome::ok(Vec::new());
        }

        debug!("Found {} similar embeddings for recall", similar.len());

        // Convert threshold to distance: higher threshold => lower max distance
        let max_distance = super::distance_from_threshold(config.similarity_threshold);

        let mut hits = Vec::new();
        for (snapshot_id, distance) in similar {
            if distance > max_distance {
                debug!(
                    "Skipping snapshot {snapshot_id} with distance {distance} (above max {max_distance})"
                );
                continue;
            }

            match self.repo.snapshot_by_id(snapshot_id) {
                Ok(Some(snapshot)) => {
                    let score = f64::from(score_from_distance(distance));
                    hits.push(RecallHit {
                        snapshot_id,
                        session_id: snapshot.session_id.to_string(),
                        created_at: snapshot.created_at.to_rfc3339(),
                        summary: snapshot.summary,
                        key_facts: snapshot.key_facts,
                        score,
                        search_type: RecallSearchType::Semantic,
                    });
                }
                Ok(None) => {
                    debug!("Snapshot {snapshot_id} not found in storage");
                }
                Err(e) => {
                    debug!("Error fetching snapshot {snapshot_id}: {e}");
                }
            }
        }

        StageOutcome::ok(hits)
    }

    /// Attempt FTS5 search with substring fallback.
    ///
    /// Returns a [`StageOutcome`]. The stage is marked `errored` only when the
    /// underlying candidate generators fail: an FTS5 error that then falls
    /// through to a *successful* substring scan is not degraded (we recovered),
    /// but an FTS5 error followed by a session-list error is.
    fn try_fts(&self, query: &str, config: &RecallQueryConfig) -> StageOutcome {
        let fetch_limit = config.max_results * 2;

        // Try FTS5 first
        match self.repo.search_fts(query, fetch_limit) {
            Ok(fts_results) if !fts_results.is_empty() => {
                debug!("FTS5 recall returned {} results", fts_results.len());
                let hits = fts_results
                    .into_iter()
                    .filter_map(|(snapshot, bm25_score)| {
                        let snapshot_id = snapshot.id?;
                        Some(RecallHit {
                            snapshot_id,
                            session_id: snapshot.session_id.to_string(),
                            created_at: snapshot.created_at.to_rfc3339(),
                            summary: snapshot.summary,
                            key_facts: snapshot.key_facts,
                            score: bm25_score,
                            search_type: RecallSearchType::Fts5,
                        })
                    })
                    .collect();
                return StageOutcome::ok(hits);
            }
            Ok(_) => {
                debug!("FTS5 recall returned no results, trying substring fallback");
            }
            Err(e) => {
                warn!("FTS5 recall failed, trying substring fallback: {e}");
            }
        }

        // Substring fallback
        self.try_substring_fallback(query, fetch_limit)
    }

    /// Fallback substring search across active sessions.
    ///
    /// Returns a [`StageOutcome`] marked `errored` when the session listing
    /// fails (the last candidate source for this stage).
    fn try_substring_fallback(&self, query: &str, limit: usize) -> StageOutcome {
        let query_lower = query.chars().take(500).collect::<String>().to_lowercase();
        let mut hits = Vec::new();

        let sessions = match self.repo.list_active_sessions() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to list sessions for substring recall: {e}");
                return StageOutcome::failed();
            }
        };

        for session in sessions.iter().take(limit.max(5)) {
            if let Ok(snapshots) = self.repo.snapshots_by_session(session.id.as_str()) {
                for snapshot in snapshots.iter().take(3) {
                    let matches_summary = snapshot
                        .summary
                        .as_ref()
                        .is_some_and(|s| s.to_lowercase().contains(&query_lower));
                    let matches_facts = snapshot
                        .key_facts
                        .as_ref()
                        .is_some_and(|s| s.to_lowercase().contains(&query_lower));

                    if (matches_summary || matches_facts)
                        && let Some(snapshot_id) = snapshot.id
                    {
                        hits.push(RecallHit {
                            snapshot_id,
                            session_id: snapshot.session_id.to_string(),
                            created_at: snapshot.created_at.to_rfc3339(),
                            summary: snapshot.summary.clone(),
                            key_facts: snapshot.key_facts.clone(),
                            score: 0.5, // Default relevance for substring matches
                            search_type: RecallSearchType::Text,
                        });
                    }

                    if hits.len() >= limit {
                        return StageOutcome::ok(hits);
                    }
                }
            }
        }

        StageOutcome::ok(hits)
    }
}
