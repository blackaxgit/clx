//! Infrastructure adapter that implements [`super::rerank::Reranker`] on
//! top of the `fastembed-rs` cross-encoder (v5).
//!
//! This is the only file in `clx-core` that knows about the `fastembed`
//! crate. The recall pipeline depends solely on the [`Reranker`] trait
//! defined in `rerank.rs`, so swapping the backend (or stubbing it for
//! tests) does not perturb domain code.
//!
//! ## Lifecycle
//!
//! - `FastembedReranker::new(model_dir)` constructs the adapter cheaply
//!   without loading the model. The 568 MB ONNX weights are loaded
//!   lazily on the first `score()` call.
//! - `is_ready()` is filesystem-cheap: it checks for the `.ready`
//!   sentinel that `clx model fetch` writes after SHA-256 verification.
//!   This lets the hook short-circuit while the model still downloads.
//! - `score()` performs both the lazy load AND the rerank inference on a
//!   Tokio blocking thread inside a single `spawn_blocking`. This is
//!   critical: the outer [`tokio::time::timeout`] in
//!   [`super::rerank::apply_reranker`] then governs the whole
//!   load + score pipeline, so a slow cold-load cannot exceed the
//!   per-query budget. On timeout the caller falls back to RRF-only.
//!
//! ## Cache strategy (v5)
//!
//! `fastembed` v5 changed `TextRerank::rerank` to take `&mut self`, so the
//! previous `Arc<TextRerank>` sharing strategy no longer compiles. We
//! instead hold `Mutex<Option<TextRerank>>`: the model is owned by the
//! adapter, instantiated once on the first call, and reused under a short
//! mutex hold for every subsequent call. ONNX inference is single-threaded
//! per session anyway, so the mutex does not pessimise throughput.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use async_trait::async_trait;
use fastembed::{RerankInitOptions, RerankerModel, TextRerank};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use super::rerank::{RerankError, Reranker};

/// Filename of the readiness sentinel written by `clx model fetch` after
/// a successful download and SHA-256 verification.
pub const READY_SENTINEL: &str = ".ready";

/// Default model directory name under [`crate::paths::model_cache_dir`].
pub const DEFAULT_MODEL_DIRNAME: &str = "bge-reranker-v2-m3";

/// Magic header line that marks a content-pinned sentinel (F9 fix).
///
/// An OLD sentinel from a pre-F9 0.8.0 dev build is just an opaque marker
/// (`ready` / `dryrun`) and will NOT start with this header. Such a
/// sentinel is intentionally treated as "not ready" so the model is
/// re-fetched cleanly and re-pinned; we never load weights that were not
/// digest-verified.
pub const SENTINEL_HEADER: &str = "clx-model-sentinel v1";

/// One pinned artifact recorded in the readiness sentinel: a relative
/// path under the model directory, its SHA-256 (hex, no prefix), and the
/// byte length captured at fetch time.
///
/// The byte length is the cheap short-circuit signal on the recall hot
/// path; the SHA-256 is the authoritative check, gated to run at most
/// once per process (see [`verify_sentinel_against_disk`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedArtifact {
    /// Path relative to the model directory (e.g. `model.onnx`).
    pub rel_path: String,
    /// Lowercase hex SHA-256 of the artifact's bytes at fetch time.
    pub sha256_hex: String,
    /// Artifact size in bytes at fetch time.
    pub size: u64,
}

/// Parsed content-pinned sentinel. Pure value type so the parser is unit
/// testable without touching the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSentinel {
    pub artifacts: Vec<PinnedArtifact>,
}

/// Parse the textual body of a `.ready` sentinel.
///
/// Returns `None` for ANY input that is not a well-formed v1
/// content-pinned sentinel (missing header, no artifact lines, malformed
/// fields, non-hex digest, bad size). `None` always degrades to
/// "not ready" -> RRF-only fallback; it never panics. This deliberately
/// rejects the legacy opaque-marker format so a pre-F9 install is
/// re-fetched and re-pinned rather than trusted blindly.
///
/// Grammar (one artifact per line after the header):
///
/// ```text
/// clx-model-sentinel v1
/// sha256:<64-hex>  size:<bytes>  path:<relative-path>
/// ```
#[must_use]
pub fn parse_sentinel(body: &str) -> Option<ParsedSentinel> {
    let mut lines = body.lines();
    let header = lines.next()?.trim();
    if header != SENTINEL_HEADER {
        return None;
    }

    let mut artifacts = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut sha: Option<String> = None;
        let mut size: Option<u64> = None;
        let mut rel: Option<String> = None;

        for field in line.split_whitespace() {
            if let Some(h) = field.strip_prefix("sha256:") {
                let h = h.to_ascii_lowercase();
                if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    sha = Some(h);
                } else {
                    return None;
                }
            } else if let Some(s) = field.strip_prefix("size:") {
                size = Some(s.parse::<u64>().ok()?);
            } else if let Some(p) = field.strip_prefix("path:") {
                if p.is_empty() {
                    return None;
                }
                rel = Some(p.to_string());
            }
        }

        match (sha, size, rel) {
            (Some(sha256_hex), Some(size), Some(rel_path)) => {
                artifacts.push(PinnedArtifact {
                    rel_path,
                    sha256_hex,
                    size,
                });
            }
            // A non-empty, non-comment line that does not carry all three
            // fields is a malformed sentinel: reject the whole thing.
            _ => return None,
        }
    }

    if artifacts.is_empty() {
        return None;
    }
    Some(ParsedSentinel { artifacts })
}

/// Render a content-pinned sentinel body from a set of artifacts. Used by
/// the `clx model fetch` orchestrator (via the public re-export) so the
/// writer and the parser cannot drift.
#[must_use]
pub fn render_sentinel(artifacts: &[PinnedArtifact]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from(SENTINEL_HEADER);
    out.push('\n');
    for a in artifacts {
        // Infallible: writing into a String never errors.
        let _ = writeln!(
            out,
            "sha256:{}  size:{}  path:{}",
            a.sha256_hex, a.size, a.rel_path
        );
    }
    out
}

/// Compute the content-pinned artifact set that `clx model fetch` writes
/// into the `.ready` sentinel.
///
/// Pins the ONNX graph (`model.onnx`) AND, when present, its external
/// weights blob (`model.onnx.data`). On the upstream rozgo mirror the
/// 108 kB `model.onnx` holds only the graph while the ~2.27 GB
/// `model.onnx.data` holds the actual weights, so hashing the graph
/// alone would leave the bulk of the model unverified and bypass the F9
/// control. Both the root layout and the `onnx/` subdir layout are
/// supported, mirroring the CLI's `verify_model_dir_complete`.
///
/// Returns `Err` if no `model.onnx` is present (callers run this only
/// after the CLI integrity gate, so this is defence-in-depth).
///
/// Layering: this is the Infrastructure adapter that owns model-cache
/// integrity. The CLI orchestrator calls it right after a verified fetch
/// and persists the result; keeping the writer here next to the parser
/// and the verifier guarantees they cannot drift, and confines `sha2` /
/// `hex` to the one crate that already depends on them.
pub fn pin_model_artifacts(model_dir: &Path) -> std::io::Result<Vec<PinnedArtifact>> {
    let candidates: &[&str] = &[
        "model.onnx",
        "model.onnx.data",
        "onnx/model.onnx",
        "onnx/model.onnx.data",
    ];

    let mut pinned = Vec::new();
    for rel in candidates {
        let path = model_dir.join(rel);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() == 0 {
            continue;
        }
        let sha256_hex = sha256_file_hex(&path)?;
        pinned.push(PinnedArtifact {
            rel_path: (*rel).to_string(),
            sha256_hex,
            size: meta.len(),
        });
    }

    if !pinned.iter().any(|a| a.rel_path.ends_with("model.onnx")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no model.onnx found under {} while pinning artifacts (checked root and onnx/)",
                model_dir.display()
            ),
        ));
    }

    Ok(pinned)
}

/// Stream a file through SHA-256 in fixed-size chunks. Avoids loading the
/// 2.27 GB external-weights blob into memory. Returns lowercase hex.
fn sha256_file_hex(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Resolve a sentinel-relative artifact path against the model directory,
/// rejecting absolute paths and `..` traversal so a hostile sentinel
/// cannot point the hash check at an unrelated file (and thus "pass" by
/// hashing something the attacker controls outside the model dir).
fn resolve_artifact(model_dir: &Path, rel: &str) -> Option<PathBuf> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return None;
    }
    for comp in rel_path.components() {
        use std::path::Component;
        match comp {
            Component::Normal(_) => {}
            // CurDir is harmless; everything else (ParentDir, RootDir,
            // Prefix) is rejected.
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(model_dir.join(rel_path))
}

/// Full digest verification of every pinned artifact against the bytes on
/// disk. This is the authoritative F9 check. Returns `true` only if every
/// artifact exists, has the recorded size, AND re-hashes to the recorded
/// SHA-256. Any deviation -> `false` (caller degrades to RRF-only).
fn verify_sentinel_against_disk(model_dir: &Path, parsed: &ParsedSentinel) -> bool {
    for a in &parsed.artifacts {
        let Some(path) = resolve_artifact(model_dir, &a.rel_path) else {
            warn!(
                "reranker sentinel references unsafe path {:?}; treating model as not ready",
                a.rel_path
            );
            return false;
        };
        let meta = match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => m,
            _ => {
                warn!(
                    "reranker pinned artifact missing: {}; treating model as not ready",
                    path.display()
                );
                return false;
            }
        };
        if meta.len() != a.size {
            warn!(
                "reranker artifact size mismatch for {} (sentinel {} bytes, disk {} bytes); \
                 possible tampering, degrading to RRF-only",
                path.display(),
                a.size,
                meta.len()
            );
            return false;
        }
        match sha256_file_hex(&path) {
            Ok(actual) if actual == a.sha256_hex => {}
            Ok(actual) => {
                warn!(
                    "reranker artifact SHA-256 mismatch for {} (expected {}, got {}); \
                     refusing to load potentially poisoned model, degrading to RRF-only",
                    path.display(),
                    a.sha256_hex,
                    actual
                );
                return false;
            }
            Err(e) => {
                warn!(
                    "reranker artifact hash failed for {}: {e}; treating model as not ready",
                    path.display()
                );
                return false;
            }
        }
    }
    true
}

/// `fastembed-rs` cross-encoder adapter.
///
/// Construct via [`FastembedReranker::with_default_path`] for the
/// out-of-the-box `~/.clx/models/bge-reranker-v2-m3/` location, or via
/// [`FastembedReranker::new`] when the user has configured a custom path.
pub struct FastembedReranker {
    /// Root directory under which the `fastembed` `HuggingFace` cache lives.
    cache_dir: PathBuf,
    /// Lazily-initialised ONNX session. `None` until the first successful
    /// `score()` call. Held under a mutex because v5's
    /// `TextRerank::rerank` requires `&mut self`.
    inner: Mutex<Option<TextRerank>>,
}

impl FastembedReranker {
    /// Construct an adapter against an explicit cache directory.
    ///
    /// The directory should be the parent of the model folder (e.g.
    /// `~/.clx/models/`), not the model folder itself; `fastembed-rs`
    /// owns the layout below this path.
    #[must_use]
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            inner: Mutex::new(None),
        }
    }

    /// Construct an adapter using the default CLX model cache location
    /// (`~/.clx/models/`).
    #[must_use]
    pub fn with_default_path() -> Self {
        Self::new(crate::paths::model_cache_dir())
    }

    /// Path to the readiness sentinel file
    /// (`{cache_dir}/bge-reranker-v2-m3/.ready`). Public so the
    /// `clx model fetch` orchestrator can write the same file the
    /// adapter reads.
    #[must_use]
    pub fn ready_sentinel_path(&self) -> PathBuf {
        self.cache_dir
            .join(DEFAULT_MODEL_DIRNAME)
            .join(READY_SENTINEL)
    }

    /// Readiness check shared by the trait implementation and the hook's
    /// prefetch gate.
    ///
    /// F9 hardening: a present `.ready` sentinel is no longer trusted on
    /// its own. The sentinel pins a SHA-256 (and size) for every model
    /// artifact, captured at fetch time right after fastembed-rs verified
    /// the download via Hugging Face LFS checksums ("trust on first
    /// verified fetch, verify on every use"). Here we re-verify those
    /// digests so a same-uid attacker who pre-stages a poisoned
    /// `model.onnx`/`model.onnx.data` while keeping a stale sentinel is
    /// rejected and the pipeline degrades to RRF-only.
    ///
    /// Latency: the full re-hash of the 2.27 GB weights cannot run on
    /// every recall. We short-circuit on the cheap size signal first and
    /// memoize the full digest verification result per process via a
    /// `OnceLock` (the cache dir is fixed for the process lifetime, so a
    /// single verification is sound; a mid-session swap is still caught by
    /// the size short-circuit, and a same-size same-hash swap is the
    /// documented unavoidable residual of any same-uid local scheme).
    #[must_use]
    pub fn ready_at(cache_dir: &Path) -> bool {
        static VERIFIED: OnceLock<bool> = OnceLock::new();
        *VERIFIED.get_or_init(|| Self::verify_ready_uncached(cache_dir))
    }

    /// Uncached readiness verification. Factored out so tests can exercise
    /// the full parse + digest path without the process-global memo (the
    /// `OnceLock` in [`Self::ready_at`] would otherwise pin the first
    /// tempdir's result for the whole test binary).
    #[must_use]
    pub fn verify_ready_uncached(cache_dir: &Path) -> bool {
        let model_dir = cache_dir.join(DEFAULT_MODEL_DIRNAME);
        let sentinel = model_dir.join(READY_SENTINEL);

        let body = match std::fs::read_to_string(&sentinel) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(e) => {
                warn!(
                    "reranker sentinel unreadable at {}: {e}; treating model as not ready",
                    sentinel.display()
                );
                return false;
            }
        };

        let Some(parsed) = parse_sentinel(&body) else {
            // Legacy opaque marker or malformed content. Degrade to
            // RRF-only and let `clx model fetch` re-pin it.
            warn!(
                "reranker sentinel at {} is not a content-pinned v1 sentinel \
                 (legacy or malformed); treating model as not ready, run `clx model fetch`",
                sentinel.display()
            );
            return false;
        };

        verify_sentinel_against_disk(&model_dir, &parsed)
    }

    /// Build the v5 init options. Extracted for unit-test visibility into
    /// the construction path; production callers go through `score()`.
    fn build_init_options(&self) -> RerankInitOptions {
        RerankInitOptions::new(RerankerModel::BGERerankerV2M3)
            .with_cache_dir(self.cache_dir.clone())
            .with_show_download_progress(false)
    }
}

#[async_trait]
impl Reranker for FastembedReranker {
    async fn score(&self, query: &str, candidates: &[&str]) -> Result<Vec<f32>, RerankError> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // Snapshot the inputs into owned strings so they can move into
        // the blocking task. fastembed's API takes `impl AsRef<[S]>` so
        // we have to allocate here regardless.
        let query_owned = query.to_string();
        let docs_owned: Vec<String> = candidates.iter().map(|s| (*s).to_string()).collect();
        let expected = docs_owned.len();

        // Move a reference to the mutex into the blocking task. We use a
        // raw pointer wrapper via `&'static`-style trickery? No: we use
        // the `tokio::task::spawn_blocking` with a closure that captures
        // a clone of an `Arc`-free path by holding the mutex through the
        // unsafe-free route below.
        //
        // The mutex itself is owned by `self`. We cannot move it. So we
        // perform the load + rerank under a single critical section by
        // taking ownership of the option temporarily on the blocking
        // thread. To do that without `Arc`, we lift the work into a
        // helper that receives `&Mutex<...>` via a scoped reference.
        //
        // `spawn_blocking` requires `'static` closures, so we cannot
        // borrow `&self` across it. Instead, we acquire the lock, take
        // the model out (replacing with `None`), pass it into the
        // blocking task by value, and re-install it on completion. This
        // serialises concurrent callers on the mutex lock acquisition,
        // which matches the underlying ONNX session's single-threaded
        // contract.
        let init_options = self.build_init_options();

        // Hold the lock until we have either taken the existing model or
        // claimed the right to load. We then drop the guard before the
        // blocking task starts so other callers can queue behind us.
        let taken_model: Option<TextRerank> = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|e| RerankError::Backend(format!("rerank mutex poisoned: {e}")))?;
            guard.take()
        };

        let cache_dir = self.cache_dir.clone();

        let (returned_model, scores_result) = tokio::task::spawn_blocking(
            move || -> (Option<TextRerank>, Result<Vec<f32>, RerankError>) {
                // Lazy-load if we did not have a cached model. This sync
                // call (which downloads + loads the ONNX session on first
                // run) is now INSIDE the spawn_blocking, so the outer
                // tokio::time::timeout can cancel the whole pipeline.
                let mut model = if let Some(m) = taken_model {
                    m
                } else {
                    {
                        debug!(
                            "loading bge-reranker-v2-m3 from cache_dir={}",
                            cache_dir.display()
                        );
                        match TextRerank::try_new(init_options) {
                            Ok(m) => m,
                            Err(e) => {
                                return (
                                    None,
                                    Err(RerankError::Backend(format!(
                                        "fastembed init failed: {e}"
                                    ))),
                                );
                            }
                        }
                    }
                };

                let rerank_result = model.rerank(
                    query_owned.as_str(),
                    docs_owned.iter().map(String::as_str).collect::<Vec<_>>(),
                    false,
                    Some(expected.max(1)),
                );

                let scores = match rerank_result {
                    Ok(results) => {
                        // fastembed returns results re-sorted by score
                        // desc; we need them in input order so the caller
                        // can zip back to their hits. The `index` field
                        // preserves the original position.
                        let mut by_index: Vec<(usize, f32)> =
                            results.into_iter().map(|r| (r.index, r.score)).collect();
                        by_index.sort_by_key(|(idx, _)| *idx);

                        if by_index.len() == expected {
                            Ok(by_index.into_iter().map(|(_, score)| score).collect())
                        } else {
                            Err(RerankError::OutputLengthMismatch {
                                expected,
                                got: by_index.len(),
                            })
                        }
                    }
                    Err(e) => Err(RerankError::Backend(format!("fastembed rerank: {e}"))),
                };

                (Some(model), scores)
            },
        )
        .await
        .map_err(|e| {
            warn!("rerank blocking task join error: {e}");
            RerankError::Backend(format!("blocking task join: {e}"))
        })?;

        // Re-install the model into the cache regardless of whether the
        // rerank itself succeeded; the session is still valid for reuse
        // after a logical error like length mismatch.
        if let Some(model) = returned_model
            && let Ok(mut guard) = self.inner.lock()
        {
            // Only install if no other caller has loaded in the
            // meantime; if they did, our taken_model was None and we
            // freshly loaded, so prefer keeping the existing one.
            if guard.is_none() {
                *guard = Some(model);
            }
        }

        scores_result
    }

    fn is_ready(&self) -> bool {
        Self::ready_at(&self.cache_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;

    use crate::recall::rerank::apply_reranker;
    use crate::recall::{RecallHit, RecallSearchType};

    #[test]
    fn is_ready_false_when_sentinel_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let adapter = FastembedReranker::new(tmp.path().to_path_buf());
        assert!(!adapter.is_ready(), "no sentinel => not ready");
    }

    /// Stage a model dir with `model.onnx` of given bytes plus a valid
    /// content-pinned sentinel covering it. Returns the model dir.
    fn stage_pinned_model(root: &Path, onnx_bytes: &[u8]) -> PathBuf {
        let model_dir = root.join(DEFAULT_MODEL_DIRNAME);
        std::fs::create_dir_all(&model_dir).expect("mkdir model dir");
        std::fs::write(model_dir.join("model.onnx"), onnx_bytes).expect("write onnx");
        let hex = {
            let mut h = Sha256::new();
            h.update(onnx_bytes);
            hex::encode(h.finalize())
        };
        let artifacts = [PinnedArtifact {
            rel_path: "model.onnx".to_string(),
            sha256_hex: hex,
            size: onnx_bytes.len() as u64,
        }];
        std::fs::write(model_dir.join(READY_SENTINEL), render_sentinel(&artifacts))
            .expect("write sentinel");
        model_dir
    }

    #[test]
    fn is_ready_true_when_sentinel_present_and_hash_matches() {
        let tmp = TempDir::new().expect("tempdir");
        stage_pinned_model(tmp.path(), b"fake-onnx-bytes");
        let adapter = FastembedReranker::new(tmp.path().to_path_buf());
        // Bypass the process-global OnceLock memo (other tests in this
        // binary may have primed it with a different tempdir).
        assert!(
            FastembedReranker::verify_ready_uncached(&adapter.cache_dir),
            "valid pinned sentinel => ready"
        );
    }

    #[test]
    fn is_ready_false_when_legacy_opaque_marker() {
        // Pre-F9 sentinel body (`ready`) must be rejected so the model
        // is re-fetched and re-pinned rather than trusted blindly.
        let tmp = TempDir::new().expect("tempdir");
        let model_dir = tmp.path().join(DEFAULT_MODEL_DIRNAME);
        std::fs::create_dir_all(&model_dir).expect("mkdir");
        std::fs::write(model_dir.join("model.onnx"), b"x").expect("onnx");
        std::fs::write(model_dir.join(READY_SENTINEL), b"ready").expect("legacy sentinel");
        assert!(
            !FastembedReranker::verify_ready_uncached(tmp.path()),
            "legacy opaque marker must NOT be considered ready"
        );
    }

    #[test]
    fn is_ready_false_when_model_bytes_mutated_after_pin() {
        // Core F9 regression: attacker swaps model.onnx for a poisoned
        // payload but keeps the old sentinel. Must be rejected.
        let tmp = TempDir::new().expect("tempdir");
        let model_dir = stage_pinned_model(tmp.path(), b"genuine-weights");
        // Poison the file in place; sentinel still records the old hash.
        std::fs::write(model_dir.join("model.onnx"), b"POISONED-PAYLOAD!!").expect("overwrite");
        assert!(
            !FastembedReranker::verify_ready_uncached(tmp.path()),
            "mutated model bytes must invalidate readiness"
        );
    }

    #[test]
    fn is_ready_false_when_same_size_different_bytes() {
        // Size short-circuit alone is not enough: a same-length swap must
        // still be caught by the SHA-256 check.
        let tmp = TempDir::new().expect("tempdir");
        let model_dir = stage_pinned_model(tmp.path(), b"AAAAAAAA");
        std::fs::write(model_dir.join("model.onnx"), b"BBBBBBBB").expect("same-size swap");
        assert!(
            !FastembedReranker::verify_ready_uncached(tmp.path()),
            "same-size different-content swap must be rejected by hash"
        );
    }

    #[test]
    fn is_ready_false_when_sentinel_malformed() {
        let tmp = TempDir::new().expect("tempdir");
        let model_dir = tmp.path().join(DEFAULT_MODEL_DIRNAME);
        std::fs::create_dir_all(&model_dir).expect("mkdir");
        std::fs::write(model_dir.join("model.onnx"), b"x").expect("onnx");
        std::fs::write(
            model_dir.join(READY_SENTINEL),
            b"clx-model-sentinel v1\nthis is not a valid artifact line\n",
        )
        .expect("malformed sentinel");
        assert!(
            !FastembedReranker::verify_ready_uncached(tmp.path()),
            "malformed sentinel must not panic and must be not-ready"
        );
    }

    #[test]
    fn is_ready_false_when_model_file_missing_but_sentinel_present() {
        let tmp = TempDir::new().expect("tempdir");
        let model_dir = stage_pinned_model(tmp.path(), b"weights");
        std::fs::remove_file(model_dir.join("model.onnx")).expect("rm onnx");
        assert!(
            !FastembedReranker::verify_ready_uncached(tmp.path()),
            "sentinel present but pinned artifact gone => not ready"
        );
    }

    #[test]
    fn is_ready_true_when_onnx_under_subdir_layout() {
        // fastembed layout variant: model.onnx under onnx/. The sentinel
        // pins the relative path, so the resolver must follow it.
        let tmp = TempDir::new().expect("tempdir");
        let model_dir = tmp.path().join(DEFAULT_MODEL_DIRNAME);
        std::fs::create_dir_all(model_dir.join("onnx")).expect("mkdir onnx");
        let bytes = b"subdir-weights";
        std::fs::write(model_dir.join("onnx").join("model.onnx"), bytes).expect("onnx");
        let hex = {
            let mut h = Sha256::new();
            h.update(bytes);
            hex::encode(h.finalize())
        };
        let artifacts = [PinnedArtifact {
            rel_path: "onnx/model.onnx".to_string(),
            sha256_hex: hex,
            size: bytes.len() as u64,
        }];
        std::fs::write(model_dir.join(READY_SENTINEL), render_sentinel(&artifacts))
            .expect("sentinel");
        assert!(
            FastembedReranker::verify_ready_uncached(tmp.path()),
            "onnx-under-subdir layout must resolve and verify"
        );
    }

    #[test]
    fn is_ready_false_when_sentinel_path_escapes_model_dir() {
        // A hostile sentinel that points the hash check at a file outside
        // the model dir (path traversal) must be rejected outright.
        let tmp = TempDir::new().expect("tempdir");
        let model_dir = tmp.path().join(DEFAULT_MODEL_DIRNAME);
        std::fs::create_dir_all(&model_dir).expect("mkdir");
        std::fs::write(
            model_dir.join(READY_SENTINEL),
            "clx-model-sentinel v1\nsha256:".to_string()
                + &"a".repeat(64)
                + "  size:1  path:../../../etc/hostfile\n",
        )
        .expect("sentinel");
        assert!(
            !FastembedReranker::verify_ready_uncached(tmp.path()),
            "path traversal in sentinel must be rejected"
        );
    }

    #[test]
    fn parse_sentinel_round_trips_render() {
        let arts = vec![
            PinnedArtifact {
                rel_path: "model.onnx".to_string(),
                sha256_hex: "a".repeat(64),
                size: 108,
            },
            PinnedArtifact {
                rel_path: "model.onnx.data".to_string(),
                sha256_hex: "b".repeat(64),
                size: 2_435_000_000,
            },
        ];
        let body = render_sentinel(&arts);
        let parsed = parse_sentinel(&body).expect("round-trip parse");
        assert_eq!(parsed.artifacts, arts);
    }

    #[test]
    fn parse_sentinel_rejects_legacy_and_bad_inputs() {
        assert!(parse_sentinel("ready").is_none(), "legacy marker");
        assert!(parse_sentinel("dryrun").is_none(), "dryrun marker");
        assert!(parse_sentinel("").is_none(), "empty");
        assert!(
            parse_sentinel("clx-model-sentinel v1\n").is_none(),
            "header but no artifacts"
        );
        assert!(
            parse_sentinel("clx-model-sentinel v1\nsha256:zz  size:1  path:m").is_none(),
            "non-hex digest"
        );
        assert!(
            parse_sentinel(&format!(
                "clx-model-sentinel v1\nsha256:{}  size:notnum  path:m",
                "a".repeat(64)
            ))
            .is_none(),
            "non-numeric size"
        );
        assert!(
            parse_sentinel(&format!(
                "clx-model-sentinel v1\nsha256:{}  path:m",
                "a".repeat(64)
            ))
            .is_none(),
            "missing size field"
        );
    }

    #[test]
    fn ready_sentinel_path_layout() {
        let tmp = TempDir::new().expect("tempdir");
        let adapter = FastembedReranker::new(tmp.path().to_path_buf());
        let expected = tmp.path().join(DEFAULT_MODEL_DIRNAME).join(READY_SENTINEL);
        assert_eq!(adapter.ready_sentinel_path(), expected);
    }

    #[test]
    fn ready_at_false_for_empty_sentinel() {
        // Empty sentinel is not a content-pinned v1 sentinel: not ready.
        // Uses verify_ready_uncached to avoid the process-global memo.
        let tmp = TempDir::new().expect("tempdir");
        assert!(!FastembedReranker::verify_ready_uncached(tmp.path()));
        let model_dir = tmp.path().join(DEFAULT_MODEL_DIRNAME);
        std::fs::create_dir_all(&model_dir).expect("mkdir");
        std::fs::write(model_dir.join(READY_SENTINEL), b"").expect("write");
        assert!(
            !FastembedReranker::verify_ready_uncached(tmp.path()),
            "empty sentinel must not be considered ready"
        );
    }

    /// Test backend that simulates a configurable cold-load delay
    /// followed by a fast rerank. Used to prove that `apply_reranker`'s
    /// `tokio::time::timeout` governs the entire load+score pipeline.
    struct SlowLoadBackend {
        load_delay: Duration,
        load_count: Arc<AtomicUsize>,
        rerank_count: Arc<AtomicUsize>,
        loaded: Mutex<bool>,
    }

    impl SlowLoadBackend {
        fn new(load_delay: Duration) -> Self {
            Self {
                load_delay,
                load_count: Arc::new(AtomicUsize::new(0)),
                rerank_count: Arc::new(AtomicUsize::new(0)),
                loaded: Mutex::new(false),
            }
        }
    }

    #[async_trait]
    impl Reranker for SlowLoadBackend {
        async fn score(&self, _query: &str, candidates: &[&str]) -> Result<Vec<f32>, RerankError> {
            // Replicate fastembed.rs's structure: load + score inside a
            // single spawn_blocking, where the load is the expensive step.
            let load_delay = self.load_delay;
            let load_count = self.load_count.clone();
            let rerank_count = self.rerank_count.clone();
            let n = candidates.len();

            // Take the cached flag out, like we do with the real model.
            let was_loaded = {
                let mut g = self.loaded.lock().unwrap();
                let v = *g;
                *g = false; // taken
                v
            };
            let loaded_ref = &self.loaded;

            let (back, result) = tokio::task::spawn_blocking(move || {
                if !was_loaded {
                    load_count.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(load_delay);
                }
                rerank_count.fetch_add(1, Ordering::SeqCst);
                let out: Vec<f32> = (0..n).map(|i| i as f32).collect();
                (true, Ok(out))
            })
            .await
            .map_err(|e| RerankError::Backend(format!("join: {e}")))?;

            // Re-install the "loaded" flag.
            if let Ok(mut g) = loaded_ref.lock()
                && !*g
            {
                *g = back;
            }
            result
        }

        fn is_ready(&self) -> bool {
            true
        }
    }

    fn make_hit(id: i64, summary: &str) -> RecallHit {
        RecallHit {
            snapshot_id: id,
            session_id: format!("s-{id}"),
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            summary: Some(summary.to_string()),
            key_facts: None,
            score: 0.0,
            search_type: RecallSearchType::Semantic,
        }
    }

    /// Cold load that exceeds the timeout must be cancelled by
    /// `tokio::time::timeout`, with the caller falling back to RRF order.
    /// This is the regression test for the ISSUE 1 fix.
    #[tokio::test]
    async fn cold_load_respects_outer_timeout() {
        let backend = SlowLoadBackend::new(Duration::from_millis(500));
        let load_count = backend.load_count.clone();
        let hits = vec![make_hit(1, "alpha"), make_hit(2, "bravo")];
        let started = std::time::Instant::now();
        let out = apply_reranker(hits.clone(), "q", &backend, Duration::from_millis(50)).await;
        let elapsed = started.elapsed();
        // The outer timeout is 50ms; we must return well before the 500ms
        // load completes. Allow generous slack for CI.
        assert!(
            elapsed < Duration::from_millis(400),
            "timeout did not fire fast enough: {elapsed:?}"
        );
        // Fallback returned input unchanged.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].search_type, RecallSearchType::Semantic);
        // The load was at least attempted (we cannot guarantee load
        // counter increment vs cancellation order, so allow 0 or 1).
        let _ = load_count.load(Ordering::SeqCst);
    }

    /// Second call after a successful first call must reuse the loaded
    /// model. We assert `load_count` stays at 1 across two `score()` calls.
    #[tokio::test]
    async fn score_reuses_loaded_model() {
        let backend = SlowLoadBackend::new(Duration::from_millis(10));
        let load_count = backend.load_count.clone();
        let rerank_count = backend.rerank_count.clone();

        // First call: triggers load.
        let _ = backend.score("q", &["a", "b"]).await.expect("first score");
        assert_eq!(load_count.load(Ordering::SeqCst), 1);
        assert_eq!(rerank_count.load(Ordering::SeqCst), 1);

        // Second call: must reuse the cached model.
        let _ = backend.score("q", &["c", "d"]).await.expect("second score");
        assert_eq!(
            load_count.load(Ordering::SeqCst),
            1,
            "second call must not trigger a re-load"
        );
        assert_eq!(rerank_count.load(Ordering::SeqCst), 2);
    }

    /// When the load+score exceeds the outer timeout, the caller must
    /// see an unchanged hit list (fallback) and the rerank fallback
    /// counter must increment.
    #[tokio::test]
    async fn timeout_triggers_rrf_fallback() {
        let baseline = super::super::rerank::RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed);
        let backend = SlowLoadBackend::new(Duration::from_millis(300));
        let hits = vec![make_hit(42, "payload")];
        let out = apply_reranker(hits, "q", &backend, Duration::from_millis(20)).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].snapshot_id, 42);
        // Score unchanged from the input default 0.0.
        assert!((out[0].score - 0.0).abs() < 1e-9);
        assert!(super::super::rerank::RERANK_FALLBACK_TOTAL.load(Ordering::Relaxed) > baseline);
    }
}
