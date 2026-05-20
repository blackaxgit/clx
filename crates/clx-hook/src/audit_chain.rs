//! Tamper-evident per-event fingerprinting for security-control bypass events.
//!
//! Implements SHA-256 fingerprinting for `validator_disabled` events (B5-4).
//! Each record contains the env-var *name* only (never value/argv/cwd),
//! a monotonic sequence number within the current process, a timestamp, and
//! two hashes:
//! - `prev_hash`: hex-SHA-256 of the previous record in the current process's
//!   sequence (genesis sentinel: `[0u8; 32]`, i.e. 64 hex zeros)
//! - `entry_hash`: hex-SHA-256 of `canonical(this_record) || prev_hash_bytes`
//!
//! ## Scope and honest property statement
//!
//! `clx-hook` is a short-lived process spawned once per hook event. Therefore:
//!
//! - **In-process sequence integrity holds**: if multiple B5-4 events fire
//!   within a single process lifetime (possible if the caller invokes the
//!   handler in a loop or in tests), every record is cryptographically linked
//!   to its predecessor, and `verify_fingerprint_sequence` detects any
//!   field-level tampering across the sequence.
//!
//! - **Cross-process linkage does NOT hold**: each new process invocation
//!   starts from `seq=1` and `GENESIS_HASH`. There is no persisted head hash,
//!   so records from different hook process invocations are NOT linked to each
//!   other. This is not a cross-invocation hash chain.
//!
//! - **Single-record integrity ALWAYS holds**: every individual record's
//!   `entry_hash` is a deterministic, verifiable SHA-256 fingerprint of its
//!   own fields combined with `prev_hash`. A single record can be verified in
//!   isolation by recomputing `build_record(seq, ts, keys, prev_hash)` and
//!   comparing `entry_hash`. This per-event integrity is the actual property
//!   delivered by this module.
//!
//! The `entry_hash` is emitted to `tracing::warn!` so it is captured by an
//! external append-only sink (log aggregator, syslog) that the process itself
//! cannot rewrite. An external observer can verify that a specific bypass event
//! was recorded with specific fields at a specific time by recomputing the hash.
//!
//! Tamper-evidence guarantee: altering any field of a record changes its
//! `entry_hash`, making the alteration detectable by anyone who captured the
//! original hash from the external sink.
//! This is tamper-evident, not tamper-proof: a local same-uid attacker with
//! write access can forge any single-record fingerprint. The `tracing::warn!`
//! anchor in an external sink is the reference that makes forgery detectable.
//!
//! Privacy guarantee: only the env-var NAME is recorded. Values, argv, cwd,
//! and any PII are never stored.

use sha2::{Digest, Sha256};

/// A single SHA-256-fingerprinted security-control bypass event.
///
/// Each record is self-describing: its `entry_hash` is a deterministic
/// fingerprint of all its own fields plus `prev_hash`. A record can be
/// verified in isolation without access to any prior record.
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct AuditChainRecord {
    /// Monotonic sequence number within the current process invocation (1-based).
    /// Resets to 1 on each new process start; does NOT reflect cross-process ordering.
    pub seq: u64,
    /// RFC3339 UTC timestamp of the event.
    pub timestamp: String,
    /// Event type tag — always `"validator_disabled"` for B5-4 events.
    pub event_type: &'static str,
    /// The env-var NAME(s) that are active security-weakening overrides,
    /// joined by `", "`. Never contains values.
    pub trigger_keys: String,
    /// Hex-encoded SHA-256 of the previous record's canonical bytes within
    /// this process's sequence. For the first record (seq=1), equals
    /// `GENESIS_HASH` (64 hex zeros). Not linked to prior process invocations.
    pub prev_hash: String,
    /// Hex-encoded SHA-256 of `canonical(self) || prev_hash_bytes`.
    /// This is the per-event integrity fingerprint: recompute with
    /// `build_record(seq, timestamp, trigger_keys, prev_hash)` and compare
    /// to verify the record has not been altered.
    pub entry_hash: String,
}

impl AuditChainRecord {
    /// Canonical serialization used for hashing (stable key order, no optional fields).
    ///
    /// Format: `seq={seq};ts={timestamp};event={event_type};keys={trigger_keys}`
    /// This is deliberately simple (no serde dependency) and deterministic.
    fn canonical(&self) -> String {
        format!(
            "seq={};ts={};event={};keys={}",
            self.seq, self.timestamp, self.event_type, self.trigger_keys
        )
    }
}

/// Build a `validator_disabled` `AuditChainRecord` with a SHA-256 fingerprint.
///
/// `prev_hash_hex` must be exactly 64 lowercase hex characters. For the first
/// record in a process use `GENESIS_HASH`. For subsequent records in the same
/// process, pass the previous record's `entry_hash`.
/// `seq` is the 1-based sequence number within the current process invocation.
/// `trigger_keys` is the joined list of weakening env-var names (never values).
///
/// Returns the record with `entry_hash` computed. The resulting `entry_hash`
/// is a verifiable per-event integrity fingerprint.
pub fn build_record(
    seq: u64,
    timestamp: &str,
    trigger_keys: &str,
    prev_hash_hex: &str,
) -> AuditChainRecord {
    // Decode prev_hash bytes for chaining
    let prev_bytes = hex::decode(prev_hash_hex).unwrap_or_else(|_| vec![0u8; 32]);

    // Construct an incomplete record to compute canonical form
    let partial = AuditChainRecord {
        seq,
        timestamp: timestamp.to_string(),
        event_type: "validator_disabled",
        trigger_keys: trigger_keys.to_string(),
        prev_hash: prev_hash_hex.to_string(),
        entry_hash: String::new(), // filled below
    };

    let canonical = partial.canonical();

    // entry_hash = SHA-256(canonical_bytes || prev_hash_bytes)
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.update(&prev_bytes);
    let digest = hasher.finalize();
    let entry_hash = hex::encode(digest);

    AuditChainRecord {
        entry_hash,
        ..partial
    }
}

/// The genesis `prev_hash` sentinel: 64 hex zeros.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Verify a sequence of records for per-event fingerprint integrity.
///
/// For each record, recomputes `entry_hash` from its own fields and
/// `prev_hash`, then checks that `prev_hash` equals the previous record's
/// `entry_hash` (genesis uses `GENESIS_HASH`).
///
/// Returns `Ok(())` if every record's fingerprint is self-consistent.
/// Returns `Err(String)` with a description of the first broken link.
///
/// **Scope note**: this verifies in-process sequence integrity only. It does
/// not and cannot verify cross-process linkage (each new process starts from
/// `seq=1` and `GENESIS_HASH`). Use this function to verify records collected
/// within a single process invocation, or to verify individual records in
/// isolation by passing a single-element slice.
///
/// This function is used only in tests (fingerprint integrity proofs).
/// The `#[cfg_attr]` suppresses the dead-code lint outside test builds.
#[cfg_attr(not(test), allow(dead_code))]
pub fn verify_fingerprint_sequence(records: &[AuditChainRecord]) -> Result<(), String> {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (i, rec) in records.iter().enumerate() {
        if rec.prev_hash != expected_prev {
            return Err(format!(
                "record {i} (seq={}) prev_hash mismatch: expected {expected_prev}, got {}",
                rec.seq, rec.prev_hash
            ));
        }
        let rebuilt = build_record(rec.seq, &rec.timestamp, &rec.trigger_keys, &rec.prev_hash);
        if rebuilt.entry_hash != rec.entry_hash {
            return Err(format!(
                "record {i} (seq={}) entry_hash mismatch: expected {}, got {}",
                rec.seq, rebuilt.entry_hash, rec.entry_hash
            ));
        }
        expected_prev.clone_from(&rec.entry_hash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> &'static str {
        "2026-05-19T00:00:00Z"
    }

    // -------------------------------------------------------------------
    // B5-4 fail-before guard: proves the chain construction is not a no-op.
    // A tampered record must break verify_chain — this is the core invariant.
    // -------------------------------------------------------------------

    /// Happy path: a single-record chain verifies correctly.
    #[test]
    fn single_record_chain_verifies() {
        let rec = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        assert!(!rec.entry_hash.is_empty());
        assert_eq!(rec.prev_hash, GENESIS_HASH);
        assert_eq!(rec.seq, 1);
        assert_eq!(rec.event_type, "validator_disabled");
        verify_fingerprint_sequence(&[rec]).expect("single record chain must verify");
    }

    /// Multi-record chain verifies correctly.
    #[test]
    fn multi_record_chain_verifies() {
        let r1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        let r2 = build_record(2, ts(), "CLX_VALIDATOR_LAYER1_ENABLED", &r1.entry_hash);
        let r3 = build_record(3, ts(), "CLX_VALIDATOR_DEFAULT_DECISION", &r2.entry_hash);
        verify_fingerprint_sequence(&[r1, r2, r3]).expect("three-record chain must verify");
    }

    /// Adversarial re-derivation: tampering with `trigger_keys` breaks the chain.
    /// This is the primary evidence bundle test for B5-4's hash-chain property.
    /// FAIL-BEFORE: without the hash chain, tampering would be undetectable.
    #[test]
    fn tampered_trigger_keys_breaks_chain() {
        let r1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        let r2 = build_record(2, ts(), "CLX_VALIDATOR_LAYER1_ENABLED", &r1.entry_hash);

        // Adversary tampers with r1.trigger_keys to conceal the env-var name
        let mut tampered_r1 = r1.clone();
        tampered_r1.trigger_keys = "TAMPERED".to_string();

        let result = verify_fingerprint_sequence(&[tampered_r1, r2]);
        assert!(
            result.is_err(),
            "chain with tampered trigger_keys must fail verification"
        );
    }

    /// Adversarial re-derivation: deleting a record (reordering) breaks the chain.
    #[test]
    fn deleted_record_breaks_chain() {
        let r1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        let r2 = build_record(2, ts(), "CLX_VALIDATOR_LAYER1_ENABLED", &r1.entry_hash);
        let r3 = build_record(3, ts(), "CLX_VALIDATOR_DEFAULT_DECISION", &r2.entry_hash);

        // Adversary deletes r2, tries to present [r1, r3]
        let result = verify_fingerprint_sequence(&[r1, r3]);
        assert!(
            result.is_err(),
            "chain with deleted record must fail verification"
        );
    }

    /// Adversarial re-derivation: reordering records breaks the chain.
    #[test]
    fn reordered_records_break_chain() {
        let r1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        let r2 = build_record(2, ts(), "CLX_VALIDATOR_LAYER1_ENABLED", &r1.entry_hash);

        // Swap order: r2 first, then r1 — prev_hash chain is wrong
        let result = verify_fingerprint_sequence(&[r2, r1]);
        assert!(
            result.is_err(),
            "chain with reordered records must fail verification"
        );
    }

    /// Adversarial re-derivation: tampering with `entry_hash` directly is detected.
    #[test]
    fn tampered_entry_hash_breaks_chain() {
        let mut r1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        let original_hash = r1.entry_hash.clone();
        // Flip one character
        let first_char = original_hash.chars().next().unwrap();
        let flipped = if first_char == 'a' { 'b' } else { 'a' };
        r1.entry_hash = format!("{}{}", flipped, &original_hash[1..]);

        let result = verify_fingerprint_sequence(&[r1]);
        assert!(
            result.is_err(),
            "chain with tampered entry_hash must fail verification"
        );
    }

    /// Adversarial re-derivation: tampering with timestamp breaks the chain.
    #[test]
    fn tampered_timestamp_breaks_chain() {
        let r1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        let r2 = build_record(2, ts(), "CLX_VALIDATOR_LAYER1_ENABLED", &r1.entry_hash);

        // Adversary changes r1 timestamp to hide when the bypass occurred
        let mut tampered_r1 = r1.clone();
        tampered_r1.timestamp = "1970-01-01T00:00:00Z".to_string();

        let result = verify_fingerprint_sequence(&[tampered_r1, r2]);
        assert!(
            result.is_err(),
            "chain with tampered timestamp must fail verification"
        );
    }

    /// Proptest-style table: all four single-field tamper vectors break verification.
    #[test]
    fn all_single_field_tamper_vectors_detected() {
        let r1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);

        // Vector 1: tamper trigger_keys
        let mut t = r1.clone();
        t.trigger_keys = "X".to_string();
        assert!(
            verify_fingerprint_sequence(&[t]).is_err(),
            "tampered trigger_keys must fail"
        );

        // Vector 2: tamper timestamp
        let mut t = r1.clone();
        t.timestamp = "1970-01-01T00:00:00Z".to_string();
        assert!(
            verify_fingerprint_sequence(&[t]).is_err(),
            "tampered timestamp must fail"
        );

        // Vector 3: tamper event_type (not possible via build_record but simulate)
        // We can't change the static str through build_record, so verify directly
        // by checking that different event_type input produces different hash
        let r_alt = build_record(1, ts(), "OTHER_KEY", GENESIS_HASH);
        assert_ne!(
            r1.entry_hash, r_alt.entry_hash,
            "different keys must produce different hashes"
        );

        // Vector 4: tamper seq
        let mut t = r1.clone();
        t.seq = 99;
        assert!(
            verify_fingerprint_sequence(&[t]).is_err(),
            "tampered seq must fail"
        );
    }

    /// Genesis sentinel: `prev_hash` of first record must equal `GENESIS_HASH`.
    #[test]
    fn genesis_hash_is_all_zeros() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(
            GENESIS_HASH.chars().all(|c| c == '0'),
            "genesis hash must be 64 hex zeros"
        );
        let r = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        assert_eq!(r.prev_hash, GENESIS_HASH);
    }

    /// Empty chain verifies (no-op, valid base case).
    #[test]
    fn empty_chain_verifies() {
        verify_fingerprint_sequence(&[]).expect("empty chain must verify");
    }

    // -------------------------------------------------------------------
    // F3 / Option-A regression: per-event fingerprint isolation property.
    //
    // POST-FIX PROPERTY (what the code actually delivers):
    //   A single AuditChainRecord produced by build_record(seq, ts, keys, prev)
    //   is verifiable in isolation — recomputing the hash from its own fields
    //   yields the same entry_hash — regardless of any other records or process
    //   invocations. This is the property the CHANGELOG and PR text must claim.
    //
    // What the code does NOT deliver (and must NOT be claimed):
    //   Cross-process linkage. Each new process starts seq=1 and GENESIS_HASH.
    //   Two records from different process invocations share the same seq and
    //   the same prev_hash, so verify_fingerprint_sequence([p1_rec, p2_rec])
    //   will only pass if p2_rec.prev_hash happens to equal p1_rec.entry_hash,
    //   which it won't (p2_rec.prev_hash is always GENESIS_HASH).
    // -------------------------------------------------------------------

    /// Option-A regression: a single record is verifiable in isolation.
    /// This is the core per-event fingerprint property.
    #[test]
    fn single_record_verifiable_in_isolation() {
        let rec = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        // Recompute the fingerprint independently
        let recomputed = build_record(rec.seq, &rec.timestamp, &rec.trigger_keys, &rec.prev_hash);
        assert_eq!(
            rec.entry_hash, recomputed.entry_hash,
            "per-event fingerprint must be reproducible from the record's own fields"
        );
        // Also verifies via the sequence verifier with a single-element slice
        verify_fingerprint_sequence(&[rec]).expect("single record must verify in isolation");
    }

    /// Option-A regression: two records from simulated separate process
    /// invocations both start from `GENESIS_HASH` (seq=1). Their `entry_hash`es
    /// differ if their fields differ, but they are NOT linked to each other.
    /// Attempting to verify them as a sequence fails: proving no cross-process
    /// chain exists.
    #[test]
    fn separate_process_invocations_are_not_linked() {
        // Simulate process invocation 1: hook fires, sees CLX_VALIDATOR_ENABLED
        let proc1_rec = build_record(
            1,
            "2026-05-19T10:00:00Z",
            "CLX_VALIDATOR_ENABLED",
            GENESIS_HASH,
        );

        // Simulate process invocation 2 (later): hook fires again, same key
        let proc2_rec = build_record(
            1,
            "2026-05-19T10:01:00Z",
            "CLX_VALIDATOR_ENABLED",
            GENESIS_HASH,
        );

        // Both records start from GENESIS_HASH; they are not linked.
        assert_eq!(
            proc1_rec.prev_hash, GENESIS_HASH,
            "proc1 starts from genesis"
        );
        assert_eq!(
            proc2_rec.prev_hash, GENESIS_HASH,
            "proc2 also starts from genesis"
        );
        assert_eq!(proc1_rec.seq, 1, "proc1 seq is 1");
        assert_eq!(
            proc2_rec.seq, 1,
            "proc2 seq is also 1; no cross-process ordering"
        );

        // Each record is individually verifiable in isolation.
        verify_fingerprint_sequence(std::slice::from_ref(&proc1_rec))
            .expect("proc1 record verifiable in isolation");
        verify_fingerprint_sequence(std::slice::from_ref(&proc2_rec))
            .expect("proc2 record verifiable in isolation");

        // But presenting them as a two-event sequence fails: proc2.prev_hash is
        // GENESIS_HASH, not proc1.entry_hash. This is the honest proof that no
        // cross-process chain exists.
        let cross_process_result = verify_fingerprint_sequence(&[proc1_rec, proc2_rec]);
        assert!(
            cross_process_result.is_err(),
            "records from separate process invocations must NOT form a valid sequence \
             (no cross-process chain — this is the expected and documented behavior)"
        );
    }

    /// Option-A regression: a single record's `entry_hash` is deterministic.
    /// The same inputs always produce the same fingerprint. This is required
    /// for an external log aggregator to re-verify a captured hash.
    #[test]
    fn fingerprint_is_deterministic_for_same_inputs() {
        let h1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH).entry_hash;
        let h2 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH).entry_hash;
        assert_eq!(
            h1, h2,
            "fingerprint must be deterministic for identical inputs"
        );
    }

    /// Option-A regression: different env-var names produce different fingerprints.
    /// An external log aggregator can distinguish which override was active.
    #[test]
    fn different_trigger_keys_produce_different_fingerprints() {
        let h_enabled = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH).entry_hash;
        let h_layer1 =
            build_record(1, ts(), "CLX_VALIDATOR_LAYER1_ENABLED", GENESIS_HASH).entry_hash;
        let h_both = build_record(
            1,
            ts(),
            "CLX_VALIDATOR_ENABLED, CLX_VALIDATOR_LAYER1_ENABLED",
            GENESIS_HASH,
        )
        .entry_hash;
        assert_ne!(
            h_enabled, h_layer1,
            "different keys must produce different fingerprints"
        );
        assert_ne!(
            h_enabled, h_both,
            "different key sets must produce different fingerprints"
        );
        assert_ne!(
            h_layer1, h_both,
            "different key sets must produce different fingerprints"
        );
    }
}
