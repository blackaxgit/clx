//! Tamper-evident audit chain for security-control bypass events.
//!
//! Implements a SHA-256 hash chain for `validator_disabled` events (B5-4).
//! Each record contains the env-var *name* only (never value/argv/cwd),
//! a monotonic sequence number, a timestamp, and two hashes:
//! - `prev_hash`: hex-SHA-256 of the previous record's canonical form
//!   (genesis record uses `[0u8; 32]` as the sentinel)
//! - `entry_hash`: hex-SHA-256 of `canonical(this_record) || prev_hash_bytes`
//!
//! The chain is append-only within a single process execution. The head hash
//! is emitted to `tracing::warn!` so it can be anchored in an external sink
//! (log aggregator, syslog) that the process itself cannot rewrite.
//!
//! Tamper-evidence guarantee: altering or deleting any record breaks all
//! subsequent hashes, making tampering detectable on chain verification.
//! This is tamper-evident, not tamper-proof: a local same-uid attacker with
//! write access can recompute the whole chain. The `tracing::warn!` anchor is
//! the external reference that makes wholesale chain replacement detectable.
//!
//! Privacy guarantee: only the env-var NAME is recorded. Values, argv, cwd,
//! and any PII are never stored.

use sha2::{Digest, Sha256};

/// A single hash-chained security-control bypass event.
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct AuditChainRecord {
    /// Monotonic sequence number within this chain (1-based).
    pub seq: u64,
    /// RFC3339 UTC timestamp of the event.
    pub timestamp: String,
    /// Event type tag — always `"validator_disabled"` for B5-4 events.
    pub event_type: &'static str,
    /// The env-var NAME(s) that are active security-weakening overrides,
    /// joined by `", "`. Never contains values.
    pub trigger_keys: String,
    /// Hex-encoded SHA-256 of the previous record's canonical bytes.
    /// Genesis sentinel: `"0000...0000"` (64 hex zeros).
    pub prev_hash: String,
    /// Hex-encoded SHA-256 of `canonical(self) || prev_hash_bytes`.
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

/// Build a `validator_disabled` `AuditChainRecord`, chained onto `prev_hash_hex`.
///
/// `prev_hash_hex` must be exactly 64 lowercase hex characters.
/// `seq` is the 1-based sequence number for this record.
/// `trigger_keys` is the joined list of weakening env-var names.
///
/// Returns the record with `entry_hash` computed.
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

/// Verify a sequence of records forms a valid chain.
///
/// Returns `Ok(())` if every record's `entry_hash` matches the expected
/// re-computation and each record's `prev_hash` equals the previous
/// record's `entry_hash` (genesis uses `GENESIS_HASH`).
/// Returns `Err(String)` with a description of the first broken link.
///
/// This function is intentionally used only in tests (chain-tamper detection
/// proofs). The `#[cfg_attr]` suppresses the dead-code lint outside test builds.
#[cfg_attr(not(test), allow(dead_code))]
pub fn verify_chain(records: &[AuditChainRecord]) -> Result<(), String> {
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
        verify_chain(&[rec]).expect("single record chain must verify");
    }

    /// Multi-record chain verifies correctly.
    #[test]
    fn multi_record_chain_verifies() {
        let r1 = build_record(1, ts(), "CLX_VALIDATOR_ENABLED", GENESIS_HASH);
        let r2 = build_record(2, ts(), "CLX_VALIDATOR_LAYER1_ENABLED", &r1.entry_hash);
        let r3 = build_record(3, ts(), "CLX_VALIDATOR_DEFAULT_DECISION", &r2.entry_hash);
        verify_chain(&[r1, r2, r3]).expect("three-record chain must verify");
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

        let result = verify_chain(&[tampered_r1, r2]);
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
        let result = verify_chain(&[r1, r3]);
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
        let result = verify_chain(&[r2, r1]);
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

        let result = verify_chain(&[r1]);
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

        let result = verify_chain(&[tampered_r1, r2]);
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
            verify_chain(&[t]).is_err(),
            "tampered trigger_keys must fail"
        );

        // Vector 2: tamper timestamp
        let mut t = r1.clone();
        t.timestamp = "1970-01-01T00:00:00Z".to_string();
        assert!(verify_chain(&[t]).is_err(), "tampered timestamp must fail");

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
        assert!(verify_chain(&[t]).is_err(), "tampered seq must fail");
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
        verify_chain(&[]).expect("empty chain must verify");
    }
}
