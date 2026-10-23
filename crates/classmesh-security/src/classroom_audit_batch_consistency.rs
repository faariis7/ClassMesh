//! Phase 12F: offline bounded audit *intent* batch consistency checking.
//!
//! No signatures, trusted start generation, persistence, replay history, OS
//! identity, policy publication or audit commit are provided here. The caller
//! supplies every record and the starting generation; an accepted batch is
//! NOT evidence that any change was authorized, durably committed or ordered
//! against a trustworthy Registry policy epoch. Future trusted writers must
//! validate identity, CAS, epochs and crash-safe policy+audit atomically.

use std::collections::BTreeSet;

use crate::{PrincipalId, classroom_audit_intent_encoding::ClassroomAuditIntentRecord};

/// A bounded number of modest audit *intent* metadata records per check.
pub const MAX_AUDIT_BATCH_ENTRIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditBatchConsistencyError {
    Empty,
    TooMany,
    InvalidStartingGeneration,
    GenerationExhausted,
    VersionGap {
        index: usize,
        expected: u64,
        found: u64,
    },
    DuplicateRequest {
        index: usize,
    },
    TimestampRegression {
        index: usize,
    },
}

/// Validate claimed *internal* sequence consistency of <=64 intent records.
///
/// The starting generation, request IDs and timestamps are untrusted inputs.
/// Replays across batches cannot be recognized here: the future durable
/// journal must separately deduplicate against persistent authenticated
/// history and reconcile against an independently protected policy epoch.
pub fn check_classroom_audit_batch_consistency(
    starting_generation: u64,
    intents: &[ClassroomAuditIntentRecord],
) -> Result<(), AuditBatchConsistencyError> {
    if intents.is_empty() {
        return Err(AuditBatchConsistencyError::Empty);
    }
    if intents.len() > MAX_AUDIT_BATCH_ENTRIES {
        return Err(AuditBatchConsistencyError::TooMany);
    }
    if starting_generation == 0 || starting_generation == u64::MAX {
        return Err(AuditBatchConsistencyError::InvalidStartingGeneration);
    }

    let mut expected_generation = starting_generation;
    let mut last_timestamp = 0;
    let mut requests: BTreeSet<(PrincipalId, u64)> = BTreeSet::new();
    for (index, intent) in intents.iter().enumerate() {
        if intent.expected_policy_generation() != expected_generation {
            return Err(AuditBatchConsistencyError::VersionGap {
                index,
                expected: expected_generation,
                found: intent.expected_policy_generation(),
            });
        }
        if intent.checked_at_unix_ms() < last_timestamp {
            return Err(AuditBatchConsistencyError::TimestampRegression { index });
        }
        if !requests.insert((intent.actor(), intent.request_id())) {
            return Err(AuditBatchConsistencyError::DuplicateRequest { index });
        }
        last_timestamp = intent.checked_at_unix_ms();
        if index + 1 != intents.len() {
            expected_generation = expected_generation
                .checked_add(1)
                .filter(|next| *next != u64::MAX)
                .ok_or(AuditBatchConsistencyError::GenerationExhausted)?;
        }
    }
    Ok(())
}
