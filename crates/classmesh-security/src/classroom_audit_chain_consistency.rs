//! Bounded, OFFLINE consistency of untrusted audit intent sequences across batches.
//!
//! Caller supplies the first generation and all records. This is NOT an
//! authenticated persistent replay history, trusted epoch, audit log, policy
//! transaction or permission grant. Passing grants no commit authority.
//! A real writer must bind enrolled Admin and current policy and atomically
//! verify/write audit+policy+protected monotonic epoch with crash recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Permission, PrincipalId,
    classroom_audit_batch_consistency::{
        AuditBatchConsistencyError, check_classroom_audit_batch_consistency,
    },
    classroom_audit_intent_encoding::ClassroomAuditIntentRecord,
};

pub const MAX_AUDIT_CHAIN_BATCHES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditChainConsistencyError {
    EmptyChain,
    TooManyBatches,
    InvalidBatch {
        batch_index: usize,
        reason: AuditBatchConsistencyError,
    },
    GenerationExhausted,
    DuplicateRequest {
        batch_index: usize,
        index: usize,
    },
    TimestampRegression {
        batch_index: usize,
        index: usize,
    },
    ContradictoryPriorPermission {
        batch_index: usize,
        index: usize,
    },
}

/// Compare up to 16 in-memory audit-intent batches (up to 64 entries each),
/// including cross-boundary order/replay and claimed after→before coherence.
/// Does not trust either the starting generation or any record.
pub fn check_classroom_audit_chain_consistency(
    starting_generation: u64,
    batches: &[&[ClassroomAuditIntentRecord]],
) -> Result<(), AuditChainConsistencyError> {
    if batches.is_empty() {
        return Err(AuditChainConsistencyError::EmptyChain);
    }
    if batches.len() > MAX_AUDIT_CHAIN_BATCHES {
        return Err(AuditChainConsistencyError::TooManyBatches);
    }

    let mut expected_generation = starting_generation;
    let mut last_timestamp: Option<u64> = None;
    let mut seen_requests: BTreeSet<(PrincipalId, u64)> = BTreeSet::new();
    let mut last_permissions: BTreeMap<(PrincipalId, Permission), bool> = BTreeMap::new();

    for (batch_index, batch) in batches.iter().enumerate() {
        check_classroom_audit_batch_consistency(expected_generation, batch).map_err(|reason| {
            AuditChainConsistencyError::InvalidBatch {
                batch_index,
                reason,
            }
        })?;
        for (index, record) in batch.iter().enumerate() {
            if last_timestamp.is_some_and(|prev| record.checked_at_unix_ms() < prev) {
                return Err(AuditChainConsistencyError::TimestampRegression { batch_index, index });
            }
            if !seen_requests.insert((record.actor(), record.request_id())) {
                return Err(AuditChainConsistencyError::DuplicateRequest { batch_index, index });
            }
            let key = (record.target(), record.permission().underlying_permission());
            if last_permissions
                .insert(key, record.new_grant())
                .is_some_and(|previous| previous != record.previous_grant())
            {
                return Err(AuditChainConsistencyError::ContradictoryPriorPermission {
                    batch_index,
                    index,
                });
            }
            last_timestamp = Some(record.checked_at_unix_ms());
        }
        if batch_index + 1 < batches.len() {
            expected_generation = expected_generation
                .checked_add(batch.len() as u64)
                .filter(|next| *next != u64::MAX)
                .ok_or(AuditChainConsistencyError::GenerationExhausted)?;
        }
    }
    Ok(())
}
