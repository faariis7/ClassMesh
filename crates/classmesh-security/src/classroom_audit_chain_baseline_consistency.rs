//! Pure OFFLINE bounded audit-chain replay against caller-supplied policy snapshots.
//! Neither snapshot, actor claim, record, nor generation is authenticated.
//! Success never authorizes a Service publish or durable policy/audit write.

use crate::{
    AuthorizationStore,
    classroom_audit_baseline_consistency::{AuditBaselineConsistencyError, replay_untrusted_batch},
    classroom_audit_chain_consistency::{
        AuditChainConsistencyError, check_classroom_audit_chain_consistency,
    },
    classroom_audit_intent_encoding::ClassroomAuditIntentRecord,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditChainBaselineError {
    Chain(AuditChainConsistencyError),
    BatchBaseline {
        batch_index: usize,
        reason: AuditBaselineConsistencyError,
    },
    FinalStateMismatch,
}

/// Replay only a bounded chain of untrusted intents on a CLONE of an untrusted
/// baseline, and compare the entire hypothetical result to an untrusted final
/// snapshot. No current Service state, credentials, disk, RPC, or OS authority.
pub fn check_classroom_audit_chain_against_baseline(
    initial: &AuthorizationStore,
    claimed_final: &AuthorizationStore,
    starting_generation: u64,
    batches: &[&[ClassroomAuditIntentRecord]],
) -> Result<(), AuditChainBaselineError> {
    check_classroom_audit_chain_consistency(starting_generation, batches)
        .map_err(AuditChainBaselineError::Chain)?;

    let mut candidate = initial.clone();
    let mut generation = starting_generation;
    for (batch_index, batch) in batches.iter().enumerate() {
        candidate = replay_untrusted_batch(&candidate, generation, batch).map_err(|reason| {
            AuditChainBaselineError::BatchBaseline {
                batch_index,
                reason,
            }
        })?;
        if batch_index + 1 < batches.len() {
            generation = generation
                .checked_add(batch.len() as u64)
                .filter(|next| *next != u64::MAX)
                .ok_or(AuditChainBaselineError::Chain(
                    AuditChainConsistencyError::GenerationExhausted,
                ))?;
        }
    }

    if &candidate != claimed_final {
        return Err(AuditChainBaselineError::FinalStateMismatch);
    }
    Ok(())
}
