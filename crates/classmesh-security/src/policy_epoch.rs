//! Pure monotonic policy-epoch decision; NOT a protected persistence anchor.
//! A caller must first authenticate an independently protected durable anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEpochError {
    MissingOrInvalidAnchor,
    InvalidCandidate,
    NotNewer { trusted: u64, candidate: u64 },
    Exhausted,
}

/// Require a nonzero strictly increasing policy generation after reading a
/// *trusted* durable anchor. Never interpret this as a signature or ACL check.
pub fn verify_next_policy_epoch(trusted: u64, candidate: u64) -> Result<(), PolicyEpochError> {
    if trusted == 0 {
        return Err(PolicyEpochError::MissingOrInvalidAnchor);
    }
    if candidate == 0 {
        return Err(PolicyEpochError::InvalidCandidate);
    }
    if trusted == u64::MAX {
        return Err(PolicyEpochError::Exhausted);
    }
    if candidate <= trusted {
        return Err(PolicyEpochError::NotNewer { trusted, candidate });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictly_advancing_epoch_only() {
        assert_eq!(verify_next_policy_epoch(4, 5), Ok(()));
        assert_eq!(
            verify_next_policy_epoch(4, 4),
            Err(PolicyEpochError::NotNewer { trusted: 4, candidate: 4 })
        );
        assert_eq!(
            verify_next_policy_epoch(4, 3),
            Err(PolicyEpochError::NotNewer { trusted: 4, candidate: 3 })
        );
    }

    #[test]
    fn invalid_anchor_zero_candidate_and_overflow_are_fail_closed() {
        assert_eq!(verify_next_policy_epoch(0, 1), Err(PolicyEpochError::MissingOrInvalidAnchor));
        assert_eq!(verify_next_policy_epoch(1, 0), Err(PolicyEpochError::InvalidCandidate));
        assert_eq!(verify_next_policy_epoch(u64::MAX, u64::MAX), Err(PolicyEpochError::Exhausted));
    }
}
