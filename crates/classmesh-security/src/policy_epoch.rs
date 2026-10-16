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
            Err(PolicyEpochError::NotNewer {
                trusted: 4,
                candidate: 4
            })
        );
        assert_eq!(
            verify_next_policy_epoch(4, 3),
            Err(PolicyEpochError::NotNewer {
                trusted: 4,
                candidate: 3
            })
        );
    }

    #[test]
    fn invalid_anchor_zero_candidate_and_overflow_are_fail_closed() {
        assert_eq!(
            verify_next_policy_epoch(0, 1),
            Err(PolicyEpochError::MissingOrInvalidAnchor)
        );
        assert_eq!(
            verify_next_policy_epoch(1, 0),
            Err(PolicyEpochError::InvalidCandidate)
        );
        assert_eq!(
            verify_next_policy_epoch(u64::MAX, u64::MAX),
            Err(PolicyEpochError::Exhausted)
        );
    }
}

#[cfg(test)]
mod transition_contract_tests {
    use super::*;

    #[test]
    fn startup_requires_exact_trusted_epoch_even_if_candidate_is_newer() {
        assert_eq!(verify_startup_policy_epoch(7, 7), Ok(()));
        assert!(verify_startup_policy_epoch(7, 8).is_err());
        assert!(verify_startup_policy_epoch(7, 6).is_err());
        assert!(verify_startup_policy_epoch(0, 7).is_err());
        assert!(verify_startup_policy_epoch(7, 0).is_err());
    }

    #[test]
    fn update_commits_trusted_epoch_before_issuing_receipt() {
        let mut committed = 7_u64;
        let receipt = commit_policy_epoch(7, 9, |candidate| {
            committed = candidate;
            Ok::<(), &'static str>(())
        }).unwrap();
        assert_eq!(committed, 9);
        assert_eq!(receipt.epoch(), 9);
    }

    #[test]
    fn failed_durable_commit_never_issues_receipt() {
        let mut attempts = 0;
        let result = commit_policy_epoch(7, 8, |_| {
            attempts += 1;
            Err::<(), _>("disk sync failed")
        });
        assert!(matches!(result, Err(EpochTransitionError::Commit("disk sync failed"))));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn invalid_transitions_do_not_touch_trusted_storage() {
        for (trusted, candidate) in [(0, 1), (1, 0), (7, 7), (7, 6), (u64::MAX, u64::MAX)] {
            let mut writes = 0;
            let result = commit_policy_epoch(trusted, candidate, |_| {
                writes += 1;
                Ok::<(), ()>(())
            });
            assert!(matches!(result, Err(EpochTransitionError::Invalid(_))));
            assert_eq!(writes, 0);
        }
    }

    #[test]
    fn crash_after_durable_commit_before_policy_publish_fails_closed_on_restart() {
        // The external policy file still contains 7 when the independently
        // protected durable anchor has already advanced to 8.
        let mut anchor = 7;
        let receipt = commit_policy_epoch(anchor, 8, |next| {
            anchor = next;
            Ok::<(), ()>(())
        }).unwrap();
        assert_eq!(receipt.epoch(), 8);
        assert!(verify_startup_policy_epoch(anchor, 7).is_err());
        assert_eq!(verify_startup_policy_epoch(anchor, 8), Ok(()));
    }
}
