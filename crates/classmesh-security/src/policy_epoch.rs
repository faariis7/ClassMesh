//! Pure monotonic policy-epoch decision; NOT a protected persistence anchor.
//! A caller must first authenticate an independently protected durable anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEpochError {
    MissingOrInvalidAnchor,
    InvalidCandidate,
    NotNewer { trusted: u64, candidate: u64 },
    Exhausted,
    StartupEpochMismatch { trusted: u64, candidate: u64 },
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


/// Startup admission for a separately authenticated durable anchor and an
/// already authenticated policy. Equality is mandatory: a newer candidate
/// cannot silently advance trust at restart, and an older one is a rollback.
/// This does NOT authenticate either input or open any files.
pub fn verify_startup_policy_epoch(trusted: u64, candidate: u64) -> Result<(), PolicyEpochError> {
    if trusted == 0 {
        return Err(PolicyEpochError::MissingOrInvalidAnchor);
    }
    if candidate == 0 {
        return Err(PolicyEpochError::InvalidCandidate);
    }
    if trusted != candidate {
        return Err(PolicyEpochError::StartupEpochMismatch { trusted, candidate });
    }
    Ok(())
}

/// Proof of successful invocation of the caller-supplied durable commit hook.
/// Not proof of OS ACL, filesystem durability, or independently trusted origin:
/// only a future authenticated anchor implementation can supply those.
#[derive(Debug, PartialEq, Eq)]
pub struct CommittedPolicyEpoch {
    epoch: u64,
}

impl CommittedPolicyEpoch {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EpochTransitionError<E> {
    Invalid(PolicyEpochError),
    Commit(E),
}

/// Validate the proposed generation before touching storage. Return a receipt
/// ONLY if the supplied *trusted durable* commit succeeds. A publisher must
/// never install policy before this returns Ok; if a crash happens after the
/// commit but before policy publication, startup equality rejects stale data.
///
/// The callback is an interface contract, NOT a trusted writer: callers must
/// separately prove protected persistence, atomicity and fsync semantics.
pub fn commit_policy_epoch<E>(
    trusted: u64,
    candidate: u64,
    durable_commit: impl FnOnce(u64) -> Result<(), E>,
) -> Result<CommittedPolicyEpoch, EpochTransitionError<E>> {
    verify_next_policy_epoch(trusted, candidate).map_err(EpochTransitionError::Invalid)?;
    durable_commit(candidate).map_err(EpochTransitionError::Commit)?;
    Ok(CommittedPolicyEpoch { epoch: candidate })
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
