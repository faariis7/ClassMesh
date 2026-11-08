//! Non-authorizing lab prototype. See docs/adr/2026-11-08-scm-bound-process-lease.md.

#[cfg(windows)]
pub mod native;

/// Exact minimum process mask. This is not a token or duplication right.
pub const READ_ONLY_PROCESS_RIGHTS: u32 = 0x0010_1000;

/// Synthetic identity used ONLY by the rejection model, not native authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub created: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Complete,
    Partial,
    Broken,
}

/// Caller-fabricated model inputs, never accepted by product authentication.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub pipe_pid: u32,
    pub pipe_session: u32,
    pub scm_pid: u32,
    pub scm_running_own_system: bool,
    pub registered_image: Option<[u8; 32]>,
    pub running_image: Option<[u8; 32]>,
    pub service: ProcessIdentity,
    pub recipient: ProcessIdentity,
    pub recipient_account_matches: bool,
    pub epoch: u64,
    pub rights: u32,
    pub inheritable: bool,
    pub service_alive: bool,
    pub transport: Transport,
}

/// Success means only that no synthetic rejection condition was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedsQualifiedReview;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected;

#[derive(Debug)]
pub struct RejectionModel {
    service: ProcessIdentity,
    recipient: ProcessIdentity,
    epoch: u64,
    image: [u8; 32],
    rejected: bool,
}

impl RejectionModel {
    pub fn new(
        service: ProcessIdentity,
        recipient: ProcessIdentity,
        epoch: u64,
        image: [u8; 32],
    ) -> Result<Self, Rejected> {
        if service.pid == 0
            || recipient.pid == 0
            || service.pid == recipient.pid
            || service.created == 0
            || recipient.created == 0
            || epoch == 0
        {
            return Err(Rejected);
        }
        Ok(Self {
            service,
            recipient,
            epoch,
            image,
            rejected: false,
        })
    }

    /// Every mismatch terminally invalidates this model generation. It never
    /// authorizes a session, even on matching caller-provided observations.
    pub fn observe(&mut self, e: &Evidence) -> Result<NeedsQualifiedReview, Rejected> {
        self.rejected |= e.pipe_pid != self.service.pid
            || e.pipe_session != 0
            || e.scm_pid != self.service.pid
            || !e.scm_running_own_system
            || e.registered_image != Some(self.image)
            || e.running_image != Some(self.image)
            || e.service != self.service
            || e.recipient != self.recipient
            || !e.recipient_account_matches
            || e.epoch != self.epoch
            || e.rights != READ_ONLY_PROCESS_RIGHTS
            || e.inheritable
            || !e.service_alive
            || e.transport != Transport::Complete;
        if self.rejected {
            Err(Rejected)
        } else {
            Ok(NeedsQualifiedReview)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Evidence {
        Evidence {
            pipe_pid: 50,
            pipe_session: 0,
            scm_pid: 50,
            scm_running_own_system: true,
            registered_image: Some([3; 32]),
            running_image: Some([3; 32]),
            service: ProcessIdentity {
                pid: 50,
                created: 100,
            },
            recipient: ProcessIdentity {
                pid: 60,
                created: 200,
            },
            recipient_account_matches: true,
            epoch: 7,
            rights: READ_ONLY_PROCESS_RIGHTS,
            inheritable: false,
            service_alive: true,
            transport: Transport::Complete,
        }
    }

    fn model() -> RejectionModel {
        let e = evidence();
        RejectionModel::new(e.service, e.recipient, 7, [3; 32]).unwrap()
    }

    #[test]
    fn matching_synthetic_evidence_only_requests_qualified_review() {
        assert_eq!(model().observe(&evidence()), Ok(NeedsQualifiedReview));
    }

    #[test]
    fn attacker_changes_each_identity_boundary_and_poison_is_terminal() {
        let changes: &[fn(&mut Evidence)] = &[
            |e| e.pipe_pid = 90,
            |e| e.pipe_session = 1,
            |e| e.scm_pid = 90,
            |e| e.scm_running_own_system = false,
            |e| e.registered_image = None,
            |e| e.running_image = None,
            |e| e.running_image = Some([4; 32]),
            |e| e.registered_image = Some([4; 32]),
            |e| e.service.pid = 90,
            |e| e.service.created += 1,
            |e| e.recipient.pid = 90,
            |e| e.recipient.created += 1,
            |e| e.recipient_account_matches = false,
            |e| e.epoch += 1,
            |e| e.rights |= 0x0001, // terminate
            |e| e.rights |= 0x0040, // duplicate handle
            |e| e.rights = 0x1000,  // query without synchronize
            |e| e.inheritable = true,
            |e| e.service_alive = false,
            |e| e.transport = Transport::Partial,
            |e| e.transport = Transport::Broken,
        ];
        for change in changes {
            let mut model = model();
            let mut e = evidence();
            change(&mut e);
            assert_eq!(model.observe(&e), Err(Rejected));
            assert_eq!(model.observe(&evidence()), Err(Rejected));
        }
    }

    #[test]
    fn service_loss_after_matching_observation_invalidates_generation() {
        let mut model = model();
        assert!(model.observe(&evidence()).is_ok());
        let mut e = evidence();
        e.service_alive = false;
        assert_eq!(model.observe(&e), Err(Rejected));
        e.service_alive = true;
        e.epoch += 1;
        assert_eq!(model.observe(&e), Err(Rejected));
    }

    #[test]
    fn invalid_initial_binding_is_rejected() {
        let e = evidence();
        assert!(RejectionModel::new(e.service, e.recipient, 0, [3; 32]).is_err());
        assert!(RejectionModel::new(e.service, e.service, 7, [3; 32]).is_err());
        assert!(
            RejectionModel::new(
                ProcessIdentity { pid: 0, created: 0 },
                e.recipient,
                7,
                [3; 32]
            )
            .is_err()
        );
    }
}
