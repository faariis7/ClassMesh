//! Non-authorizing lab prototype. See docs/adr/2026-11-08-scm-bound-process-lease.md.

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
            service: ProcessIdentity { pid: 50, created: 100 },
            recipient: ProcessIdentity { pid: 60, created: 200 },
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
        assert!(RejectionModel::new(ProcessIdentity { pid: 0, created: 0 }, e.recipient, 7, [3; 32]).is_err());
    }
}
