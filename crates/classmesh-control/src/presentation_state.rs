use classmesh_security::PrincipalId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationOwner {
    pub principal_id: PrincipalId,
    pub control_session_id: u64,
    pub presentation_id: u64,
    pub stream_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationOwnershipError {
    InvalidControlSession,
    InvalidPresentationId,
    InvalidStreamId,
    Busy,
    NotOwner,
    PresentationMismatch,
}

#[derive(Debug, Default)]
pub struct PresentationOwnership {
    owner: Option<PresentationOwner>,
}

impl PresentationOwnership {
    #[must_use]
    pub const fn owner(&self) -> Option<PresentationOwner> {
        self.owner
    }

    pub fn start(
        &mut self,
        principal_id: PrincipalId,
        control_session_id: u64,
        presentation_id: u64,
        stream_id: u64,
    ) -> Result<PresentationOwner, PresentationOwnershipError> {
        if control_session_id == 0 {
            return Err(PresentationOwnershipError::InvalidControlSession);
        }
        if presentation_id == 0 {
            return Err(PresentationOwnershipError::InvalidPresentationId);
        }
        if stream_id == 0 {
            return Err(PresentationOwnershipError::InvalidStreamId);
        }

        let requested = PresentationOwner {
            principal_id,
            control_session_id,
            presentation_id,
            stream_id,
        };
        match self.owner {
            None => {
                self.owner = Some(requested);
                Ok(requested)
            }
            Some(current) if current == requested => Ok(current),
            Some(_) => Err(PresentationOwnershipError::Busy),
        }
    }

    pub fn stop(
        &mut self,
        principal_id: PrincipalId,
        control_session_id: u64,
        presentation_id: u64,
    ) -> Result<PresentationOwner, PresentationOwnershipError> {
        let current = self
            .owner
            .ok_or(PresentationOwnershipError::NotOwner)?;
        if current.principal_id != principal_id || current.control_session_id != control_session_id {
            return Err(PresentationOwnershipError::NotOwner);
        }
        if current.presentation_id != presentation_id {
            return Err(PresentationOwnershipError::PresentationMismatch);
        }
        self.owner = None;
        Ok(current)
    }

    pub fn release_session(
        &mut self,
        principal_id: PrincipalId,
        control_session_id: u64,
    ) -> Option<PresentationOwner> {
        let current = self.owner?;
        if current.principal_id == principal_id && current.control_session_id == control_session_id {
            self.owner = None;
            Some(current)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    #[test]
    fn one_session_owns_one_presentation_and_exact_retry_is_idempotent() {
        let mut state = PresentationOwnership::default();
        let owner = state
            .start(principal(1), 10, 20, 30)
            .expect("first presentation should acquire ownership");
        assert_eq!(state.owner(), Some(owner));
        assert_eq!(
            state.start(principal(1), 10, 20, 30),
            Ok(owner),
            "exact request retry should not create a second owner"
        );
        assert_eq!(
            state.start(principal(2), 11, 21, 31),
            Err(PresentationOwnershipError::Busy)
        );
    }

    #[test]
    fn stop_requires_exact_owner_and_presentation() {
        let mut state = PresentationOwnership::default();
        state.start(principal(1), 10, 20, 30).unwrap();

        assert_eq!(
            state.stop(principal(2), 10, 20),
            Err(PresentationOwnershipError::NotOwner)
        );
        assert_eq!(
            state.stop(principal(1), 10, 99),
            Err(PresentationOwnershipError::PresentationMismatch)
        );
        assert!(state.owner().is_some());

        assert_eq!(
            state.stop(principal(1), 10, 20).map(|owner| owner.stream_id),
            Ok(30)
        );
        assert!(state.owner().is_none());
    }

    #[test]
    fn disconnect_cleanup_releases_only_the_exact_authenticated_session() {
        let mut state = PresentationOwnership::default();
        state.start(principal(1), 10, 20, 30).unwrap();

        assert!(state.release_session(principal(1), 11).is_none());
        assert!(state.release_session(principal(2), 10).is_none());
        assert!(state.owner().is_some());

        let released = state
            .release_session(principal(1), 10)
            .expect("exact session should release presentation");
        assert_eq!(released.presentation_id, 20);
        assert!(state.owner().is_none());
    }

    #[test]
    fn zero_identifiers_fail_without_mutating_state() {
        let mut state = PresentationOwnership::default();
        assert_eq!(
            state.start(principal(1), 0, 20, 30),
            Err(PresentationOwnershipError::InvalidControlSession)
        );
        assert_eq!(
            state.start(principal(1), 10, 0, 30),
            Err(PresentationOwnershipError::InvalidPresentationId)
        );
        assert_eq!(
            state.start(principal(1), 10, 20, 0),
            Err(PresentationOwnershipError::InvalidStreamId)
        );
        assert!(state.owner().is_none());
    }
}
