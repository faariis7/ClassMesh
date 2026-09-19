#![forbid(unsafe_code)]

pub mod persistence;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialFingerprint(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    Teacher,
    StudentDevice,
    Administrator,
    Service,
    SessionWorker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    ViewMonitoring,
    ViewInteractive,
    ControlInput,
    StartPresentation,
    ReceivePresentation,
    SendFile,
    ReceiveFile,
    LockDevice,
    RestartDevice,
    ShutdownDevice,
    ManageEnrollment,
    ManagePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    Active,
    Retiring,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub fingerprint: CredentialFingerprint,
    pub state: CredentialState,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: Option<u64>,
    pub revoked_at_unix_ms: Option<u64>,
}

impl CredentialRecord {
    #[must_use]
    pub const fn active(fingerprint: CredentialFingerprint, issued_at_unix_ms: u64) -> Self {
        Self {
            fingerprint,
            state: CredentialState::Active,
            issued_at_unix_ms,
            expires_at_unix_ms: None,
            revoked_at_unix_ms: None,
        }
    }

    #[must_use]
    pub fn is_accepted_at(&self, now_unix_ms: u64) -> bool {
        if self.issued_at_unix_ms > now_unix_ms {
            return false;
        }
        if self.state == CredentialState::Revoked {
            return false;
        }
        if self
            .revoked_at_unix_ms
            .is_some_and(|revoked_at| revoked_at <= now_unix_ms)
        {
            return false;
        }
        if self
            .expires_at_unix_ms
            .is_some_and(|expires_at| expires_at <= now_unix_ms)
        {
            return false;
        }
        true
    }

    pub fn mark_retiring(&mut self) {
        if self.state == CredentialState::Active {
            self.state = CredentialState::Retiring;
        }
    }

    pub fn revoke(&mut self, now_unix_ms: u64) {
        self.state = CredentialState::Revoked;
        self.revoked_at_unix_ms = Some(now_unix_ms);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMutationError {
    DuplicateCredential,
    CredentialNotFound,
    ReplacementMustBeActive,
    InvalidRotationOverlapDeadline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    pub enabled: bool,
    pub permissions: BTreeSet<Permission>,
    pub credentials: BTreeMap<CredentialFingerprint, CredentialRecord>,
}

impl Principal {
    #[must_use]
    pub fn allows(&self, permission: Permission) -> bool {
        self.enabled && self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn accepts_credential(&self, fingerprint: CredentialFingerprint, now_unix_ms: u64) -> bool {
        self.enabled
            && self
                .credentials
                .get(&fingerprint)
                .is_some_and(|credential| credential.is_accepted_at(now_unix_ms))
    }

    pub fn add_credential(
        &mut self,
        credential: CredentialRecord,
    ) -> Result<(), CredentialMutationError> {
        if self.credentials.contains_key(&credential.fingerprint) {
            return Err(CredentialMutationError::DuplicateCredential);
        }
        self.credentials.insert(credential.fingerprint, credential);
        Ok(())
    }

    /// Adds a replacement credential and bounds the overlap of all previous credentials.
    ///
    /// Existing credentials become retiring and may authenticate only until the earlier of
    /// their current expiry or `overlap_until_unix_ms`. The overlap deadline must be later
    /// than the replacement credential's issue time.
    pub fn rotate_to_bounded(
        &mut self,
        replacement: CredentialRecord,
        overlap_until_unix_ms: u64,
    ) -> Result<(), CredentialMutationError> {
        if overlap_until_unix_ms <= replacement.issued_at_unix_ms {
            return Err(CredentialMutationError::InvalidRotationOverlapDeadline);
        }
        if replacement.state != CredentialState::Active {
            return Err(CredentialMutationError::ReplacementMustBeActive);
        }
        if self.credentials.contains_key(&replacement.fingerprint) {
            return Err(CredentialMutationError::DuplicateCredential);
        }

        for credential in self.credentials.values_mut() {
            credential.mark_retiring();
            credential.expires_at_unix_ms = Some(
                credential
                    .expires_at_unix_ms
                    .map_or(overlap_until_unix_ms, |current| {
                        current.min(overlap_until_unix_ms)
                    }),
            );
        }
        self.credentials
            .insert(replacement.fingerprint, replacement);
        Ok(())
    }

    pub fn revoke_credential(
        &mut self,
        fingerprint: CredentialFingerprint,
        now_unix_ms: u64,
    ) -> Result<(), CredentialMutationError> {
        let Some(credential) = self.credentials.get_mut(&fingerprint) else {
            return Err(CredentialMutationError::CredentialNotFound);
        };
        credential.revoke(now_unix_ms);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentState {
    Unenrolled,
    PendingApproval,
    Enrolled,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRecord {
    pub principal: PrincipalId,
    pub state: EnrollmentState,
    pub pending_credential: Option<CredentialFingerprint>,
    pub enrolled_at_unix_ms: Option<u64>,
    pub revoked_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentError {
    AlreadyEnrolled,
    Revoked,
    NotPending,
    PendingCredentialMismatch,
}

impl EnrollmentRecord {
    #[must_use]
    pub const fn new(principal: PrincipalId) -> Self {
        Self {
            principal,
            state: EnrollmentState::Unenrolled,
            pending_credential: None,
            enrolled_at_unix_ms: None,
            revoked_at_unix_ms: None,
        }
    }

    pub fn request(&mut self, credential: CredentialFingerprint) -> Result<(), EnrollmentError> {
        match self.state {
            EnrollmentState::Unenrolled => {
                self.state = EnrollmentState::PendingApproval;
                self.pending_credential = Some(credential);
                Ok(())
            }
            EnrollmentState::PendingApproval => {
                if self.pending_credential == Some(credential) {
                    Ok(())
                } else {
                    Err(EnrollmentError::PendingCredentialMismatch)
                }
            }
            EnrollmentState::Enrolled => Err(EnrollmentError::AlreadyEnrolled),
            EnrollmentState::Revoked => Err(EnrollmentError::Revoked),
        }
    }

    pub fn approve(&mut self, now_unix_ms: u64) -> Result<CredentialFingerprint, EnrollmentError> {
        if self.state != EnrollmentState::PendingApproval {
            return Err(EnrollmentError::NotPending);
        }
        let credential = self
            .pending_credential
            .take()
            .ok_or(EnrollmentError::NotPending)?;
        self.state = EnrollmentState::Enrolled;
        self.enrolled_at_unix_ms = Some(now_unix_ms);
        self.revoked_at_unix_ms = None;
        Ok(credential)
    }

    pub fn revoke(&mut self, now_unix_ms: u64) {
        self.state = EnrollmentState::Revoked;
        self.pending_credential = None;
        self.revoked_at_unix_ms = Some(now_unix_ms);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationStoreError {
    CredentialOwnedByAnotherPrincipal {
        fingerprint: CredentialFingerprint,
        owner: PrincipalId,
    },
}

#[derive(Debug, Default)]
pub struct AuthorizationStore {
    principals: BTreeMap<PrincipalId, Principal>,
    credential_owners: BTreeMap<CredentialFingerprint, PrincipalId>,
}

impl AuthorizationStore {
    pub fn upsert(&mut self, principal: Principal) -> Result<(), AuthorizationStoreError> {
        for fingerprint in principal.credentials.keys() {
            if let Some(owner) = self.credential_owners.get(fingerprint) {
                if *owner != principal.id {
                    return Err(AuthorizationStoreError::CredentialOwnedByAnotherPrincipal {
                        fingerprint: *fingerprint,
                        owner: *owner,
                    });
                }
            }
        }

        if let Some(previous) = self.principals.get(&principal.id) {
            for fingerprint in previous.credentials.keys() {
                if self.credential_owners.get(fingerprint) == Some(&principal.id) {
                    self.credential_owners.remove(fingerprint);
                }
            }
        }

        for fingerprint in principal.credentials.keys() {
            self.credential_owners.insert(*fingerprint, principal.id);
        }
        self.principals.insert(principal.id, principal);
        Ok(())
    }

    #[must_use]
    pub fn authorize(&self, principal: PrincipalId, permission: Permission) -> bool {
        self.principals
            .get(&principal)
            .is_some_and(|record| record.allows(permission))
    }

    #[must_use]
    pub fn principal_for_credential(
        &self,
        fingerprint: CredentialFingerprint,
        now_unix_ms: u64,
    ) -> Option<PrincipalId> {
        let principal_id = *self.credential_owners.get(&fingerprint)?;
        let principal = self.principals.get(&principal_id)?;
        principal
            .accepts_credential(fingerprint, now_unix_ms)
            .then_some(principal_id)
    }

    #[must_use]
    pub fn authorize_credential(
        &self,
        fingerprint: CredentialFingerprint,
        permission: Permission,
        now_unix_ms: u64,
    ) -> bool {
        let Some(principal) = self.principal_for_credential(fingerprint, now_unix_ms) else {
            return false;
        };
        self.authorize(principal, permission)
    }

    pub fn disable(&mut self, principal: PrincipalId) -> bool {
        let Some(record) = self.principals.get_mut(&principal) else {
            return false;
        };
        record.enabled = false;
        true
    }
}

/// Bounded replay window for monotonically assigned command sequence numbers.
///
/// This is not a cryptographic anti-replay mechanism by itself. It is application-level duplicate
/// suppression intended to sit inside an authenticated transport/session.
#[derive(Debug)]
pub struct ReplayWindow {
    capacity: usize,
    seen: BTreeSet<u64>,
    order: VecDeque<u64>,
}

impl ReplayWindow {
    /// # Panics
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "replay window must be non-zero");
        Self {
            capacity,
            seen: BTreeSet::new(),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// Returns true only the first time a sequence number is observed inside the bounded window.
    pub fn accept(&mut self, sequence: u64) -> bool {
        if self.seen.contains(&sequence) {
            return false;
        }
        while self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.order.push_back(sequence);
        self.seen.insert(sequence);
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPeerValidation {
    Accepted,
    WrongSession,
    WrongProcess,
    WrongPrincipal,
    ChallengeFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedWorkerPeer {
    pub session_id: u32,
    pub process_id: u32,
    pub principal: PrincipalId,
}

impl ExpectedWorkerPeer {
    #[must_use]
    pub fn validate_metadata(
        self,
        session_id: u32,
        process_id: u32,
        principal: PrincipalId,
    ) -> LocalPeerValidation {
        if session_id != self.session_id {
            return LocalPeerValidation::WrongSession;
        }
        if process_id != self.process_id {
            return LocalPeerValidation::WrongProcess;
        }
        if principal != self.principal {
            return LocalPeerValidation::WrongPrincipal;
        }
        LocalPeerValidation::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn fingerprint(value: u8) -> CredentialFingerprint {
        CredentialFingerprint([value; 32])
    }

    fn teacher_with_credential(
        principal_id: PrincipalId,
        credential: CredentialFingerprint,
    ) -> Principal {
        let mut permissions = BTreeSet::new();
        permissions.insert(Permission::ViewMonitoring);
        let mut credentials = BTreeMap::new();
        credentials.insert(credential, CredentialRecord::active(credential, 10));
        Principal {
            id: principal_id,
            kind: PrincipalKind::Teacher,
            enabled: true,
            permissions,
            credentials,
        }
    }

    #[test]
    fn enrollment_cannot_skip_or_silently_switch_approval_credential() {
        let mut record = EnrollmentRecord::new(id(1));
        assert_eq!(record.approve(10), Err(EnrollmentError::NotPending));

        record
            .request(fingerprint(1))
            .expect("request should succeed");
        assert_eq!(
            record.request(fingerprint(2)),
            Err(EnrollmentError::PendingCredentialMismatch)
        );

        let approved = record.approve(20).expect("approval should succeed");
        assert_eq!(approved, fingerprint(1));
        assert_eq!(record.state, EnrollmentState::Enrolled);
        assert_eq!(record.pending_credential, None);
    }

    #[test]
    fn credential_rotation_keeps_principal_identity_and_bounds_overlap() {
        let principal_id = id(2);
        let old = fingerprint(10);
        let new = fingerprint(11);
        let mut principal = teacher_with_credential(principal_id, old);

        principal
            .rotate_to_bounded(CredentialRecord::active(new, 20), 40)
            .expect("bounded rotation should succeed");

        assert_eq!(principal.id, principal_id);
        assert_eq!(
            principal
                .credentials
                .get(&old)
                .map(|credential| (credential.state, credential.expires_at_unix_ms)),
            Some((CredentialState::Retiring, Some(40)))
        );
        assert!(principal.accepts_credential(old, 39));
        assert!(!principal.accepts_credential(old, 40));
        assert!(principal.accepts_credential(new, 40));
    }

    #[test]
    fn bounded_rotation_preserves_earlier_expiry_and_rejects_invalid_deadline() {
        let principal_id = id(12);
        let old = fingerprint(50);
        let new = fingerprint(51);
        let mut principal = teacher_with_credential(principal_id, old);
        principal
            .credentials
            .get_mut(&old)
            .expect("old credential")
            .expires_at_unix_ms = Some(30);

        principal
            .rotate_to_bounded(CredentialRecord::active(new, 20), 40)
            .expect("bounded rotation should succeed");
        assert_eq!(
            principal
                .credentials
                .get(&old)
                .and_then(|credential| credential.expires_at_unix_ms),
            Some(30)
        );

        let another = fingerprint(52);
        assert_eq!(
            principal.rotate_to_bounded(CredentialRecord::active(another, 60), 60),
            Err(CredentialMutationError::InvalidRotationOverlapDeadline)
        );
    }

    #[test]
    fn expired_or_revoked_credentials_do_not_authenticate() {
        let fp = fingerprint(5);
        let mut credential = CredentialRecord::active(fp, 10);
        credential.expires_at_unix_ms = Some(30);
        assert!(!credential.is_accepted_at(9));
        assert!(credential.is_accepted_at(10));
        assert!(credential.is_accepted_at(29));
        assert!(!credential.is_accepted_at(30));

        credential.expires_at_unix_ms = None;
        credential.revoke(40);
        assert!(!credential.is_accepted_at(40));
        assert!(!credential.is_accepted_at(50));
    }

    #[test]
    fn authorization_store_resolves_credential_to_stable_principal_across_rotation() {
        let principal_id = id(3);
        let old = fingerprint(20);
        let new = fingerprint(21);
        let mut principal = teacher_with_credential(principal_id, old);
        let mut store = AuthorizationStore::default();

        store
            .upsert(principal.clone())
            .expect("initial identity should register");
        assert_eq!(store.principal_for_credential(old, 15), Some(principal_id));
        assert!(store.authorize_credential(old, Permission::ViewMonitoring, 15));

        principal
            .rotate_to_bounded(CredentialRecord::active(new, 20), 40)
            .expect("bounded rotation should succeed");
        store
            .upsert(principal.clone())
            .expect("rotated identity should register");

        assert_eq!(store.principal_for_credential(old, 25), Some(principal_id));
        assert_eq!(store.principal_for_credential(new, 25), Some(principal_id));

        principal
            .revoke_credential(old, 30)
            .expect("old credential should revoke");
        store
            .upsert(principal)
            .expect("revoked identity should update");

        assert_eq!(store.principal_for_credential(old, 30), None);
        assert_eq!(store.principal_for_credential(new, 30), Some(principal_id));
    }

    #[test]
    fn one_credential_cannot_be_bound_to_two_principals() {
        let shared = fingerprint(33);
        let mut store = AuthorizationStore::default();
        store
            .upsert(teacher_with_credential(id(1), shared))
            .expect("first principal should own credential");

        assert_eq!(
            store.upsert(teacher_with_credential(id(2), shared)),
            Err(AuthorizationStoreError::CredentialOwnedByAnotherPrincipal {
                fingerprint: shared,
                owner: id(1),
            })
        );
    }

    #[test]
    fn authorization_is_permission_and_enabled_state_specific() {
        let fp = fingerprint(9);
        let principal = teacher_with_credential(id(4), fp);
        let mut store = AuthorizationStore::default();
        store.upsert(principal).expect("principal should register");
        assert!(store.authorize(id(4), Permission::ViewMonitoring));
        assert!(!store.authorize(id(4), Permission::ShutdownDevice));
        assert!(store.disable(id(4)));
        assert!(!store.authorize(id(4), Permission::ViewMonitoring));
        assert_eq!(store.principal_for_credential(fp, 20), None);
    }

    #[test]
    fn replay_window_rejects_recent_duplicate_but_stays_bounded() {
        let mut window = ReplayWindow::new(2);
        assert!(window.accept(1));
        assert!(!window.accept(1));
        assert!(window.accept(2));
        assert!(window.accept(3));
        assert!(window.accept(1));
    }

    #[test]
    fn expected_worker_binds_local_ipc_to_session_and_process() {
        let expected = ExpectedWorkerPeer {
            session_id: 4,
            process_id: 100,
            principal: id(7),
        };
        assert_eq!(
            expected.validate_metadata(4, 100, id(7)),
            LocalPeerValidation::Accepted
        );
        assert_eq!(
            expected.validate_metadata(5, 100, id(7)),
            LocalPeerValidation::WrongSession
        );
    }
}
