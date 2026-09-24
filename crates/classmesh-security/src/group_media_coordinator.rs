use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroize;

use crate::group_media::{
    GROUP_MEDIA_KEY_BYTES, GroupMediaEpoch, GroupMediaError, GroupMediaKeyMaterial,
    GroupMediaSender,
};
use crate::{AuthorizationStore, Permission, PrincipalId};

pub const DEFAULT_MAX_GROUP_MEDIA_RECEIVERS: usize = 64;
pub const MAX_GROUP_MEDIA_RECEIVERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMediaRegistration {
    Added,
    AlreadyRegistered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMediaReceiverInstallState {
    AwaitingKey,
    KeyIssued(GroupMediaEpoch),
    Installed(GroupMediaEpoch),
}

pub struct GroupMediaKeyGrant {
    principal: PrincipalId,
    epoch: GroupMediaEpoch,
    key_bytes: [u8; GROUP_MEDIA_KEY_BYTES],
}

impl GroupMediaKeyGrant {
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn epoch(&self) -> GroupMediaEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn key_bytes(&self) -> &[u8; GROUP_MEDIA_KEY_BYTES] {
        &self.key_bytes
    }
}

impl Drop for GroupMediaKeyGrant {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

#[derive(Debug)]
pub enum GroupMediaCoordinatorError {
    InvalidReceiverLimit,
    ReceiverLimitExceeded,
    UnauthorizedReceiver,
    ReceiverNotRegistered,
    NoActiveEpoch,
    RotationRequired,
    KeyNotIssued,
    StaleEpoch,
    EpochExhausted,
    Crypto(GroupMediaError),
}

impl fmt::Display for GroupMediaCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for GroupMediaCoordinatorError {}

impl From<GroupMediaError> for GroupMediaCoordinatorError {
    fn from(value: GroupMediaError) -> Self {
        Self::Crypto(value)
    }
}

struct ReceiverState {
    install: GroupMediaReceiverInstallState,
}

struct ActiveEpoch {
    epoch: GroupMediaEpoch,
    key: GroupMediaKeyMaterial,
    sender: GroupMediaSender,
}

pub struct GroupMediaCoordinator {
    receivers: BTreeMap<PrincipalId, ReceiverState>,
    max_receivers: usize,
    last_epoch: u32,
    active: Option<ActiveEpoch>,
    rotation_required: bool,
}

impl Default for GroupMediaCoordinator {
    fn default() -> Self {
        Self {
            receivers: BTreeMap::new(),
            max_receivers: DEFAULT_MAX_GROUP_MEDIA_RECEIVERS,
            last_epoch: 0,
            active: None,
            rotation_required: false,
        }
    }
}

impl GroupMediaCoordinator {
    pub fn with_limit(max_receivers: usize) -> Result<Self, GroupMediaCoordinatorError> {
        let _ = max_receivers;
        todo!("implemented after coordinator invariant tests")
    }

    pub fn register_receiver(
        &mut self,
        authorization: &AuthorizationStore,
        principal: PrincipalId,
    ) -> Result<GroupMediaRegistration, GroupMediaCoordinatorError> {
        let _ = (authorization, principal);
        todo!("implemented after coordinator invariant tests")
    }

    pub fn remove_receiver(&mut self, principal: PrincipalId) -> bool {
        let _ = principal;
        todo!("implemented after coordinator invariant tests")
    }

    pub fn begin_epoch(&mut self) -> Result<GroupMediaEpoch, GroupMediaCoordinatorError> {
        todo!("implemented after coordinator invariant tests")
    }

    pub fn issue_key(
        &mut self,
        authorization: &AuthorizationStore,
        principal: PrincipalId,
    ) -> Result<GroupMediaKeyGrant, GroupMediaCoordinatorError> {
        let _ = (authorization, principal);
        todo!("implemented after coordinator invariant tests")
    }

    pub fn mark_installed(
        &mut self,
        authorization: &AuthorizationStore,
        principal: PrincipalId,
        epoch: GroupMediaEpoch,
    ) -> Result<(), GroupMediaCoordinatorError> {
        let _ = (authorization, principal, epoch);
        todo!("implemented after coordinator invariant tests")
    }

    pub fn seal_frame(
        &mut self,
        authorization: &AuthorizationStore,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, GroupMediaCoordinatorError> {
        let _ = (authorization, plaintext, associated_data);
        todo!("implemented after coordinator invariant tests")
    }

    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.receivers.len()
    }

    #[must_use]
    pub const fn active_epoch(&self) -> Option<GroupMediaEpoch> {
        match &self.active {
            Some(active) => Some(active.epoch),
            None => None,
        }
    }

    #[must_use]
    pub const fn rotation_required(&self) -> bool {
        self.rotation_required
    }

    #[must_use]
    pub fn receiver_state(
        &self,
        principal: PrincipalId,
    ) -> Option<GroupMediaReceiverInstallState> {
        self.receivers.get(&principal).map(|state| state.install)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::{
        CredentialFingerprint, CredentialRecord, Principal, PrincipalKind,
    };

    use super::*;

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn store(entries: &[(u8, bool)]) -> AuthorizationStore {
        let mut store = AuthorizationStore::default();
        for (value, can_receive) in entries {
            let principal_id = principal(*value);
            let fingerprint = CredentialFingerprint([value.wrapping_add(100); 32]);
            let mut permissions = BTreeSet::new();
            if *can_receive {
                permissions.insert(Permission::ReceivePresentation);
            }
            let mut credentials = BTreeMap::new();
            credentials.insert(
                fingerprint,
                CredentialRecord::active(fingerprint, 1),
            );
            store
                .upsert(Principal {
                    id: principal_id,
                    kind: PrincipalKind::StudentDevice,
                    enabled: true,
                    permissions,
                    credentials,
                })
                .expect("test principal should register");
        }
        store
    }

    #[test]
    fn receiver_registration_requires_live_receive_permission() {
        let authorization = store(&[(1, true), (2, false)]);
        let mut coordinator = GroupMediaCoordinator::default();

        assert_eq!(
            coordinator.register_receiver(&authorization, principal(1)),
            Ok(GroupMediaRegistration::Added)
        );
        assert!(matches!(
            coordinator.register_receiver(&authorization, principal(2)),
            Err(GroupMediaCoordinatorError::UnauthorizedReceiver)
        ));
        assert_eq!(coordinator.receiver_count(), 1);
    }

    #[test]
    fn receiver_membership_is_bounded_and_duplicate_registration_is_idempotent() {
        let authorization = store(&[(1, true), (2, true), (3, true)]);
        let mut coordinator = GroupMediaCoordinator::with_limit(2).expect("bounded coordinator");

        assert_eq!(
            coordinator.register_receiver(&authorization, principal(1)),
            Ok(GroupMediaRegistration::Added)
        );
        assert_eq!(
            coordinator.register_receiver(&authorization, principal(1)),
            Ok(GroupMediaRegistration::AlreadyRegistered)
        );
        assert_eq!(
            coordinator.register_receiver(&authorization, principal(2)),
            Ok(GroupMediaRegistration::Added)
        );
        assert!(matches!(
            coordinator.register_receiver(&authorization, principal(3)),
            Err(GroupMediaCoordinatorError::ReceiverLimitExceeded)
        ));
        assert_eq!(coordinator.receiver_count(), 2);
    }

    #[test]
    fn key_issue_and_install_are_exact_principal_and_epoch_bound() {
        let authorization = store(&[(1, true), (2, true)]);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("registered receiver");
        let epoch = coordinator.begin_epoch().expect("epoch");

        let grant = coordinator
            .issue_key(&authorization, principal(1))
            .expect("authorized grant");
        assert_eq!(grant.principal(), principal(1));
        assert_eq!(grant.epoch(), epoch);
        assert_eq!(
            coordinator.receiver_state(principal(1)),
            Some(GroupMediaReceiverInstallState::KeyIssued(epoch))
        );

        assert!(matches!(
            coordinator.mark_installed(
                &authorization,
                principal(1),
                GroupMediaEpoch::new(epoch.get() + 1).expect("future epoch"),
            ),
            Err(GroupMediaCoordinatorError::StaleEpoch)
        ));
        coordinator
            .mark_installed(&authorization, principal(1), epoch)
            .expect("exact epoch install");
        assert_eq!(
            coordinator.receiver_state(principal(1)),
            Some(GroupMediaReceiverInstallState::Installed(epoch))
        );

        assert!(matches!(
            coordinator.issue_key(&authorization, principal(2)),
            Err(GroupMediaCoordinatorError::ReceiverNotRegistered)
        ));
    }

    #[test]
    fn membership_change_during_active_epoch_blocks_media_until_rotation() {
        let authorization = store(&[(1, true), (2, true)]);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("first receiver");
        let first = coordinator.begin_epoch().expect("first epoch");
        coordinator
            .issue_key(&authorization, principal(1))
            .expect("first key");
        coordinator
            .mark_installed(&authorization, principal(1), first)
            .expect("first install");

        assert!(coordinator
            .seal_frame(&authorization, b"frame", b"presentation-binding")
            .is_ok());

        coordinator
            .register_receiver(&authorization, principal(2))
            .expect("new receiver");
        assert!(coordinator.rotation_required());
        assert!(matches!(
            coordinator.seal_frame(&authorization, b"blocked", b"presentation-binding"),
            Err(GroupMediaCoordinatorError::RotationRequired)
        ));
        assert!(matches!(
            coordinator.issue_key(&authorization, principal(2)),
            Err(GroupMediaCoordinatorError::RotationRequired)
        ));

        let second = coordinator.begin_epoch().expect("rotated epoch");
        assert_eq!(second.get(), first.get() + 1);
        assert!(!coordinator.rotation_required());
        assert_eq!(
            coordinator.receiver_state(principal(1)),
            Some(GroupMediaReceiverInstallState::AwaitingKey)
        );
        assert_eq!(
            coordinator.receiver_state(principal(2)),
            Some(GroupMediaReceiverInstallState::AwaitingKey)
        );
    }

    #[test]
    fn live_permission_revocation_evicts_receiver_and_requires_rotation_before_more_media() {
        let mut authorization = store(&[(1, true)]);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("registered receiver");
        let epoch = coordinator.begin_epoch().expect("epoch");
        coordinator
            .issue_key(&authorization, principal(1))
            .expect("grant");
        coordinator
            .mark_installed(&authorization, principal(1), epoch)
            .expect("install");

        authorization.disable(principal(1));
        assert!(matches!(
            coordinator.seal_frame(&authorization, b"frame", b"binding"),
            Err(GroupMediaCoordinatorError::RotationRequired)
        ));
        assert_eq!(coordinator.receiver_count(), 0);
        assert!(coordinator.rotation_required());
    }

    #[test]
    fn removal_during_active_epoch_requires_rotation_but_does_not_destroy_control_state() {
        let authorization = store(&[(1, true)]);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("receiver");
        coordinator.begin_epoch().expect("epoch");

        assert!(coordinator.remove_receiver(principal(1)));
        assert!(coordinator.rotation_required());
        assert_eq!(coordinator.receiver_count(), 0);
        assert!(!coordinator.remove_receiver(principal(1)));
    }

    #[test]
    fn epoch_counter_is_monotonic_and_exhaustion_fails_closed() {
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator.last_epoch = u32::MAX;
        assert!(matches!(
            coordinator.begin_epoch(),
            Err(GroupMediaCoordinatorError::EpochExhausted)
        ));
        assert!(coordinator.active_epoch().is_none());
    }

    #[test]
    fn invalid_receiver_limits_are_rejected() {
        assert!(matches!(
            GroupMediaCoordinator::with_limit(0),
            Err(GroupMediaCoordinatorError::InvalidReceiverLimit)
        ));
        assert!(matches!(
            GroupMediaCoordinator::with_limit(MAX_GROUP_MEDIA_RECEIVERS + 1),
            Err(GroupMediaCoordinatorError::InvalidReceiverLimit)
        ));
    }
}
