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
        match self {
            Self::InvalidReceiverLimit => formatter.write_str("invalid group-media receiver limit"),
            Self::ReceiverLimitExceeded => {
                formatter.write_str("group-media receiver limit exceeded")
            }
            Self::UnauthorizedReceiver => {
                formatter.write_str("group-media receiver is unauthorized")
            }
            Self::ReceiverNotRegistered => {
                formatter.write_str("group-media receiver is not registered")
            }
            Self::NoActiveEpoch => formatter.write_str("no active group-media epoch"),
            Self::RotationRequired => formatter.write_str("group-media epoch rotation is required"),
            Self::KeyNotIssued => formatter.write_str("group-media key was not issued to receiver"),
            Self::StaleEpoch => formatter.write_str("group-media epoch is stale"),
            Self::EpochExhausted => formatter.write_str("group-media epoch space is exhausted"),
            Self::Crypto(error) => write!(formatter, "group-media crypto failure: {error}"),
        }
    }
}

impl std::error::Error for GroupMediaCoordinatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

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
        if max_receivers == 0 || max_receivers > MAX_GROUP_MEDIA_RECEIVERS {
            return Err(GroupMediaCoordinatorError::InvalidReceiverLimit);
        }
        Ok(Self {
            receivers: BTreeMap::new(),
            max_receivers,
            last_epoch: 0,
            active: None,
            rotation_required: false,
        })
    }

    pub fn register_receiver(
        &mut self,
        authorization: &AuthorizationStore,
        principal: PrincipalId,
    ) -> Result<GroupMediaRegistration, GroupMediaCoordinatorError> {
        if !authorization.authorize(principal, Permission::ReceivePresentation) {
            return Err(GroupMediaCoordinatorError::UnauthorizedReceiver);
        }
        if self.receivers.contains_key(&principal) {
            return Ok(GroupMediaRegistration::AlreadyRegistered);
        }
        if self.receivers.len() >= self.max_receivers {
            return Err(GroupMediaCoordinatorError::ReceiverLimitExceeded);
        }

        self.receivers.insert(
            principal,
            ReceiverState {
                install: GroupMediaReceiverInstallState::AwaitingKey,
            },
        );
        if self.active.is_some() {
            self.rotation_required = true;
        }
        Ok(GroupMediaRegistration::Added)
    }

    pub fn remove_receiver(&mut self, principal: PrincipalId) -> bool {
        let removed = self.receivers.remove(&principal).is_some();
        if removed && self.active.is_some() {
            self.rotation_required = true;
        }
        removed
    }

    pub fn begin_epoch(&mut self) -> Result<GroupMediaEpoch, GroupMediaCoordinatorError> {
        let next = self
            .last_epoch
            .checked_add(1)
            .ok_or(GroupMediaCoordinatorError::EpochExhausted)?;
        let epoch = GroupMediaEpoch::new(next)?;
        let key = GroupMediaKeyMaterial::generate()?;
        let sender = GroupMediaSender::new(epoch, &key)?;

        for state in self.receivers.values_mut() {
            state.install = GroupMediaReceiverInstallState::AwaitingKey;
        }

        self.active = Some(ActiveEpoch { epoch, key, sender });
        self.last_epoch = next;
        self.rotation_required = false;
        Ok(epoch)
    }

    pub fn end_epoch(&mut self) -> Option<GroupMediaEpoch> {
        let ended = self.active.take().map(|active| active.epoch);
        if ended.is_some() {
            for state in self.receivers.values_mut() {
                state.install = GroupMediaReceiverInstallState::AwaitingKey;
            }
        }
        self.rotation_required = false;
        ended
    }

    pub fn issue_key(
        &mut self,
        authorization: &AuthorizationStore,
        principal: PrincipalId,
    ) -> Result<GroupMediaKeyGrant, GroupMediaCoordinatorError> {
        self.reconcile_authorization(authorization);
        if !authorization.authorize(principal, Permission::ReceivePresentation) {
            return Err(GroupMediaCoordinatorError::UnauthorizedReceiver);
        }
        if self.rotation_required {
            return Err(GroupMediaCoordinatorError::RotationRequired);
        }

        let active = self
            .active
            .as_ref()
            .ok_or(GroupMediaCoordinatorError::NoActiveEpoch)?;
        let state = self
            .receivers
            .get_mut(&principal)
            .ok_or(GroupMediaCoordinatorError::ReceiverNotRegistered)?;
        state.install = GroupMediaReceiverInstallState::KeyIssued(active.epoch);

        Ok(GroupMediaKeyGrant {
            principal,
            epoch: active.epoch,
            key_bytes: active.key.copy_bytes(),
        })
    }

    pub fn mark_installed(
        &mut self,
        authorization: &AuthorizationStore,
        principal: PrincipalId,
        epoch: GroupMediaEpoch,
    ) -> Result<(), GroupMediaCoordinatorError> {
        self.reconcile_authorization(authorization);
        if !authorization.authorize(principal, Permission::ReceivePresentation) {
            return Err(GroupMediaCoordinatorError::UnauthorizedReceiver);
        }
        if self.rotation_required {
            return Err(GroupMediaCoordinatorError::RotationRequired);
        }

        let active_epoch = self
            .active
            .as_ref()
            .map(|active| active.epoch)
            .ok_or(GroupMediaCoordinatorError::NoActiveEpoch)?;
        if epoch != active_epoch {
            return Err(GroupMediaCoordinatorError::StaleEpoch);
        }

        let state = self
            .receivers
            .get_mut(&principal)
            .ok_or(GroupMediaCoordinatorError::ReceiverNotRegistered)?;
        match state.install {
            GroupMediaReceiverInstallState::AwaitingKey => {
                Err(GroupMediaCoordinatorError::KeyNotIssued)
            }
            GroupMediaReceiverInstallState::KeyIssued(issued) if issued == epoch => {
                state.install = GroupMediaReceiverInstallState::Installed(epoch);
                Ok(())
            }
            GroupMediaReceiverInstallState::Installed(installed) if installed == epoch => Ok(()),
            GroupMediaReceiverInstallState::KeyIssued(_)
            | GroupMediaReceiverInstallState::Installed(_) => {
                Err(GroupMediaCoordinatorError::StaleEpoch)
            }
        }
    }

    pub fn seal_frame(
        &mut self,
        authorization: &AuthorizationStore,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, GroupMediaCoordinatorError> {
        self.reconcile_authorization(authorization);
        if self.rotation_required {
            return Err(GroupMediaCoordinatorError::RotationRequired);
        }

        let active = self
            .active
            .as_mut()
            .ok_or(GroupMediaCoordinatorError::NoActiveEpoch)?;
        active
            .sender
            .seal_frame(plaintext, associated_data)
            .map_err(Into::into)
    }

    fn reconcile_authorization(&mut self, authorization: &AuthorizationStore) {
        let before = self.receivers.len();
        self.receivers.retain(|principal, _| {
            authorization.authorize(*principal, Permission::ReceivePresentation)
        });
        if self.receivers.len() != before && self.active.is_some() {
            self.rotation_required = true;
        }
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
    pub fn receiver_state(&self, principal: PrincipalId) -> Option<GroupMediaReceiverInstallState> {
        self.receivers.get(&principal).map(|state| state.install)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::{CredentialFingerprint, CredentialRecord, Principal, PrincipalKind};

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
            credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 1));
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

        assert!(matches!(
            coordinator.register_receiver(&authorization, principal(1)),
            Ok(GroupMediaRegistration::Added)
        ));
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

        assert!(matches!(
            coordinator.register_receiver(&authorization, principal(1)),
            Ok(GroupMediaRegistration::Added)
        ));
        assert!(matches!(
            coordinator.register_receiver(&authorization, principal(1)),
            Ok(GroupMediaRegistration::AlreadyRegistered)
        ));
        assert!(matches!(
            coordinator.register_receiver(&authorization, principal(2)),
            Ok(GroupMediaRegistration::Added)
        ));
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

        assert!(
            coordinator
                .seal_frame(&authorization, b"frame", b"presentation-binding")
                .is_ok()
        );

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
    fn ending_epoch_drops_active_key_state_without_reusing_epoch_number() {
        let authorization = store(&[(1, true)]);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("receiver");
        let first = coordinator.begin_epoch().expect("first epoch");
        coordinator
            .issue_key(&authorization, principal(1))
            .expect("grant");

        assert_eq!(coordinator.end_epoch(), Some(first));
        assert!(coordinator.active_epoch().is_none());
        assert_eq!(
            coordinator.receiver_state(principal(1)),
            Some(GroupMediaReceiverInstallState::AwaitingKey)
        );
        assert!(matches!(
            coordinator.seal_frame(&authorization, b"frame", b"binding"),
            Err(GroupMediaCoordinatorError::NoActiveEpoch)
        ));

        let second = coordinator.begin_epoch().expect("second epoch");
        assert_eq!(second.get(), first.get() + 1);
    }

    #[test]
    fn pending_receiver_does_not_block_healthy_receiver_media() {
        let authorization = store(&[(1, true), (2, true)]);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, principal(1))
            .expect("healthy receiver");
        coordinator
            .register_receiver(&authorization, principal(2))
            .expect("slow receiver");
        let epoch = coordinator.begin_epoch().expect("epoch");

        coordinator
            .issue_key(&authorization, principal(1))
            .expect("healthy key");
        coordinator
            .mark_installed(&authorization, principal(1), epoch)
            .expect("healthy install");

        assert_eq!(
            coordinator.receiver_state(principal(2)),
            Some(GroupMediaReceiverInstallState::AwaitingKey)
        );
        assert!(
            coordinator
                .seal_frame(&authorization, b"frame", b"presentation-binding")
                .is_ok(),
            "a slow receiver must not create a global key-install barrier"
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
        let mut coordinator = GroupMediaCoordinator {
            last_epoch: u32::MAX,
            ..GroupMediaCoordinator::default()
        };
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
