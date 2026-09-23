use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub const DEFAULT_MAX_MULTICAST_MEMBERSHIPS: usize = 8;
pub const MAX_MULTICAST_MEMBERSHIPS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MulticastMembership {
    group: Ipv4Addr,
    interface: Ipv4Addr,
}

impl MulticastMembership {
    pub fn new(group: Ipv4Addr, interface: Ipv4Addr) -> Result<Self, MulticastContractError> {
        if !group.is_multicast() {
            return Err(MulticastContractError::InvalidGroup);
        }
        if interface.is_multicast() {
            return Err(MulticastContractError::InvalidInterface);
        }
        Ok(Self { group, interface })
    }

    #[must_use]
    pub const fn group(self) -> Ipv4Addr {
        self.group
    }

    #[must_use]
    pub const fn interface(self) -> Ipv4Addr {
        self.interface
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastContractError {
    InvalidGroup,
    InvalidInterface,
    InvalidMaxMemberships,
    MaxMembershipsExceeded,
    MembershipLimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipChange {
    Joined,
    AlreadyJoined,
    Left,
    NotJoined,
}

#[derive(Debug)]
pub struct MulticastMembershipRegistry {
    memberships: BTreeSet<MulticastMembership>,
    max_memberships: usize,
}

impl Default for MulticastMembershipRegistry {
    fn default() -> Self {
        Self {
            memberships: BTreeSet::new(),
            max_memberships: DEFAULT_MAX_MULTICAST_MEMBERSHIPS,
        }
    }
}

impl MulticastMembershipRegistry {
    pub fn with_limit(max_memberships: usize) -> Result<Self, MulticastContractError> {
        if max_memberships == 0 {
            return Err(MulticastContractError::InvalidMaxMemberships);
        }
        if max_memberships > MAX_MULTICAST_MEMBERSHIPS {
            return Err(MulticastContractError::MaxMembershipsExceeded);
        }
        Ok(Self {
            memberships: BTreeSet::new(),
            max_memberships,
        })
    }

    pub fn join(
        &mut self,
        membership: MulticastMembership,
    ) -> Result<MembershipChange, MulticastContractError> {
        if self.memberships.contains(&membership) {
            return Ok(MembershipChange::AlreadyJoined);
        }
        if self.memberships.len() >= self.max_memberships {
            return Err(MulticastContractError::MembershipLimitReached);
        }
        self.memberships.insert(membership);
        Ok(MembershipChange::Joined)
    }

    pub fn leave(&mut self, membership: MulticastMembership) -> MembershipChange {
        if self.memberships.remove(&membership) {
            MembershipChange::Left
        } else {
            MembershipChange::NotJoined
        }
    }

    pub fn take_all(&mut self) -> Vec<MulticastMembership> {
        let memberships = self.memberships.iter().copied().collect();
        self.memberships.clear();
        memberships
    }

    #[must_use]
    pub fn contains(&self, membership: MulticastMembership) -> bool {
        self.memberships.contains(&membership)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.memberships.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memberships.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastProbeFailure {
    JoinFailed,
    ProbeDatagramNotObserved,
    LeaveFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastProbeOutcome {
    Available,
    Unavailable(MulticastProbeFailure),
}

impl MulticastProbeOutcome {
    /// UdpMulticast must not be advertised from API presence alone.
    ///
    /// A runtime may advertise the capability only after a bounded probe has
    /// demonstrated join + probe-datagram reception + clean leave. This is
    /// runtime evidence, not classroom-scale physical qualification.
    #[must_use]
    pub const fn can_advertise_udp_multicast(self) -> bool {
        matches!(self, Self::Available)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MulticastProbeObservation {
    pub joined: bool,
    pub probe_datagram_observed: bool,
    pub left_cleanly: bool,
}

#[must_use]
pub const fn evaluate_multicast_probe(
    observation: MulticastProbeObservation,
) -> MulticastProbeOutcome {
    if !observation.joined {
        return MulticastProbeOutcome::Unavailable(MulticastProbeFailure::JoinFailed);
    }
    if !observation.left_cleanly {
        return MulticastProbeOutcome::Unavailable(MulticastProbeFailure::LeaveFailed);
    }
    if !observation.probe_datagram_observed {
        return MulticastProbeOutcome::Unavailable(
            MulticastProbeFailure::ProbeDatagramNotObserved,
        );
    }
    MulticastProbeOutcome::Available
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership(group_last: u8, interface_last: u8) -> MulticastMembership {
        MulticastMembership::new(
            Ipv4Addr::new(239, 10, 20, group_last),
            Ipv4Addr::new(192, 168, 50, interface_last),
        )
        .expect("valid classroom multicast membership")
    }

    #[test]
    fn membership_requires_multicast_group_and_non_multicast_interface() {
        assert_eq!(
            MulticastMembership::new(
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 20),
            ),
            Err(MulticastContractError::InvalidGroup)
        );
        assert_eq!(
            MulticastMembership::new(
                Ipv4Addr::new(239, 10, 20, 30),
                Ipv4Addr::new(239, 10, 20, 31),
            ),
            Err(MulticastContractError::InvalidInterface)
        );
    }

    #[test]
    fn duplicate_join_is_idempotent_and_does_not_consume_membership_budget() {
        let mut registry = MulticastMembershipRegistry::with_limit(1).expect("valid limit");
        let membership = membership(30, 10);

        assert_eq!(registry.join(membership), Ok(MembershipChange::Joined));
        assert_eq!(
            registry.join(membership),
            Ok(MembershipChange::AlreadyJoined)
        );
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn membership_is_bounded_and_leave_is_explicit() {
        let mut registry = MulticastMembershipRegistry::with_limit(2).expect("valid limit");
        let first = membership(30, 10);
        let second = membership(31, 10);
        let third = membership(32, 10);

        assert_eq!(registry.join(first), Ok(MembershipChange::Joined));
        assert_eq!(registry.join(second), Ok(MembershipChange::Joined));
        assert_eq!(
            registry.join(third),
            Err(MulticastContractError::MembershipLimitReached)
        );
        assert!(registry.contains(first));
        assert_eq!(registry.leave(first), MembershipChange::Left);
        assert_eq!(registry.leave(first), MembershipChange::NotJoined);
        assert!(!registry.contains(first));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn cleanup_clears_bounded_membership_state() {
        let mut registry = MulticastMembershipRegistry::default();
        registry.join(membership(30, 10)).expect("first membership");
        registry.join(membership(31, 10)).expect("second membership");

        let cleanup = registry.take_all();
        assert_eq!(cleanup.len(), 2);
        assert!(cleanup.contains(&membership(30, 10)));
        assert!(cleanup.contains(&membership(31, 10)));
        assert!(registry.is_empty());
        assert!(registry.take_all().is_empty());
    }

    #[test]
    fn capability_requires_join_receive_and_clean_leave_probe_evidence() {
        let available = evaluate_multicast_probe(MulticastProbeObservation {
            joined: true,
            probe_datagram_observed: true,
            left_cleanly: true,
        });
        assert_eq!(available, MulticastProbeOutcome::Available);
        assert!(available.can_advertise_udp_multicast());

        for (observation, failure) in [
            (
                MulticastProbeObservation {
                    joined: false,
                    probe_datagram_observed: false,
                    left_cleanly: false,
                },
                MulticastProbeFailure::JoinFailed,
            ),
            (
                MulticastProbeObservation {
                    joined: true,
                    probe_datagram_observed: false,
                    left_cleanly: true,
                },
                MulticastProbeFailure::ProbeDatagramNotObserved,
            ),
            (
                MulticastProbeObservation {
                    joined: true,
                    probe_datagram_observed: true,
                    left_cleanly: false,
                },
                MulticastProbeFailure::LeaveFailed,
            ),
        ] {
            let outcome = evaluate_multicast_probe(observation);
            assert_eq!(outcome, MulticastProbeOutcome::Unavailable(failure));
            assert!(!outcome.can_advertise_udp_multicast());
        }
    }

    #[test]
    fn invalid_or_unbounded_membership_limit_is_rejected() {
        assert!(matches!(
            MulticastMembershipRegistry::with_limit(0),
            Err(MulticastContractError::InvalidMaxMemberships)
        ));
        assert!(matches!(
            MulticastMembershipRegistry::with_limit(MAX_MULTICAST_MEMBERSHIPS + 1),
            Err(MulticastContractError::MaxMembershipsExceeded)
        ));
    }
}
