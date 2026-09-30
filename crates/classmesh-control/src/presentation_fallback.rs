use std::collections::BTreeSet;

use classmesh_protocol::Capability;
use classmesh_security::PrincipalId;
use classmesh_security::group_media_coordinator::MAX_GROUP_MEDIA_RECEIVERS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationFallbackError {
    InvalidStreamId,
    InvalidFallbackLimit,
    RequiredCapabilityMissing(Capability),
    FallbackLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationFallbackChange {
    Enabled,
    AlreadyEnabled,
}

/// Bounded Teacher-side admission policy for explicit per-receiver unicast fallback.
///
/// This coordinator does not infer transport health, packet-loss thresholds or classroom topology.
/// A caller must first establish that a currently authenticated presentation receiver should be
/// treated as an outlier, then call `request_unicast` with that receiver's negotiated capabilities.
///
/// Admission requires the existing Teacher Presentation + SFrame contract and an explicitly
/// negotiated UDP-unicast capability. Multicast capability is intentionally not required: a
/// receiver whose local multicast probe failed is a valid fallback candidate. The coordinator owns
/// no sockets, keys, authorization records or control-session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationFallbackCoordinator {
    stream_id: u32,
    max_unicast_receivers: usize,
    unicast_receivers: BTreeSet<PrincipalId>,
}

impl PresentationFallbackCoordinator {
    pub fn with_limit(
        stream_id: u32,
        max_unicast_receivers: usize,
    ) -> Result<Self, PresentationFallbackError> {
        if stream_id == 0 {
            return Err(PresentationFallbackError::InvalidStreamId);
        }
        if max_unicast_receivers == 0 || max_unicast_receivers > MAX_GROUP_MEDIA_RECEIVERS {
            return Err(PresentationFallbackError::InvalidFallbackLimit);
        }

        Ok(Self {
            stream_id,
            max_unicast_receivers,
            unicast_receivers: BTreeSet::new(),
        })
    }

    #[must_use]
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn max_unicast_receivers(&self) -> usize {
        self.max_unicast_receivers
    }

    #[must_use]
    pub fn unicast_receiver_count(&self) -> usize {
        self.unicast_receivers.len()
    }

    #[must_use]
    pub fn is_unicast_fallback(&self, receiver: PrincipalId) -> bool {
        self.unicast_receivers.contains(&receiver)
    }

    pub fn request_unicast(
        &mut self,
        receiver: PrincipalId,
        negotiated_capabilities: &BTreeSet<Capability>,
    ) -> Result<PresentationFallbackChange, PresentationFallbackError> {
        for required in [
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpUnicast,
        ] {
            if !negotiated_capabilities.contains(&required) {
                return Err(PresentationFallbackError::RequiredCapabilityMissing(
                    required,
                ));
            }
        }

        if self.unicast_receivers.contains(&receiver) {
            return Ok(PresentationFallbackChange::AlreadyEnabled);
        }
        if self.unicast_receivers.len() >= self.max_unicast_receivers {
            return Err(PresentationFallbackError::FallbackLimitExceeded);
        }

        self.unicast_receivers.insert(receiver);
        Ok(PresentationFallbackChange::Enabled)
    }

    pub fn restore_multicast(&mut self, receiver: PrincipalId) -> bool {
        self.unicast_receivers.remove(&receiver)
    }

    pub fn clear(&mut self) {
        self.unicast_receivers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn fallback_capabilities() -> BTreeSet<Capability> {
        BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpUnicast,
        ])
    }

    #[test]
    fn constructor_requires_nonzero_stream_and_bounded_outlier_limit() {
        assert_eq!(
            PresentationFallbackCoordinator::with_limit(0, 1),
            Err(PresentationFallbackError::InvalidStreamId)
        );
        assert_eq!(
            PresentationFallbackCoordinator::with_limit(7, 0),
            Err(PresentationFallbackError::InvalidFallbackLimit)
        );
        assert_eq!(
            PresentationFallbackCoordinator::with_limit(7, MAX_GROUP_MEDIA_RECEIVERS + 1),
            Err(PresentationFallbackError::InvalidFallbackLimit)
        );
    }

    #[test]
    fn fallback_requires_presentation_sframe_and_unicast_contracts() {
        let receiver = principal(1);
        for missing in [
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
            Capability::UdpUnicast,
        ] {
            let mut capabilities = fallback_capabilities();
            capabilities.remove(&missing);
            let mut coordinator =
                PresentationFallbackCoordinator::with_limit(7, 2).expect("valid coordinator");

            assert_eq!(
                coordinator.request_unicast(receiver, &capabilities),
                Err(PresentationFallbackError::RequiredCapabilityMissing(
                    missing
                ))
            );
            assert_eq!(coordinator.unicast_receiver_count(), 0);
        }
    }

    #[test]
    fn multicast_capability_is_not_required_for_a_probe_failed_outlier() {
        let receiver = principal(9);
        let capabilities = fallback_capabilities();
        assert!(!capabilities.contains(&Capability::UdpMulticast));
        let mut coordinator =
            PresentationFallbackCoordinator::with_limit(7, 1).expect("valid coordinator");

        assert_eq!(
            coordinator.request_unicast(receiver, &capabilities),
            Ok(PresentationFallbackChange::Enabled)
        );
        assert!(coordinator.is_unicast_fallback(receiver));
    }

    #[test]
    fn fallback_is_explicit_idempotent_and_bounded() {
        let capabilities = fallback_capabilities();
        let first = principal(1);
        let second = principal(2);
        let third = principal(3);
        let mut coordinator =
            PresentationFallbackCoordinator::with_limit(7, 2).expect("valid coordinator");

        assert_eq!(
            coordinator.request_unicast(first, &capabilities),
            Ok(PresentationFallbackChange::Enabled)
        );
        assert_eq!(
            coordinator.request_unicast(first, &capabilities),
            Ok(PresentationFallbackChange::AlreadyEnabled)
        );
        assert_eq!(
            coordinator.request_unicast(second, &capabilities),
            Ok(PresentationFallbackChange::Enabled)
        );
        assert_eq!(
            coordinator.request_unicast(third, &capabilities),
            Err(PresentationFallbackError::FallbackLimitExceeded)
        );

        assert_eq!(coordinator.unicast_receiver_count(), 2);
        assert!(coordinator.is_unicast_fallback(first));
        assert!(coordinator.is_unicast_fallback(second));
        assert!(!coordinator.is_unicast_fallback(third));
    }

    #[test]
    fn receiver_can_return_to_multicast_without_affecting_other_outliers() {
        let capabilities = fallback_capabilities();
        let first = principal(1);
        let second = principal(2);
        let mut coordinator =
            PresentationFallbackCoordinator::with_limit(7, 2).expect("valid coordinator");

        coordinator
            .request_unicast(first, &capabilities)
            .expect("first fallback");
        coordinator
            .request_unicast(second, &capabilities)
            .expect("second fallback");

        assert!(coordinator.restore_multicast(first));
        assert!(!coordinator.restore_multicast(first));
        assert!(!coordinator.is_unicast_fallback(first));
        assert!(coordinator.is_unicast_fallback(second));
        assert_eq!(coordinator.unicast_receiver_count(), 1);

        coordinator.clear();
        assert_eq!(coordinator.unicast_receiver_count(), 0);
    }
}
