use std::collections::BTreeMap;

use crate::MediaTransport;
use crate::adaptation::{QualityTier, StreamDecision};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceiverId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CohortKind {
    WiredMulticast,
    DirectUnicast,
    WebRtc,
    ReliableFallback,
}

impl CohortKind {
    #[must_use]
    pub const fn from_transport(transport: MediaTransport) -> Self {
        match transport {
            MediaTransport::UdpMulticast => Self::WiredMulticast,
            MediaTransport::UdpUnicast | MediaTransport::QuicDatagram => Self::DirectUnicast,
            MediaTransport::WebRtc => Self::WebRtc,
            MediaTransport::ReliableFallback => Self::ReliableFallback,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CohortKey {
    pub kind: CohortKind,
    pub tier: QualityTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverRoute {
    pub receiver: ReceiverId,
    pub cohort: CohortKey,
}

/// Maintains per-receiver routing without allowing one outlier to downgrade healthy peers.
#[derive(Debug, Default)]
pub struct CohortRouter {
    routes: BTreeMap<ReceiverId, CohortKey>,
}

impl CohortRouter {
    pub fn update(&mut self, receiver: ReceiverId, decision: StreamDecision) -> ReceiverRoute {
        let cohort = CohortKey {
            kind: CohortKind::from_transport(decision.transport),
            tier: decision.tier,
        };
        self.routes.insert(receiver, cohort);
        ReceiverRoute { receiver, cohort }
    }

    pub fn remove(&mut self, receiver: ReceiverId) -> bool {
        self.routes.remove(&receiver).is_some()
    }

    #[must_use]
    pub fn route(&self, receiver: ReceiverId) -> Option<CohortKey> {
        self.routes.get(&receiver).copied()
    }

    #[must_use]
    pub fn members(&self, cohort: CohortKey) -> Vec<ReceiverId> {
        self.routes
            .iter()
            .filter_map(|(receiver, current)| (*current == cohort).then_some(*receiver))
            .collect()
    }

    #[must_use]
    pub fn cohort_counts(&self) -> BTreeMap<CohortKey, usize> {
        let mut counts = BTreeMap::new();
        for cohort in self.routes.values() {
            *counts.entry(*cohort).or_insert(0) += 1;
        }
        counts
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::adaptation::{StreamDecision, StreamProfile};

    use super::*;

    fn decision(transport: MediaTransport, tier: QualityTier) -> StreamDecision {
        StreamDecision {
            transport,
            tier,
            profile: StreamProfile::new(1280, 720, 30, 2_500),
        }
    }

    #[test]
    fn weak_receiver_moves_without_downgrading_multicast_peers() {
        let mut router = CohortRouter::default();
        let high_multicast = CohortKey {
            kind: CohortKind::WiredMulticast,
            tier: QualityTier::High,
        };

        router.update(
            ReceiverId(1),
            decision(MediaTransport::UdpMulticast, QualityTier::High),
        );
        router.update(
            ReceiverId(2),
            decision(MediaTransport::UdpMulticast, QualityTier::High),
        );
        router.update(
            ReceiverId(3),
            decision(MediaTransport::UdpMulticast, QualityTier::High),
        );
        assert_eq!(router.members(high_multicast).len(), 3);

        router.update(
            ReceiverId(3),
            decision(MediaTransport::ReliableFallback, QualityTier::Emergency),
        );
        assert_eq!(
            router.members(high_multicast),
            vec![ReceiverId(1), ReceiverId(2)]
        );
        assert_eq!(
            router.route(ReceiverId(3)),
            Some(CohortKey {
                kind: CohortKind::ReliableFallback,
                tier: QualityTier::Emergency
            })
        );
    }

    #[test]
    fn wireless_and_wired_receivers_can_coexist() {
        let mut router = CohortRouter::default();
        router.update(
            ReceiverId(10),
            decision(MediaTransport::UdpMulticast, QualityTier::High),
        );
        router.update(
            ReceiverId(11),
            decision(MediaTransport::QuicDatagram, QualityTier::Medium),
        );
        let counts = router.cohort_counts();
        assert_eq!(counts.values().copied().sum::<usize>(), 2);
        assert_eq!(counts.len(), 2);
    }
}
