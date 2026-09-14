use std::collections::{BTreeSet, VecDeque};

use crate::MediaPacket;

const MAX_TRACKED_GAP: u32 = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceObservation {
    First,
    InOrder,
    Gap { missing: u32 },
    ReorderedOrDuplicate,
}

/// Tracks datagram sequence gaps without treating packet loss as a connection failure.
#[derive(Debug, Default)]
pub struct SequenceTracker {
    highest: Option<u32>,
    missing: BTreeSet<u32>,
    received: u64,
    reordered_or_duplicate: u64,
}

impl SequenceTracker {
    pub fn observe(&mut self, sequence: u32) -> SequenceObservation {
        self.received = self.received.saturating_add(1);
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            return SequenceObservation::First;
        };

        let expected = highest.wrapping_add(1);
        if sequence == expected {
            self.highest = Some(sequence);
            return SequenceObservation::InOrder;
        }

        // Sequence numbers are compared in a half-range window so normal u32 wrapping is safe.
        let ahead = sequence.wrapping_sub(expected);
        if ahead < (u32::MAX / 2) {
            let tracked = ahead.min(MAX_TRACKED_GAP);
            for offset in 0..tracked {
                self.missing.insert(expected.wrapping_add(offset));
            }
            self.highest = Some(sequence);
            return SequenceObservation::Gap { missing: ahead };
        }

        if self.missing.remove(&sequence) {
            self.reordered_or_duplicate = self.reordered_or_duplicate.saturating_add(1);
            return SequenceObservation::ReorderedOrDuplicate;
        }

        self.reordered_or_duplicate = self.reordered_or_duplicate.saturating_add(1);
        SequenceObservation::ReorderedOrDuplicate
    }

    #[must_use]
    pub fn missing_sequences(&self) -> Vec<u32> {
        self.missing.iter().copied().collect()
    }

    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    #[must_use]
    pub const fn reordered_or_duplicate(&self) -> u64 {
        self.reordered_or_duplicate
    }
}

#[derive(Debug, Clone)]
struct CachedPacket {
    stored_at_us: u64,
    packet: MediaPacket,
}

/// Small time- and count-bounded cache used for NACK retransmission.
///
/// It is intentionally not a reliable queue: once media is too old, recovery should use a new
/// keyframe rather than increasing live latency.
#[derive(Debug)]
pub struct RetransmitCache {
    entries: VecDeque<CachedPacket>,
    max_packets: usize,
    max_age_us: u64,
}

impl RetransmitCache {
    /// # Panics
    /// Panics if `max_packets` is zero.
    #[must_use]
    pub fn new(max_packets: usize, max_age_us: u64) -> Self {
        assert!(
            max_packets > 0,
            "retransmit cache must hold at least one packet"
        );
        Self {
            entries: VecDeque::with_capacity(max_packets),
            max_packets,
            max_age_us,
        }
    }

    pub fn insert(&mut self, now_us: u64, packet: MediaPacket) {
        self.prune(now_us);
        while self.entries.len() >= self.max_packets {
            let _ = self.entries.pop_front();
        }
        self.entries.push_back(CachedPacket {
            stored_at_us: now_us,
            packet,
        });
    }

    pub fn prune(&mut self, now_us: u64) {
        while self
            .entries
            .front()
            .is_some_and(|entry| now_us.saturating_sub(entry.stored_at_us) > self.max_age_us)
        {
            let _ = self.entries.pop_front();
        }
    }

    #[must_use]
    pub fn find(&self, frame_id: u64, packet_index: u16) -> Option<&MediaPacket> {
        self.entries
            .iter()
            .rev()
            .find(|entry| {
                entry.packet.header.frame_id == frame_id
                    && entry.packet.header.packet_index == packet_index
            })
            .map(|entry| &entry.packet)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::media::{MediaFlags, MediaPacketHeader};

    use super::*;

    fn packet(frame_id: u64, index: u16) -> MediaPacket {
        MediaPacket {
            header: MediaPacketHeader {
                protocol_major: 0,
                protocol_minor: 1,
                flags: MediaFlags::NONE,
                stream_id: 1,
                frame_id,
                sequence: u32::from(index),
                packet_index: index,
                packet_count: 3,
                timestamp_us: 1,
                payload_len: 1,
            },
            payload: vec![index.to_le_bytes()[0]],
        }
    }

    #[test]
    fn tracker_records_gap_and_clears_late_packet() {
        let mut tracker = SequenceTracker::default();
        assert_eq!(tracker.observe(10), SequenceObservation::First);
        assert_eq!(tracker.observe(12), SequenceObservation::Gap { missing: 1 });
        assert_eq!(tracker.missing_sequences(), vec![11]);
        assert_eq!(
            tracker.observe(11),
            SequenceObservation::ReorderedOrDuplicate
        );
        assert!(tracker.missing_sequences().is_empty());
    }

    #[test]
    fn sequence_wrap_is_treated_as_in_order() {
        let mut tracker = SequenceTracker::default();
        let _ = tracker.observe(u32::MAX);
        assert_eq!(tracker.observe(0), SequenceObservation::InOrder);
    }

    #[test]
    fn retransmit_cache_is_bounded_and_expires_old_media() {
        let mut cache = RetransmitCache::new(2, 100);
        cache.insert(0, packet(1, 0));
        cache.insert(10, packet(1, 1));
        cache.insert(20, packet(1, 2));
        assert_eq!(cache.len(), 2);
        assert!(cache.find(1, 0).is_none());
        assert!(cache.find(1, 2).is_some());
        cache.prune(500);
        assert!(cache.is_empty());
    }
}
