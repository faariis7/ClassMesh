//! Bounded, opt-in multicast evidence. Each endpoint owns its trace on one
//! thread. Records carry header metadata only and are exported after capture.
use std::net::SocketAddr;
use std::time::{Instant, SystemTime};

use classmesh_protocol::media::MediaPacketHeader;

use crate::multicast_receiver::MulticastPacketDropReason;

pub const MAX_DELIVERY_EVENTS: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStage {
    Written,
    WriteFailed,
    SocketAccepted,
    SocketRejected,
    Malformed,
    Queued,
    QueueFull,
    QueueDisconnected,
    FrameAssembled,
    FrameQueueFull,
    FrameQueueDisconnected,
    StaleFrame,
    InvalidFrame,
}

impl DeliveryStage {
    pub const ALL: [Self; 13] = [
        Self::Written,
        Self::WriteFailed,
        Self::SocketAccepted,
        Self::SocketRejected,
        Self::Malformed,
        Self::Queued,
        Self::QueueFull,
        Self::QueueDisconnected,
        Self::FrameAssembled,
        Self::FrameQueueFull,
        Self::FrameQueueDisconnected,
        Self::StaleFrame,
        Self::InvalidFrame,
    ];
}

#[derive(Debug, Clone, Copy)]
pub struct DeliveryEvent {
    pub stage: DeliveryStage,
    pub elapsed_us: u64,
    pub packet: Option<MediaPacketHeader>,
    pub peer: Option<SocketAddr>,
    pub frame_id: Option<u64>,
    pub rejection: Option<MulticastPacketDropReason>,
}

#[derive(Debug)]
pub struct DeliveryTrace {
    started: Instant,
    wall_start: SystemTime,
    events: Vec<DeliveryEvent>,
    counts: [u64; DeliveryStage::ALL.len()],
    omitted: u64,
}

impl DeliveryTrace {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            wall_start: SystemTime::now(),
            events: Vec::with_capacity(MAX_DELIVERY_EVENTS),
            counts: [0; DeliveryStage::ALL.len()],
            omitted: 0,
        }
    }

    #[must_use]
    pub fn elapsed_us(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub const fn wall_start(&self) -> SystemTime {
        self.wall_start
    }

    #[must_use]
    pub fn events(&self) -> &[DeliveryEvent] {
        &self.events
    }

    #[must_use]
    pub const fn count(&self, stage: DeliveryStage) -> u64 {
        self.counts[stage as usize]
    }

    #[must_use]
    pub const fn omitted(&self) -> u64 {
        self.omitted
    }

    pub fn record(
        &mut self,
        stage: DeliveryStage,
        frame_id: Option<u64>,
        rejection: Option<MulticastPacketDropReason>,
    ) {
        self.push(DeliveryEvent {
            stage,
            elapsed_us: self.elapsed_us(),
            packet: None,
            peer: None,
            frame_id,
            rejection,
        });
    }

    pub(crate) fn record_packet(
        &mut self,
        stage: DeliveryStage,
        elapsed_us: u64,
        packet: MediaPacketHeader,
        peer: SocketAddr,
        rejection: Option<MulticastPacketDropReason>,
    ) {
        self.push(DeliveryEvent {
            stage,
            elapsed_us,
            packet: Some(packet),
            peer: Some(peer),
            frame_id: Some(packet.frame_id),
            rejection,
        });
    }

    fn push(&mut self, event: DeliveryEvent) {
        let count = &mut self.counts[event.stage as usize];
        *count = count.saturating_add(1);
        if self.events.len() < MAX_DELIVERY_EVENTS {
            self.events.push(event);
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }
}

impl Default for DeliveryTrace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_trace_keeps_counting_without_expanding_or_replacing_the_prefix() {
        let mut trace = DeliveryTrace::new();
        for frame in 0..MAX_DELIVERY_EVENTS as u64 {
            trace.record(DeliveryStage::Queued, Some(frame), None);
        }
        trace.record(DeliveryStage::QueueFull, Some(9_999), None);

        assert_eq!(trace.events().len(), MAX_DELIVERY_EVENTS);
        assert_eq!(trace.events()[0].frame_id, Some(0));
        assert_eq!(trace.omitted(), 1);
        assert_eq!(
            trace.count(DeliveryStage::Queued),
            MAX_DELIVERY_EVENTS as u64
        );
        assert_eq!(trace.count(DeliveryStage::QueueFull), 1);
    }
}
