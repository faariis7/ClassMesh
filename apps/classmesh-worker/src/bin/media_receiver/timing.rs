use std::collections::BTreeMap;

use classmesh_network::receiver::ReceiverEvent;
use classmesh_protocol::media::MediaPacketHeader;

// Match the recorded-media lab input limit. Keep samples after expiry or
// completion so that reporting can wait until after the receive loop.
const MAX_FRAME_SAMPLES: usize = 240;

#[derive(Debug)]
struct FrameSample {
    expected_packets: u16,
    packets_observed: u16,
    first_read_wait_us: u64,
    first_received_us: u64,
    last_received_us: u64,
    max_between_reads_us: u64,
    max_later_read_us: u64,
    ready_us: Option<u64>,
    stale_drops: u16,
}

#[derive(Default)]
pub(super) struct FragmentTimings {
    samples: BTreeMap<(u32, u64), FrameSample>,
    reports: Vec<(u64, u64)>,
}

impl FragmentTimings {
    pub(super) fn observe_packet(
        &mut self,
        header: MediaPacketHeader,
        read_started_us: u64,
        received_us: u64,
    ) {
        let key = (header.stream_id, header.frame_id);
        if self.samples.len() >= MAX_FRAME_SAMPLES && !self.samples.contains_key(&key) {
            return;
        }
        let sample = self.samples.entry(key).or_insert(FrameSample {
            expected_packets: header.packet_count,
            packets_observed: 0,
            first_read_wait_us: received_us.saturating_sub(read_started_us),
            first_received_us: received_us,
            last_received_us: received_us,
            max_between_reads_us: 0,
            max_later_read_us: 0,
            ready_us: None,
            stale_drops: 0,
        });
        if sample.ready_us.is_none() {
            if sample.packets_observed > 0 {
                sample.max_between_reads_us = sample
                    .max_between_reads_us
                    .max(read_started_us.saturating_sub(sample.last_received_us));
                sample.max_later_read_us = sample
                    .max_later_read_us
                    .max(received_us.saturating_sub(read_started_us));
            }
            sample.last_received_us = received_us;
            sample.packets_observed = sample.packets_observed.saturating_add(1);
        }
    }

    pub(super) fn observe_events(&mut self, events: &[ReceiverEvent], now_us: u64) {
        for event in events {
            match event {
                ReceiverEvent::FrameReady(frame) => {
                    if let Some(sample) = self.samples.get_mut(&(frame.stream_id, frame.frame_id)) {
                        sample.ready_us = Some(now_us);
                    }
                }
                ReceiverEvent::DroppedStaleFrame {
                    stream_id,
                    frame_id,
                } => {
                    if let Some(sample) = self.samples.get_mut(&(*stream_id, *frame_id)) {
                        sample.stale_drops = sample.stale_drops.saturating_add(1);
                    }
                }
                ReceiverEvent::NeedNack { .. } | ReceiverEvent::NeedKeyframe { .. } => {}
            }
        }
    }

    pub(super) fn observe_status_report(&mut self, datagrams: u64, elapsed_us: u64) {
        if self.reports.len() < MAX_FRAME_SAMPLES {
            self.reports.push((datagrams, elapsed_us));
        }
    }

    pub(super) fn report(&self) {
        for &(datagrams, elapsed_us) in &self.reports {
            eprintln!("receiver status timing: datagrams={datagrams} elapsed_us={elapsed_us}");
        }
        for (&(stream_id, frame_id), sample) in &self.samples {
            let first_to_last_us = sample
                .last_received_us
                .saturating_sub(sample.first_received_us);
            let first_to_ready_us = sample
                .ready_us
                .map(|ready| ready.saturating_sub(sample.first_received_us));
            let last_to_ready_us = sample
                .ready_us
                .map(|ready| ready.saturating_sub(sample.last_received_us));
            eprintln!(
                "receiver fragment timing: stream_id={stream_id} frame_id={frame_id} packets_observed={} expected_packets={} first_read_wait_us={} first_to_last_us={first_to_last_us} first_to_ready_us={first_to_ready_us:?} last_to_ready_us={last_to_ready_us:?} stale_drops={} max_between_reads_us={} max_later_read_us={}",
                sample.packets_observed,
                sample.expected_packets,
                sample.first_read_wait_us,
                sample.stale_drops
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use classmesh_network::AssembledFrame;
    use classmesh_protocol::media::MediaFlags;

    use super::*;

    #[test]
    fn samples_are_capped_and_still_track_existing_frames() {
        let mut timings = FragmentTimings::default();
        let mut header = MediaPacketHeader {
            protocol_major: 0,
            protocol_minor: 4,
            flags: MediaFlags::FRAME_START,
            stream_id: 1,
            frame_id: 0,
            sequence: 0,
            packet_index: 0,
            packet_count: 2,
            timestamp_us: 0,
            payload_len: 1,
        };
        for frame_id in 0..1_000 {
            header.frame_id = frame_id;
            timings.observe_packet(header, 0, 10);
        }
        assert_eq!(timings.samples.len(), MAX_FRAME_SAMPLES);
        header.frame_id = 0;
        header.flags = MediaFlags::FRAME_END;
        header.packet_index = 1;
        timings.observe_packet(header, 11, 20);
        timings.observe_events(
            &[ReceiverEvent::FrameReady(AssembledFrame {
                stream_id: 1,
                frame_id: 0,
                timestamp_us: 0,
                keyframe: false,
                data: vec![1, 2],
            })],
            22,
        );
        let sample = &timings.samples[&(1, 0)];
        assert_eq!(sample.packets_observed, 2);
        assert_eq!(sample.first_received_us, 10);
        assert_eq!(sample.last_received_us, 20);
        assert_eq!(sample.ready_us, Some(22));
        assert_eq!(sample.max_between_reads_us, 1);
        assert_eq!(sample.max_later_read_us, 9);
    }
}
