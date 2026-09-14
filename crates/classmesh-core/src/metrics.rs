use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatencySummary {
    pub samples: usize,
    pub p50_ms: f32,
    pub p95_ms: f32,
    pub max_ms: f32,
}

#[derive(Debug)]
pub struct RollingLatency {
    values_ms: VecDeque<f32>,
    capacity: usize,
}

impl RollingLatency {
    /// # Panics
    /// Panics when `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "latency window must be non-zero");
        Self {
            values_ms: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn record(&mut self, value_ms: f32) -> bool {
        if !value_ms.is_finite() || value_ms < 0.0 {
            return false;
        }
        while self.values_ms.len() >= self.capacity {
            let _ = self.values_ms.pop_front();
        }
        self.values_ms.push_back(value_ms);
        true
    }

    #[must_use]
    pub fn summary(&self) -> Option<LatencySummary> {
        if self.values_ms.is_empty() {
            return None;
        }
        let mut values: Vec<f32> = self.values_ms.iter().copied().collect();
        values.sort_by(f32::total_cmp);
        Some(LatencySummary {
            samples: values.len(),
            p50_ms: percentile(&values, 50),
            p95_ms: percentile(&values, 95),
            max_ms: *values.last().expect("non-empty latency values"),
        })
    }
}

fn percentile(sorted: &[f32], percentile: usize) -> f32 {
    let last = sorted.len() - 1;
    let index = last.saturating_mul(percentile).div_ceil(100).min(last);
    sorted[index]
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MediaCounters {
    pub captured_frames: u64,
    pub encoded_frames: u64,
    pub sent_packets: u64,
    pub received_packets: u64,
    pub decoded_frames: u64,
    pub rendered_frames: u64,
    pub dropped_frames: u64,
    pub dropped_packets: u64,
    pub reordered_packets: u64,
    pub keyframes: u64,
    pub nack_requests: u64,
    pub capture_recoveries: u64,
    pub codec_recoveries: u64,
}

impl MediaCounters {
    pub fn saturating_add_assign(&mut self, delta: Self) {
        self.captured_frames = self.captured_frames.saturating_add(delta.captured_frames);
        self.encoded_frames = self.encoded_frames.saturating_add(delta.encoded_frames);
        self.sent_packets = self.sent_packets.saturating_add(delta.sent_packets);
        self.received_packets = self.received_packets.saturating_add(delta.received_packets);
        self.decoded_frames = self.decoded_frames.saturating_add(delta.decoded_frames);
        self.rendered_frames = self.rendered_frames.saturating_add(delta.rendered_frames);
        self.dropped_frames = self.dropped_frames.saturating_add(delta.dropped_frames);
        self.dropped_packets = self.dropped_packets.saturating_add(delta.dropped_packets);
        self.reordered_packets = self
            .reordered_packets
            .saturating_add(delta.reordered_packets);
        self.keyframes = self.keyframes.saturating_add(delta.keyframes);
        self.nack_requests = self.nack_requests.saturating_add(delta.nack_requests);
        self.capture_recoveries = self
            .capture_recoveries
            .saturating_add(delta.capture_recoveries);
        self.codec_recoveries = self.codec_recoveries.saturating_add(delta.codec_recoveries);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PipelineSnapshot {
    pub counters: MediaCounters,
    pub capture: Option<LatencySummary>,
    pub encode: Option<LatencySummary>,
    pub queue: Option<LatencySummary>,
    pub decode: Option<LatencySummary>,
    pub render: Option<LatencySummary>,
}

#[derive(Debug)]
pub struct PipelineMetrics {
    counters: MediaCounters,
    capture: RollingLatency,
    encode: RollingLatency,
    queue: RollingLatency,
    decode: RollingLatency,
    render: RollingLatency,
}

impl PipelineMetrics {
    #[must_use]
    pub fn new(window_size: usize) -> Self {
        Self {
            counters: MediaCounters::default(),
            capture: RollingLatency::new(window_size),
            encode: RollingLatency::new(window_size),
            queue: RollingLatency::new(window_size),
            decode: RollingLatency::new(window_size),
            render: RollingLatency::new(window_size),
        }
    }

    pub fn add_counters(&mut self, delta: MediaCounters) {
        self.counters.saturating_add_assign(delta);
    }

    pub fn record_capture_ms(&mut self, value: f32) -> bool {
        self.capture.record(value)
    }

    pub fn record_encode_ms(&mut self, value: f32) -> bool {
        self.encode.record(value)
    }

    pub fn record_queue_ms(&mut self, value: f32) -> bool {
        self.queue.record(value)
    }

    pub fn record_decode_ms(&mut self, value: f32) -> bool {
        self.decode.record(value)
    }

    pub fn record_render_ms(&mut self, value: f32) -> bool {
        self.render.record(value)
    }

    #[must_use]
    pub fn snapshot(&self) -> PipelineSnapshot {
        PipelineSnapshot {
            counters: self.counters,
            capture: self.capture.summary(),
            encode: self.encode.summary(),
            queue: self.queue.summary(),
            decode: self.decode.summary(),
            render: self.render.summary(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_latency_is_bounded_and_rejects_invalid_values() {
        let mut latency = RollingLatency::new(3);
        assert!(!latency.record(f32::NAN));
        assert!(!latency.record(-1.0));
        for value in [1.0, 2.0, 3.0, 100.0] {
            assert!(latency.record(value));
        }
        let summary = latency.summary().expect("window has samples");
        assert_eq!(summary.samples, 3);
        assert_eq!(summary.max_ms, 100.0);
        assert_eq!(summary.p50_ms, 3.0);
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let mut counters = MediaCounters {
            captured_frames: u64::MAX,
            ..MediaCounters::default()
        };
        counters.saturating_add_assign(MediaCounters {
            captured_frames: 1,
            ..MediaCounters::default()
        });
        assert_eq!(counters.captured_frames, u64::MAX);
    }
}
