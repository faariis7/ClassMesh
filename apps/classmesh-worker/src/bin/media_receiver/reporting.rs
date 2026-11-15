use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use classmesh_network::transport::{UdpReceiverIntervalSampler, UdpReceiverStats};

use super::{ReceiverCounters, RecoveryTelemetry};

const REPORT_INTERVAL: Duration = Duration::from_secs(1);
const PENDING_REPORTS: usize = 1;
const MAX_STATUS_TIMINGS: usize = 240;

pub(super) struct StatusSnapshot {
    pub sampled_us: u64,
    pub stats: UdpReceiverStats,
    pub counters: ReceiverCounters,
    pub recovery: RecoveryTelemetry,
}

pub(super) struct StatusReporter {
    tx: SyncSender<StatusSnapshot>,
    done: Receiver<io::Result<()>>,
    next_report: Instant,
    dropped: u64,
}

impl StatusReporter {
    pub(super) fn start(
        writer: impl Write + Send + 'static,
        initial_stats: UdpReceiverStats,
        start: Instant,
        fragment_timing: bool,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(PENDING_REPORTS);
        let (done_tx, done) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("classmesh-receiver-status".to_owned())
            .spawn(move || {
                let _ = done_tx.send(write_reports(writer, rx, initial_stats, fragment_timing));
            })?;
        Ok(Self {
            tx,
            done,
            next_report: start,
            dropped: 0,
        })
    }

    pub(super) fn publish_if_due(
        &mut self,
        now: Instant,
        snapshot: impl FnOnce() -> StatusSnapshot,
    ) {
        if now < self.next_report {
            return;
        }
        self.next_report = now + REPORT_INTERVAL;
        if self.tx.try_send(snapshot()).is_err() {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    // Allow a normal CLI shutdown to flush the pending status before the
    // final summary. A stalled sink never holds the receiver open indefinitely.
    pub(super) fn finish(self, timeout: Duration) -> io::Result<Option<u64>> {
        drop(self.tx);
        match self.done.recv_timeout(timeout) {
            Ok(result) => result.map(|()| Some(self.dropped)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("receiver status writer stopped"))
            }
        }
    }
}

fn write_reports(
    mut sink: impl Write,
    rx: Receiver<StatusSnapshot>,
    initial_stats: UdpReceiverStats,
    fragment_timing: bool,
) -> io::Result<()> {
    let mut telemetry = UdpReceiverIntervalSampler::default();
    telemetry.observe(0, initial_stats);
    for (index, snapshot) in rx.into_iter().enumerate() {
        let StatusSnapshot {
            sampled_us,
            stats,
            counters,
            recovery,
        } = snapshot;
        let started = (fragment_timing && index < MAX_STATUS_TIMINGS).then(Instant::now);
        if let Some(interval) = telemetry.observe(sampled_us, stats) {
            writeln!(
                sink,
                "receiver measured interval: elapsed_ms={} datagrams={} frames={} gap_events={} missing_sequence_ids={} reordered={} datagrams_per_sec={:.1} frames_per_sec={:.1}",
                interval.elapsed_us / 1_000,
                interval.datagrams_received,
                interval.frames_completed,
                interval.gap_events,
                interval.missing_sequence_ids,
                interval.reordered_or_duplicate,
                interval.datagrams_per_second(),
                interval.frames_per_second(),
            )?;
        }
        writeln!(
            sink,
            "receiver stats: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} sequence_missing_packets={} reordered={} nack_requests={} keyframe_requests={} feedback_sent={} feedback_errors={} stale_drops={} decoded_gpu_frames={} presented_frames={} present_errors={} decode_errors={} decode_waiting_frames={} gpu_recoveries={} forced_gpu_recoveries={} last_gpu_recovery_ms={:.2} longest_gpu_recovery_ms={:.2}",
            stats.datagrams_received,
            counters.frames,
            counters.bytes,
            counters.keyframes,
            stats.sequence_gaps_observed,
            stats.missing_datagrams_observed,
            stats.reordered_or_duplicate,
            counters.nack_requests,
            counters.keyframe_requests,
            counters.feedback_sent,
            counters.feedback_errors,
            counters.stale_drops,
            counters.decoded_gpu_frames,
            counters.presented_frames,
            counters.present_errors,
            counters.decode_errors,
            counters.decode_waiting_frames,
            recovery.recoveries,
            recovery.forced_recoveries,
            recovery.last.as_secs_f64() * 1_000.0,
            recovery.longest.as_secs_f64() * 1_000.0
        )?;
        if let Some(started) = started {
            writeln!(
                sink,
                "receiver status timing: datagrams={} elapsed_us={}",
                stats.datagrams_received,
                started.elapsed().as_micros()
            )?;
        }
    }
    sink.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct BlockingSink {
        first_write: Option<(mpsc::Sender<()>, Receiver<()>)>,
        lines: mpsc::Sender<()>,
        output: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for BlockingSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some((entered, release)) = self.first_write.take() {
                entered.send(()).unwrap();
                release
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(io::Error::other)?;
            }
            self.output.lock().unwrap().extend_from_slice(bytes);
            for _ in bytes.iter().filter(|&&byte| byte == b'\n') {
                let _ = self.lines.send(());
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn publish(reporter: &mut StatusReporter, start: Instant, second: u64) {
        reporter.publish_if_due(start + Duration::from_secs(second), || StatusSnapshot {
            sampled_us: second * 1_000_000,
            stats: UdpReceiverStats {
                datagrams_received: second * 10,
                frames_completed: second,
                ..UdpReceiverStats::default()
            },
            counters: ReceiverCounters {
                frames: second,
                ..ReceiverCounters::default()
            },
            recovery: RecoveryTelemetry::default(),
        });
    }

    #[test]
    fn blocked_sink_has_one_pending_snapshot_and_resumes_with_measured_deltas() {
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (lines_tx, lines) = mpsc::channel();
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = BlockingSink {
            first_write: Some((entered_tx, release_rx)),
            lines: lines_tx,
            output: Arc::clone(&output),
        };
        let start = Instant::now();
        let mut reporter =
            StatusReporter::start(writer, UdpReceiverStats::default(), start, false).unwrap();

        publish(&mut reporter, start, 0);
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        for second in 1..=4_097 {
            publish(&mut reporter, start, second);
        }

        release.send(()).unwrap();
        // The initial status and the pending snapshot's interval + status.
        for _ in 0..3 {
            lines.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        publish(&mut reporter, start, 4_098);
        assert_eq!(
            reporter.finish(Duration::from_secs(2)).unwrap(),
            Some(4_096)
        );

        let out = output.lock().unwrap();
        let out = std::str::from_utf8(&out).unwrap();
        assert_eq!(out.matches("receiver stats:").count(), 3);
        assert!(out.contains("elapsed_ms=4097000 datagrams=40970 frames=4097"));
        assert!(out.contains("datagrams_per_sec=10.0 frames_per_sec=1.0"));
        assert!(out.contains("receiver stats: datagrams=40980 frames=4098"));
    }

    #[test]
    fn a_stalled_sink_cannot_hold_shutdown_open() {
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (lines, _) = mpsc::channel();
        let writer = BlockingSink {
            first_write: Some((entered_tx, release_rx)),
            lines,
            output: Arc::new(Mutex::new(Vec::new())),
        };
        let start = Instant::now();
        let mut reporter =
            StatusReporter::start(writer, UdpReceiverStats::default(), start, false).unwrap();
        publish(&mut reporter, start, 0);
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(reporter.finish(Duration::ZERO).unwrap(), None);
        release.send(()).unwrap();
    }
}
