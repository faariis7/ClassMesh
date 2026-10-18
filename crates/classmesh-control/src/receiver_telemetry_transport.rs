//! Strict, fixed-width diagnostic payload and bounded pre-IPC mailbox.
//!
//! Encoding is NOT authentication: a future Service must receive this only over
//! a separately authenticated and authorized Worker channel, pin the current
//! owner + receiver binding, and revalidate before forwarding or adaptation.
//! This module adds no transport, threads, IPC message ID or privileges.
use std::sync::{Arc, Mutex, TryLockError, Weak};

use crate::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetrySnapshot,
};

pub const RECEIVER_TELEMETRY_WIRE_VERSION: u16 = 1;
pub const RECEIVER_TELEMETRY_WIRE_LEN: usize = 136;
const WIRE_MAGIC: [u8; 4] = *b"CMRT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryWireError {
    InvalidLength,
    BadMagic,
    UnsupportedVersion(u16),
    NonzeroReserved,
    InvalidBinding,
    InvalidSequence,
    Inactive,
    BindingMismatch,
    NonmonotonicSequence,
    /// Never wrap a lifetime/incarnation number to recreate a revoked lease.
    LifecycleExhausted,
}

fn write_u32(output: &mut [u8; RECEIVER_TELEMETRY_WIRE_LEN], offset: &mut usize, value: u32) {
    output[*offset..*offset + 4].copy_from_slice(&value.to_be_bytes());
    *offset += 4;
}

fn write_u64(output: &mut [u8; RECEIVER_TELEMETRY_WIRE_LEN], offset: &mut usize, value: u64) {
    output[*offset..*offset + 8].copy_from_slice(&value.to_be_bytes());
    *offset += 8;
}

fn read_u32(input: &[u8], offset: &mut usize) -> u32 {
    let result = u32::from_be_bytes(
        input[*offset..*offset + 4]
            .try_into()
            .expect("fixed-length telemetry frame validated"),
    );
    *offset += 4;
    result
}

fn read_u64(input: &[u8], offset: &mut usize) -> u64 {
    let result = u64::from_be_bytes(
        input[*offset..*offset + 8]
            .try_into()
            .expect("fixed-length telemetry frame validated"),
    );
    *offset += 8;
    result
}

/// Encode the full exact identity and eight independent playback counters.
/// No authentication or transport is implied by producing these bytes.
pub fn encode_receiver_telemetry(
    sample: &ReceiverTelemetrySnapshot,
) -> Result<[u8; RECEIVER_TELEMETRY_WIRE_LEN], ReceiverTelemetryWireError> {
    if !sample.binding.is_valid() {
        return Err(ReceiverTelemetryWireError::InvalidBinding);
    }
    if sample.sequence == 0 {
        return Err(ReceiverTelemetryWireError::InvalidSequence);
    }
    let binding = sample.binding;
    let counters = sample.counters;
    let mut output = [0_u8; RECEIVER_TELEMETRY_WIRE_LEN];
    output[..4].copy_from_slice(&WIRE_MAGIC);
    output[4..6].copy_from_slice(&RECEIVER_TELEMETRY_WIRE_VERSION.to_be_bytes());
    // output[6..8] are reserved zero bytes.
    let mut at = 8;
    write_u32(&mut output, &mut at, binding.process_id);
    write_u32(&mut output, &mut at, binding.session_id);
    write_u64(&mut output, &mut at, binding.worker_generation);
    write_u64(&mut output, &mut at, binding.control_session_id);
    write_u64(&mut output, &mut at, binding.request_id);
    write_u64(&mut output, &mut at, binding.presentation_id);
    write_u32(&mut output, &mut at, binding.stream_id);
    write_u32(&mut output, &mut at, binding.epoch);
    write_u64(&mut output, &mut at, binding.receiver_generation);
    write_u64(&mut output, &mut at, sample.sequence);
    write_u64(&mut output, &mut at, counters.authenticated_frames);
    write_u64(&mut output, &mut at, counters.rejected_frames);
    write_u64(&mut output, &mut at, counters.decoded_frames);
    write_u64(&mut output, &mut at, counters.presented_frames);
    write_u64(&mut output, &mut at, counters.present_errors);
    write_u64(&mut output, &mut at, counters.decode_errors);
    write_u64(&mut output, &mut at, counters.keyframe_waits);
    write_u64(&mut output, &mut at, counters.queue_drops);
    debug_assert_eq!(at, RECEIVER_TELEMETRY_WIRE_LEN);
    Ok(output)
}

/// Refuse arbitrary version/reserved bytes and partial/overlong frames before
/// parsing. Decoding alone does not authenticate the producer.
pub fn decode_receiver_telemetry(
    input: &[u8],
) -> Result<ReceiverTelemetrySnapshot, ReceiverTelemetryWireError> {
    if input.len() != RECEIVER_TELEMETRY_WIRE_LEN {
        return Err(ReceiverTelemetryWireError::InvalidLength);
    }
    if input[..4] != WIRE_MAGIC {
        return Err(ReceiverTelemetryWireError::BadMagic);
    }
    let version = u16::from_be_bytes([input[4], input[5]]);
    if version != RECEIVER_TELEMETRY_WIRE_VERSION {
        return Err(ReceiverTelemetryWireError::UnsupportedVersion(version));
    }
    if input[6] != 0 || input[7] != 0 {
        return Err(ReceiverTelemetryWireError::NonzeroReserved);
    }
    let mut at = 8;
    let binding = ReceiverTelemetryBinding {
        process_id: read_u32(input, &mut at),
        session_id: read_u32(input, &mut at),
        worker_generation: read_u64(input, &mut at),
        control_session_id: read_u64(input, &mut at),
        request_id: read_u64(input, &mut at),
        presentation_id: read_u64(input, &mut at),
        stream_id: read_u32(input, &mut at),
        epoch: read_u32(input, &mut at),
        receiver_generation: read_u64(input, &mut at),
    };
    if !binding.is_valid() {
        return Err(ReceiverTelemetryWireError::InvalidBinding);
    }
    let sequence = read_u64(input, &mut at);
    if sequence == 0 {
        return Err(ReceiverTelemetryWireError::InvalidSequence);
    }
    let counters = ReceiverPlaybackCounters {
        authenticated_frames: read_u64(input, &mut at),
        rejected_frames: read_u64(input, &mut at),
        decoded_frames: read_u64(input, &mut at),
        presented_frames: read_u64(input, &mut at),
        present_errors: read_u64(input, &mut at),
        decode_errors: read_u64(input, &mut at),
        keyframe_waits: read_u64(input, &mut at),
        queue_drops: read_u64(input, &mut at),
    };
    debug_assert_eq!(at, RECEIVER_TELEMETRY_WIRE_LEN);
    Ok(ReceiverTelemetrySnapshot {
        binding,
        sequence,
        counters,
    })
}

/// A one-report slot for a future best-effort sender. Publishing only writes
/// memory and never blocks a decode/render thread on network/pipe I/O.
/// Actual sender integration must use independent nonblocking scheduling.
#[derive(Debug, Default)]
pub struct ReceiverTelemetryMailbox {
    active: Option<ReceiverTelemetryBinding>,
    last_sequence: Option<u64>,
    pending: Option<ReceiverTelemetrySnapshot>,
}

impl ReceiverTelemetryMailbox {
    pub fn activate(
        &mut self,
        binding: ReceiverTelemetryBinding,
    ) -> Result<(), ReceiverTelemetryWireError> {
        if !binding.is_valid() {
            return Err(ReceiverTelemetryWireError::InvalidBinding);
        }
        if self.active != Some(binding) {
            self.active = Some(binding);
            self.last_sequence = None;
            self.pending = None;
        }
        Ok(())
    }

    pub fn clear_if_matches(&mut self, binding: ReceiverTelemetryBinding) -> bool {
        if self.active != Some(binding) {
            return false;
        }
        self.active = None;
        self.last_sequence = None;
        self.pending = None;
        true
    }

    /// Returns whether an older unsent report was replaced, not a packet loss
    /// estimate. Never let an unverified report activate the binding itself.
    pub fn offer(
        &mut self,
        sample: ReceiverTelemetrySnapshot,
    ) -> Result<bool, ReceiverTelemetryWireError> {
        let Some(active) = self.active else {
            return Err(ReceiverTelemetryWireError::Inactive);
        };
        if sample.binding != active {
            return Err(ReceiverTelemetryWireError::BindingMismatch);
        }
        if sample.sequence == 0 {
            return Err(ReceiverTelemetryWireError::InvalidSequence);
        }
        if self
            .last_sequence
            .is_some_and(|last| sample.sequence <= last)
        {
            return Err(ReceiverTelemetryWireError::NonmonotonicSequence);
        }
        let replaced = self.pending.replace(sample).is_some();
        self.last_sequence = Some(sample.sequence);
        Ok(replaced)
    }

    /// A stale receiver cannot drain data from a new binding.
    pub fn take_matching(
        &mut self,
        binding: ReceiverTelemetryBinding,
    ) -> Option<ReceiverTelemetrySnapshot> {
        (self.active == Some(binding))
            .then(|| self.pending.take())
            .flatten()
    }
}

/// A nonblocking, constant-space producer/consumer handoff for later Worker
/// diagnostic IPC. The decode/render thread must NEVER wait on a mutex or pipe.
/// No sender or authenticated transport is introduced by this wrapper.
#[derive(Debug, Default)]
struct ReceiverTelemetryConcurrentState {
    mailbox: ReceiverTelemetryMailbox,
    // Strictly increasing on any new activation, even the same identity after
    // clear. Never reset on revocation or reuse after overflow.
    incarnation: u64,
}

/// A diagnostic sample checked out of the bounded mailbox for a *potential*
/// future sender. It is not a Worker credential or Service authorization.
#[derive(Debug, Clone)]
pub struct ReceiverTelemetrySendLease {
    report: ReceiverTelemetrySnapshot,
    incarnation: u64,
    // Weak lifetime pins the originating mailbox allocation identity, but
    // does not keep a revoked Worker state alive just for a queued report.
    owner: Weak<Mutex<ReceiverTelemetryConcurrentState>>,
}

impl PartialEq for ReceiverTelemetrySendLease {
    fn eq(&self, other: &Self) -> bool {
        self.report == other.report
            && self.incarnation == other.incarnation
            && Weak::ptr_eq(&self.owner, &other.owner)
    }
}

impl Eq for ReceiverTelemetrySendLease {}

impl ReceiverTelemetrySendLease {
    #[must_use]
    pub const fn snapshot(&self) -> ReceiverTelemetrySnapshot {
        self.report
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReceiverTelemetryConcurrentMailbox {
    state: Arc<Mutex<ReceiverTelemetryConcurrentState>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryConcurrentError {
    /// The consumer or lifecycle owner currently holds the bounded slot.
    Busy,
    /// A writer panic invalidated the slot; do not recover untrusted state.
    Poisoned,
    Wire(ReceiverTelemetryWireError),
}

impl ReceiverTelemetryConcurrentMailbox {
    fn try_access<R>(
        &self,
        access: impl FnOnce(
            &mut ReceiverTelemetryConcurrentState,
        ) -> Result<R, ReceiverTelemetryWireError>,
    ) -> Result<R, ReceiverTelemetryConcurrentError> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(ReceiverTelemetryConcurrentError::Busy),
            Err(TryLockError::Poisoned(_)) => {
                return Err(ReceiverTelemetryConcurrentError::Poisoned);
            }
        };
        access(&mut state).map_err(ReceiverTelemetryConcurrentError::Wire)
    }

    /// Only an independent trusted owner may activate an exact Worker binding;
    /// report bytes never acquire ownership of this slot.
    pub fn try_activate(
        &self,
        binding: ReceiverTelemetryBinding,
    ) -> Result<(), ReceiverTelemetryConcurrentError> {
        self.try_access(|state| {
            if !binding.is_valid() {
                return Err(ReceiverTelemetryWireError::InvalidBinding);
            }
            if state.mailbox.active != Some(binding) {
                let next = state
                    .incarnation
                    .checked_add(1)
                    .ok_or(ReceiverTelemetryWireError::LifecycleExhausted)?;
                state.mailbox.activate(binding)?;
                state.incarnation = next;
            }
            Ok(())
        })
    }

    /// Publish by copy only, without waiting for a pipe, blocking lock or
    /// consumer. `true` means an older unsent sample was replaced, not loss.
    pub fn try_offer(
        &self,
        report: ReceiverTelemetrySnapshot,
    ) -> Result<bool, ReceiverTelemetryConcurrentError> {
        self.try_access(|state| state.mailbox.offer(report))
    }

    /// Remove an exact binding without revoking a newer replacement.
    pub fn try_clear_if_matches(
        &self,
        binding: ReceiverTelemetryBinding,
    ) -> Result<bool, ReceiverTelemetryConcurrentError> {
        self.try_access(|state| Ok(state.mailbox.clear_if_matches(binding)))
    }

    /// Check out the latest report for a hypothetical asynchronous sender.
    /// The lease tracks the exact incarnation as well as the report sequence;
    /// it MUST be checked again before future I/O outside this lock.
    pub fn try_checkout_matching(
        &self,
        binding: ReceiverTelemetryBinding,
    ) -> Result<Option<ReceiverTelemetrySendLease>, ReceiverTelemetryConcurrentError> {
        let owner = Arc::downgrade(&self.state);
        self.try_access(|state| {
            Ok(state
                .mailbox
                .take_matching(binding)
                .map(|report| ReceiverTelemetrySendLease {
                    report,
                    incarnation: state.incarnation,
                    owner,
                }))
        })
    }

    /// Short, nonblocking local invalidation check. A clear+reactivate of the
    /// SAME binding rejects the old lease (no ABA); a newer offered sample
    /// also invalidates the old checkout. This is NOT atomic with I/O and is
    /// NOT authentication. Future senders must additionally recheck the real
    /// authenticated Worker+receiver authority at the transport boundary.
    pub fn try_lease_is_current(
        &self,
        lease: &ReceiverTelemetrySendLease,
    ) -> Result<bool, ReceiverTelemetryConcurrentError> {
        // Another mailbox can have the same binding, incarnation and sequence.
        // Reject that lookalike before consulting local state.
        if !Weak::ptr_eq(&lease.owner, &Arc::downgrade(&self.state)) {
            return Ok(false);
        }
        self.try_access(|state| {
            Ok(state.mailbox.active == Some(lease.report.binding)
                && state.incarnation == lease.incarnation
                && state.mailbox.last_sequence == Some(lease.report.sequence))
        })
    }
}

#[cfg(test)]
mod concurrent_mailbox_tests {
    use super::*;

    fn binding(epoch: u32) -> ReceiverTelemetryBinding {
        ReceiverTelemetryBinding {
            process_id: 101,
            session_id: 102,
            worker_generation: 103,
            control_session_id: 104,
            request_id: 105,
            presentation_id: 106,
            stream_id: 107,
            epoch,
            receiver_generation: 108,
        }
    }

    fn snapshot(epoch: u32, sequence: u64) -> ReceiverTelemetrySnapshot {
        ReceiverTelemetrySnapshot {
            binding: binding(epoch),
            sequence,
            counters: ReceiverPlaybackCounters::default(),
        }
    }

    fn drain(
        mail: &ReceiverTelemetryConcurrentMailbox,
        binding: ReceiverTelemetryBinding,
    ) -> Result<Option<ReceiverTelemetrySnapshot>, ReceiverTelemetryConcurrentError> {
        mail.try_checkout_matching(binding)
            .map(|lease| lease.map(|value| value.snapshot()))
    }

    #[test]
    fn try_lock_publisher_coalesces_ten_thousand_reports_in_one_slot() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        for seq in 1..=10_000 {
            assert_eq!(mail.try_offer(snapshot(1, seq)), Ok(seq != 1));
        }
        assert_eq!(drain(&mail, binding(1)), Ok(Some(snapshot(1, 10_000))));
        assert_eq!(drain(&mail, binding(1)), Ok(None));
    }

    #[test]
    fn worker_try_offer_and_sender_try_take_never_wait_on_held_lock() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        let guard = mail.state.lock().unwrap();
        assert_eq!(
            mail.try_offer(snapshot(1, 1)),
            Err(ReceiverTelemetryConcurrentError::Busy)
        );
        assert_eq!(
            drain(&mail, binding(1)),
            Err(ReceiverTelemetryConcurrentError::Busy)
        );
        assert_eq!(
            mail.try_clear_if_matches(binding(1)),
            Err(ReceiverTelemetryConcurrentError::Busy)
        );
        drop(guard);
        assert_eq!(mail.try_offer(snapshot(1, 1)), Ok(false));
    }

    #[test]
    fn poisoned_shared_mailbox_fails_closed_instead_of_unwinding_worker() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        let clone = mail.clone();
        assert!(
            std::thread::spawn(move || {
                let _hold = clone.state.lock().unwrap();
                panic!("intentional locked thread failure");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            mail.try_offer(snapshot(1, 1)),
            Err(ReceiverTelemetryConcurrentError::Poisoned)
        );
        assert_eq!(
            drain(&mail, binding(1)),
            Err(ReceiverTelemetryConcurrentError::Poisoned)
        );
    }

    #[test]
    fn sender_thread_detects_revocation_and_same_identity_aba_after_checkout() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        mail.try_offer(snapshot(1, 1)).unwrap();

        let sender = mail.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let lease = sender.try_checkout_matching(binding(1)).unwrap().unwrap();
            ready_tx.send(lease.snapshot()).unwrap();
            resume_rx.recv().unwrap();
            sender.try_lease_is_current(&lease)
        });
        assert_eq!(ready_rx.recv().unwrap(), snapshot(1, 1));
        assert_eq!(mail.try_clear_if_matches(binding(1)), Ok(true));
        mail.try_activate(binding(1)).unwrap();
        mail.try_offer(snapshot(1, 1)).unwrap();
        resume_tx.send(()).unwrap();
        assert_eq!(task.join().unwrap(), Ok(false));
        let fresh = mail.try_checkout_matching(binding(1)).unwrap().unwrap();
        assert_eq!(mail.try_lease_is_current(&fresh), Ok(true));
    }

    #[test]
    fn checked_out_lease_does_not_keep_abandoned_mailbox_alive() {
        let lease = {
            let mail = ReceiverTelemetryConcurrentMailbox::default();
            mail.try_activate(binding(1)).unwrap();
            mail.try_offer(snapshot(1, 1)).unwrap();
            mail.try_checkout_matching(binding(1)).unwrap().unwrap()
        };
        assert!(lease.owner.upgrade().is_none());
        let replacement = ReceiverTelemetryConcurrentMailbox::default();
        replacement.try_activate(binding(1)).unwrap();
        replacement.try_offer(snapshot(1, 1)).unwrap();
        assert_eq!(replacement.try_lease_is_current(&lease), Ok(false));
    }

    #[test]
    fn identical_mailbox_identities_are_not_interchangeable_across_instances() {
        let first = ReceiverTelemetryConcurrentMailbox::default();
        let second = ReceiverTelemetryConcurrentMailbox::default();
        for mail in [&first, &second] {
            mail.try_activate(binding(1)).unwrap();
            mail.try_offer(snapshot(1, 1)).unwrap();
        }
        let lease = first.try_checkout_matching(binding(1)).unwrap().unwrap();
        assert_eq!(first.try_lease_is_current(&lease), Ok(true));
        assert_eq!(first.clone().try_lease_is_current(&lease), Ok(true));
        assert_eq!(second.try_lease_is_current(&lease), Ok(false));
    }

    #[test]
    fn checked_out_sample_is_revoked_on_exact_clear_and_same_binding_reactivation() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        mail.try_offer(snapshot(1, 1)).unwrap();
        let prior = mail.try_checkout_matching(binding(1)).unwrap().unwrap();
        assert_eq!(prior.snapshot(), snapshot(1, 1));
        assert_eq!(mail.try_lease_is_current(&prior), Ok(true));
        assert_eq!(mail.try_clear_if_matches(binding(1)), Ok(true));
        assert_eq!(mail.try_lease_is_current(&prior), Ok(false));
        mail.try_activate(binding(1)).unwrap();
        mail.try_offer(snapshot(1, 1)).unwrap();
        assert_eq!(mail.try_lease_is_current(&prior), Ok(false));
        let fresh = mail.try_checkout_matching(binding(1)).unwrap().unwrap();
        assert_eq!(fresh.snapshot(), prior.snapshot());
        assert_ne!(
            fresh, prior,
            "same binding and sequence must not resurrect a revoked lease"
        );
        assert_eq!(mail.try_lease_is_current(&fresh), Ok(true));
    }

    #[test]
    fn old_send_lease_is_invalidated_by_any_newer_coalesced_sample() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        mail.try_offer(snapshot(1, 1)).unwrap();
        let prior = mail.try_checkout_matching(binding(1)).unwrap().unwrap();
        mail.try_activate(binding(1)).unwrap();
        assert_eq!(
            mail.try_lease_is_current(&prior),
            Ok(true),
            "identical activation is not revocation"
        );
        assert_eq!(mail.try_offer(snapshot(1, 2)), Ok(false));
        assert_eq!(mail.try_lease_is_current(&prior), Ok(false));
        let newer = mail.try_checkout_matching(binding(1)).unwrap().unwrap();
        assert_eq!(newer.snapshot(), snapshot(1, 2));
        assert_eq!(mail.try_lease_is_current(&newer), Ok(true));
        assert_eq!(
            mail.try_offer(snapshot(1, 1)),
            Err(ReceiverTelemetryConcurrentError::Wire(
                ReceiverTelemetryWireError::NonmonotonicSequence
            ))
        );
    }

    #[test]
    fn lease_validation_is_nonblocking_and_fails_closed_if_lock_is_poisoned() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        mail.try_offer(snapshot(1, 1)).unwrap();
        let lease = mail.try_checkout_matching(binding(1)).unwrap().unwrap();
        let clone = mail.clone();
        let guard = mail.state.lock().unwrap();
        assert_eq!(
            clone.try_lease_is_current(&lease),
            Err(ReceiverTelemetryConcurrentError::Busy)
        );
        drop(guard);
        assert_eq!(clone.try_lease_is_current(&lease), Ok(true));
        assert!(
            std::thread::spawn(move || {
                let _guard = clone.state.lock().unwrap();
                panic!("intentional poison");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            mail.try_lease_is_current(&lease),
            Err(ReceiverTelemetryConcurrentError::Poisoned)
        );
    }

    #[test]
    fn exhausted_lease_incarnation_rejects_reactivation_without_overflow() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        mail.state.lock().unwrap().incarnation = u64::MAX;
        assert_eq!(mail.try_clear_if_matches(binding(1)), Ok(true));
        assert_eq!(
            mail.try_activate(binding(1)),
            Err(ReceiverTelemetryConcurrentError::Wire(
                ReceiverTelemetryWireError::LifecycleExhausted
            ))
        );
        assert_eq!(
            mail.try_offer(snapshot(1, 1)),
            Err(ReceiverTelemetryConcurrentError::Wire(
                ReceiverTelemetryWireError::Inactive
            ))
        );
    }

    #[test]
    fn replaced_binding_cannot_drain_or_revoke_new_epoch() {
        let mail = ReceiverTelemetryConcurrentMailbox::default();
        mail.try_activate(binding(1)).unwrap();
        mail.try_offer(snapshot(1, 1)).unwrap();
        mail.try_activate(binding(2)).unwrap();
        assert_eq!(mail.try_clear_if_matches(binding(1)), Ok(false));
        assert_eq!(drain(&mail, binding(1)), Ok(None));
        assert_eq!(
            mail.try_offer(snapshot(1, 2)),
            Err(ReceiverTelemetryConcurrentError::Wire(
                ReceiverTelemetryWireError::BindingMismatch
            ))
        );
        assert_eq!(mail.try_offer(snapshot(2, 1)), Ok(false));
        assert_eq!(drain(&mail, binding(2)), Ok(Some(snapshot(2, 1))));
    }
}
