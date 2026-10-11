//! Inactive future-v12 Service-side sensitive clipboard response inbox.
//! All chunks are wiped in-place; stored bytes are bounded/zeroizing. This
//! module does not replace or modify the active v11 generic IPC Service pipe.
use zeroize::Zeroize;

use super::clipboard_read_gate::{
    SENSITIVE_CLIPBOARD_READ_DEADLINE_MS, SensitiveClipboardReadAcceptanceGate,
    SensitiveReadAcceptError,
};
use super::clipboard_read_stream::{ClipboardStreamError, SensitiveClipboardReadStream};
use super::clipboard_read_success::{ClipboardReadSuccessBinding, SensitiveClipboardReadSuccess};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveInboxError {
    ClockRegression,
    Expired,
    Finished,
    Stream(ClipboardStreamError),
    Acceptance(SensitiveReadAcceptError),
}

/// Single authorized pending Worker clipboard response. Fails closed on every
/// error, timeout, cancellation, Worker replacement or replay.
#[derive(Debug)]
pub struct SensitiveClipboardReadInbox {
    gate: SensitiveClipboardReadAcceptanceGate,
    stream: SensitiveClipboardReadStream,
    started_at_ms: u64,
    expires_at_ms: u64,
    closed: bool,
}

impl SensitiveClipboardReadInbox {
    pub fn new(
        expected: ClipboardReadSuccessBinding,
        now_ms: u64,
    ) -> Result<Self, SensitiveReadAcceptError> {
        let gate = SensitiveClipboardReadAcceptanceGate::new(expected, now_ms)?;
        let expires_at_ms = now_ms
            .checked_add(SENSITIVE_CLIPBOARD_READ_DEADLINE_MS)
            .ok_or(SensitiveReadAcceptError::ClockOverflow)?;
        Ok(Self {
            gate,
            stream: SensitiveClipboardReadStream::default(),
            started_at_ms: now_ms,
            expires_at_ms,
            closed: false,
        })
    }

    /// Drop the buffered sensitive frame *now*, not only on object drop.
    /// The caller must invoke this on control disconnect/permission revocation
    /// and when the active Worker incarnation changes.
    pub fn cancel(&mut self) -> bool {
        if self.closed {
            return false;
        }
        self.closed = true;
        self.gate.cancel();
        self.stream = SensitiveClipboardReadStream::default();
        true
    }

    /// Sweep the single-flight deadline even when no new pipe bytes arrive.
    /// The caller should invoke this from its Worker/Service lifecycle tick.
    pub fn expire(&mut self, now_ms: u64) -> bool {
        if self.closed {
            return false;
        }
        if now_ms < self.started_at_ms || now_ms >= self.expires_at_ms {
            return self.cancel();
        }
        false
    }

    /// Each incoming piece is erased even on early timeout, invalid state,
    /// malformed header or unknown/replaced Worker identity.
    pub fn push_chunk(
        &mut self,
        incoming: &mut [u8],
        now_ms: u64,
    ) -> Result<Option<SensitiveClipboardReadSuccess>, SensitiveInboxError> {
        if self.closed {
            incoming.zeroize();
            return Err(SensitiveInboxError::Finished);
        }
        if now_ms < self.started_at_ms {
            incoming.zeroize();
            self.cancel();
            return Err(SensitiveInboxError::ClockRegression);
        }
        if now_ms >= self.expires_at_ms {
            incoming.zeroize();
            self.cancel();
            return Err(SensitiveInboxError::Expired);
        }

        match self.stream.push_bytes(incoming) {
            Ok(None) => Ok(None),
            Ok(Some(payload)) => {
                self.closed = true;
                // On both success and rejection, this is a one-shot receiver.
                // The gate drops mismatched clipboard text without logging.
                let result = self.gate.accept(payload, now_ms);
                if result.is_err() {
                    self.gate.cancel();
                }
                result.map(Some).map_err(SensitiveInboxError::Acceptance)
            }
            Err(err) => {
                self.cancel();
                Err(SensitiveInboxError::Stream(err))
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc_sensitive::{
        ClipboardReadSuccessBinding, SensitiveClipboardReadSuccess,
        encode_sensitive_clipboard_read_frame,
    };
    use zeroize::Zeroizing;

    fn binding() -> ClipboardReadSuccessBinding {
        ClipboardReadSuccessBinding {
            worker_process_id: 42,
            worker_session_id: 7,
            worker_generation: 4,
            control_session_id: 77,
            control_sequence: 101,
            request_id: 19,
        }
    }

    fn frame(identity: ClipboardReadSuccessBinding) -> Zeroizing<Vec<u8>> {
        let secret = SensitiveClipboardReadSuccess::new(
            identity,
            Zeroizing::new("مرحبا 🌙".as_bytes().to_vec()),
        )
        .expect("valid test clipboard");
        encode_sensitive_clipboard_read_frame(&secret)
    }

    #[test]
    fn fragmented_bound_unicode_returns_exactly_one_secret_and_erases_input() {
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100).expect("registered");
        let mut wire = frame(binding());
        assert!(
            inbox
                .push_chunk(&mut wire[..8], 101)
                .expect("header part")
                .is_none()
        );
        assert!(
            inbox
                .push_chunk(&mut wire[8..12], 102)
                .expect("header")
                .is_none()
        );
        let result = inbox
            .push_chunk(&mut wire[12..], 103)
            .expect("current bound result")
            .expect("complete");
        assert_eq!(result.text(), "مرحبا 🌙");
        assert!(wire.iter().all(|b| *b == 0));
        assert!(!format!("{inbox:?}").contains("مرحبا"));
        let mut extra = [2_u8; 5];
        assert_eq!(
            inbox.push_chunk(&mut extra, 104).err(),
            Some(SensitiveInboxError::Finished)
        );
        assert_eq!(extra, [0_u8; 5]);
    }

    #[test]
    fn substituted_worker_generation_is_rejected_and_closes_inbox() {
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100).expect("registered");
        let mut wire = frame(ClipboardReadSuccessBinding {
            worker_generation: binding().worker_generation + 1,
            ..binding()
        });
        assert_eq!(
            inbox.push_chunk(&mut wire, 101).err(),
            Some(SensitiveInboxError::Acceptance(
                SensitiveReadAcceptError::Mismatch
            )),
        );
        assert!(wire.iter().all(|b| *b == 0));
        let mut correct = frame(binding());
        assert_eq!(
            inbox.push_chunk(&mut correct, 102).err(),
            Some(SensitiveInboxError::Finished)
        );
        assert!(correct.iter().all(|b| *b == 0));
    }

    #[test]
    fn timeout_between_fragments_closes_and_wipes_late_input() {
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100).expect("registered");
        let mut wire = frame(binding());
        assert!(
            inbox
                .push_chunk(&mut wire[..8], 101)
                .expect("partial")
                .is_none()
        );
        let boundary = 100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS;
        assert_eq!(
            inbox.push_chunk(&mut wire[8..], boundary).err(),
            Some(SensitiveInboxError::Expired)
        );
        assert!(wire.iter().all(|b| *b == 0));
    }

    #[test]
    fn malformed_header_and_clock_regression_close_pending_authority() {
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100).expect("registered");
        let mut wire = frame(binding());
        wire[0] = 0;
        assert!(matches!(
            inbox.push_chunk(&mut wire, 101),
            Err(SensitiveInboxError::Stream(_))
        ));
        assert!(wire.iter().all(|b| *b == 0));
        let mut fresh = SensitiveClipboardReadInbox::new(binding(), 100).expect("registered");
        let mut chunk = [1_u8; 4];
        assert_eq!(
            fresh.push_chunk(&mut chunk, 99).err(),
            Some(SensitiveInboxError::ClockRegression)
        );
        assert_eq!(chunk, [0; 4]);
    }

    #[test]
    fn idle_timeout_without_new_data_revokes_pending_authority() {
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100).expect("registered");
        let mut wire = frame(binding());
        assert!(
            inbox
                .push_chunk(&mut wire[..8], 101)
                .expect("partial")
                .is_none()
        );
        assert!(!inbox.expire(100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS - 1));
        assert!(inbox.expire(100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS));
        assert!(!inbox.expire(100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS + 1));
        assert_eq!(
            inbox.push_chunk(&mut wire[8..], 9999).err(),
            Some(SensitiveInboxError::Finished)
        );
        assert!(wire.iter().all(|b| *b == 0));
    }

    #[test]
    fn cancellation_during_partial_frame_fails_closed() {
        let mut inbox = SensitiveClipboardReadInbox::new(binding(), 100).expect("registered");
        let mut wire = frame(binding());
        assert!(
            inbox
                .push_chunk(&mut wire[..16], 101)
                .expect("partial")
                .is_none()
        );
        assert!(inbox.cancel());
        assert!(!inbox.cancel());
        assert_eq!(
            inbox.push_chunk(&mut wire[16..], 102).err(),
            Some(SensitiveInboxError::Finished)
        );
        assert!(wire.iter().all(|b| *b == 0));
    }
}
