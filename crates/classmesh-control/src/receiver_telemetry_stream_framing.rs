//! Bounded, fixed-width framing for a future authenticated Worker -> Service
//! telemetry Named Pipe byte stream.
//!
//! A real pipe read may split or combine fixed 136-byte diagnostics. This
//! passive parser preserves no more than one partial frame and accepts at most
//! four complete-frame-worths of bytes per read. It does NOT authenticate a
//! pipe client, bind the Service runtime, or authorize report admission.
//! Callers must separately verify the OS peer and the current Worker/receiver
//! lifetime, then pass each decoded report through the Service admission gate.
use crate::receiver_telemetry::{ReceiverTelemetryBinding, ReceiverTelemetrySnapshot};
use crate::receiver_telemetry_transport::{
    RECEIVER_TELEMETRY_WIRE_LEN, ReceiverTelemetryWireError, decode_receiver_telemetry,
};

/// No arbitrarily long read/coalescing allocation or unbounded backlog.
pub const MAX_RECEIVER_TELEMETRY_READ_BYTES: usize = RECEIVER_TELEMETRY_WIRE_LEN * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryFrameStreamError {
    InvalidBinding,
    Inactive,
    WrongServiceOwner,
    Disconnected,
    OversizedRead,
    ReportBindingMismatch,
    Wire(ReceiverTelemetryWireError),
}

/// A single independently verified Service-owned receiver and up to one
/// incomplete diagnostic. The caller must serialize activation and read
/// processing with Service peer revocation and key/runtime changes.
#[derive(Debug)]
pub struct ReceiverTelemetryFrameStream {
    active: Option<ReceiverTelemetryBinding>,
    pending: [u8; RECEIVER_TELEMETRY_WIRE_LEN],
    pending_len: usize,
}

impl Default for ReceiverTelemetryFrameStream {
    fn default() -> Self {
        Self {
            active: None,
            pending: [0; RECEIVER_TELEMETRY_WIRE_LEN],
            pending_len: 0,
        }
    }
}

impl ReceiverTelemetryFrameStream {
    /// The trusted Service, never the incoming bytes, activates the exact
    /// authorized runtime after separately checking the authenticated peer.
    pub fn activate_verified(
        &mut self,
        binding: ReceiverTelemetryBinding,
    ) -> Result<(), ReceiverTelemetryFrameStreamError> {
        if !binding.is_valid() {
            return Err(ReceiverTelemetryFrameStreamError::InvalidBinding);
        }
        if self.active != Some(binding) {
            self.reset_pending();
            self.active = Some(binding);
        }
        Ok(())
    }

    /// A delayed teardown of an older session must not revoke its successor.
    pub fn clear_if_matches(&mut self, binding: ReceiverTelemetryBinding) -> bool {
        if self.active != Some(binding) {
            return false;
        }
        self.deactivate();
        true
    }

    /// Consume one actual bounded pipe read. A zero-length read represents
    /// disconnect. Wrong Service ownership fails without consuming a pending
    /// frame; other framing/wire errors invalidate this connection entirely.
    ///
    /// Reports returned here are **not authenticated or admitted**: pipe peer
    /// identity and live Service lifecycle must be verified independently.
    /// A whole batch fails atomically if any constituent frame is malformed.
    pub fn accept_verified(
        &mut self,
        service_current_owner: ReceiverTelemetryBinding,
        bytes: &[u8],
    ) -> Result<Vec<ReceiverTelemetrySnapshot>, ReceiverTelemetryFrameStreamError> {
        let Some(active) = self.active else {
            return Err(ReceiverTelemetryFrameStreamError::Inactive);
        };
        if active != service_current_owner {
            return Err(ReceiverTelemetryFrameStreamError::WrongServiceOwner);
        }
        if bytes.is_empty() {
            self.deactivate();
            return Err(ReceiverTelemetryFrameStreamError::Disconnected);
        }
        if bytes.len() > MAX_RECEIVER_TELEMETRY_READ_BYTES {
            self.deactivate();
            return Err(ReceiverTelemetryFrameStreamError::OversizedRead);
        }

        let mut reports = Vec::with_capacity(4);
        for &byte in bytes {
            self.pending[self.pending_len] = byte;
            self.pending_len += 1;
            if self.pending_len == RECEIVER_TELEMETRY_WIRE_LEN {
                let report = match decode_receiver_telemetry(&self.pending) {
                    Ok(report) => report,
                    Err(error) => {
                        self.deactivate();
                        return Err(ReceiverTelemetryFrameStreamError::Wire(error));
                    }
                };
                if report.binding != active {
                    self.deactivate();
                    return Err(ReceiverTelemetryFrameStreamError::ReportBindingMismatch);
                }
                reports.push(report);
                self.reset_pending();
            }
        }
        Ok(reports)
    }

    fn deactivate(&mut self) {
        self.active = None;
        self.reset_pending();
    }

    fn reset_pending(&mut self) {
        self.pending[..self.pending_len].fill(0);
        self.pending_len = 0;
    }
}
