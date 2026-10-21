//! Bounded, fixed-width framing for a future authenticated Worker -> Service
//! telemetry Named Pipe byte stream.
//!
//! A real pipe read may split or combine fixed 136-byte diagnostics. This
//! passive parser preserves no more than one partial frame and accepts at most
//! four complete-frame-worths of bytes per read. It does NOT authenticate a
//! pipe client, bind the Service runtime, or authorize report admission.
//! Callers must separately verify the OS peer and the current Worker/receiver
//! lifetime, then pass each decoded report through the Service admission gate.
use std::time::{Duration, Instant};

use crate::receiver_telemetry::{ReceiverTelemetryBinding, ReceiverTelemetrySnapshot};
use crate::receiver_telemetry_transport::{
    RECEIVER_TELEMETRY_WIRE_LEN, ReceiverTelemetryWireError, decode_receiver_telemetry,
};

/// No arbitrarily long read/coalescing allocation or unbounded backlog.
pub const MAX_RECEIVER_TELEMETRY_READ_BYTES: usize = RECEIVER_TELEMETRY_WIRE_LEN * 4;

/// A fragmented diagnostic must complete promptly from the first Service
/// receive timestamp; later chunks never extend this fixed deadline.
pub const MAX_RECEIVER_TELEMETRY_PARTIAL_AGE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryFrameStreamError {
    InvalidBinding,
    Inactive,
    WrongServiceOwner,
    Disconnected,
    OversizedRead,
    PartialTimedOut,
    PartialClockRegression,
    MixedClockModes,
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
    pending_started_at: Option<Instant>,
}

impl Default for ReceiverTelemetryFrameStream {
    fn default() -> Self {
        Self {
            active: None,
            pending: [0; RECEIVER_TELEMETRY_WIRE_LEN],
            pending_len: 0,
            pending_started_at: None,
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

    /// Enforce a finite partial-frame deadline even when no further bytes
    /// arrive. The privileged Service must schedule this from its OWN clock,
    /// independently of the Worker or data read loop.
    pub fn expire_partial_after_verified_owner(
        &mut self,
        service_current_owner: ReceiverTelemetryBinding,
        service_now: Instant,
    ) -> Result<(), ReceiverTelemetryFrameStreamError> {
        self.verify_owner(service_current_owner)?;
        if self.pending_len == 0 {
            return Ok(());
        }
        let Some(since) = self.pending_started_at else {
            self.deactivate();
            return Err(ReceiverTelemetryFrameStreamError::MixedClockModes);
        };
        if service_now < since {
            self.deactivate();
            return Err(ReceiverTelemetryFrameStreamError::PartialClockRegression);
        }
        if service_now.duration_since(since) > MAX_RECEIVER_TELEMETRY_PARTIAL_AGE {
            self.deactivate();
            return Err(ReceiverTelemetryFrameStreamError::PartialTimedOut);
        }
        Ok(())
    }

    /// Service-monotonic timestamped read, with an absolute partial deadline
    /// measured from the FIRST fragment. A different complete frame after an
    /// earlier completion receives its own first-fragment timestamp.
    pub fn accept_verified_at(
        &mut self,
        service_current_owner: ReceiverTelemetryBinding,
        bytes: &[u8],
        service_received_at: Instant,
    ) -> Result<Vec<ReceiverTelemetrySnapshot>, ReceiverTelemetryFrameStreamError> {
        self.expire_partial_after_verified_owner(service_current_owner, service_received_at)?;
        self.accept_verified_inner(service_current_owner, bytes, Some(service_received_at))
    }

    /// Legacy untimed pure parsing for test harnesses only. Production Service
    /// code MUST use accept_verified_at + periodic expiry from its own clock.
    /// It cannot splice fresh untimed data into a timestamped partial record.
    ///
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
        self.verify_owner(service_current_owner)?;
        if self.pending_started_at.is_some() {
            self.deactivate();
            return Err(ReceiverTelemetryFrameStreamError::MixedClockModes);
        }
        self.accept_verified_inner(service_current_owner, bytes, None)
    }

    fn verify_owner(
        &self,
        service_current_owner: ReceiverTelemetryBinding,
    ) -> Result<ReceiverTelemetryBinding, ReceiverTelemetryFrameStreamError> {
        let Some(active) = self.active else {
            return Err(ReceiverTelemetryFrameStreamError::Inactive);
        };
        if active != service_current_owner {
            return Err(ReceiverTelemetryFrameStreamError::WrongServiceOwner);
        }
        Ok(active)
    }

    fn accept_verified_inner(
        &mut self,
        service_current_owner: ReceiverTelemetryBinding,
        bytes: &[u8],
        service_received_at: Option<Instant>,
    ) -> Result<Vec<ReceiverTelemetrySnapshot>, ReceiverTelemetryFrameStreamError> {
        let active = self.verify_owner(service_current_owner)?;
        if self.pending_len > 0
            && self.pending_started_at.is_none()
            && service_received_at.is_some()
        {
            self.deactivate();
            return Err(ReceiverTelemetryFrameStreamError::MixedClockModes);
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
            if self.pending_len == 0 {
                self.pending_started_at = service_received_at;
            }
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
        self.pending_started_at = None;
    }
}
