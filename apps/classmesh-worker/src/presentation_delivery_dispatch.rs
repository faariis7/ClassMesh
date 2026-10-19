//! One-shot, best-effort Worker diagnostic dispatch seam, deliberately OFF by
//! default. No sender thread, pipe connection, I/O, privilege or IPC type is
//! introduced here. The caller MUST separately authenticate its live Windows
//! Service peer and verify its active receiver/Worker generation before every
//! call and again at the transport I/O boundary.
//!
//! The callback named `verify_current_service_peer` is an injected trusted
//! decision; supplying `|_| true` does NOT create OS authentication.
//! `try_send_nonblocking` MUST attempt a complete fixed-size frame without
//! blocking, queuing unbounded data or retrying. This portable function cannot
//! enforce OS handle flags and is NOT activated in the production Worker.
//! The checks are necessarily non-atomic with actual I/O: the privileged
//! Service MUST also reject stale/unauthorized telemetry upon arrival.

use classmesh_control::receiver_telemetry::ReceiverTelemetryBinding;
use classmesh_control::receiver_telemetry_transport::{
    RECEIVER_TELEMETRY_WIRE_LEN, ReceiverTelemetryConcurrentError, ReceiverTelemetryWireError,
    encode_receiver_telemetry,
};

use crate::presentation_delivery_publisher::PresentationDeliveryReadonlySender;

/// A sink must attempt only a complete, nonblocking frame; partial writes
/// are discarded, never resumed on the media/control thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryTryWriteError {
    WouldBlock,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryDispatchOutcome {
    /// Nothing checked out; new future samples are still eligible.
    NoReport,
    /// Service authority unavailable before checkout or changed before send.
    UnverifiedPeer,
    /// Lease expired or was superseded/revoked after checkout.
    StaleLease,
    /// Another local thread held the one-slot mutex; no waiting.
    Busy,
    /// Poisoned mailbox is unusable; fail closed.
    Poisoned,
    /// Local producer state or fixed frame validation failed.
    InvalidFrame(ReceiverTelemetryWireError),
    /// Report discarded after a *single* nonblocking attempt.
    DroppedBackpressure,
    DroppedDisconnected,
    /// Sink accepted exactly one fixed-size frame.
    Sent,
}

/// Attempt at most one Worker-local diagnostic frame outside the decode/render
/// and control loops. This performs *no* OS authentication or transport wiring.
///
/// The caller must inject independently authenticated, live Service ownership,
/// including Worker process/session/generation, key epoch and exact receiver
/// incarnation. The closure must NOT derive its answer from Worker-supplied
/// telemetry bytes. It is called before dequeue and again immediately before
/// local lease validation and the injected one-shot nonblocking write.
///
/// Dropping on backpressure is deliberate: there is no retry queue, sleep,
/// sender thread or blocking operation. A newer producer sample may replace
/// the discarded report. Even a successful local check cannot prevent a
/// revocation racing with I/O: Service-side admission remains mandatory.
pub fn try_dispatch_once<V, W>(
    sender: &PresentationDeliveryReadonlySender,
    receiver: ReceiverTelemetryBinding,
    mut verify_current_service_peer: V,
    mut try_send_nonblocking: W,
) -> TelemetryDispatchOutcome
where
    V: FnMut(ReceiverTelemetryBinding) -> bool,
    W: FnMut(&[u8; RECEIVER_TELEMETRY_WIRE_LEN]) -> Result<(), TelemetryTryWriteError>,
{
    if !receiver.is_valid() || !verify_current_service_peer(receiver) {
        return TelemetryDispatchOutcome::UnverifiedPeer;
    }

    let lease = match sender.try_checkout_matching(receiver) {
        Ok(Some(lease)) => lease,
        Ok(None) => return TelemetryDispatchOutcome::NoReport,
        Err(ReceiverTelemetryConcurrentError::Busy) => return TelemetryDispatchOutcome::Busy,
        Err(ReceiverTelemetryConcurrentError::Poisoned) => {
            return TelemetryDispatchOutcome::Poisoned;
        }
        Err(ReceiverTelemetryConcurrentError::Wire(e)) => {
            return TelemetryDispatchOutcome::InvalidFrame(e);
        }
    };
    let frame = match encode_receiver_telemetry(&lease.snapshot()) {
        Ok(frame) => frame,
        Err(e) => return TelemetryDispatchOutcome::InvalidFrame(e),
    };
    if !verify_current_service_peer(receiver) {
        return TelemetryDispatchOutcome::UnverifiedPeer;
    }
    match sender.lease_is_current(&lease) {
        Ok(true) => {}
        Ok(false) => return TelemetryDispatchOutcome::StaleLease,
        Err(ReceiverTelemetryConcurrentError::Busy) => return TelemetryDispatchOutcome::Busy,
        Err(ReceiverTelemetryConcurrentError::Poisoned) => {
            return TelemetryDispatchOutcome::Poisoned;
        }
        Err(ReceiverTelemetryConcurrentError::Wire(e)) => {
            return TelemetryDispatchOutcome::InvalidFrame(e);
        }
    }
    match try_send_nonblocking(&frame) {
        Ok(()) => TelemetryDispatchOutcome::Sent,
        Err(TelemetryTryWriteError::WouldBlock) => TelemetryDispatchOutcome::DroppedBackpressure,
        Err(TelemetryTryWriteError::Disconnected) => TelemetryDispatchOutcome::DroppedDisconnected,
    }
}
