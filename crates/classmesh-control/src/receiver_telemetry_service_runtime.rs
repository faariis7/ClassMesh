//! Service-owned protected key confirmation and passive receiver telemetry lifetime.
//!
//! This is a pure, **in-process** Service state machine, NOT a peer authenticator,
//! IPC channel or source of RTT/loss/2s adaptive metrics. The Service must
//! independently authenticate the Windows pipe peer, own the authorized grant,
//! and serialize Worker/key/receiver lifecycle changes with admission.
//! No Worker report bytes may provide the active key or receiver generation.

use std::time::Instant;

use crate::receiver_telemetry::{ReceiverTelemetryBinding, ReceiverTelemetryDecision};
use crate::receiver_telemetry_service_admission::{
    ReceiverTelemetryServiceAdmission, ReceiverTelemetryServiceAdmissionError,
};
use crate::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryServiceLifecycleError, ReceiverTelemetryStart,
    ReceiverTelemetryStartAck,
};
use crate::receiver_telemetry_stream_framing::{
    ReceiverTelemetryFrameStream, ReceiverTelemetryFrameStreamError,
};
use crate::receiver_telemetry_transport::encode_receiver_telemetry;

/// The exact authorized protected key grant, copied from a Service-owned
/// committed grant and confirmed by its independently correlated Worker ACK.
/// The grant request ID is distinct from the later media start request ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverTelemetryAuthorizedKey {
    pub control_session_id: u64,
    pub key_grant_request_id: u64,
    pub presentation_id: u64,
    pub stream_id: u32,
    pub epoch: u32,
}

impl ReceiverTelemetryAuthorizedKey {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.control_session_id != 0
            && self.key_grant_request_id != 0
            && self.presentation_id != 0
            && self.stream_id != 0
            && self.epoch != 0
    }

    #[must_use]
    pub const fn matches_start(self, start: ReceiverTelemetryStart) -> bool {
        self.control_session_id == start.control_session_id
            && self.presentation_id == start.presentation_id
            && self.stream_id == start.stream_id
            && self.epoch == start.epoch
    }
}

/// Exact Worker receiver grant issued only by this Service-owned state
/// machine after a separately correlated protected key install and media
/// receiver start. Immutable private fields avoid casual construction by
/// other crates; it is **not** a cryptographic credential or IPC message.
/// A real transport must authenticate this grant and verify the OS peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverTelemetryWorkerGrant {
    receiver: ReceiverTelemetryBinding,
    protected_key: ReceiverTelemetryAuthorizedKey,
}

impl ReceiverTelemetryWorkerGrant {
    #[must_use]
    pub const fn receiver(self) -> ReceiverTelemetryBinding {
        self.receiver
    }

    #[must_use]
    pub const fn protected_key_grant(self) -> ReceiverTelemetryAuthorizedKey {
        self.protected_key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryServiceRuntimeError {
    InvalidKey,
    KeyNotConfirmed,
    KeyOwnerMismatch,
    KeyMismatch,
    Start(ReceiverTelemetryServiceLifecycleError),
}

/// Errors from passive byte-stream assembly and Service-owned admission.
/// Neither peer identity nor the current key may be inferred from the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTelemetryServiceStreamError {
    NotAuthorized,
    Framing(ReceiverTelemetryFrameStreamError),
    NonmonotonicBatch,
    Admission(ReceiverTelemetryServiceAdmissionError),
}

/// A single Service-owned receiver slot: key installation/teardown and
/// receiver runtime/admission advance within one serialized owner.
#[derive(Debug, Default)]
pub struct ReceiverTelemetryServiceRuntime {
    confirmed_key: Option<(
        ReceiverTelemetryAuthorizedKey,
        ReceiverTelemetryCurrentWorker,
    )>,
    admission: ReceiverTelemetryServiceAdmission,
    framing: ReceiverTelemetryFrameStream,
}

impl ReceiverTelemetryServiceRuntime {
    /// A *new* key install has been dispatched to the Worker. The Worker may
    /// replace its receive key before replying, so retire the old report
    /// identity and confirmation immediately; rejected/missing ACKs fail closed.
    pub fn key_install_started(&mut self) {
        self.revoke_active();
        self.confirmed_key = None;
    }

    /// Called only after the Service matched the Worker key-install result
    /// to the pending authorized grant, and revalidated the OS peer plus
    /// exact Service-managed Worker generation.
    pub fn confirm_key_installed(
        &mut self,
        key: ReceiverTelemetryAuthorizedKey,
        current_worker: ReceiverTelemetryCurrentWorker,
    ) -> Result<(), ReceiverTelemetryServiceRuntimeError> {
        if !key.is_valid()
            || current_worker.process_id == 0
            || current_worker.session_id == 0
            || current_worker.worker_generation == 0
        {
            return Err(ReceiverTelemetryServiceRuntimeError::InvalidKey);
        }
        self.revoke_active();
        self.confirmed_key = Some((key, current_worker));
        Ok(())
    }

    /// Media start ACKs may only activate the exact Service-authorized,
    /// Worker-confirmed key under the SAME currently authenticated Worker.
    /// Epoch and Worker generation are absent from the start ACK and must
    /// never be synthesized from it.
    pub fn activate_correlated_start(
        &mut self,
        pending: ReceiverTelemetryStart,
        current_worker: ReceiverTelemetryCurrentWorker,
        reply: ReceiverTelemetryStartAck,
    ) -> Result<ReceiverTelemetryBinding, ReceiverTelemetryServiceRuntimeError> {
        let (key, installed_worker) = self
            .confirmed_key
            .ok_or(ReceiverTelemetryServiceRuntimeError::KeyNotConfirmed)?;
        if current_worker != installed_worker {
            return Err(ReceiverTelemetryServiceRuntimeError::KeyOwnerMismatch);
        }
        if !key.matches_start(pending) {
            return Err(ReceiverTelemetryServiceRuntimeError::KeyMismatch);
        }
        let binding = self
            .admission
            .activate_after_correlated_reply(pending, current_worker, reply)
            .map_err(ReceiverTelemetryServiceRuntimeError::Start)?;
        // This exact receiver lifetime is Service-minted, not sent by the
        // Worker. The framing slot advances atomically with admission in the
        // same owner and is cleared by every lifecycle revocation path.
        if self.framing.activate_verified(binding).is_err() {
            self.key_install_started();
            return Err(ReceiverTelemetryServiceRuntimeError::Start(
                ReceiverTelemetryServiceLifecycleError::InvalidBinding,
            ));
        }
        Ok(binding)
    }

    /// Only an exact Service-owned grant revocation can retire this key.
    /// An older grant with the same presentation/stream/epoch but a different
    /// key-grant request ID must not revoke the current runtime.
    pub fn revoke_matching_key(&mut self, key: ReceiverTelemetryAuthorizedKey) -> bool {
        if !self
            .confirmed_key
            .is_some_and(|(confirmed, _)| confirmed == key)
        {
            return false;
        }
        self.key_install_started();
        true
    }

    /// The OS-authenticated Worker was replaced/stopped/disconnected. Never
    /// reset the monotonically increasing receiver generation across restarts.
    pub fn worker_changed(&mut self) {
        self.key_install_started();
    }

    /// Read-only snapshot, not a proof the OS peer is still running.
    #[must_use]
    pub fn current(&self) -> Option<ReceiverTelemetryBinding> {
        self.admission.current()
    }

    /// Issue the exact current Worker receiver grant only after the
    /// Service-authorized protected key and Worker start ACK are both
    /// confirmed under this same independently verified Worker incarnation.
    ///
    /// This is an in-process snapshot, NOT OS peer authentication and NOT
    /// delivery through an authenticated Service-to-Worker transport.
    #[must_use]
    pub fn worker_grant_after_verified_peer(
        &self,
        current_worker: ReceiverTelemetryCurrentWorker,
    ) -> Option<ReceiverTelemetryWorkerGrant> {
        let (key, installed_worker) = self.confirmed_key?;
        if installed_worker != current_worker {
            return None;
        }
        let receiver = self.admission.current()?;
        if !receiver.is_valid()
            || receiver.process_id != current_worker.process_id
            || receiver.session_id != current_worker.session_id
            || receiver.worker_generation != current_worker.worker_generation
            || receiver.control_session_id != key.control_session_id
            || receiver.presentation_id != key.presentation_id
            || receiver.stream_id != key.stream_id
            || receiver.epoch != key.epoch
        {
            return None;
        }
        Some(ReceiverTelemetryWorkerGrant {
            receiver,
            protected_key: key,
        })
    }

    /// Process one bounded byte-mode named-pipe read in the same Service-owned
    /// serialized key/Worker/runtime lifetime as frame and replay admission.
    ///
    /// The caller MUST independently attest the actual Windows OS pipe peer
    /// and live launched Worker generation before entry. A copied peer value
    /// is not a credential, and this method adds no IPC or sender.
    ///
    /// Coalesced records use latest-only admission: earlier record timestamps
    /// cannot be reconstructed from a single Service arrival clock. Gaps
    /// rebaseline in the existing Service gate; never synthesize RTT/packet
    /// loss or declare an old observation healthy. Malformed/reordered input
    /// and admission failures revoke the active telemetry key and runtime.
    pub fn observe_stream_chunk_after_verified_peer(
        &mut self,
        current_worker: ReceiverTelemetryCurrentWorker,
        bytes: &[u8],
        service_received_at: Instant,
    ) -> Result<Option<ReceiverTelemetryDecision>, ReceiverTelemetryServiceStreamError> {
        let Some(grant) = self.worker_grant_after_verified_peer(current_worker) else {
            // A stale caller cannot mutate a replacement receiver or drain
            // its partial record, even when it copied an older binding.
            return Err(ReceiverTelemetryServiceStreamError::NotAuthorized);
        };
        let binding = grant.receiver();
        let reports = match self
            .framing
            .accept_verified_at(binding, bytes, service_received_at)
        {
            Ok(reports) => reports,
            Err(error) => {
                self.key_install_started();
                return Err(ReceiverTelemetryServiceStreamError::Framing(error));
            }
        };
        if !reports
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
        {
            self.key_install_started();
            return Err(ReceiverTelemetryServiceStreamError::NonmonotonicBatch);
        }
        let Some(latest) = reports.last().copied() else {
            return Ok(None);
        };
        // The bounded parser strictly decoded this exact report, and the
        // existing Service ingress accepts only a fixed-width versioned wire.
        // Re-encoding preserves the current checked transport contract.
        let wire = match encode_receiver_telemetry(&latest) {
            Ok(wire) => wire,
            Err(error) => {
                self.key_install_started();
                return Err(ReceiverTelemetryServiceStreamError::Framing(
                    ReceiverTelemetryFrameStreamError::Wire(error),
                ));
            }
        };
        match self
            .admission
            .observe_after_verified_peer(current_worker, &wire, service_received_at)
        {
            Ok(decision) => Ok(Some(decision)),
            Err(error) => {
                self.key_install_started();
                Err(ReceiverTelemetryServiceStreamError::Admission(error))
            }
        }
    }

    /// Called on a bounded Service timer even if the pipe reader is idle.
    /// Do not let untrusted partial data linger indefinitely. Caller must
    /// verify the active OS-authenticated Worker and serialize lifecycle.
    pub fn expire_partial_stream_after_verified_peer(
        &mut self,
        current_worker: ReceiverTelemetryCurrentWorker,
        service_now: Instant,
    ) -> Result<(), ReceiverTelemetryServiceStreamError> {
        let Some(grant) = self.worker_grant_after_verified_peer(current_worker) else {
            return Err(ReceiverTelemetryServiceStreamError::NotAuthorized);
        };
        match self
            .framing
            .expire_partial_after_verified_owner(grant.receiver(), service_now)
        {
            Ok(()) => Ok(()),
            Err(error) => {
                self.key_install_started();
                Err(ReceiverTelemetryServiceStreamError::Framing(error))
            }
        }
    }

    /// Diagnostic report: exact current Worker must still be verified by the
    /// caller, and transport bytes remain untrusted until parsed/admitted.
    pub fn observe_after_verified_peer(
        &mut self,
        current_worker: ReceiverTelemetryCurrentWorker,
        bytes: &[u8],
        service_received_at: Instant,
    ) -> Result<ReceiverTelemetryDecision, ReceiverTelemetryServiceAdmissionError> {
        self.admission
            .observe_after_verified_peer(current_worker, bytes, service_received_at)
    }

    #[must_use]
    pub fn has_fresh_for_verified_peer(
        &self,
        current_worker: ReceiverTelemetryCurrentWorker,
        now: Instant,
    ) -> bool {
        self.admission
            .has_fresh_for_verified_peer(current_worker, now)
    }

    fn revoke_active(&mut self) {
        if let Some(binding) = self.admission.current() {
            self.framing.clear_if_matches(binding);
            self.admission.clear_if_matches(binding);
        }
    }
}
