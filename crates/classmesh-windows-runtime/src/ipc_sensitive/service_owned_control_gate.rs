//! Inactive future-v12, non-payload Service authority recheck seam.
//!
//! This is a testable policy contract, NOT a connected Service accessor,
//! authenticated protocol, Windows HANDLE attestation or clipboard transfer.
//! Callers must supply fresh Service-owned state, not Worker metadata.
//! This module MUST NOT be used to activate legacy v11 ClipboardRead.
use super::clipboard_read_gate::SENSITIVE_CLIPBOARD_READ_DEADLINE_MS;
use super::clipboard_read_success::ClipboardReadSuccessBinding;
use super::clipboard_read_transport_gate::SensitiveReadGrants;

/// OS evidence and policy from a future live Service-owned accessor.
/// This plain value cannot attest its own provenance or authorize bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveServiceReadState {
    pub binding: ClipboardReadSuccessBinding,
    pub grants: SensitiveReadGrants,
    pub native_client_pid: u32,
    pub native_client_session: u32,
    pub original_worker_alive: bool,
    pub control_authenticated: bool,
}

/// Inert test stage labels only; no payload or IPC is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceReadStage {
    Connected,
    BeforeRead,
    Fragment,
    BeforeDelivery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceReadGateError {
    InvalidBinding,
    ClockOverflow,
    AuthorityUnavailable,
    ControlUnavailable,
    PermissionRevoked,
    BindingChanged,
    WorkerDead,
    PeerMismatch,
    ClockRegression,
    Expired,
    BadStage,
    BudgetExceeded,
    AlreadyUsed,
}

/// Pure-test fragment-step budget, NOT a wire format limit.
pub const MAX_POLICY_FRAGMENTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingStage {
    Initial,
    Connected,
    Reading,
    Consumed,
    Denied,
}

/// Fail-closed, one-shot model. Does not maintain cross-request anti-replay,
/// connect to the actual Windows SCM, or provision a v12 secret.
#[derive(Debug)]
pub struct ServiceReadGate {
    expected: ClipboardReadSuccessBinding,
    last_checked_ms: u64,
    deadline_ms: u64,
    stage: PendingStage,
    fragments: usize,
}

impl ServiceReadGate {
    /// The callback must query live authenticated Service control, both
    /// grants, original Worker OS HANDLE liveness and native pipe peer.
    /// Passing an old by-value snapshot defeats this contract.
    pub fn new(
        expected: ClipboardReadSuccessBinding,
        now_ms: u64,
        current_service_state: impl FnOnce() -> Option<LiveServiceReadState>,
    ) -> Result<Self, ServiceReadGateError> {
        if !expected.is_valid() {
            return Err(ServiceReadGateError::InvalidBinding);
        }
        let deadline_ms = now_ms
            .checked_add(SENSITIVE_CLIPBOARD_READ_DEADLINE_MS)
            .ok_or(ServiceReadGateError::ClockOverflow)?;
        Self::validate(expected, current_service_state())?;
        Ok(Self {
            expected,
            last_checked_ms: now_ms,
            deadline_ms,
            stage: PendingStage::Initial,
            fragments: 0,
        })
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(
            self.stage,
            PendingStage::Initial | PendingStage::Connected | PendingStage::Reading
        )
    }

    /// Re-sample the Service accessor at every stage. Never touches a
    /// Windows pipe, clipboard text, key, or IPC version negotiation.
    pub fn check(
        &mut self,
        next: ServiceReadStage,
        now_ms: u64,
        current_service_state: impl FnOnce() -> Option<LiveServiceReadState>,
    ) -> Result<(), ServiceReadGateError> {
        if !self.is_pending() {
            return Err(ServiceReadGateError::AlreadyUsed);
        }
        let result = self.check_once(next, now_ms, current_service_state);
        if result.is_err() {
            self.stage = PendingStage::Denied;
        }
        result
    }

    fn check_once(
        &mut self,
        next: ServiceReadStage,
        now_ms: u64,
        current_service_state: impl FnOnce() -> Option<LiveServiceReadState>,
    ) -> Result<(), ServiceReadGateError> {
        if now_ms < self.last_checked_ms {
            return Err(ServiceReadGateError::ClockRegression);
        }
        if now_ms >= self.deadline_ms {
            return Err(ServiceReadGateError::Expired);
        }
        let accepted = matches!(
            (self.stage, next),
            (PendingStage::Initial, ServiceReadStage::Connected)
                | (PendingStage::Connected, ServiceReadStage::BeforeRead)
                | (PendingStage::Reading, ServiceReadStage::Fragment)
        ) || (self.stage == PendingStage::Reading
            && self.fragments > 0
            && next == ServiceReadStage::BeforeDelivery);
        if !accepted {
            return Err(ServiceReadGateError::BadStage);
        }
        if next == ServiceReadStage::Fragment && self.fragments >= MAX_POLICY_FRAGMENTS {
            return Err(ServiceReadGateError::BudgetExceeded);
        }
        Self::validate(self.expected, current_service_state())?;
        self.last_checked_ms = now_ms;
        match next {
            ServiceReadStage::Connected => self.stage = PendingStage::Connected,
            ServiceReadStage::BeforeRead => self.stage = PendingStage::Reading,
            ServiceReadStage::Fragment => self.fragments += 1,
            ServiceReadStage::BeforeDelivery => self.stage = PendingStage::Consumed,
        }
        Ok(())
    }

    #[must_use]
    pub fn cancel(&mut self) -> bool {
        let was_pending = self.is_pending();
        self.stage = PendingStage::Denied;
        was_pending
    }

    fn validate(
        expected: ClipboardReadSuccessBinding,
        current: Option<LiveServiceReadState>,
    ) -> Result<(), ServiceReadGateError> {
        let Some(current) = current else {
            return Err(ServiceReadGateError::AuthorityUnavailable);
        };
        if !current.control_authenticated {
            return Err(ServiceReadGateError::ControlUnavailable);
        }
        if !current.grants.allows_read() {
            return Err(ServiceReadGateError::PermissionRevoked);
        }
        if !current.binding.is_valid() || current.binding != expected {
            return Err(ServiceReadGateError::BindingChanged);
        }
        if !current.original_worker_alive {
            return Err(ServiceReadGateError::WorkerDead);
        }
        if current.native_client_pid != expected.worker_process_id
            || current.native_client_session != expected.worker_session_id
        {
            return Err(ServiceReadGateError::PeerMismatch);
        }
        Ok(())
    }
}
