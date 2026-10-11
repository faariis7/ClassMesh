//! Authenticated Service-side acceptance policy for one *future* sensitive
//! Worker clipboard read success. Pure in-memory policy: no Service wiring,
//! no OS clipboard access and no generic IPC decoder activation.
//!
//! A pending identity must originate from authenticated ReadClipboard dispatch.
//! Every rejected secret payload is consumed and erased via Zeroizing on drop.
use super::clipboard_read_success::{ClipboardReadSuccessBinding, SensitiveClipboardReadSuccess};

/// Align this guard with the existing Service clipboard Worker timeout.
/// A pending text-bearing result must never outlive the active Worker request.
pub const SENSITIVE_CLIPBOARD_READ_DEADLINE_MS: u64 = 2_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveReadAcceptError {
    InvalidBinding,
    ClockOverflow,
    ClockRegression,
    Expired,
    Mismatch,
    Missing,
}

/// One pending result, bound to all six current Worker and control identifiers.
/// Secret-bearing results are never logged, cloned, or stored by this guard.
#[derive(Debug)]
pub struct SensitiveClipboardReadAcceptanceGate {
    pending: Option<ClipboardReadSuccessBinding>,
    started_at_ms: u64,
    expires_at_ms: u64,
}

impl SensitiveClipboardReadAcceptanceGate {
    pub fn new(
        expected: ClipboardReadSuccessBinding,
        now_ms: u64,
    ) -> Result<Self, SensitiveReadAcceptError> {
        if !expected.is_valid() {
            return Err(SensitiveReadAcceptError::InvalidBinding);
        }
        let expires_at_ms = now_ms
            .checked_add(SENSITIVE_CLIPBOARD_READ_DEADLINE_MS)
            .ok_or(SensitiveReadAcceptError::ClockOverflow)?;
        Ok(Self {
            pending: Some(expected),
            started_at_ms: now_ms,
            expires_at_ms,
        })
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Invalidate on control disconnect/revocation or Worker replacement.
    /// Any later result is rejected and its owned text is zeroized on drop.
    pub fn cancel(&mut self) -> bool {
        self.pending.take().is_some()
    }

    /// Never return user text until the exact current six-part binding and
    /// monotonic deadline are validated. Even mismatched payloads are owned
    /// and dropped immediately without echoing secret text.
    pub fn accept(
        &mut self,
        payload: SensitiveClipboardReadSuccess,
        now_ms: u64,
    ) -> Result<SensitiveClipboardReadSuccess, SensitiveReadAcceptError> {
        let Some(expected) = self.pending else {
            return Err(SensitiveReadAcceptError::Missing);
        };
        if now_ms < self.started_at_ms {
            self.pending = None;
            return Err(SensitiveReadAcceptError::ClockRegression);
        }
        if now_ms >= self.expires_at_ms {
            self.pending = None;
            return Err(SensitiveReadAcceptError::Expired);
        }
        if payload.binding() != expected {
            return Err(SensitiveReadAcceptError::Mismatch);
        }
        self.pending = None;
        Ok(payload)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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

    fn result_for(b: ClipboardReadSuccessBinding) -> SensitiveClipboardReadSuccess {
        SensitiveClipboardReadSuccess::new(b, Zeroizing::new("سري é😀".as_bytes().to_vec()))
            .expect("valid sensitive payload")
    }

    #[test]
    fn exact_one_shot_accepts_before_timeout_then_rejects_replay() {
        let mut gate = SensitiveClipboardReadAcceptanceGate::new(binding(), 100)
            .expect("valid nonzero identifiers");
        assert!(gate.is_pending());
        let result = gate
            .accept(
                result_for(binding()),
                100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS - 1,
            )
            .expect("only current pending operation succeeds");
        assert_eq!(result.text(), "سري é😀");
        assert!(!gate.is_pending());
        assert_eq!(
            gate.accept(result_for(binding()), 101).err(),
            Some(SensitiveReadAcceptError::Missing),
        );
    }

    #[test]
    fn wrong_six_field_binding_never_consumes_pending_operation() {
        let base = binding();
        let mutations = [
            ClipboardReadSuccessBinding {
                worker_process_id: 43,
                ..base
            },
            ClipboardReadSuccessBinding {
                worker_session_id: 8,
                ..base
            },
            ClipboardReadSuccessBinding {
                worker_generation: 5,
                ..base
            },
            ClipboardReadSuccessBinding {
                control_session_id: 78,
                ..base
            },
            ClipboardReadSuccessBinding {
                control_sequence: 102,
                ..base
            },
            ClipboardReadSuccessBinding {
                request_id: 20,
                ..base
            },
        ];
        let mut gate = SensitiveClipboardReadAcceptanceGate::new(base, 100).expect("valid");
        for changed in mutations {
            assert_eq!(
                gate.accept(result_for(changed), 101).err(),
                Some(SensitiveReadAcceptError::Mismatch),
            );
            assert!(
                gate.is_pending(),
                "mismatched responses never consume the valid read"
            );
        }
        assert!(gate.accept(result_for(base), 102).is_ok());
    }

    #[test]
    fn expiry_and_clock_regression_poison_pending_result() {
        let base = binding();
        let mut gate = SensitiveClipboardReadAcceptanceGate::new(base, 100).expect("valid");
        assert_eq!(
            gate.accept(result_for(base), 99).err(),
            Some(SensitiveReadAcceptError::ClockRegression),
        );
        assert!(!gate.is_pending());
        let mut gate = SensitiveClipboardReadAcceptanceGate::new(base, 100).expect("valid");
        assert_eq!(
            gate.accept(result_for(base), 100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS)
                .err(),
            Some(SensitiveReadAcceptError::Expired),
        );
        assert!(!gate.is_pending());
        assert_eq!(
            gate.accept(
                result_for(base),
                100 + SENSITIVE_CLIPBOARD_READ_DEADLINE_MS + 1
            )
            .err(),
            Some(SensitiveReadAcceptError::Missing),
        );
    }

    #[test]
    fn cancellation_drops_pending_authority_on_disconnect_or_worker_replacement() {
        let mut gate = SensitiveClipboardReadAcceptanceGate::new(binding(), 100).expect("valid");
        assert!(gate.cancel());
        assert!(!gate.cancel());
        assert!(!gate.is_pending());
        assert_eq!(
            gate.accept(result_for(binding()), 101).err(),
            Some(SensitiveReadAcceptError::Missing)
        );
    }

    #[test]
    fn invalid_binding_and_deadline_overflow_reject_registration() {
        let base = binding();
        for bad in [
            ClipboardReadSuccessBinding {
                worker_process_id: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                worker_session_id: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                worker_generation: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                control_session_id: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                control_sequence: 0,
                ..base
            },
            ClipboardReadSuccessBinding {
                request_id: 0,
                ..base
            },
        ] {
            assert_eq!(
                SensitiveClipboardReadAcceptanceGate::new(bad, 100).err(),
                Some(SensitiveReadAcceptError::InvalidBinding)
            );
        }
        assert_eq!(
            SensitiveClipboardReadAcceptanceGate::new(base, u64::MAX).err(),
            Some(SensitiveReadAcceptError::ClockOverflow),
        );
    }
}
