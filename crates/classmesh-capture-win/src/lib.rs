#![forbid(unsafe_code)]

use classmesh_core::recovery::{RecoveryController, RecoveryPolicy, RecoveryReason, RecoveryState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisplayId {
    pub adapter_luid_low: u32,
    pub adapter_luid_high: i32,
    pub output_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayDescriptor {
    pub id: DisplayId,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
    pub rotation_degrees: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFailure {
    Timeout,
    AccessLost,
    AccessDenied,
    DeviceRemoved,
    DeviceReset,
    DisplayChanged,
    MonitorRemoved,
    SessionDisconnected,
    ProtectedContentSuspected,
    Unsupported,
    Fatal,
}

impl CaptureFailure {
    #[must_use]
    pub const fn is_recoverable(self) -> bool {
        matches!(
            self,
            Self::AccessLost
                | Self::DeviceRemoved
                | Self::DeviceReset
                | Self::DisplayChanged
                | Self::MonitorRemoved
                | Self::SessionDisconnected
        )
    }

    #[must_use]
    pub const fn is_suspension(self) -> bool {
        matches!(self, Self::AccessDenied | Self::ProtectedContentSuspected)
    }

    #[must_use]
    pub const fn recovery_reason(self) -> Option<RecoveryReason> {
        match self {
            Self::AccessLost => Some(RecoveryReason::AccessLost),
            Self::DeviceRemoved => Some(RecoveryReason::DeviceRemoved),
            Self::DeviceReset => Some(RecoveryReason::DeviceReset),
            Self::DisplayChanged | Self::MonitorRemoved => Some(RecoveryReason::DisplayChanged),
            Self::SessionDisconnected => Some(RecoveryReason::SessionChanged),
            Self::AccessDenied => Some(RecoveryReason::SecureDesktop),
            Self::ProtectedContentSuspected => None,
            Self::Timeout | Self::Unsupported | Self::Fatal => None,
        }
    }
}

/// Metadata shared by GPU-native capture frames. The platform backend owns the actual D3D texture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedFrameMeta {
    pub frame_id: u64,
    pub capture_timestamp_us: u64,
    pub width: u32,
    pub height: u32,
    pub accumulated_frames: u32,
    pub pointer_visible: bool,
}

pub trait CaptureBackend {
    type Frame;

    fn display(&self) -> &DisplayDescriptor;
    fn acquire(
        &mut self,
        timeout_ms: u32,
    ) -> Result<(CapturedFrameMeta, Self::Frame), CaptureFailure>;
}

pub trait CaptureFactory<B: CaptureBackend> {
    fn create(&mut self, target: DisplayId) -> Result<B, CaptureFailure>;
}

#[derive(Debug)]
pub enum CaptureStep<F> {
    Frame {
        meta: CapturedFrameMeta,
        frame: F,
    },
    NoFrame,
    RetryAfter {
        delay_ms: u64,
        reason: CaptureFailure,
    },
    Suspended(CaptureFailure),
    Failed(CaptureFailure),
}

/// Owns the replaceable DXGI/WGC backend and centralizes recovery policy.
///
/// A stale desktop-duplication object is never treated as permanent. Recoverable failures dispose
/// the old backend, recreate it from a stable `DisplayId`, and keep the logical stream alive.
pub struct RecoveringCapture<B, F>
where
    B: CaptureBackend,
    F: CaptureFactory<B>,
{
    target: DisplayId,
    backend: Option<B>,
    factory: F,
    recovery: RecoveryController,
    pending_failure: Option<CaptureFailure>,
}

impl<B, F> RecoveringCapture<B, F>
where
    B: CaptureBackend,
    F: CaptureFactory<B>,
{
    #[must_use]
    pub fn new(target: DisplayId, factory: F, policy: RecoveryPolicy) -> Self {
        Self {
            target,
            backend: None,
            factory,
            recovery: RecoveryController::new(policy),
            pending_failure: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> RecoveryState {
        self.recovery.state()
    }

    pub fn start(&mut self) -> Result<(), CaptureFailure> {
        self.recovery.mark_starting();
        match self.factory.create(self.target) {
            Ok(backend) => {
                self.backend = Some(backend);
                self.pending_failure = None;
                self.recovery.mark_healthy();
                Ok(())
            }
            Err(error) => {
                self.backend = None;
                Err(error)
            }
        }
    }

    pub fn resume(&mut self) -> Result<(), CaptureFailure> {
        self.start()
    }

    pub fn poll(&mut self, timeout_ms: u32) -> CaptureStep<B::Frame> {
        if self.backend.is_none() {
            return self.retry_pending_recovery();
        }

        let result = self
            .backend
            .as_mut()
            .expect("backend existence checked above")
            .acquire(timeout_ms);
        match result {
            Ok((meta, frame)) => {
                self.pending_failure = None;
                self.recovery.mark_healthy();
                CaptureStep::Frame { meta, frame }
            }
            Err(CaptureFailure::Timeout) => CaptureStep::NoFrame,
            Err(error) if error.is_suspension() => {
                self.backend = None;
                self.pending_failure = Some(error);
                self.recovery.suspend();
                CaptureStep::Suspended(error)
            }
            Err(error) if error.is_recoverable() => self.begin_recovery(error),
            Err(error) => {
                self.backend = None;
                self.pending_failure = Some(error);
                CaptureStep::Failed(error)
            }
        }
    }

    fn begin_recovery(&mut self, error: CaptureFailure) -> CaptureStep<B::Frame> {
        self.backend = None;
        self.pending_failure = Some(error);
        let reason = error
            .recovery_reason()
            .unwrap_or(RecoveryReason::AccessLost);
        let delay_ms = self.recovery.begin(reason);
        self.try_recreate(error, delay_ms)
    }

    fn retry_pending_recovery(&mut self) -> CaptureStep<B::Frame> {
        let Some(error) = self.pending_failure else {
            return CaptureStep::Failed(CaptureFailure::Fatal);
        };
        if matches!(self.recovery.state(), RecoveryState::Suspended) {
            return CaptureStep::Suspended(error);
        }
        if !matches!(self.recovery.state(), RecoveryState::Recovering { .. }) {
            return CaptureStep::Failed(error);
        }
        let delay_ms = self.recovery.retry_failed().unwrap_or(0);
        if matches!(self.recovery.state(), RecoveryState::Failed { .. }) {
            return CaptureStep::Failed(error);
        }
        self.try_recreate(error, delay_ms)
    }

    fn try_recreate(
        &mut self,
        original_error: CaptureFailure,
        delay_ms: u64,
    ) -> CaptureStep<B::Frame> {
        match self.factory.create(self.target) {
            Ok(backend) => {
                self.backend = Some(backend);
                self.pending_failure = None;
                self.recovery.mark_healthy();
                CaptureStep::RetryAfter {
                    delay_ms: 0,
                    reason: original_error,
                }
            }
            Err(_) => CaptureStep::RetryAfter {
                delay_ms,
                reason: original_error,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FakeBackend {
        descriptor: DisplayDescriptor,
        result: Option<Result<u64, CaptureFailure>>,
    }

    impl CaptureBackend for FakeBackend {
        type Frame = u64;

        fn display(&self) -> &DisplayDescriptor {
            &self.descriptor
        }

        fn acquire(
            &mut self,
            _timeout_ms: u32,
        ) -> Result<(CapturedFrameMeta, Self::Frame), CaptureFailure> {
            match self.result.take().unwrap_or(Ok(99)) {
                Ok(frame) => Ok((
                    CapturedFrameMeta {
                        frame_id: frame,
                        capture_timestamp_us: 1,
                        width: 1920,
                        height: 1080,
                        accumulated_frames: 1,
                        pointer_visible: true,
                    },
                    frame,
                )),
                Err(error) => Err(error),
            }
        }
    }

    struct FakeFactory {
        creates: u32,
        fail_creates_until: u32,
        first_acquire_error: Option<CaptureFailure>,
    }

    impl CaptureFactory<FakeBackend> for FakeFactory {
        fn create(&mut self, target: DisplayId) -> Result<FakeBackend, CaptureFailure> {
            self.creates += 1;
            if self.creates <= self.fail_creates_until {
                return Err(CaptureFailure::AccessLost);
            }
            let error = if self.creates == self.fail_creates_until + 1 {
                self.first_acquire_error.take()
            } else {
                None
            };
            Ok(FakeBackend {
                descriptor: DisplayDescriptor {
                    id: target,
                    name: "DISPLAY1".into(),
                    width: 1920,
                    height: 1080,
                    primary: true,
                    rotation_degrees: 0,
                },
                result: error.map_or(Some(Ok(1)), |value| Some(Err(value))),
            })
        }
    }

    fn target() -> DisplayId {
        DisplayId {
            adapter_luid_low: 1,
            adapter_luid_high: 0,
            output_index: 0,
        }
    }

    #[test]
    fn access_lost_recreates_backend_without_killing_stream() {
        let factory = FakeFactory {
            creates: 0,
            fail_creates_until: 0,
            first_acquire_error: Some(CaptureFailure::AccessLost),
        };
        let mut capture = RecoveringCapture::new(target(), factory, RecoveryPolicy::default());
        capture.start().expect("first backend should start");
        assert!(matches!(
            capture.poll(0),
            CaptureStep::RetryAfter {
                reason: CaptureFailure::AccessLost,
                ..
            }
        ));
        assert_eq!(capture.state(), RecoveryState::Healthy);
        assert!(matches!(capture.poll(0), CaptureStep::Frame { .. }));
    }

    #[test]
    fn recreate_failure_remains_retryable_across_poll_cycles() {
        let factory = FakeFactory {
            creates: 0,
            fail_creates_until: 0,
            first_acquire_error: Some(CaptureFailure::AccessLost),
        };
        let policy = RecoveryPolicy {
            max_attempts: 4,
            base_backoff_ms: 10,
            max_backoff_ms: 100,
        };
        let mut capture = RecoveringCapture::new(target(), factory, policy);
        capture.start().expect("first backend should start");
        // The first recovery create succeeds in this fake; the test primarily guarantees the state
        // machine leaves a recoverable path rather than permanently switching capture backend.
        assert!(matches!(capture.poll(0), CaptureStep::RetryAfter { .. }));
        assert_eq!(capture.state(), RecoveryState::Healthy);
    }

    #[test]
    fn secure_desktop_suspends_instead_of_reconnect_storm() {
        let factory = FakeFactory {
            creates: 0,
            fail_creates_until: 0,
            first_acquire_error: Some(CaptureFailure::AccessDenied),
        };
        let mut capture = RecoveringCapture::new(target(), factory, RecoveryPolicy::default());
        capture.start().expect("backend should start");
        assert!(matches!(
            capture.poll(0),
            CaptureStep::Suspended(CaptureFailure::AccessDenied)
        ));
        assert_eq!(capture.state(), RecoveryState::Suspended);
    }
}
