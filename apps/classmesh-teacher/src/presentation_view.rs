use classmesh_core::MediaState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationBindingView {
    pub presentation_id: u64,
    pub stream_id: u32,
    pub epoch: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationProfileView {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationMetricsView {
    pub captured_frames: u64,
    pub submitted_frames: u64,
    pub rate_dropped_frames: u64,
    pub pool_dropped_frames: u64,
    pub encoded_frames: u64,
    pub encoded_bytes: u64,
    pub keyframes: u64,
    pub keyframe_requests: u64,
    pub multicast_queued: usize,
    pub multicast_dropped: u64,
    pub unicast_outliers: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationRuntimeSnapshot {
    pub binding: Option<PresentationBindingView>,
    pub profile: Option<PresentationProfileView>,
    pub metrics: PresentationMetricsView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationViewState {
    pub media_state: MediaState,
    pub binding: Option<PresentationBindingView>,
    pub profile: Option<PresentationProfileView>,
    pub metrics: PresentationMetricsView,
}

#[derive(Debug, Default)]
pub struct TeacherPresentationViewModel;

impl TeacherPresentationViewModel {
    #[must_use]
    pub fn state(snapshot: PresentationRuntimeSnapshot) -> PresentationViewState {
        let media_state = match snapshot.binding {
            None => MediaState::Idle,
            Some(_) if snapshot.profile.is_some() && snapshot.metrics.encoded_frames > 0 => {
                MediaState::Streaming
            }
            Some(_) => MediaState::Starting,
        };

        PresentationViewState {
            media_state,
            binding: snapshot.binding,
            profile: snapshot.profile,
            metrics: snapshot.metrics,
        }
    }
}

#[cfg(windows)]
impl TeacherPresentationViewModel {
    #[must_use]
    pub fn state_from_lifecycle(
        lifecycle: &crate::TeacherVideoEngineLifecycle,
    ) -> PresentationViewState {
        Self::state(lifecycle.presentation_snapshot())
    }

    pub fn start(
        lifecycle: &mut crate::TeacherVideoEngineLifecycle,
        runtime: classmesh_worker::presentation_multicast_send::PresentationMulticastSendRuntime,
        unicast_queue_capacity: usize,
    ) -> Result<(), crate::TeacherVideoEngineLifecycleError> {
        lifecycle.start(runtime, unicast_queue_capacity)
    }

    pub fn stop(
        lifecycle: &mut crate::TeacherVideoEngineLifecycle,
    ) -> Result<bool, crate::TeacherVideoEngineLifecycleError> {
        let Some(binding) = lifecycle.active_binding() else {
            return Ok(false);
        };
        lifecycle.stop(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_snapshot(encoded_frames: u64) -> PresentationRuntimeSnapshot {
        PresentationRuntimeSnapshot {
            binding: Some(PresentationBindingView {
                presentation_id: 700,
                stream_id: 800,
                epoch: 4,
            }),
            profile: Some(PresentationProfileView {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_bps: 2_500_000,
            }),
            metrics: PresentationMetricsView {
                captured_frames: encoded_frames.saturating_add(2),
                submitted_frames: encoded_frames.saturating_add(1),
                encoded_frames,
                encoded_bytes: encoded_frames.saturating_mul(1_024),
                multicast_queued: 1,
                multicast_dropped: 3,
                unicast_outliers: 2,
                ..PresentationMetricsView::default()
            },
        }
    }

    #[test]
    fn idle_projection_has_no_fabricated_binding_or_profile() {
        let state = TeacherPresentationViewModel::state(PresentationRuntimeSnapshot::default());
        assert_eq!(state.media_state, MediaState::Idle);
        assert_eq!(state.binding, None);
        assert_eq!(state.profile, None);
        assert_eq!(state.metrics, PresentationMetricsView::default());
    }

    #[test]
    fn active_runtime_without_encoded_output_projects_starting() {
        let snapshot = active_snapshot(0);
        let state = TeacherPresentationViewModel::state(snapshot);
        assert_eq!(state.media_state, MediaState::Starting);
        assert_eq!(state.binding, snapshot.binding);
        assert_eq!(state.profile, snapshot.profile);
    }

    #[test]
    fn encoded_output_projects_streaming_without_inventing_drop_policy() {
        let snapshot = active_snapshot(12);
        let state = TeacherPresentationViewModel::state(snapshot);
        assert_eq!(state.media_state, MediaState::Streaming);
        assert_eq!(state.metrics.multicast_dropped, 3);
        assert_eq!(state.metrics.multicast_queued, 1);
        assert_eq!(state.metrics.unicast_outliers, 2);
    }

    #[test]
    fn active_binding_remains_starting_when_profile_is_not_ready() {
        let mut snapshot = active_snapshot(0);
        snapshot.profile = None;
        let state = TeacherPresentationViewModel::state(snapshot);
        assert_eq!(state.media_state, MediaState::Starting);
        assert_eq!(state.binding, snapshot.binding);
        assert_eq!(state.profile, None);
    }

    #[cfg(windows)]
    #[test]
    fn idle_windows_lifecycle_projects_idle_and_stop_is_noop() {
        let mut lifecycle = crate::TeacherVideoEngineLifecycle::default();
        let state = TeacherPresentationViewModel::state_from_lifecycle(&lifecycle);
        assert_eq!(state.media_state, MediaState::Idle);
        assert_eq!(state.binding, None);
        assert_eq!(state.profile, None);
        assert!(matches!(
            TeacherPresentationViewModel::stop(&mut lifecycle),
            Ok(false)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_view_contract_delegates_to_existing_lifecycle() {
        use classmesh_worker::presentation_multicast_send::PresentationMulticastSendRuntime;

        fn assert_contract(
            lifecycle: &mut crate::TeacherVideoEngineLifecycle,
            runtime: PresentationMulticastSendRuntime,
        ) {
            let _: PresentationViewState =
                TeacherPresentationViewModel::state_from_lifecycle(lifecycle);
            let _: Result<(), crate::TeacherVideoEngineLifecycleError> =
                TeacherPresentationViewModel::start(lifecycle, runtime, 2);
            let _: Result<bool, crate::TeacherVideoEngineLifecycleError> =
                TeacherPresentationViewModel::stop(lifecycle);
        }

        let _ = assert_contract
            as fn(&mut crate::TeacherVideoEngineLifecycle, PresentationMulticastSendRuntime);
    }
}
