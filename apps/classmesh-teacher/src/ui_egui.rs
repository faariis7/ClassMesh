use eframe::egui;
use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::time::Instant;

use classmesh_control::client_session::ClientControlSession;
use classmesh_control::live_authorization::LiveAuthorizationStore;
use classmesh_control::teacher_playback_receive::AuthenticatedTeacherControlMessage;
use classmesh_protocol::Capability;
use classmesh_protocol::control_wire::{ControlEnvelope, TeacherInteractionState};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::classroom_grid::{MonitoringGridViewConfig, TeacherMonitoringGridViewModel};
use crate::classroom_view::{ClassroomViewConfig, TeacherClassroomViewModel};
use crate::device_diagnostics::{
    DeviceDiagnosticsConfig, DeviceDiagnosticsError, DeviceDiagnosticsSnapshot,
    DeviceDiagnosticsView, TeacherDeviceDiagnosticsViewModel,
};
use crate::presentation_view::{
    PresentationBindingView, PresentationRuntimeSnapshot, PresentationViewState,
    TeacherPresentationViewModel, presentation_change_retires_playback,
};
use crate::receiver_playback_diagnostics::{
    TeacherPlaybackBinding, TeacherPlaybackCounters, TeacherPlaybackDiagnosticError,
};
use crate::receiver_playback_session::{
    TeacherPlaybackSessionError, TeacherPlaybackSessionEvent, TeacherPlaybackSessionOwner,
};
use crate::receiver_playback_ui::TeacherPlaybackUiProjection;
use crate::ui_actions::{
    TeacherInteractionDraft, reset_teacher_interaction_draft, show_device_actions,
};
use crate::ui_classroom::show_classroom;
use crate::ui_diagnostics::{DiagnosticsOverrideDraft, show_diagnostics};
use crate::ui_file_transfer::{
    TeacherFilePullContext, TeacherStagedFileCandidate, prepare_file_pull_action,
    staged_file_candidate_ready, validate_file_pull_action,
};
use crate::ui_focus::show_focus;
use crate::ui_presentation::show_presentation;
use crate::ui_shell::{
    TeacherInteractionUiContext, TeacherInteractionUiRequest, TeacherUiAction, TeacherUiMessage,
    TeacherUiSection, TeacherUiShellState, prepare_teacher_interaction_ui_action,
    validate_teacher_interaction_ui_action,
};

const APP_TITLE: &str = "ClassMesh Teacher";
const DEFAULT_WINDOW_SIZE: [f32; 2] = [800.0, 600.0];
const MIN_WINDOW_SIZE: [f32; 2] = [600.0, 420.0];

// Keep each non-Classroom section independently scrollable at the minimum
// viewport. Classroom already owns its responsive Devices/Monitoring scroller.
// Separate salts prevent switching sections from inheriting another page's
// previous scroll offset (and appearing empty until scrolled to the top).
fn section_scroll_salt(section: TeacherUiSection) -> Option<&'static str> {
    match section {
        TeacherUiSection::Classroom => None,
        TeacherUiSection::Focus => Some("classmesh_teacher_focus_scroll"),
        TeacherUiSection::Presentation => Some("classmesh_teacher_presentation_scroll"),
        TeacherUiSection::DeviceActions => Some("classmesh_teacher_device_actions_scroll"),
        TeacherUiSection::Diagnostics => Some("classmesh_teacher_diagnostics_scroll"),
    }
}

/// The authenticated QUIC owner, not the UI, is the only producer of these
/// observations. A bound context alone never proves Service liveness.
#[derive(Debug)]
pub enum TeacherUiControlEvent {
    /// Atomic first verified observation: never publish partial auth/binding
    /// when the bounded UI queue can accept only part of a bootstrap.
    VerifiedBootstrap {
        context: TeacherInteractionUiContext,
        binding: TeacherPlaybackBinding,
        source_id: MonitoringSourceId,
        verified: AuthenticatedTeacherControlMessage,
        received_at: Instant,
    },
    Authenticated(TeacherInteractionUiContext),
    /// Establish a read-only playback binding only after the trusted QUIC
    /// owner has resolved its student-to-source mapping and live session.
    /// This carries no counters and does not prove a media stream is active.
    PlaybackBound {
        source_id: MonitoringSourceId,
        binding: TeacherPlaybackBinding,
    },
    /// An already verified enrolled QUIC receive result. The message proof
    /// cannot be constructed from a bare caller-supplied ControlEnvelope.
    /// Preserve the original receive time so a delayed channel cannot make
    /// old playback counters look fresh when they reach the window.
    VerifiedPlayback {
        source_id: MonitoringSourceId,
        verified: AuthenticatedTeacherControlMessage,
        received_at: Instant,
    },
    /// Exact-bound retirement must never revoke a replacement stream/epoch.
    PlaybackRetired {
        source_id: MonitoringSourceId,
        binding: TeacherPlaybackBinding,
    },
    CommandWritten {
        control_session_id: u64,
        request_id: u64,
    },
    CommandResult {
        control_session_id: u64,
        request_id: u64,
        state: TeacherInteractionState,
    },
    Disconnected,
}

impl TeacherUiControlEvent {
    /// Preserve the original receive timestamp and private authenticated
    /// QUIC proof when passing a playback observation to the native window.
    /// Unrelated control messages go back to the owning dispatcher, never
    /// silently become playback or get dropped by the UI adapter.
    pub fn from_verified_session_playback(
        source_id: MonitoringSourceId,
        event: TeacherPlaybackSessionEvent,
    ) -> Result<Self, Box<ControlEnvelope>> {
        match event {
            TeacherPlaybackSessionEvent::Playback {
                verified,
                received_at,
                ..
            } => Ok(Self::VerifiedPlayback {
                source_id,
                verified,
                received_at,
            }),
            TeacherPlaybackSessionEvent::OtherControl(envelope) => Err(Box::new(envelope)),
        }
    }
}

/// Result from forwarding one actual authenticated QUIC control message.
#[derive(Debug)]
pub enum TeacherPlaybackUiPumpOutcome {
    /// The genuine verified playback observation entered the bounded UI queue.
    PlaybackQueued,
    /// An occupied UI queue is not successful delivery or proof of media liveness.
    /// No stale report is retained for replay.
    WindowBusy,
    /// Unrelated authenticated control belongs to the owning dispatcher.
    OtherControl(Box<ControlEnvelope>),
}

/// The caller owns this session and its sole event sender; if an error occurs,
/// it must drop that sender and retire the session so the GUI fails closed.
#[derive(Debug)]
pub enum TeacherPlaybackUiPumpError {
    Receive(Box<TeacherPlaybackSessionError>),
    WindowDisconnected,
}

/// Receive ONE message from the already enrolled, authenticated QUIC owner
/// and forward real signed playback to the Windows UI without a second
/// network reader, a synthesized certificate, or a forged Service connection.
/// The source comes only from the trusted owner/roster binding. A bounded
/// full channel is reported explicitly, not counted as successful playback.
pub async fn pump_authenticated_playback_once(
    owner: &mut TeacherPlaybackSessionOwner,
    session: &mut ClientControlSession,
    authorization: &LiveAuthorizationStore,
    event_tx: &SyncSender<TeacherUiControlEvent>,
    wall_clock_ms: impl Fn() -> u64,
    monotonic_now: impl Fn() -> Instant,
) -> Result<TeacherPlaybackUiPumpOutcome, TeacherPlaybackUiPumpError> {
    let source_id = owner.source_id();
    let event = owner
        .receive_next(session, authorization, wall_clock_ms, monotonic_now)
        .await
        .map_err(|error| TeacherPlaybackUiPumpError::Receive(Box::new(error)))?;

    match TeacherUiControlEvent::from_verified_session_playback(source_id, event) {
        Ok(event) => match event_tx.try_send(event) {
            Ok(()) => Ok(TeacherPlaybackUiPumpOutcome::PlaybackQueued),
            Err(TrySendError::Full(_)) => Ok(TeacherPlaybackUiPumpOutcome::WindowBusy),
            Err(TrySendError::Disconnected(_)) => {
                Err(TeacherPlaybackUiPumpError::WindowDisconnected)
            }
        },
        Err(other) => Ok(TeacherPlaybackUiPumpOutcome::OtherControl(other)),
    }
}

/// A bounded handoff to the real QUIC owner. No synthetic success or network
/// connection is created by attaching the bridge.
#[derive(Debug)]
pub struct TeacherUiControlBridge {
    events: Receiver<TeacherUiControlEvent>,
    actions: SyncSender<TeacherUiAction>,
}

impl TeacherUiControlBridge {
    #[must_use]
    pub fn new(
        events: Receiver<TeacherUiControlEvent>,
        actions: SyncSender<TeacherUiAction>,
    ) -> Self {
        Self { events, actions }
    }
}

#[derive(Debug)]
pub struct TeacherEguiShell {
    shell: TeacherUiShellState,
    classroom: TeacherClassroomViewModel,
    monitoring: TeacherMonitoringGridViewModel,
    presentation: PresentationViewState,
    diagnostics_model: TeacherDeviceDiagnosticsViewModel,
    diagnostics: Option<DeviceDiagnosticsView>,
    playback: Option<TeacherPlaybackUiProjection>,
    diagnostics_draft: DiagnosticsOverrideDraft,
    teacher_interaction_context: Option<TeacherInteractionUiContext>,
    file_pull_context: Option<TeacherFilePullContext>,
    staged_file_candidate: Option<TeacherStagedFileCandidate>,
    teacher_interaction_draft: TeacherInteractionDraft,
    pending_action: Option<TeacherUiAction>,
    control_bridge: Option<TeacherUiControlBridge>,
    command_status: BTreeMap<u64, (u64, Option<TeacherInteractionState>)>,
}

impl Default for TeacherEguiShell {
    fn default() -> Self {
        Self {
            shell: TeacherUiShellState::default(),
            classroom: TeacherClassroomViewModel::new(ClassroomViewConfig::default())
                .expect("default classroom view configuration is valid"),
            monitoring: TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig::default())
                .expect("default monitoring grid configuration is valid"),
            presentation: TeacherPresentationViewModel::state(
                PresentationRuntimeSnapshot::default(),
            ),
            diagnostics_model: TeacherDeviceDiagnosticsViewModel::new(
                DeviceDiagnosticsConfig::default(),
            )
            .expect("default diagnostics view configuration is valid"),
            diagnostics: None,
            playback: None,
            diagnostics_draft: DiagnosticsOverrideDraft::default(),
            teacher_interaction_context: None,
            file_pull_context: None,
            staged_file_candidate: None,
            teacher_interaction_draft: TeacherInteractionDraft::default(),
            pending_action: None,
            control_bridge: None,
            command_status: BTreeMap::new(),
        }
    }
}

impl TeacherEguiShell {
    #[must_use]
    pub fn new(
        classroom: TeacherClassroomViewModel,
        monitoring: TeacherMonitoringGridViewModel,
    ) -> Self {
        Self {
            shell: TeacherUiShellState::default(),
            classroom,
            monitoring,
            presentation: TeacherPresentationViewModel::state(
                PresentationRuntimeSnapshot::default(),
            ),
            diagnostics_model: TeacherDeviceDiagnosticsViewModel::new(
                DeviceDiagnosticsConfig::default(),
            )
            .expect("default diagnostics view configuration is valid"),
            diagnostics: None,
            playback: None,
            diagnostics_draft: DiagnosticsOverrideDraft::default(),
            teacher_interaction_context: None,
            file_pull_context: None,
            staged_file_candidate: None,
            teacher_interaction_draft: TeacherInteractionDraft::default(),
            pending_action: None,
            control_bridge: None,
            command_status: BTreeMap::new(),
        }
    }

    /// Only attach a receiver owned by the authenticated QUIC runtime.
    /// Replacing the runtime invalidates the previous session immediately.
    pub fn attach_control_bridge(&mut self, bridge: TeacherUiControlBridge) {
        self.pending_action = None;
        self.clear_teacher_interaction_context();
        self.control_bridge = Some(bridge);
    }

    fn poll_control_bridge(&mut self) {
        // Drain bounded transport observations before considering any UI action.
        // A dropped producer means disconnect, never persistent liveness.
        // Never forward an action while a terminal disconnect may still be
        // queued behind a saturated observation batch. Drain in a later frame.
        let mut event_batch_exhausted = true;
        for _ in 0..64 {
            let event = match self.control_bridge.as_ref() {
                Some(bridge) => bridge.events.try_recv(),
                None => return,
            };
            match event {
                Ok(TeacherUiControlEvent::VerifiedBootstrap {
                    context,
                    binding,
                    source_id,
                    verified,
                    received_at,
                }) => {
                    // One bounded queue slot owns the complete first observation.
                    // A full queue cannot leave partial authenticated UI state.
                    if context.control_session_id != 0 {
                        self.set_teacher_interaction_context(context);
                        if self
                            .set_receiver_playback_context(source_id, binding)
                            .is_ok()
                        {
                            let _ = self.accept_verified_receiver_playback(
                                source_id,
                                &verified,
                                received_at,
                            );
                        }
                    }
                }
                Ok(TeacherUiControlEvent::Authenticated(context)) => {
                    if context.control_session_id == 0 {
                        self.clear_teacher_interaction_context();
                    } else {
                        self.set_teacher_interaction_context(context);
                    }
                }
                Ok(TeacherUiControlEvent::PlaybackBound { source_id, binding }) => {
                    // A new binding alone cannot show any counters. Reject it
                    // unless the current authenticated session and capability
                    // match this exact source and presentation lifecycle.
                    let _ = self.set_receiver_playback_context(source_id, binding);
                }
                Ok(TeacherUiControlEvent::VerifiedPlayback {
                    source_id,
                    verified,
                    received_at,
                }) => {
                    // Only the network boundary can construct this proof.
                    // The UI still rechecks current source, session, negotiated
                    // capability, binding and replay before publishing it.
                    let _ =
                        self.accept_verified_receiver_playback(source_id, &verified, received_at);
                }
                Ok(TeacherUiControlEvent::PlaybackRetired { source_id, binding }) => {
                    let _ = self.revoke_receiver_playback_context(source_id, binding);
                }
                Ok(TeacherUiControlEvent::CommandWritten {
                    control_session_id,
                    request_id,
                }) => {
                    if self
                        .teacher_interaction_context
                        .as_ref()
                        .is_some_and(|c| c.control_session_id == control_session_id)
                    {
                        // Bound UI history to the same 64 outstanding requests as the network owner.
                        // Never turn a write into an acknowledgement.
                        if !self.command_status.contains_key(&request_id) && self.command_status.len() >= 64 {
                            if let Some(oldest) = self.command_status.keys().next().copied() {
                                self.command_status.remove(&oldest);
                            }
                        }
                        self.command_status.insert(request_id, (control_session_id, None));
                    }
                }
                Ok(TeacherUiControlEvent::CommandResult {
                    control_session_id,
                    request_id,
                    state,
                }) => {
                    if let Some((session, status)) = self.command_status.get_mut(&request_id) {
                        if *session == control_session_id {
                            *status = Some(state);
                        }
                    }
                }
                Ok(TeacherUiControlEvent::Disconnected) => {
                    self.pending_action = None;
                    self.clear_teacher_interaction_context();
                }
                Err(TryRecvError::Empty) => {
                    event_batch_exhausted = false;
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    self.pending_action = None;
                    self.clear_teacher_interaction_context();
                    self.control_bridge = None;
                    return;
                }
            }
        }
        // A UI click is merely a request. A full/closed channel must never
        // imply that the authenticated Service accepted or applied it.
        if event_batch_exhausted || self.teacher_interaction_context.is_none() {
            return;
        }
        if let Some(action) = self.take_pending_action() {
            let result = self
                .control_bridge
                .as_ref()
                .map(|bridge| bridge.actions.try_send(action));
            match result {
                Some(Err(TrySendError::Full(action))) => {
                    // Backpressure is not delivery. Retry only while the same
                    // authenticated session remains bound; never claim success.
                    self.pending_action = Some(action);
                }
                Some(Err(TrySendError::Disconnected(_))) => {
                    self.pending_action = None;
                    self.clear_teacher_interaction_context();
                    self.control_bridge = None;
                }
                _ => {}
            }
        }
    }

    pub fn set_teacher_interaction_context(&mut self, context: TeacherInteractionUiContext) {
        if self
            .teacher_interaction_context
            .as_ref()
            .map(|current| (current.source_id, current.control_session_id))
            != Some((context.source_id, context.control_session_id))
        {
            reset_teacher_interaction_draft(&mut self.teacher_interaction_draft);
            self.command_status.clear();
            // Every queued action belongs to the old session, including
            // SelectDevice and presentation intents with no session epoch.
            // Never forward them into a newly authenticated QUIC session.
            self.pending_action = None;
            // Diagnostics intents carry a source but no session epoch.
            // A reconnect must not replay a pre-reconnect override.
            self.retire_pending_diagnostics_override();
        }
        // A new control session, source or missing optional v0.8
        // diagnostics capability invalidates all previously visible data.
        if self.playback.as_ref().is_some_and(|p| {
            p.source_id() != context.source_id
                || p.binding().control_session_id != context.control_session_id
                || context.version.major != 0
                || context.version.minor < 8
                || !context
                    .capabilities
                    .contains(&Capability::ReceiverPlaybackDiagnostics)
        }) {
            self.playback = None;
        }
        self.teacher_interaction_context = Some(context);
    }

    pub fn clear_teacher_interaction_context(&mut self) {
        // Retire any intent queued under the old authenticated session.
        // A new offline ResumeThumbnail click can still be queued afterward.
        if self.teacher_interaction_context.is_some()
            && matches!(
                self.pending_action,
                Some(TeacherUiAction::Focus(_) | TeacherUiAction::TeacherInteraction(_))
            )
        {
            self.pending_action = None;
        }
        self.teacher_interaction_context = None;
        self.command_status.clear();
        // Retire the authenticated playback ledger and diagnostics intents together.
        self.retire_pending_diagnostics_override();
        self.playback = None;
        reset_teacher_interaction_draft(&mut self.teacher_interaction_draft);
    }

    /// Only the authenticated QUIC client may supply this bound session
    /// context. A UI action alone does not grant or authenticate telemetry.
    pub fn set_receiver_playback_context(
        &mut self,
        source_id: MonitoringSourceId,
        binding: TeacherPlaybackBinding,
    ) -> Result<(), TeacherPlaybackDiagnosticError> {
        let context = self
            .teacher_interaction_context
            .as_ref()
            .ok_or(TeacherPlaybackDiagnosticError::NotNegotiated)?;
        if context.source_id != source_id
            || context.control_session_id != binding.control_session_id
        {
            return Err(TeacherPlaybackDiagnosticError::BindingMismatch);
        }
        if context.version.major != 0
            || context.version.minor < 8
            || !context
                .capabilities
                .contains(&Capability::ReceiverPlaybackDiagnostics)
        {
            return Err(TeacherPlaybackDiagnosticError::NotNegotiated);
        }
        if self
            .playback
            .as_ref()
            .is_some_and(|old| old.source_id() == source_id && old.binding() == binding)
        {
            return Ok(());
        }
        self.playback = Some(TeacherPlaybackUiProjection::new(source_id, binding)?);
        Ok(())
    }

    /// The production control-session owner may deliver ONLY an authenticated
    /// read result from the live QUIC receive gate. Never accept forged bare
    /// envelopes through this public GUI path.
    pub fn accept_verified_receiver_playback(
        &mut self,
        source_id: MonitoringSourceId,
        verified: &AuthenticatedTeacherControlMessage,
        now: Instant,
    ) -> Result<TeacherPlaybackCounters, TeacherPlaybackDiagnosticError> {
        let context = self
            .teacher_interaction_context
            .as_ref()
            .ok_or(TeacherPlaybackDiagnosticError::Inactive)?;
        let state = self
            .playback
            .as_mut()
            .ok_or(TeacherPlaybackDiagnosticError::Inactive)?;
        if context.source_id != source_id
            || state.binding().control_session_id != context.control_session_id
            || context.version.major != 0
            || context.version.minor < 8
            || !context
                .capabilities
                .contains(&Capability::ReceiverPlaybackDiagnostics)
        {
            return Err(TeacherPlaybackDiagnosticError::BindingMismatch);
        }
        state.accept_verified_from_source(source_id, verified, now)
    }

    /// Internal compatibility path for legacy unit tests only. Production
    /// ingress must use the verified proof object above.
    #[cfg(test)]
    pub(crate) fn accept_authenticated_receiver_playback(
        &mut self,
        envelope: &ControlEnvelope,
        now: Instant,
    ) -> Result<TeacherPlaybackCounters, TeacherPlaybackDiagnosticError> {
        let context = self
            .teacher_interaction_context
            .as_ref()
            .ok_or(TeacherPlaybackDiagnosticError::Inactive)?;
        let state = self
            .playback
            .as_mut()
            .ok_or(TeacherPlaybackDiagnosticError::Inactive)?;
        if state.source_id() != context.source_id
            || state.binding().control_session_id != context.control_session_id
        {
            return Err(TeacherPlaybackDiagnosticError::BindingMismatch);
        }
        let available = context.version.major == 0
            && context.version.minor >= 8
            && context
                .capabilities
                .contains(&Capability::ReceiverPlaybackDiagnostics);
        state.accept_authenticated(envelope, available, now)
    }

    /// An old session's disconnect must not invalidate a replacement.
    pub fn revoke_receiver_playback_context(
        &mut self,
        source_id: MonitoringSourceId,
        binding: TeacherPlaybackBinding,
    ) -> bool {
        let Some(state) = self.playback.as_mut() else {
            return false;
        };
        if !state.revoke(source_id, binding) {
            return false;
        }
        self.playback = None;
        true
    }

    #[must_use]
    fn visible_receiver_playback_at(&self, now: Instant) -> Option<TeacherPlaybackCounters> {
        let selected = self.classroom.selected()?;
        self.playback.as_ref()?.visible(selected, now)
    }

    pub fn set_file_pull_context(&mut self, context: TeacherFilePullContext) {
        if self.file_pull_context.as_ref().is_some_and(|current| {
            (current.source_id, current.control_session_id)
                != (context.source_id, context.control_session_id)
        }) || !classmesh_protocol::file_transfer::file_transfer_pull_available(
            context.version,
            &context.capabilities,
        ) {
            self.staged_file_candidate = None;
        }
        self.file_pull_context = Some(context);
    }

    pub fn clear_file_pull_context(&mut self) {
        self.file_pull_context = None;
        self.staged_file_candidate = None;
    }

    pub fn set_staged_file_candidate(&mut self, candidate: TeacherStagedFileCandidate) {
        self.staged_file_candidate = Some(candidate);
    }

    pub fn clear_staged_file_candidate(&mut self) {
        self.staged_file_candidate = None;
    }

    pub fn set_presentation_snapshot(&mut self, snapshot: PresentationRuntimeSnapshot) {
        let next = TeacherPresentationViewModel::state(snapshot);
        if self.playback.as_ref().is_some_and(|current| {
            let bound = current.binding();
            presentation_change_retires_playback(
                self.presentation.binding,
                next.binding,
                PresentationBindingView {
                    presentation_id: bound.presentation_id,
                    stream_id: bound.stream_id,
                    epoch: bound.epoch,
                },
            )
        }) {
            self.playback = None;
        }
        self.presentation = next;
    }

    pub fn update_diagnostics(
        &mut self,
        snapshot: DeviceDiagnosticsSnapshot<'_>,
    ) -> Result<(), DeviceDiagnosticsError> {
        let view = self.diagnostics_model.project(snapshot)?;
        if self.diagnostics.as_ref().map(|current| current.source_id) != Some(view.source_id) {
            self.diagnostics_draft = DiagnosticsOverrideDraft::default();
            self.retire_pending_diagnostics_override();
            if self
                .playback
                .as_ref()
                .is_some_and(|p| p.source_id() != view.source_id)
            {
                self.playback = None;
            }
        }
        self.diagnostics = Some(view);
        Ok(())
    }

    fn retire_pending_diagnostics_override(&mut self) {
        // A newly authenticated snapshot for the same source must not revive
        // an intent queued before the old snapshot was revoked (ABA).
        // Preserve local Automatic cleanup, including during disconnects.
        if matches!(
            self.pending_action.as_ref(),
            Some(TeacherUiAction::Diagnostics(action))
                if !matches!(
                    action.request,
                    crate::device_diagnostics::TroubleshootingOverrideRequest::Automatic
                )
        ) {
            self.pending_action = None;
        }
    }

    pub fn clear_diagnostics(&mut self) {
        self.diagnostics = None;
        self.retire_pending_diagnostics_override();
        // The trusted source was removed; never resurrect previously
        // authenticated counters after a new device snapshot appears.
        self.playback = None;
        self.diagnostics_draft = DiagnosticsOverrideDraft::default();
    }

    /// A queued Focus intent is only a UI hint. Recheck the current
    /// selection and observed session state at handoff; the engine still
    /// performs its authoritative live permission and session checks.
    fn focus_action_still_current(&self, focus: crate::ui_shell::TeacherFocusUiAction) -> bool {
        let source_id = focus.source_id();
        if self.classroom.selected() != Some(source_id) {
            return false;
        }
        let Some(row) = self
            .classroom
            .rows()
            .into_iter()
            .find(|row| row.source_id == source_id)
        else {
            return false;
        };
        match focus {
            crate::ui_shell::TeacherFocusUiAction::RequestInteractive { .. } => {
                self.teacher_interaction_context
                    .as_ref()
                    .is_some_and(|context| {
                        context.control_session_id != 0 && context.source_id == source_id
                    })
                    && !row.interactive_active
                    && row.health.presence == classmesh_core::presence::PresenceState::Online
                    && row.health.service_ready
                    && row.health.worker_ready
            }
            // Returning to local monitoring is still useful during a
            // disconnect; never require network readiness for cleanup.
            crate::ui_shell::TeacherFocusUiAction::ResumeThumbnail { .. } => row.interactive_active,
        }
    }

    #[must_use]
    pub fn take_pending_action(&mut self) -> Option<TeacherUiAction> {
        let action = self.pending_action.take()?;
        if let TeacherUiAction::Focus(focus) = &action {
            if !self.focus_action_still_current(*focus) {
                return None;
            }
        }
        if let TeacherUiAction::TeacherInteraction(interaction) = &action {
            validate_teacher_interaction_ui_action(
                interaction,
                &self.classroom,
                self.teacher_interaction_context.as_ref(),
            )
            .ok()?;
        }
        // The Diagnostics page checks readiness when clicked, but a queued
        // override can outlive selection or device health changes. Retire it
        // before engine handoff, while still allowing offline Automatic reset.
        // The engine remains responsible for authoritative authorization and
        // physical-path evidence at apply time.
        if let TeacherUiAction::Diagnostics(diagnostics) = &action {
            // The click was offered by a selected, visible diagnostics snapshot.
            // Revoking/replacing that snapshot must retire queued non-cleanup
            // overrides even when the classroom row still reports Online.
            // Automatic remains a local cleanup request during disconnects.
            let cleanup = matches!(
                diagnostics.request,
                crate::device_diagnostics::TroubleshootingOverrideRequest::Automatic
            );
            if (!cleanup
                && self.diagnostics.as_ref().map(|view| view.source_id)
                    != Some(diagnostics.source_id))
                || self.classroom.selected() != Some(diagnostics.source_id)
                || !self.classroom.rows().into_iter().any(|row| {
                    row.source_id == diagnostics.source_id
                        && crate::ui_diagnostics::override_action_available(
                            diagnostics.request,
                            row.health,
                            false,
                        )
                })
            {
                return None;
            }
        }
        // UI snapshots are not authorization, but a newer local lifecycle
        // observation must retire obsolete Start/Stop intents before handoff.
        // The actual presentation lifecycle still revalidates at apply time.
        if let TeacherUiAction::Presentation(presentation) = &action {
            let current = self.presentation.binding;
            let still_current = match presentation {
                crate::ui_shell::TeacherPresentationUiAction::Start => current.is_none(),
                crate::ui_shell::TeacherPresentationUiAction::Stop { binding } => {
                    current == Some(*binding)
                }
            };
            if !still_current {
                return None;
            }
        }
        if let TeacherUiAction::FilePull(pull) = &action {
            validate_file_pull_action(
                pull,
                self.classroom.selected(),
                self.file_pull_context.as_ref(),
            )
            .ok()?;
            // The selected session may still be valid after its trusted staged
            // offer was revoked or replaced. A queued click must not outlive
            // that exact transfer/source offer. Runtime authorization is still
            // independently enforced at the authenticated QUIC boundary.
            let candidate = self.staged_file_candidate?;
            if !staged_file_candidate_ready(
                candidate,
                self.classroom.selected(),
                self.file_pull_context.as_ref(),
            ) || candidate.source_id != pull.source_id
                || candidate.control_session_id != pull.control_session_id
                || pull.request.transfer_id.as_slice() != &candidate.transfer_id[..]
                || pull.request.source_id.as_slice() != &candidate.opaque_source_id[..]
            {
                return None;
            }
        }
        Some(action)
    }

    fn queue_action(&mut self, action: TeacherUiAction) {
        if self.pending_action.is_none() {
            self.pending_action = Some(action);
        }
    }

    fn queue_teacher_interaction_request(&mut self, request: TeacherInteractionUiRequest) {
        let Some(source_id) = self.classroom.selected() else {
            return;
        };
        let Ok(action) = prepare_teacher_interaction_ui_action(
            source_id,
            request,
            &self.classroom,
            self.teacher_interaction_context.as_ref(),
        ) else {
            return;
        };
        self.queue_action(TeacherUiAction::TeacherInteraction(action));
    }

    pub fn queue_file_pull_request(&mut self, transfer_id: [u8; 16], source_id: [u8; 16]) {
        let Some(selected) = self.classroom.selected() else {
            return;
        };
        let Ok(action) = prepare_file_pull_action(
            selected,
            transfer_id,
            source_id,
            self.classroom.selected(),
            self.file_pull_context.as_ref(),
        ) else {
            return;
        };
        self.queue_action(TeacherUiAction::FilePull(action));
    }

    fn navigate(&mut self, section: TeacherUiSection) {
        let _ = self.shell.handle(TeacherUiMessage::Navigate(section));
    }

    fn handle_navigation_shortcuts(&mut self, ctx: &egui::Context) {
        // AltGr is reported as Ctrl+Alt on some Windows keyboard layouts.
        // Require bare Alt so text input and platform shortcuts are untouched.
        let bare_alt = ctx.input(|input| {
            input.modifiers.alt
                && !input.modifiers.ctrl
                && !input.modifiers.shift
                && !input.modifiers.command
                && !input.modifiers.mac_cmd
        });
        if !bare_alt {
            return;
        }

        for (key, section) in [
            (egui::Key::Num1, TeacherUiSection::Classroom),
            (egui::Key::Num2, TeacherUiSection::Focus),
            (egui::Key::Num3, TeacherUiSection::Presentation),
            (egui::Key::Num4, TeacherUiSection::DeviceActions),
            (egui::Key::Num5, TeacherUiSection::Diagnostics),
        ] {
            if ctx.input_mut(|input| input.consume_key(egui::Modifiers::ALT, key)) {
                self.navigate(section);
                break;
            }
        }
    }

    fn navigation(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for (section, label, shortcut) in [
                (TeacherUiSection::Classroom, "Classroom", "Alt+1"),
                (TeacherUiSection::Focus, "Focus", "Alt+2"),
                (TeacherUiSection::Presentation, "Presentation", "Alt+3"),
                (TeacherUiSection::DeviceActions, "Device Actions", "Alt+4"),
                (TeacherUiSection::Diagnostics, "Diagnostics", "Alt+5"),
            ] {
                let selected = self.shell.active_section() == section;
                if ui
                    .selectable_label(selected, label)
                    .on_hover_text(format!("Keyboard shortcut: {shortcut}"))
                    .clicked()
                {
                    self.navigate(section);
                }
            }
        });
    }

    fn section_body(&mut self, ui: &mut egui::Ui) {
        match self.shell.active_section() {
            TeacherUiSection::Classroom => {
                show_classroom(ui, &mut self.shell, &mut self.classroom, &self.monitoring)
            }
            TeacherUiSection::Focus => {
                if let Some(message) =
                    show_focus(ui, &self.classroom, self.pending_action.is_some())
                {
                    if let Some(action) = self.shell.handle(message) {
                        self.queue_action(action);
                    }
                }
            }
            TeacherUiSection::Presentation => {
                if let Some(message) =
                    show_presentation(ui, self.presentation, self.pending_action.is_some())
                {
                    if let Some(action) = self.shell.handle(message) {
                        self.queue_action(action);
                    }
                }
            }
            TeacherUiSection::DeviceActions => {
                if let Some(request) = show_device_actions(
                    ui,
                    self.classroom.selected(),
                    self.teacher_interaction_context.as_ref(),
                    &mut self.teacher_interaction_draft,
                    self.pending_action.is_some(),
                ) {
                    self.queue_teacher_interaction_request(request);
                }
                ui.separator();
                ui.strong("Receive staged file");
                let ready = self.staged_file_candidate.is_some_and(|candidate| {
                    staged_file_candidate_ready(
                        candidate,
                        self.classroom.selected(),
                        self.file_pull_context.as_ref(),
                    )
                });
                if !ready {
                    ui.small("No authorized staged file is available for the selected device.");
                }
                if ui
                    .add_enabled(
                        ready && self.pending_action.is_none(),
                        egui::Button::new("Receive staged file"),
                    )
                    .clicked()
                {
                    if let Some(candidate) = self.staged_file_candidate {
                        self.queue_file_pull_request(
                            candidate.transfer_id,
                            candidate.opaque_source_id,
                        );
                    }
                }
            }
            TeacherUiSection::Diagnostics => {
                let now = Instant::now();
                // Retire stale counters even when the teacher does not
                // interact with the GUI after the last valid report.
                if let Some(delay) = self.classroom.selected().and_then(|source| {
                    self.playback
                        .as_ref()
                        .and_then(|projection| projection.repaint_after_expiry(source, now))
                }) {
                    ui.ctx().request_repaint_after(delay);
                }
                let playback = self.visible_receiver_playback_at(now);
                if let Some(message) = show_diagnostics(
                    ui,
                    self.classroom.selected(),
                    self.diagnostics.as_ref(),
                    playback,
                    &mut self.diagnostics_draft,
                    self.pending_action.is_some(),
                ) {
                    if let Some(action) = self.shell.handle(message) {
                        self.queue_action(action);
                    }
                }
            }
        }
    }
}

// The window can start before any authenticated QUIC session exists. Never
// present an offline console as connected just because the process is running.
// A context injected by a client is not proof of a currently live Service link.
fn control_connection_label(context: Option<&TeacherInteractionUiContext>) -> &'static str {
    match context {
        Some(context) if context.control_session_id != 0 => {
            "Session context bound — live Service connection unverified"
        }
        _ => "Offline — no authenticated control session",
    }
}

impl eframe::App for TeacherEguiShell {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_control_bridge();
        // std::sync::mpsc does not wake egui. Poll while the QUIC-owned
        // bridge exists so idle windows observe disconnects and new sessions.
        if self.control_bridge.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        self.handle_navigation_shortcuts(ctx);
        egui::TopBottomPanel::top("classmesh_teacher_navigation").show(ctx, |ui| {
            self.navigation(ui);
        });

        egui::TopBottomPanel::bottom("classmesh_teacher_connection_status").show(ctx, |ui| {
            ui.small(control_connection_label(
                self.teacher_interaction_context.as_ref(),
            ));
            for (&request_id, &(_, state)) in self.command_status.iter().rev().take(3) {
                let label = match state {
                    None => "Sent over QUIC — no Service ACK",
                    Some(TeacherInteractionState::Accepted) => {
                        "Worker accepted — completion unconfirmed"
                    }
                    Some(TeacherInteractionState::Completed) => "Worker reported completed",
                    Some(TeacherInteractionState::Rejected) => "Worker rejected command",
                    Some(TeacherInteractionState::Failed) => "Worker reported failure",
                    _ => "Invalid command state",
                };
                ui.small(format!("Request {request_id}: {label}"));
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(salt) = section_scroll_salt(self.shell.active_section()) {
                egui::ScrollArea::vertical()
                    .id_salt(salt)
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.section_body(ui));
            } else {
                self.section_body(ui);
            }
        });
    }
}

fn teacher_native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(DEFAULT_WINDOW_SIZE)
            .with_min_inner_size(MIN_WINDOW_SIZE)
            .with_clamp_size_to_monitor_size(true),
        ..Default::default()
    }
}

/// Launch with channels supplied by the authenticated QUIC runtime. The
/// caller must own the session producer and command consumer for the lifetime
/// of this window; the UI never constructs or impersonates a live session.
pub fn run_teacher_ui_with_control_bridge(bridge: TeacherUiControlBridge) -> eframe::Result<()> {
    eframe::run_native(
        APP_TITLE,
        teacher_native_options(),
        Box::new(move |_creation_context| {
            let mut app = TeacherEguiShell::default();
            app.attach_control_bridge(bridge);
            Ok(Box::new(app))
        }),
    )
}

/// Standalone UI remains explicitly disconnected until a real QUIC owner
/// supplies its authenticated control bridge.
pub fn run_teacher_ui() -> eframe::Result<()> {
    eframe::run_native(
        APP_TITLE,
        teacher_native_options(),
        Box::new(|_creation_context| Ok(Box::<TeacherEguiShell>::default())),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use classmesh_core::MediaState;
    use classmesh_core::presence::{DeviceHealth, PresenceState};
    use classmesh_core::transport_topology::TransportTopologyEvidence;
    use classmesh_protocol::Capability;
    use classmesh_protocol::control_wire::TeacherInteractionKind;
    use classmesh_video::monitoring_scheduler::MonitoringSourceId;

    use crate::classroom_view::{ClassroomDeviceRow, ClassroomDeviceSnapshot};
    use crate::device_diagnostics::{DEFAULT_MAX_DIAGNOSTIC_CODES, DeviceDiagnosticsError};
    use crate::ui_shell::{TeacherFocusUiAction, TeacherPresentationUiAction};

    use super::*;

    #[test]
    fn authenticated_bridge_disconnect_retires_context_without_fake_liveness() {
        use std::sync::mpsc::sync_channel;
        let (event_tx, event_rx) = sync_channel(2);
        let (action_tx, _action_rx) = sync_channel(1);
        let mut app = TeacherEguiShell::default();
        app.attach_control_bridge(TeacherUiControlBridge::new(event_rx, action_tx));
        assert!(app.teacher_interaction_context.is_none());
        event_tx
            .send(TeacherUiControlEvent::Authenticated(interaction_context(
                BTreeSet::new(),
            )))
            .unwrap();
        app.poll_control_bridge();
        assert!(app.teacher_interaction_context.is_some());
        event_tx.send(TeacherUiControlEvent::Disconnected).unwrap();
        app.poll_control_bridge();
        assert!(app.teacher_interaction_context.is_none());
        event_tx
            .send(TeacherUiControlEvent::Authenticated(interaction_context(
                BTreeSet::new(),
            )))
            .unwrap();
        drop(event_tx);
        app.poll_control_bridge();
        assert!(app.teacher_interaction_context.is_none());
        assert!(app.control_bridge.is_none());
    }

    #[test]
    fn playback_bridge_requires_exact_authenticated_binding_and_retires_only_exact_owner() {
        use std::sync::mpsc::sync_channel;

        let (event_tx, event_rx) = sync_channel(8);
        let (action_tx, _action_rx) = sync_channel(1);
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.attach_control_bridge(TeacherUiControlBridge::new(event_rx, action_tx));

        // No authenticated QUIC owner: even a plausible media binding is inert.
        event_tx
            .send(TeacherUiControlEvent::PlaybackBound {
                source_id: MonitoringSourceId(7),
                binding: bound_playback(),
            })
            .unwrap();
        app.poll_control_bridge();
        assert!(app.playback.is_none());

        event_tx
            .send(TeacherUiControlEvent::Authenticated(interaction_context(
                BTreeSet::from([Capability::ReceiverPlaybackDiagnostics]),
            )))
            .unwrap();
        event_tx
            .send(TeacherUiControlEvent::PlaybackBound {
                source_id: MonitoringSourceId(8),
                binding: bound_playback(),
            })
            .unwrap();
        app.poll_control_bridge();
        assert!(
            app.playback.is_none(),
            "other-device playback must be rejected"
        );

        event_tx
            .send(TeacherUiControlEvent::PlaybackBound {
                source_id: MonitoringSourceId(7),
                binding: bound_playback(),
            })
            .unwrap();
        app.poll_control_bridge();
        assert!(app.playback.is_some());

        let mut old = bound_playback();
        old.control_session_id += 1;
        event_tx
            .send(TeacherUiControlEvent::PlaybackRetired {
                source_id: MonitoringSourceId(7),
                binding: old,
            })
            .unwrap();
        app.poll_control_bridge();
        assert!(
            app.playback.is_some(),
            "stale teardown must not revoke current playback"
        );

        event_tx
            .send(TeacherUiControlEvent::PlaybackRetired {
                source_id: MonitoringSourceId(7),
                binding: bound_playback(),
            })
            .unwrap();
        app.poll_control_bridge();
        assert!(
            app.playback.is_none(),
            "exact owner teardown must retire playback"
        );
    }

    #[test]
    fn playback_event_adapter_returns_unrelated_control_without_forging_ui_media() {
        let envelope = playback_frame();
        let result = TeacherUiControlEvent::from_verified_session_playback(
            MonitoringSourceId(7),
            TeacherPlaybackSessionEvent::OtherControl(envelope.clone()),
        );
        assert_eq!(*result.unwrap_err(), envelope);
    }

    #[test]
    fn bridge_playback_sample_requires_the_real_verified_quic_proof_type() {
        // No public API may promote a caller-created bare ControlEnvelope to
        // playback; this event must carry the verified, privately constructed
        // result of live authenticated QUIC receive.
        fn event_from_verified(
            source_id: MonitoringSourceId,
            verified: AuthenticatedTeacherControlMessage,
            received_at: Instant,
        ) -> TeacherUiControlEvent {
            TeacherUiControlEvent::VerifiedPlayback {
                source_id,
                verified,
                received_at,
            }
        }
        let _: fn(
            MonitoringSourceId,
            AuthenticatedTeacherControlMessage,
            Instant,
        ) -> TeacherUiControlEvent = event_from_verified;
    }

    #[test]
    fn bridge_backlog_must_not_dispatch_before_terminal_disconnect() {
        use std::sync::mpsc::sync_channel;
        let (event_tx, event_rx) = sync_channel(128);
        let (action_tx, action_rx) = sync_channel(1);
        let mut app = TeacherEguiShell::default();
        app.attach_control_bridge(TeacherUiControlBridge::new(event_rx, action_tx));
        for _ in 0..65 {
            event_tx
                .send(TeacherUiControlEvent::Authenticated(interaction_context(
                    BTreeSet::new(),
                )))
                .unwrap();
        }
        event_tx.send(TeacherUiControlEvent::Disconnected).unwrap();
        app.queue_action(TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7))));
        app.poll_control_bridge();
        assert!(
            action_rx.try_recv().is_err(),
            "must not dispatch while control events remain unread"
        );
        app.poll_control_bridge();
        assert!(app.teacher_interaction_context.is_none());
    }

    #[test]
    fn authenticated_session_rotation_retires_pending_selection() {
        use std::sync::mpsc::sync_channel;
        let (event_tx, event_rx) = sync_channel(4);
        let (action_tx, action_rx) = sync_channel(1);
        action_tx.send(TeacherUiAction::SelectDevice(None)).unwrap();
        let mut app = TeacherEguiShell::default();
        app.attach_control_bridge(TeacherUiControlBridge::new(event_rx, action_tx));
        let first = interaction_context(BTreeSet::new());
        let mut next = interaction_context(BTreeSet::new());
        next.control_session_id = first.control_session_id + 1;
        event_tx
            .send(TeacherUiControlEvent::Authenticated(first))
            .unwrap();
        // Establish the authenticated epoch before queuing a new user intent.
        // An action created offline must be retired at first authentication.
        app.poll_control_bridge();
        assert!(app.teacher_interaction_context.is_some());
        app.queue_action(TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7))));
        app.poll_control_bridge();
        assert!(
            app.pending_action.is_some(),
            "backpressure should retain intent"
        );
        event_tx
            .send(TeacherUiControlEvent::Authenticated(next))
            .unwrap();
        let _ = action_rx.try_recv().unwrap();
        app.poll_control_bridge();
        assert!(
            app.pending_action.is_none(),
            "old session intent must be retired"
        );
        assert!(
            action_rx.try_recv().is_err(),
            "must not forward stale selection"
        );
    }

    #[test]
    fn pre_authenticated_selection_cannot_be_replayed_after_session_establishment() {
        use std::sync::mpsc::sync_channel;
        let (event_tx, event_rx) = sync_channel(2);
        let (action_tx, action_rx) = sync_channel(1);
        let mut app = TeacherEguiShell::default();
        app.attach_control_bridge(TeacherUiControlBridge::new(event_rx, action_tx));

        // An offline selection must not be promoted into an authenticated
        // QUIC session just because the peer connects in a later frame.
        app.queue_action(TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7))));
        app.poll_control_bridge();
        assert!(app.pending_action.is_some());
        assert!(action_rx.try_recv().is_err());

        event_tx
            .send(TeacherUiControlEvent::Authenticated(interaction_context(
                BTreeSet::new(),
            )))
            .unwrap();
        app.poll_control_bridge();
        assert!(app.teacher_interaction_context.is_some());
        assert!(app.pending_action.is_none());
        assert!(
            action_rx.try_recv().is_err(),
            "pre-authentication selection must never cross into the new session"
        );
    }

    #[test]
    fn full_control_channel_retries_only_until_disconnect() {
        use std::sync::mpsc::sync_channel;
        let (event_tx, event_rx) = sync_channel(4);
        let (action_tx, action_rx) = sync_channel(1);
        action_tx.send(TeacherUiAction::SelectDevice(None)).unwrap();
        let mut app = TeacherEguiShell::default();
        app.attach_control_bridge(TeacherUiControlBridge::new(event_rx, action_tx));
        event_tx
            .send(TeacherUiControlEvent::Authenticated(interaction_context(
                BTreeSet::new(),
            )))
            .unwrap();
        // Backpressure applies to commands queued in an already authenticated
        // epoch, not stale pre-authentication commands (which must be dropped).
        app.poll_control_bridge();
        assert!(app.teacher_interaction_context.is_some());
        app.queue_action(TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7))));
        app.poll_control_bridge();
        assert!(
            app.pending_action.is_some(),
            "full channel must not silently drop an intent"
        );
        let _ = action_rx.try_recv().unwrap();
        app.poll_control_bridge();
        assert!(matches!(
            action_rx.try_recv(),
            Ok(TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7))))
        ));
        assert!(app.pending_action.is_none());
        action_rx.try_recv().err(); // channel is now empty
        app.queue_action(TeacherUiAction::SelectDevice(Some(MonitoringSourceId(8))));
        event_tx.send(TeacherUiControlEvent::Disconnected).unwrap();
        app.poll_control_bridge();
        assert!(app.teacher_interaction_context.is_none());
        assert!(
            app.pending_action.is_none(),
            "disconnect must retire queued intents"
        );
        assert!(
            action_rx.try_recv().is_err(),
            "disconnect must not forward stale intent"
        );
    }

    #[test]
    fn native_window_status_never_claims_control_without_authenticated_session() {
        assert_eq!(
            control_connection_label(None),
            "Offline — no authenticated control session"
        );
        let mut context = interaction_context(BTreeSet::new());
        context.control_session_id = 0;
        assert_eq!(
            control_connection_label(Some(&context)),
            "Offline — no authenticated control session"
        );
        context.control_session_id = 77;
        assert_eq!(
            control_connection_label(Some(&context)),
            "Session context bound — live Service connection unverified"
        );
    }

    fn send_navigation_key(
        app: &mut TeacherEguiShell,
        key: egui::Key,
        modifiers: egui::Modifiers,
        pressed: bool,
    ) {
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            modifiers,
            events: vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers,
            }],
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| app.handle_navigation_shortcuts(ctx));
    }

    #[test]
    fn alt_digit_shortcuts_navigate_all_five_teacher_sections() {
        let mut app = TeacherEguiShell::default();
        for (key, expected) in [
            (egui::Key::Num2, TeacherUiSection::Focus),
            (egui::Key::Num3, TeacherUiSection::Presentation),
            (egui::Key::Num4, TeacherUiSection::DeviceActions),
            (egui::Key::Num5, TeacherUiSection::Diagnostics),
            (egui::Key::Num1, TeacherUiSection::Classroom),
        ] {
            send_navigation_key(&mut app, key, egui::Modifiers::ALT, true);
            assert_eq!(app.shell.active_section(), expected);
        }
    }

    #[test]
    fn navigation_shortcuts_do_not_intercept_typing_or_altgr() {
        let mut app = TeacherEguiShell::default();
        app.navigate(TeacherUiSection::Diagnostics);
        for modifiers in [
            egui::Modifiers::NONE,
            egui::Modifiers::CTRL,
            egui::Modifiers::SHIFT,
            egui::Modifiers {
                alt: true,
                ctrl: true,
                ..Default::default()
            },
            egui::Modifiers {
                alt: true,
                shift: true,
                ..Default::default()
            },
        ] {
            send_navigation_key(&mut app, egui::Key::Num1, modifiers, true);
            assert_eq!(app.shell.active_section(), TeacherUiSection::Diagnostics);
        }
        send_navigation_key(&mut app, egui::Key::Num1, egui::Modifiers::ALT, false);
        assert_eq!(app.shell.active_section(), TeacherUiSection::Diagnostics);
    }

    #[test]
    fn long_teacher_sections_have_a_scroll_owner_at_the_minimum_viewport() {
        // Classroom owns its own responsive scroll area; other sections
        // must remain reachable when their content exceeds 420 points.
        assert_eq!(section_scroll_salt(TeacherUiSection::Classroom), None);
        let mut unique_scroll_ids = BTreeSet::new();
        for section in [
            TeacherUiSection::Focus,
            TeacherUiSection::Presentation,
            TeacherUiSection::DeviceActions,
            TeacherUiSection::Diagnostics,
        ] {
            let salt = section_scroll_salt(section).expect("section must scroll");
            assert!(
                unique_scroll_ids.insert(salt),
                "{section:?} reused a scroll ID"
            );
        }
    }

    #[test]
    fn queued_presentation_start_is_dropped_if_a_stream_appears_before_handoff() {
        let mut app = TeacherEguiShell::default();
        app.queue_action(TeacherUiAction::Presentation(
            TeacherPresentationUiAction::Start,
        ));
        app.set_presentation_snapshot(PresentationRuntimeSnapshot {
            binding: Some(crate::presentation_view::PresentationBindingView {
                presentation_id: 9,
                stream_id: 4,
                epoch: 1,
            }),
            ..PresentationRuntimeSnapshot::default()
        });
        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn queued_presentation_stop_is_dropped_if_binding_changes_or_stops() {
        let original = crate::presentation_view::PresentationBindingView {
            presentation_id: 9,
            stream_id: 4,
            epoch: 1,
        };
        for replacement in [
            Some(crate::presentation_view::PresentationBindingView {
                epoch: 2,
                ..original
            }),
            None,
        ] {
            let mut app = TeacherEguiShell::default();
            app.set_presentation_snapshot(PresentationRuntimeSnapshot {
                binding: Some(original),
                ..PresentationRuntimeSnapshot::default()
            });
            app.queue_action(TeacherUiAction::Presentation(
                TeacherPresentationUiAction::Stop { binding: original },
            ));
            app.set_presentation_snapshot(PresentationRuntimeSnapshot {
                binding: replacement,
                ..PresentationRuntimeSnapshot::default()
            });
            assert_eq!(app.take_pending_action(), None);
        }
    }

    #[test]
    fn queued_presentation_actions_survive_when_runtime_binding_is_unchanged() {
        let mut app = TeacherEguiShell::default();
        let start = TeacherUiAction::Presentation(TeacherPresentationUiAction::Start);
        app.queue_action(start.clone());
        assert_eq!(app.take_pending_action(), Some(start));

        let binding = crate::presentation_view::PresentationBindingView {
            presentation_id: 9,
            stream_id: 4,
            epoch: 1,
        };
        app.set_presentation_snapshot(PresentationRuntimeSnapshot {
            binding: Some(binding),
            ..PresentationRuntimeSnapshot::default()
        });
        let stop = TeacherUiAction::Presentation(TeacherPresentationUiAction::Stop { binding });
        app.queue_action(stop.clone());
        assert_eq!(app.take_pending_action(), Some(stop));
    }

    #[test]
    fn queued_focus_start_requires_nonzero_control_session_at_handoff() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let start = TeacherUiAction::Focus(TeacherFocusUiAction::RequestInteractive {
            source_id: MonitoringSourceId(7),
        });
        app.queue_action(start.clone());
        assert_eq!(
            app.take_pending_action(),
            None,
            "offline UI cannot start focus"
        );

        let mut zero = interaction_context(BTreeSet::new());
        zero.control_session_id = 0;
        app.set_teacher_interaction_context(zero);
        app.queue_action(start.clone());
        assert_eq!(
            app.take_pending_action(),
            None,
            "zero session is not authorized"
        );

        app.set_teacher_interaction_context(interaction_context(BTreeSet::new()));
        app.queue_action(start.clone());
        assert_eq!(app.take_pending_action(), Some(start));
    }

    #[test]
    fn queued_focus_start_rejects_session_bound_to_different_device() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let mut other = interaction_context(BTreeSet::new());
        other.source_id = MonitoringSourceId(8);
        app.set_teacher_interaction_context(other);
        app.queue_action(TeacherUiAction::Focus(
            TeacherFocusUiAction::RequestInteractive {
                source_id: MonitoringSourceId(7),
            },
        ));
        assert_eq!(
            app.take_pending_action(),
            None,
            "a session for another device must never authorize focus"
        );
    }

    #[test]
    fn queued_focus_start_is_retired_on_control_session_replacement_but_not_refresh() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let old = interaction_context(BTreeSet::new());
        app.set_teacher_interaction_context(old.clone());
        let start = TeacherUiAction::Focus(TeacherFocusUiAction::RequestInteractive {
            source_id: MonitoringSourceId(7),
        });
        app.queue_action(start.clone());
        app.set_teacher_interaction_context(old);
        assert_eq!(app.take_pending_action(), Some(start.clone()));

        app.queue_action(start);
        let mut replacement = interaction_context(BTreeSet::new());
        replacement.control_session_id = 78;
        app.set_teacher_interaction_context(replacement);
        assert_eq!(
            app.take_pending_action(),
            None,
            "a queued Focus start must not survive a new control session"
        );
    }

    #[test]
    fn queued_focus_intent_is_retired_on_disconnect_but_new_offline_cleanup_is_allowed() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::new()));
        let start = TeacherUiAction::Focus(TeacherFocusUiAction::RequestInteractive {
            source_id: MonitoringSourceId(7),
        });
        app.queue_action(start);
        app.clear_teacher_interaction_context();
        assert_eq!(app.take_pending_action(), None);

        app.classroom
            .upsert(ClassroomDeviceSnapshot {
                source_id: MonitoringSourceId(7),
                display_name: "Student 07".to_owned(),
                health: DeviceHealth {
                    presence: PresenceState::Offline,
                    media: MediaState::Recovering,
                    service_ready: false,
                    worker_ready: false,
                },
                quality_tier: None,
                thumbnail_available: false,
                interactive_active: true,
            })
            .unwrap();
        let cleanup = TeacherUiAction::Focus(TeacherFocusUiAction::ResumeThumbnail {
            source_id: MonitoringSourceId(7),
        });
        app.queue_action(cleanup.clone());
        assert_eq!(app.take_pending_action(), Some(cleanup));
    }

    #[test]
    fn queued_focus_start_is_dropped_after_selection_or_device_readiness_changes() {
        for (presence, service_ready, worker_ready, selected) in [
            (PresenceState::Offline, true, true, true),
            (PresenceState::Connecting, true, true, true),
            (PresenceState::ControlRecovering, true, true, true),
            (PresenceState::Online, false, true, true),
            (PresenceState::Online, true, false, true),
            (PresenceState::Online, true, true, false),
        ] {
            let mut app = TeacherEguiShell::default();
            select_test_device(&mut app);
            app.queue_action(TeacherUiAction::Focus(
                TeacherFocusUiAction::RequestInteractive {
                    source_id: MonitoringSourceId(7),
                },
            ));
            if selected {
                app.classroom
                    .upsert(ClassroomDeviceSnapshot {
                        source_id: MonitoringSourceId(7),
                        display_name: "Student 07".to_owned(),
                        health: DeviceHealth {
                            presence,
                            media: MediaState::Recovering,
                            service_ready,
                            worker_ready,
                        },
                        quality_tier: None,
                        thumbnail_available: false,
                        interactive_active: false,
                    })
                    .unwrap();
            } else {
                app.classroom.select(None).unwrap();
            }
            assert_eq!(
                app.take_pending_action(),
                None,
                "stale Focus start must be retired: {presence:?}, service={service_ready}, worker={worker_ready}, selected={selected}"
            );
        }
    }

    #[test]
    fn queued_focus_handoff_requires_matching_interactive_state_but_allows_offline_resume() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        // Focus requests are legal only with a nonzero bound control session.
        // The separate offline test verifies that missing/zero sessions deny.
        app.set_teacher_interaction_context(interaction_context(BTreeSet::new()));
        let start = TeacherUiAction::Focus(TeacherFocusUiAction::RequestInteractive {
            source_id: MonitoringSourceId(7),
        });
        app.queue_action(start.clone());
        assert_eq!(app.take_pending_action(), Some(start.clone()));

        let resume = TeacherUiAction::Focus(TeacherFocusUiAction::ResumeThumbnail {
            source_id: MonitoringSourceId(7),
        });
        app.queue_action(resume.clone());
        assert_eq!(
            app.take_pending_action(),
            None,
            "no active session to resume"
        );

        app.classroom
            .upsert(ClassroomDeviceSnapshot {
                source_id: MonitoringSourceId(7),
                display_name: "Student 07".to_owned(),
                health: DeviceHealth {
                    presence: PresenceState::Offline,
                    media: MediaState::Recovering,
                    service_ready: false,
                    worker_ready: false,
                },
                quality_tier: None,
                thumbnail_available: false,
                interactive_active: true,
            })
            .unwrap();
        app.queue_action(resume.clone());
        assert_eq!(app.take_pending_action(), Some(resume));
        app.queue_action(start);
        assert_eq!(
            app.take_pending_action(),
            None,
            "active session must not start twice"
        );
    }

    #[test]
    fn teacher_ui_viewport_has_explicit_default_and_minimum_size() {
        let options = teacher_native_options();

        assert_eq!(
            options.viewport.inner_size,
            Some(egui::vec2(DEFAULT_WINDOW_SIZE[0], DEFAULT_WINDOW_SIZE[1]))
        );
        assert_eq!(
            options.viewport.min_inner_size,
            Some(egui::vec2(MIN_WINDOW_SIZE[0], MIN_WINDOW_SIZE[1]))
        );
        assert_eq!(options.viewport.clamp_size_to_monitor_size, Some(true));
    }

    #[test]
    fn presentation_snapshot_is_projected_through_existing_11d_view_model() {
        let mut app = TeacherEguiShell::default();
        app.set_presentation_snapshot(PresentationRuntimeSnapshot {
            binding: Some(crate::presentation_view::PresentationBindingView {
                presentation_id: 700,
                stream_id: 800,
                epoch: 4,
            }),
            profile: Some(crate::presentation_view::PresentationProfileView {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_bps: 2_500_000,
            }),
            metrics: crate::presentation_view::PresentationMetricsView {
                encoded_frames: 12,
                ..crate::presentation_view::PresentationMetricsView::default()
            },
        });

        assert_eq!(
            app.presentation.media_state,
            classmesh_core::MediaState::Streaming
        );
        assert_eq!(app.presentation.binding.unwrap().presentation_id, 700);
        assert_eq!(app.presentation.metrics.encoded_frames, 12);
    }

    #[test]
    fn diagnostics_projection_enforces_11e_code_bound_before_storage() {
        let mut app = TeacherEguiShell::default();
        let row = ClassroomDeviceRow {
            source_id: MonitoringSourceId(7),
            display_name: "Student 07".into(),
            health: DeviceHealth {
                presence: PresenceState::Online,
                media: MediaState::Recovering,
                worker_ready: true,
                service_ready: true,
            },
            quality_tier: None,
            thumbnail_available: true,
            interactive_active: false,
            selected: true,
        };
        let codes = ["diagnostic.code"; DEFAULT_MAX_DIAGNOSTIC_CODES + 1];

        assert_eq!(
            app.update_diagnostics(DeviceDiagnosticsSnapshot {
                device: &row,
                quality_sample: None,
                active_path: None,
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &codes,
            }),
            Err(DeviceDiagnosticsError::TooManyDiagnosticCodes)
        );
        assert!(app.diagnostics.is_none());
    }

    fn select_test_device(app: &mut TeacherEguiShell) {
        app.classroom
            .upsert(ClassroomDeviceSnapshot {
                source_id: MonitoringSourceId(7),
                display_name: "Student 07".to_owned(),
                health: DeviceHealth {
                    presence: PresenceState::Online,
                    media: MediaState::Idle,
                    worker_ready: true,
                    service_ready: true,
                },
                quality_tier: None,
                thumbnail_available: true,
                interactive_active: false,
            })
            .unwrap();
        app.classroom.select(Some(MonitoringSourceId(7))).unwrap();
    }

    fn interaction_context(capabilities: BTreeSet<Capability>) -> TeacherInteractionUiContext {
        TeacherInteractionUiContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities,
        }
    }

    fn bound_playback() -> TeacherPlaybackBinding {
        TeacherPlaybackBinding {
            control_session_id: 77,
            presentation_id: 25,
            stream_id: 12,
            epoch: 2,
        }
    }

    fn playback_frame() -> ControlEnvelope {
        use classmesh_protocol::control_wire::{
            ProtocolVersion, ReceiverPlaybackDiagnostic, control_envelope,
        };
        ControlEnvelope {
            control_session_id: 77,
            sequence: 9,
            protocol_version: Some(ProtocolVersion { major: 0, minor: 8 }),
            request_id: 0,
            payload: Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(
                ReceiverPlaybackDiagnostic {
                    presentation_id: 25,
                    stream_id: 12,
                    epoch: 2,
                    receiver_generation: 3,
                    sequence: 1,
                    interval_ms: 5_000,
                    authenticated_frames: 100,
                    rejected_frames: 0,
                    decoded_frames: 92,
                    presented_frames: 90,
                    present_errors: 1,
                    decode_errors: 2,
                    keyframe_waits: 0,
                    queue_drops: 1,
                },
            )),
        }
    }

    #[test]
    fn teacher_ui_displays_only_authenticated_selected_and_fresh_receiver_playback() {
        use std::time::Duration;
        let now = Instant::now();
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::ReceiverPlaybackDiagnostics,
        ])));
        assert_eq!(app.visible_receiver_playback_at(now), None);
        app.set_receiver_playback_context(MonitoringSourceId(7), bound_playback())
            .unwrap();
        let sample = app
            .accept_authenticated_receiver_playback(&playback_frame(), now)
            .unwrap();
        assert_eq!(sample.presented_frames, 90);
        assert_eq!(sample.queue_drops, 1);
        assert_eq!(app.visible_receiver_playback_at(now), Some(sample));
        app.classroom.select(None).unwrap();
        assert_eq!(app.visible_receiver_playback_at(now), None);
        app.classroom.select(Some(MonitoringSourceId(7))).unwrap();
        assert_eq!(
            app.visible_receiver_playback_at(now + Duration::from_secs(11)),
            None
        );
        assert_eq!(
            app.accept_authenticated_receiver_playback(
                &playback_frame(),
                now + Duration::from_secs(12)
            ),
            Err(TeacherPlaybackDiagnosticError::Replay)
        );
        assert_eq!(
            app.visible_receiver_playback_at(now + Duration::from_secs(12)),
            None
        );
    }

    #[test]
    fn presentation_epoch_change_and_stop_discard_previous_receiver_playback() {
        use crate::presentation_view::PresentationBindingView;
        use classmesh_protocol::control_wire::control_envelope;
        let now = Instant::now();
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let mut snapshot = PresentationRuntimeSnapshot {
            binding: Some(PresentationBindingView {
                presentation_id: 25,
                stream_id: 12,
                epoch: 2,
            }),
            ..PresentationRuntimeSnapshot::default()
        };
        app.set_presentation_snapshot(snapshot);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::ReceiverPlaybackDiagnostics,
        ])));
        app.set_receiver_playback_context(MonitoringSourceId(7), bound_playback())
            .unwrap();
        let accepted = app
            .accept_authenticated_receiver_playback(&playback_frame(), now)
            .unwrap();
        assert_eq!(app.visible_receiver_playback_at(now), Some(accepted));

        // Same presentation, ordinary metrics refresh: preserve the data.
        snapshot.metrics.encoded_frames = 42;
        app.set_presentation_snapshot(snapshot);
        assert_eq!(app.visible_receiver_playback_at(now), Some(accepted));

        // Rekeying the same stream is a new binding even with the same
        // source, principal, control session and other identifiers.
        snapshot.binding.as_mut().unwrap().epoch += 1;
        app.set_presentation_snapshot(snapshot);
        assert_eq!(app.visible_receiver_playback_at(now), None);
        assert_eq!(
            app.accept_authenticated_receiver_playback(&playback_frame(), now),
            Err(TeacherPlaybackDiagnosticError::Inactive)
        );

        let mut next_binding = bound_playback();
        next_binding.epoch += 1;
        let mut next_frame = playback_frame();
        if let Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(ref mut report)) =
            next_frame.payload
        {
            report.epoch += 1;
        }
        app.set_receiver_playback_context(MonitoringSourceId(7), next_binding)
            .unwrap();
        app.accept_authenticated_receiver_playback(&next_frame, now)
            .unwrap();
        assert!(app.visible_receiver_playback_at(now).is_some());
        app.set_presentation_snapshot(PresentationRuntimeSnapshot::default());
        assert_eq!(app.visible_receiver_playback_at(now), None);
    }

    #[test]
    fn disconnect_discards_receiver_playback_binding_and_counters() {
        let now = Instant::now();
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let context =
            interaction_context(BTreeSet::from([Capability::ReceiverPlaybackDiagnostics]));
        app.set_teacher_interaction_context(context.clone());
        app.set_receiver_playback_context(MonitoringSourceId(7), bound_playback())
            .unwrap();
        app.accept_authenticated_receiver_playback(&playback_frame(), now)
            .unwrap();
        assert!(app.playback.is_some());
        app.clear_teacher_interaction_context();
        assert!(
            app.playback.is_none(),
            "disconnect must erase old playback ledger"
        );
        app.set_teacher_interaction_context(context);
        assert_eq!(app.visible_receiver_playback_at(now), None);
    }

    #[test]
    fn clearing_diagnostics_erases_previous_authenticated_playback() {
        let now = Instant::now();
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::ReceiverPlaybackDiagnostics,
        ])));
        app.set_receiver_playback_context(MonitoringSourceId(7), bound_playback())
            .unwrap();
        app.accept_authenticated_receiver_playback(&playback_frame(), now)
            .unwrap();
        assert!(app.visible_receiver_playback_at(now).is_some());
        app.clear_diagnostics();
        assert!(app.visible_receiver_playback_at(now).is_none());
    }

    #[test]
    fn teacher_ui_rejects_legacy_and_changed_context_and_stale_teardown() {
        let now = Instant::now();
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::new()));
        assert_eq!(
            app.set_receiver_playback_context(MonitoringSourceId(7), bound_playback()),
            Err(TeacherPlaybackDiagnosticError::NotNegotiated)
        );
        assert_eq!(app.visible_receiver_playback_at(now), None);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::ReceiverPlaybackDiagnostics,
        ])));
        app.set_receiver_playback_context(MonitoringSourceId(7), bound_playback())
            .unwrap();
        app.accept_authenticated_receiver_playback(&playback_frame(), now)
            .unwrap();
        let mut stale = bound_playback();
        stale.control_session_id = 76;
        assert!(!app.revoke_receiver_playback_context(MonitoringSourceId(7), stale));
        assert!(app.visible_receiver_playback_at(now).is_some());
        let mut changed =
            interaction_context(BTreeSet::from([Capability::ReceiverPlaybackDiagnostics]));
        changed.control_session_id = 78;
        app.set_teacher_interaction_context(changed);
        assert_eq!(app.visible_receiver_playback_at(now), None);
        assert_eq!(
            app.accept_authenticated_receiver_playback(&playback_frame(), now),
            Err(TeacherPlaybackDiagnosticError::Inactive)
        );
        let mut old =
            interaction_context(BTreeSet::from([Capability::ReceiverPlaybackDiagnostics]));
        old.version.minor = 7;
        app.set_teacher_interaction_context(old);
        assert_eq!(
            app.set_receiver_playback_context(MonitoringSourceId(7), bound_playback()),
            Err(TeacherPlaybackDiagnosticError::NotNegotiated)
        );
    }

    #[test]
    fn control_session_change_resets_teacher_interaction_draft_and_stales_pending_action() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));

        let mut reconnected = interaction_context(BTreeSet::from([Capability::TeacherMessage]));
        reconnected.control_session_id = 78;
        app.set_teacher_interaction_context(reconnected);

        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn queued_teacher_message_cannot_cross_session_rebind_or_disconnect() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let old = interaction_context(BTreeSet::from([Capability::TeacherMessage]));
        app.set_teacher_interaction_context(old.clone());
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "old session".to_owned(),
        ));
        let mut next = old.clone();
        next.control_session_id = 78;
        app.set_teacher_interaction_context(next);
        assert_eq!(app.take_pending_action(), None);

        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "disconnected".to_owned(),
        ));
        app.clear_teacher_interaction_context();
        app.set_teacher_interaction_context(old);
        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn device_action_queue_builds_only_valid_source_bound_protocol_action() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));

        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "Class starts now.".to_owned(),
        ));

        let Some(TeacherUiAction::TeacherInteraction(action)) = app.take_pending_action() else {
            panic!("expected Teacher interaction action");
        };
        assert_eq!(action.source_id, MonitoringSourceId(7));
        assert_eq!(
            classmesh_protocol::teacher_interaction::validate_request(&action.request),
            Ok(TeacherInteractionKind::Message)
        );
    }

    #[test]
    fn device_action_queue_fails_closed_for_missing_or_stale_context() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);

        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));
        assert_eq!(app.take_pending_action(), None);

        app.set_teacher_interaction_context(TeacherInteractionUiContext {
            source_id: MonitoringSourceId(8),
            control_session_id: 88,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::TeacherMessage]),
        });
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));
        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn device_action_queue_respects_exact_open_target_capability() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));

        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::App(
            classmesh_protocol::control_wire::AppIdentity::Calculator,
        ));
        assert_eq!(app.take_pending_action(), None);

        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::OpenTarget,
        ])));
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::App(
            classmesh_protocol::control_wire::AppIdentity::Calculator,
        ));
        assert!(matches!(
            app.take_pending_action(),
            Some(TeacherUiAction::TeacherInteraction(_))
        ));
    }

    #[test]
    fn queued_teacher_interaction_is_revalidated_at_dispatch_handoff() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));

        app.classroom.select(None).unwrap();
        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn queued_teacher_interaction_is_dropped_if_capability_changes_before_handoff() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));

        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::OpenTarget,
        ])));
        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn file_pull_handoff_rechecks_exact_selection_session_and_capability() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let context = TeacherFilePullContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
        };
        app.set_file_pull_context(context.clone());
        app.set_staged_file_candidate(TeacherStagedFileCandidate {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            transfer_id: [1; 16],
            opaque_source_id: [2; 16],
        });
        app.queue_file_pull_request([1; 16], [2; 16]);
        app.set_file_pull_context(TeacherFilePullContext {
            control_session_id: 78,
            ..context.clone()
        });
        assert_eq!(app.take_pending_action(), None);

        app.set_file_pull_context(context.clone());
        app.set_staged_file_candidate(TeacherStagedFileCandidate {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            transfer_id: [1; 16],
            opaque_source_id: [2; 16],
        });
        app.queue_file_pull_request([1; 16], [2; 16]);
        app.classroom.select(None).unwrap();
        assert_eq!(app.take_pending_action(), None);

        app.classroom.select(Some(MonitoringSourceId(7))).unwrap();
        app.set_file_pull_context(context);
        app.set_staged_file_candidate(TeacherStagedFileCandidate {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            transfer_id: [1; 16],
            opaque_source_id: [2; 16],
        });
        app.queue_file_pull_request([1; 16], [2; 16]);
        assert!(matches!(
            app.take_pending_action(),
            Some(TeacherUiAction::FilePull(_))
        ));
    }

    #[test]
    fn queued_file_pull_is_retired_if_trusted_staged_candidate_is_revoked_or_replaced() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let context = TeacherFilePullContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
        };
        let candidate = TeacherStagedFileCandidate {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            transfer_id: [1; 16],
            opaque_source_id: [2; 16],
        };
        app.set_file_pull_context(context);
        app.set_staged_file_candidate(candidate);
        app.queue_file_pull_request(candidate.transfer_id, candidate.opaque_source_id);
        app.clear_staged_file_candidate();
        assert_eq!(
            app.take_pending_action(),
            None,
            "revoked offer must not dispatch"
        );

        app.set_staged_file_candidate(candidate);
        app.queue_file_pull_request(candidate.transfer_id, candidate.opaque_source_id);
        app.set_staged_file_candidate(TeacherStagedFileCandidate {
            transfer_id: [3; 16],
            ..candidate
        });
        assert_eq!(
            app.take_pending_action(),
            None,
            "replaced offer must not dispatch"
        );

        app.set_staged_file_candidate(candidate);
        app.queue_file_pull_request(candidate.transfer_id, candidate.opaque_source_id);
        assert!(matches!(
            app.take_pending_action(),
            Some(TeacherUiAction::FilePull(_))
        ));
    }

    #[test]
    fn reconnect_discards_staged_candidate_and_never_reactivates_it() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let context = TeacherFilePullContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
        };
        let candidate = TeacherStagedFileCandidate {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            transfer_id: [1; 16],
            opaque_source_id: [2; 16],
        };
        app.set_file_pull_context(context.clone());
        app.set_staged_file_candidate(candidate);
        assert_eq!(app.staged_file_candidate, Some(candidate));
        app.set_file_pull_context(TeacherFilePullContext {
            control_session_id: 78,
            ..context.clone()
        });
        assert_eq!(app.staged_file_candidate, None);
        app.set_file_pull_context(context);
        assert_eq!(app.staged_file_candidate, None);
    }

    #[test]
    fn revoked_file_transfer_capability_discards_staged_candidate() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let context = TeacherFilePullContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
        };
        let candidate = TeacherStagedFileCandidate {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            transfer_id: [1; 16],
            opaque_source_id: [2; 16],
        };
        app.set_file_pull_context(context.clone());
        app.set_staged_file_candidate(candidate);
        let mut revoked = context.clone();
        revoked.capabilities.clear();
        app.set_file_pull_context(revoked);
        assert_eq!(app.staged_file_candidate, None);
        app.set_file_pull_context(context);
        assert_eq!(app.staged_file_candidate, None);
    }

    #[test]
    fn queued_diagnostics_override_is_retired_on_control_session_rotation() {
        use crate::device_diagnostics::TroubleshootingOverrideRequest;
        use crate::ui_shell::TeacherDiagnosticsUiAction;

        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let row = app
            .classroom
            .rows()
            .into_iter()
            .find(|row| row.source_id == MonitoringSourceId(7))
            .expect("selected classroom row");
        let refresh = |app: &mut TeacherEguiShell| {
            app.update_diagnostics(DeviceDiagnosticsSnapshot {
                device: &row,
                quality_sample: None,
                active_path: None,
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &[],
            })
            .expect("valid diagnostics");
        };
        let original = interaction_context(BTreeSet::new());
        let quality = TeacherUiAction::Diagnostics(TeacherDiagnosticsUiAction {
            source_id: MonitoringSourceId(7),
            request: TroubleshootingOverrideRequest::Quality {
                stream_kind: classmesh_core::StreamKind::Monitoring,
                tier: classmesh_core::adaptation::QualityTier::Low,
            },
        });
        app.set_teacher_interaction_context(original.clone());
        refresh(&mut app);
        app.queue_action(quality.clone());
        app.set_teacher_interaction_context(original.clone());
        assert_eq!(
            app.take_pending_action(),
            Some(quality.clone()),
            "a same-session refresh must not discard a valid override"
        );

        app.queue_action(quality.clone());
        let mut replacement = original.clone();
        replacement.control_session_id += 1;
        app.set_teacher_interaction_context(replacement);
        assert_eq!(
            app.take_pending_action(),
            None,
            "a queued override from an old control session must not reach the new session"
        );

        app.queue_action(quality);
        app.clear_teacher_interaction_context();
        assert_eq!(
            app.take_pending_action(),
            None,
            "disconnect must retire a queued non-cleanup override"
        );

        let cleanup = TeacherUiAction::Diagnostics(TeacherDiagnosticsUiAction {
            source_id: MonitoringSourceId(7),
            request: TroubleshootingOverrideRequest::Automatic,
        });
        app.queue_action(cleanup.clone());
        assert_eq!(
            app.take_pending_action(),
            Some(cleanup),
            "local Automatic cleanup remains available after disconnect"
        );
    }

    #[test]
    fn queued_diagnostics_override_does_not_outlive_its_visible_snapshot() {
        use crate::device_diagnostics::TroubleshootingOverrideRequest;
        use crate::ui_shell::TeacherDiagnosticsUiAction;

        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let row = app
            .classroom
            .rows()
            .into_iter()
            .find(|row| row.source_id == MonitoringSourceId(7))
            .expect("selected classroom row");
        let update = |app: &mut TeacherEguiShell, device: &ClassroomDeviceRow| {
            app.update_diagnostics(DeviceDiagnosticsSnapshot {
                device,
                quality_sample: None,
                active_path: None,
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &[],
            })
            .expect("valid diagnostics");
        };
        let quality = TeacherUiAction::Diagnostics(TeacherDiagnosticsUiAction {
            source_id: MonitoringSourceId(7),
            request: TroubleshootingOverrideRequest::Quality {
                stream_kind: classmesh_core::StreamKind::Monitoring,
                tier: classmesh_core::adaptation::QualityTier::Low,
            },
        });

        update(&mut app, &row);
        app.queue_action(quality.clone());
        app.clear_diagnostics();
        assert_eq!(
            app.take_pending_action(),
            None,
            "a revoked diagnostics snapshot must retire its queued override"
        );

        update(&mut app, &row);
        app.queue_action(quality.clone());
        app.clear_diagnostics();
        update(&mut app, &row);
        assert_eq!(
            app.take_pending_action(),
            None,
            "restoring the same source must not revive a revoked queued override"
        );

        update(&mut app, &row);
        app.queue_action(quality.clone());
        let mut replacement = row.clone();
        replacement.source_id = MonitoringSourceId(8);
        update(&mut app, &replacement);
        assert_eq!(
            app.take_pending_action(),
            None,
            "diagnostics for a different source must retire the old override"
        );

        update(&mut app, &row);
        app.queue_action(quality.clone());
        assert_eq!(
            app.take_pending_action(),
            Some(quality),
            "unchanged selected diagnostics must retain an allowed override"
        );

        let cleanup = TeacherUiAction::Diagnostics(TeacherDiagnosticsUiAction {
            source_id: MonitoringSourceId(7),
            request: TroubleshootingOverrideRequest::Automatic,
        });
        app.queue_action(cleanup.clone());
        app.clear_diagnostics();
        assert_eq!(
            app.take_pending_action(),
            Some(cleanup),
            "automatic cleanup must remain available after diagnostics revocation"
        );
    }

    #[test]
    fn queued_diagnostics_override_is_rechecked_at_ui_handoff() {
        use crate::device_diagnostics::TroubleshootingOverrideRequest;
        use crate::ui_shell::TeacherDiagnosticsUiAction;

        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let source_id = MonitoringSourceId(7);
        let quality = TeacherUiAction::Diagnostics(TeacherDiagnosticsUiAction {
            source_id,
            request: TroubleshootingOverrideRequest::Quality {
                stream_kind: classmesh_core::StreamKind::Monitoring,
                tier: classmesh_core::adaptation::QualityTier::Low,
            },
        });

        app.queue_action(quality.clone());
        app.classroom.select(None).unwrap();
        assert_eq!(
            app.take_pending_action(),
            None,
            "a queued override must not reach the engine after selection changes"
        );

        app.classroom.select(Some(source_id)).unwrap();
        app.queue_action(quality);
        app.classroom
            .upsert(ClassroomDeviceSnapshot {
                source_id,
                display_name: "Student 07".to_owned(),
                health: DeviceHealth {
                    presence: PresenceState::Offline,
                    media: MediaState::Recovering,
                    service_ready: false,
                    worker_ready: false,
                },
                quality_tier: None,
                thumbnail_available: false,
                interactive_active: false,
            })
            .unwrap();
        assert_eq!(
            app.take_pending_action(),
            None,
            "new overrides must not be handed off after the device becomes unavailable"
        );

        let cleanup = TeacherUiAction::Diagnostics(TeacherDiagnosticsUiAction {
            source_id,
            request: TroubleshootingOverrideRequest::Automatic,
        });
        app.queue_action(cleanup.clone());
        assert_eq!(
            app.take_pending_action(),
            Some(cleanup),
            "return-to-automatic remains available while offline"
        );
    }

    #[test]
    fn pending_action_slot_is_bounded_and_preserves_oldest_action() {
        let mut app = TeacherEguiShell::default();
        let first = TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7)));
        let second = TeacherUiAction::Focus(TeacherFocusUiAction::RequestInteractive {
            source_id: MonitoringSourceId(7),
        });

        app.queue_action(first.clone());
        app.queue_action(second);

        assert_eq!(app.take_pending_action(), Some(first));
        assert_eq!(app.take_pending_action(), None);
    }
}
