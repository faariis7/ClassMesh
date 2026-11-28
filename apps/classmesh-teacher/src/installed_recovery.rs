//! Bound the installed Teacher's replacement sessions independently of a single QUIC connection.
use std::time::Duration;

use classmesh_control::quic::DEFAULT_RECONNECT_POLICY;

const STABLE_CONNECTION: Duration = Duration::from_secs(15);

#[derive(Default)]
struct RetryBudget {
    attempts: u8,
}

impl RetryBudget {
    fn after_session(&mut self, duration: Duration) {
        if duration >= STABLE_CONNECTION {
            self.attempts = 0;
        }
    }

    fn next_delay(&mut self) -> Option<Duration> {
        if self.attempts >= DEFAULT_RECONNECT_POLICY.max_attempts {
            return None;
        }
        self.attempts += 1;
        Some(Duration::from_millis(
            DEFAULT_RECONNECT_POLICY.backoff_ms(self.attempts),
        ))
    }
}

#[cfg(windows)]
pub(crate) use windows::run_installed_recovery;

#[cfg(windows)]
mod windows {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender},
    };
    use std::time::Instant;

    use classmesh_control::handshake::HandshakeError;
    use classmesh_control::teacher_playback_receive::AuthenticatedTeacherReceiveError;
    use classmesh_core::recovery::RecoveryPolicy;

    use super::*;
    use crate::connected_command::TeacherCommandSendError;
    use crate::connected_runtime::{
        TeacherConnectedPlaybackError as SessionError, drive_installed_teacher_control,
        send_window_event,
    };
    use crate::installed_presentation::{InstalledPresentation, PresentationRoute};
    use crate::receiver_playback_session::TeacherPlaybackSessionError;
    use crate::trusted_startup::{InstalledTeacherStartup, PreparedTeacher};
    use crate::ui_egui::TeacherUiControlEvent;
    use crate::ui_shell::TeacherUiAction;

    const RECOVERY_WINDOW: Duration = Duration::from_secs(40);

    fn can_recover(error: &SessionError) -> bool {
        match error {
            SessionError::Receive(error) => {
                matches!(error.as_ref(), TeacherPlaybackSessionError::Receive(
                    AuthenticatedTeacherReceiveError::Transport(transport)
                ) if transport.can_reconnect())
            }
            SessionError::Command(TeacherCommandSendError::Transport(transport)) => {
                transport.can_reconnect()
            }
            SessionError::Reconnect => true,
            _ => false,
        }
    }

    async fn window_closed(flag: &AtomicBool) {
        while !flag.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub(crate) async fn run_installed_recovery(
        startup: InstalledTeacherStartup,
        mut prepared: PreparedTeacher,
        events: SyncSender<TeacherUiControlEvent>,
        mut actions: Receiver<TeacherUiAction>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<(), SessionError> {
        let mut generation = 1_u64;
        let mut budget = RetryBudget::default();
        let mut recovery_deadline = None;
        loop {
            let PreparedTeacher {
                endpoint,
                session,
                route,
                authorization,
                clock,
                presentation,
                ..
            } = prepared;
            let started = Instant::now();
            let result = drive_installed_teacher_control(
                InstalledPresentation::new(
                    presentation,
                    PresentationRoute {
                        route,
                        authorization: Arc::new(authorization),
                        clock,
                    },
                ),
                session,
                events.clone(),
                &mut actions,
                generation,
            )
            .await;
            drop(endpoint);
            if shutdown.load(Ordering::Acquire) {
                return result;
            }
            let Err(error) = result else {
                return Ok(());
            };
            if !can_recover(&error) {
                send_window_event(
                    &events,
                    TeacherUiControlEvent::RecoveryFailed(
                        "The authenticated session ended. Check eligibility and reopen Teacher.",
                    ),
                )?;
                return Err(error);
            }

            let duration = started.elapsed();
            budget.after_session(duration);
            if duration >= STABLE_CONNECTION || recovery_deadline.is_none() {
                recovery_deadline = Some(tokio::time::Instant::now() + RECOVERY_WINDOW);
            }
            send_window_event(&events, TeacherUiControlEvent::Recovering)?;
            let deadline = recovery_deadline.expect("retry window started");
            let attempt = async {
                while let Some(delay) = budget.next_delay() {
                    tokio::time::sleep(delay).await;
                    match startup
                        .connect(RecoveryPolicy {
                            max_attempts: 1,
                            ..DEFAULT_RECONNECT_POLICY
                        })
                        .await
                    {
                        Ok(next) => {
                            let hello = &next.session.established.negotiated;
                            if hello.role == classmesh_protocol::ControlRole::Teacher
                                && hello.version.major == 0 && hello.version.minor >= 8
                                && !classmesh_protocol::teacher_interaction::teacher_message_available(hello.version, &hello.capabilities)
                            {
                                next.session.connection.close(0u32.into(), b"Teacher waiting for current Worker");
                                continue;
                            }
                            return Ok(Some(next));
                        }
                        Err(error)
                            if matches!(error.downcast_ref::<HandshakeError>(),
                            Some(HandshakeError::Transport(transport)) if transport.can_reconnect()) =>
                            {}
                        Err(error) => {
                            return Err(SessionError::Recovery(error.to_string()));
                        }
                    }
                }
                Ok(None)
            };
            let outcome = tokio::select! {
                biased;
                _ = window_closed(&shutdown) => return Ok(()),
                outcome = tokio::time::timeout_at(deadline, attempt) => outcome,
            };
            prepared = match outcome {
                Ok(Ok(Some(next))) => next,
                Ok(Err(error)) => {
                    send_window_event(
                        &events,
                        TeacherUiControlEvent::RecoveryFailed(
                            "Reconnection was rejected. Check enrollment or policy and reopen Teacher.",
                        ),
                    )?;
                    return Err(error);
                }
                Ok(Ok(None)) | Err(_) => {
                    send_window_event(
                        &events,
                        TeacherUiControlEvent::RecoveryFailed(
                            "Student is still unavailable. Check the network and Student Service, then reopen Teacher.",
                        ),
                    )?;
                    return Err(SessionError::Recovery(
                        "Student reconnect deadline exhausted".into(),
                    ));
                }
            };
            generation = generation
                .checked_add(1)
                .ok_or(SessionError::SessionMismatch)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_budget_caps_backoff_and_recovers_after_each_stable_connection() {
        let mut budget = RetryBudget::default();
        for _ in 0..3 {
            assert_eq!(budget.next_delay(), Some(Duration::from_millis(200)));
            budget.after_session(Duration::from_millis(200));
            assert_eq!(budget.next_delay(), Some(Duration::from_millis(400)));
            let remaining: Vec<_> = std::iter::from_fn(|| budget.next_delay()).collect();
            assert_eq!(
                remaining.len(),
                DEFAULT_RECONNECT_POLICY.max_attempts as usize - 2
            );
            assert!(remaining.iter().all(|d| *d <= Duration::from_secs(5)));
            assert!(budget.next_delay().is_none());
            budget.after_session(STABLE_CONNECTION);
        }
    }
}
