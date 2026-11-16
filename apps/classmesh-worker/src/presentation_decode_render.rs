use std::time::Duration;

#[cfg(any(windows, test))]
use std::time::Instant;

use classmesh_network::AssembledFrame;

#[cfg(windows)]
use classmesh_codec_win::mf_decoder::{DecoderOutput, MfH264Decoder};

#[cfg(any(windows, test))]
const MAX_OUTPUT_STEPS_PER_PUMP: usize = 32;
#[cfg(any(windows, test))]
const MAX_SHUTDOWN_OUTPUT_STEPS: usize = 8 * MAX_OUTPUT_STEPS_PER_PUMP;
#[cfg(any(windows, test))]
const SHUTDOWN_OUTPUT_TIME: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationRecoveryTelemetry {
    pub recoveries: u64,
    pub forced_recoveries: u64,
    pub last: Duration,
    pub longest: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationDecodeBatch {
    pub decoded: usize,
    pub presented: usize,
    pub present_errors: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationDecodeStep {
    Decoded(PresentationDecodeBatch),
    WaitingForKeyframe,
}

#[cfg(any(windows, test))]
fn finish_outputs(
    deadline: Instant,
    mut step: impl FnMut(&mut PresentationDecodeBatch) -> Result<bool, Box<dyn std::error::Error>>,
) -> Result<PresentationDecodeBatch, Box<dyn std::error::Error>> {
    let mut batch = PresentationDecodeBatch::default();
    // Media Foundation's synchronous calls cannot be cancelled in flight.
    // This bounds further calls and runs only on the standalone receiver's
    // shutdown path, after it has stopped receiving.
    for _ in 0..MAX_SHUTDOWN_OUTPUT_STEPS {
        if Instant::now() >= deadline {
            return Err(incomplete_drain("elapsed-time budget exhausted", &batch));
        }
        if step(&mut batch)? {
            return Ok(batch);
        }
    }
    Err(incomplete_drain("output-step budget exhausted", &batch))
}

#[cfg(any(windows, test))]
fn incomplete_drain(reason: &str, batch: &PresentationDecodeBatch) -> Box<dyn std::error::Error> {
    format!(
        "incomplete H.264 drain after {} decoded frames and {} presents: {reason}",
        batch.decoded, batch.presented
    )
    .into()
}

// A minimized DXGI presenter returns success without swapping a frame. Keep
// receiver telemetry tied to actual Present() calls, not successful skips.
#[cfg(any(windows, test))]
const fn count_presented_outcome(presented: usize, was_presented: bool) -> usize {
    if was_presented {
        presented.saturating_add(1)
    } else {
        presented
    }
}

// A failed device-loss rebuild is a media-local fatal condition. The caller
// must tear down the receiver/decoder instead of continuing with a lost GPU.
#[cfg(any(windows, test))]
#[must_use]
const fn keep_window_stream_alive(
    window_open: bool,
    device_lost: bool,
    recovery_succeeded: bool,
) -> bool {
    window_open && (!device_lost || recovery_succeeded)
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecoderState {
    AwaitingKeyframe,
    Running,
    ResetRequired,
    Retired,
}

#[cfg(any(windows, test))]
impl DecoderState {
    fn complete_reset(&mut self, succeeded: bool) {
        *self = if succeeded {
            Self::AwaitingKeyframe
        } else {
            Self::Retired
        };
    }

    fn complete_submission<E>(&mut self, submitted: Result<(), E>) -> Result<(), E> {
        *self = if submitted.is_ok() {
            Self::Running
        } else {
            Self::ResetRequired
        };
        submitted
    }

    fn can_submit(self, keyframe: bool) -> bool {
        match self {
            Self::AwaitingKeyframe => keyframe,
            Self::Running => true,
            Self::ResetRequired | Self::Retired => false,
        }
    }
}

#[cfg(windows)]
pub struct PresentationDecodeRuntime {
    decoder: Option<MfH264Decoder>,
    presentation: Option<crate::receiver_render::PresentationWindow>,
    _platform: classmesh_codec_win::mf::MfPlatform,
    state: DecoderState,
    gpu_recoveries: u64,
    forced_recoveries: u64,
    recover_after_frames: Option<u64>,
    decoder_eligible_frames: u64,
    last_recovery: Duration,
    longest_recovery: Duration,
}

#[cfg(windows)]
impl PresentationDecodeRuntime {
    pub fn new(
        render_enabled: bool,
        recover_after_frames: Option<u64>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use crate::receiver_render::PresentationWindow;
        use classmesh_codec_win::mf::MfPlatform;

        let platform = MfPlatform::startup()?;
        let (device, decoder) = Self::create_decoder_device()?;
        let presentation = if render_enabled {
            Some(PresentationWindow::new(&device, 1280, 720)?)
        } else {
            None
        };

        Ok(Self {
            decoder: Some(decoder),
            presentation,
            _platform: platform,
            state: DecoderState::AwaitingKeyframe,
            gpu_recoveries: 0,
            forced_recoveries: 0,
            recover_after_frames,
            decoder_eligible_frames: 0,
            last_recovery: Duration::ZERO,
            longest_recovery: Duration::ZERO,
        })
    }

    fn create_decoder_device() -> Result<
        (
            windows::Win32::Graphics::Direct3D11::ID3D11Device,
            MfH264Decoder,
        ),
        Box<dyn std::error::Error>,
    > {
        use classmesh_codec_win::d3d11::create_default_video_device;
        use classmesh_codec_win::mf_decoder::enumerate_h264_decoders;
        use windows::Win32::Graphics::Direct3D11::ID3D11VideoDevice;
        use windows::core::Interface;

        let device = create_default_video_device()?;
        // Creating a D3D11 renderer device alone does not qualify its video
        // interfaces. The GPU decoder/presenter requires a video-capable device.
        device
            .cast::<ID3D11VideoDevice>()
            .map_err(|error| format!("D3D11 device does not expose ID3D11VideoDevice: {error}"))?;
        let candidates = enumerate_h264_decoders()?;
        if candidates.is_empty() {
            return Err("Media Foundation returned no H.264 decoder candidates".into());
        }

        let mut failures = Vec::new();
        for candidate in candidates {
            let name = candidate.name().to_owned();
            let clsid = candidate.clsid().to_owned();
            match MfH264Decoder::new(candidate, &device) {
                Ok(decoder) => {
                    eprintln!("D3D11 decode candidate selected: {name} ({clsid})");
                    return Ok((device, decoder));
                }
                Err(error) => failures.push(format!("{name}: {error}")),
            }
        }

        Err(format!(
            "no D3D11-aware H.264 decoder could be activated: {}",
            failures.join(" | ")
        )
        .into())
    }

    fn rebuild_gpu_pipeline(&mut self, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Rebuild is transactional from the caller's perspective. A failed
        // decoder or presenter rebuild leaves this instance unusable.
        self.state = DecoderState::Retired;
        drop(self.decoder.take());
        let started = Instant::now();
        eprintln!("rebuilding student D3D11 decoder/presenter pipeline: reason={reason}");
        let (new_device, new_decoder) = Self::create_decoder_device()?;

        if let Some(presentation) = self.presentation.as_mut() {
            presentation.recover_device(&new_device)?;
        }

        self.decoder = Some(new_decoder);
        self.state.complete_reset(true);
        self.gpu_recoveries = self.gpu_recoveries.saturating_add(1);
        let elapsed = started.elapsed();
        self.last_recovery = elapsed;
        self.longest_recovery = self.longest_recovery.max(elapsed);
        eprintln!(
            "student GPU media pipeline rebuilt; waiting for keyframe (recovery #{}, elapsed_ms={:.2})",
            self.gpu_recoveries,
            elapsed.as_secs_f64() * 1_000.0
        );
        Ok(())
    }

    pub fn submit(
        &mut self,
        frame: &AssembledFrame,
    ) -> Result<PresentationDecodeStep, Box<dyn std::error::Error>> {
        let result = self.submit_frame(frame);
        if result.is_err() {
            self.recover_after_loss();
        }
        result
    }

    fn submit_frame(
        &mut self,
        frame: &AssembledFrame,
    ) -> Result<PresentationDecodeStep, Box<dyn std::error::Error>> {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        if self.is_retired() {
            return Err("presentation decoder retired after a failed reset".into());
        }
        if !self.state.can_submit(frame.keyframe) {
            return Ok(PresentationDecodeStep::WaitingForKeyframe);
        }

        self.decoder_eligible_frames = self.decoder_eligible_frames.saturating_add(1);
        if self
            .recover_after_frames
            .is_some_and(|threshold| self.decoder_eligible_frames >= threshold)
        {
            self.recover_after_frames = None;
            eprintln!(
                "triggering scheduled live-stream GPU media recovery at decoder frame {} (keyframe={})",
                self.decoder_eligible_frames, frame.keyframe
            );
            self.rebuild_gpu_pipeline("scheduled live-stream recovery test")?;
            self.forced_recoveries = self.forced_recoveries.saturating_add(1);
            if !frame.keyframe {
                return Ok(PresentationDecodeStep::WaitingForKeyframe);
            }
        }

        // After a discontinuity, don't present any queued output before
        // the fresh IDR has been accepted by the reset transform.
        let mut batch = if self.waiting_for_keyframe() {
            PresentationDecodeBatch::default()
        } else {
            self.drain_decoded(true)?
        };
        if !self.state.can_submit(frame.keyframe) {
            return Ok(PresentationDecodeStep::Decoded(batch));
        }

        let submitted = match self.submit_access_unit(frame) {
            Err(error) if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost => {
                self.rebuild_gpu_pipeline("decoder input device loss")?;
                if !frame.keyframe {
                    return Ok(PresentationDecodeStep::Decoded(batch));
                }
                self.submit_access_unit(frame)
            }
            result => result,
        };

        self.state.complete_submission(submitted)?;
        batch.add(self.drain_decoded(true)?);
        Ok(PresentationDecodeStep::Decoded(batch))
    }

    fn submit_access_unit(&mut self, frame: &AssembledFrame) -> windows::core::Result<()> {
        self.decoder
            .as_mut()
            .expect("an active presentation has a decoder")
            .submit_access_unit(&frame.data, frame.timestamp_us)
    }

    fn drain_decoded(
        &mut self,
        recover_device_loss: bool,
    ) -> Result<PresentationDecodeBatch, Box<dyn std::error::Error>> {
        let mut batch = PresentationDecodeBatch::default();
        for _ in 0..MAX_OUTPUT_STEPS_PER_PUMP {
            if self.poll_and_present(&mut batch, recover_device_loss)? {
                break;
            }
        }
        Ok(batch)
    }

    // True means the current pump has ended. During final drain, NeedInput is
    // the only successful terminal result because device recovery is disabled.
    fn poll_and_present(
        &mut self,
        batch: &mut PresentationDecodeBatch,
        recover_device_loss: bool,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        let frame = match self
            .decoder
            .as_ref()
            .expect("an active presentation has a decoder")
            .poll_decoded()
        {
            Ok(DecoderOutput::Frame(frame)) => frame,
            Ok(DecoderOutput::Progress) => return Ok(false),
            Ok(DecoderOutput::NeedInput) => return Ok(true),
            Err(error)
                if recover_device_loss
                    && classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost =>
            {
                self.rebuild_gpu_pipeline("decoder output device loss")?;
                return Ok(true);
            }
            Err(error) => return Err(error.into()),
        };
        batch.decoded = batch.decoded.saturating_add(1);
        if let Some(presentation) = self.presentation.as_mut() {
            match presentation.present(&frame) {
                Ok(classmesh_render_win::PresentOutcome::Presented) => {
                    batch.presented = count_presented_outcome(batch.presented, true);
                }
                Ok(classmesh_render_win::PresentOutcome::SkippedSuspended) => {
                    batch.presented = count_presented_outcome(batch.presented, false);
                }
                Err(error) => {
                    batch.present_errors = batch.present_errors.saturating_add(1);
                    if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                        if !recover_device_loss {
                            return Err(error.into());
                        }
                        drop(frame);
                        self.rebuild_gpu_pipeline("presentation device loss")?;
                        return Ok(true);
                    }
                    eprintln!("D3D11 presentation failed while decode remains healthy: {error}");
                }
            }
        }
        Ok(false)
    }

    #[must_use]
    pub const fn waiting_for_keyframe(&self) -> bool {
        matches!(self.state, DecoderState::AwaitingKeyframe)
    }

    #[must_use]
    pub const fn is_retired(&self) -> bool {
        matches!(self.state, DecoderState::Retired)
    }

    pub fn recover_after_loss(&mut self) {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        if self.is_retired() {
            return;
        }
        let flushed = self
            .decoder
            .as_mut()
            .expect("an active presentation has a decoder")
            .flush()
            .and_then(|()| {
                self.presentation.as_mut().map_or(
                    Ok(()),
                    crate::receiver_render::PresentationWindow::clear_frame,
                )
            });
        self.state.complete_reset(flushed.is_ok());
        if let Err(error) = flushed {
            if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                if let Err(recovery_error) = self.rebuild_gpu_pipeline("playback reset device loss")
                {
                    eprintln!(
                        "GPU pipeline rebuild failed during loss recovery; retiring receiver: {recovery_error}"
                    );
                }
            } else {
                drop(self.decoder.take());
                eprintln!("playback reset failed; retiring receiver: {error}");
            }
        }
    }

    pub fn pump_window(&mut self) -> bool {
        if self.is_retired() {
            return false;
        }
        let (open, device_lost) = match self.presentation.as_mut() {
            Some(presentation) => {
                let open = presentation.pump_messages();
                let device_lost = presentation.take_device_lost();
                (open, device_lost)
            }
            None => (true, false),
        };

        let recovery_succeeded = if open && device_lost {
            match self.rebuild_gpu_pipeline("presentation window device loss") {
                Ok(()) => true,
                Err(error) => {
                    eprintln!(
                        "GPU pipeline rebuild failed after window resize device loss: {error}; stopping media receiver"
                    );
                    false
                }
            }
        } else {
            true
        };
        keep_window_stream_alive(open, device_lost, recovery_succeeded)
    }

    pub fn finish(&mut self) -> Result<PresentationDecodeBatch, Box<dyn std::error::Error>> {
        if self.is_retired() {
            return Err("presentation decoder retired before shutdown drain".into());
        }
        let should_drain = self.state == DecoderState::Running;
        self.state = DecoderState::Retired;
        let decoded = if should_drain {
            let deadline = Instant::now() + SHUTDOWN_OUTPUT_TIME;
            self.decoder
                .as_mut()
                .expect("an active presentation has a decoder")
                .begin_drain()
                .map_err(Into::into)
                .and_then(|()| {
                    finish_outputs(deadline, |batch| {
                        if let Some(window) = self.presentation.as_mut() {
                            if !window.pump_messages() {
                                return Err(incomplete_drain("student window closed", batch));
                            }
                            if window.take_device_lost() {
                                return Err(incomplete_drain("presentation device lost", batch));
                            }
                        }
                        self.poll_and_present(batch, false)
                    })
                })
        } else {
            Ok(PresentationDecodeBatch::default())
        };
        let stopped = self
            .decoder
            .take()
            .expect("an active presentation has a decoder")
            .end_streaming();
        let batch = decoded?;
        stopped?;
        Ok(batch)
    }

    #[must_use]
    pub const fn recovery_telemetry(&self) -> PresentationRecoveryTelemetry {
        PresentationRecoveryTelemetry {
            recoveries: self.gpu_recoveries,
            forced_recoveries: self.forced_recoveries,
            last: self.last_recovery,
            longest: self.longest_recovery,
        }
    }
}

#[cfg(windows)]
impl PresentationDecodeBatch {
    fn add(&mut self, other: Self) {
        self.decoded = self.decoded.saturating_add(other.decoded);
        self.presented = self.presented.saturating_add(other.presented);
        self.present_errors = self.present_errors.saturating_add(other.present_errors);
    }
}

#[cfg(not(windows))]
pub struct PresentationDecodeRuntime;

#[cfg(not(windows))]
impl PresentationDecodeRuntime {
    pub fn new(
        _render_enabled: bool,
        _recover_after_frames: Option<u64>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Err("--decode/--render are supported only by the Windows media receiver".into())
    }

    pub fn submit(
        &mut self,
        _frame: &AssembledFrame,
    ) -> Result<PresentationDecodeStep, Box<dyn std::error::Error>> {
        Err("hardware decode is unavailable on this platform".into())
    }

    #[must_use]
    pub const fn waiting_for_keyframe(&self) -> bool {
        true
    }

    pub fn recover_after_loss(&mut self) {}

    pub fn pump_window(&mut self) -> bool {
        true
    }

    pub fn finish(&mut self) -> Result<PresentationDecodeBatch, Box<dyn std::error::Error>> {
        Ok(PresentationDecodeBatch::default())
    }

    #[must_use]
    pub const fn recovery_telemetry(&self) -> PresentationRecoveryTelemetry {
        PresentationRecoveryTelemetry {
            recoveries: 0,
            forced_recoveries: 0,
            last: Duration::ZERO,
            longest: Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod window_recovery_tests {
    use super::{count_presented_outcome, keep_window_stream_alive};

    #[test]
    fn shutdown_drains_past_one_live_pump_until_need_input() {
        use super::{Instant, MAX_OUTPUT_STEPS_PER_PUMP, SHUTDOWN_OUTPUT_TIME, finish_outputs};

        let mut remaining = MAX_OUTPUT_STEPS_PER_PUMP + 3;
        let mut saw_need_input = false;
        let batch = finish_outputs(Instant::now() + SHUTDOWN_OUTPUT_TIME, |batch| {
            if remaining == 0 {
                saw_need_input = true;
                return Ok(true);
            }
            remaining -= 1;
            batch.decoded += 1;
            Ok(false)
        })
        .unwrap();

        assert_eq!(remaining, 0, "shutdown returned with pending output");
        assert!(saw_need_input, "completion requires an explicit NeedInput");
        assert_eq!(batch.decoded, MAX_OUTPUT_STEPS_PER_PUMP + 3);
    }

    #[test]
    fn shutdown_progress_without_need_input_exhausts_the_budget() {
        use super::{Instant, MAX_SHUTDOWN_OUTPUT_STEPS, SHUTDOWN_OUTPUT_TIME, finish_outputs};

        let mut steps = 0;
        let error = finish_outputs(Instant::now() + SHUTDOWN_OUTPUT_TIME, |_| {
            steps += 1;
            Ok(false)
        })
        .unwrap_err();
        assert_eq!(steps, MAX_SHUTDOWN_OUTPUT_STEPS);
        assert!(error.to_string().contains("output-step budget exhausted"));
    }

    #[test]
    fn shutdown_expired_deadline_stops_before_polling() {
        use super::{Instant, finish_outputs};

        let error =
            finish_outputs(Instant::now(), |_| panic!("expired drain polled output")).unwrap_err();
        assert!(error.to_string().contains("elapsed-time budget exhausted"));
    }

    #[test]
    fn rejected_decoder_reset_retires_the_pipeline_even_for_an_idr() {
        use super::DecoderState;
        let mut state = DecoderState::Running;
        state.complete_reset(false);
        assert_eq!(state, DecoderState::Retired);
        assert!(!state.can_submit(false));
        assert!(!state.can_submit(true));
    }

    #[test]
    fn successful_decoder_reset_admits_only_a_keyframe() {
        use super::DecoderState;
        let mut state = DecoderState::Running;
        state.complete_reset(true);
        assert_eq!(state, DecoderState::AwaitingKeyframe);
        assert!(!state.can_submit(false));
        assert!(state.can_submit(true));
    }

    #[test]
    fn rejected_idr_does_not_unlock_delta_submission_after_reset() {
        use super::DecoderState;
        let mut state = DecoderState::Running;
        state.complete_reset(true);

        assert!(state.can_submit(true));
        assert_eq!(
            state.complete_submission(Err("input rejected")),
            Err("input rejected")
        );
        assert!(!state.can_submit(false));
        assert!(!state.can_submit(true));
        state.complete_reset(true);
        assert_eq!(state.complete_submission(Ok::<_, &str>(())), Ok(()));
        assert!(state.can_submit(false));
    }

    #[test]
    fn failed_running_submission_requires_reset_before_any_more_input() {
        use super::DecoderState;
        let mut state = DecoderState::Running;
        assert_eq!(
            state.complete_submission(Err("input rejected")),
            Err("input rejected")
        );
        assert!(
            !state.can_submit(false),
            "delta cannot use a broken reference chain"
        );
        assert!(
            !state.can_submit(true),
            "even an IDR must wait for the flush"
        );
        state.complete_reset(true);
        assert!(state.can_submit(true));
        assert!(!state.can_submit(false));
    }

    #[test]
    fn suspended_frames_do_not_inflate_successful_present_count() {
        assert_eq!(count_presented_outcome(4, false), 4);
        assert_eq!(count_presented_outcome(4, true), 5);
        assert_eq!(count_presented_outcome(usize::MAX, true), usize::MAX);
    }

    #[test]
    fn failed_window_gpu_rebuild_ends_only_the_media_path() {
        assert!(!keep_window_stream_alive(true, true, false));
        assert!(keep_window_stream_alive(true, true, true));
        assert!(keep_window_stream_alive(true, false, false));
        assert!(!keep_window_stream_alive(false, false, true));
        assert!(!keep_window_stream_alive(false, true, true));
    }
}
