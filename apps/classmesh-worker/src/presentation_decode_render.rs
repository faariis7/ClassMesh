use std::time::Duration;

#[cfg(windows)]
use std::time::Instant;

use classmesh_network::AssembledFrame;

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

#[cfg(windows)]
pub struct PresentationDecodeRuntime {
    decoder: classmesh_codec_win::mf_decoder::MfH264Decoder,
    presentation: Option<crate::receiver_render::PresentationWindow>,
    device: windows::Win32::Graphics::Direct3D11::ID3D11Device,
    _platform: classmesh_codec_win::mf::MfPlatform,
    render_enabled: bool,
    waiting_for_keyframe: bool,
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
            decoder,
            presentation,
            device,
            _platform: platform,
            render_enabled,
            waiting_for_keyframe: true,
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
            classmesh_codec_win::mf_decoder::MfH264Decoder,
        ),
        Box<dyn std::error::Error>,
    > {
        use classmesh_codec_win::d3d11::create_default_video_device;
        use classmesh_codec_win::mf_decoder::{MfH264Decoder, enumerate_h264_decoders};

        let device = create_default_video_device()?;
        let candidates = enumerate_h264_decoders()?;
        if candidates.is_empty() {
            return Err("Media Foundation returned no H.264 decoder candidates".into());
        }

        let mut failures = Vec::new();
        for candidate in &candidates {
            match MfH264Decoder::new(candidate, &device) {
                Ok(decoder) => {
                    eprintln!(
                        "hardware decode candidate selected: {} ({})",
                        candidate.name(),
                        candidate.clsid()
                    );
                    return Ok((device, decoder));
                }
                Err(error) => failures.push(format!("{}: {error}", candidate.name())),
            }
        }

        Err(format!(
            "no D3D11-aware H.264 decoder could be activated: {}",
            failures.join(" | ")
        )
        .into())
    }

    fn rebuild_gpu_pipeline(&mut self, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
        use crate::receiver_render::PresentationWindow;

        let started = Instant::now();
        eprintln!("rebuilding student D3D11 decoder/presenter pipeline: reason={reason}");
        let (new_device, new_decoder) = Self::create_decoder_device()?;

        if self.render_enabled {
            if let Some(presentation) = self.presentation.as_mut() {
                presentation.recover_device(&new_device)?;
            } else {
                self.presentation = Some(PresentationWindow::new(&new_device, 1280, 720)?);
            }
        }

        self.decoder = new_decoder;
        self.device = new_device;
        self.waiting_for_keyframe = true;
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
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        if self.waiting_for_keyframe && !frame.keyframe {
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

        let mut batch = self.drain_decoded()?;
        if self.waiting_for_keyframe {
            if !frame.keyframe {
                return Ok(PresentationDecodeStep::Decoded(batch));
            }
            self.waiting_for_keyframe = false;
        }

        match self
            .decoder
            .submit_access_unit(&frame.data, frame.timestamp_us)
        {
            Ok(()) => {}
            Err(error) if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost => {
                self.rebuild_gpu_pipeline("decoder input device loss")?;
                if !frame.keyframe {
                    return Ok(PresentationDecodeStep::Decoded(batch));
                }
                self.waiting_for_keyframe = false;
                self.decoder
                    .submit_access_unit(&frame.data, frame.timestamp_us)?;
            }
            Err(error) => return Err(error.into()),
        }

        batch.add(self.drain_decoded()?);
        Ok(PresentationDecodeStep::Decoded(batch))
    }

    fn drain_decoded(&mut self) -> Result<PresentationDecodeBatch, Box<dyn std::error::Error>> {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        let frames = match self.decoder.poll_decoded() {
            Ok(frames) => frames,
            Err(error) if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost => {
                self.rebuild_gpu_pipeline("decoder output device loss")?;
                return Ok(PresentationDecodeBatch::default());
            }
            Err(error) => return Err(error.into()),
        };
        let mut batch = PresentationDecodeBatch {
            decoded: frames.len(),
            ..PresentationDecodeBatch::default()
        };
        let mut device_lost = false;
        for frame in &frames {
            if let Some(presentation) = self.presentation.as_mut() {
                match presentation.present(frame) {
                    Ok(classmesh_render_win::PresentOutcome::Presented) => {
                        batch.presented = count_presented_outcome(batch.presented, true);
                    }
                    Ok(classmesh_render_win::PresentOutcome::SkippedSuspended) => {
                        batch.presented = count_presented_outcome(batch.presented, false);
                    }
                    Err(error) => {
                        batch.present_errors = batch.present_errors.saturating_add(1);
                        if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                            device_lost = true;
                            eprintln!(
                                "D3D11 presentation reported device loss; rebuilding shared GPU media pipeline"
                            );
                            break;
                        }
                        eprintln!(
                            "D3D11 presentation failed while decode remains healthy: {error}"
                        );
                    }
                }
            }
        }

        if device_lost {
            drop(frames);
            self.rebuild_gpu_pipeline("presentation device loss")?;
        }
        Ok(batch)
    }

    #[must_use]
    pub const fn waiting_for_keyframe(&self) -> bool {
        self.waiting_for_keyframe
    }

    pub fn recover_after_loss(&mut self) {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        if let Err(error) = self.decoder.flush() {
            if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                if let Err(recovery_error) = self.rebuild_gpu_pipeline("decoder flush device loss")
                {
                    eprintln!("GPU pipeline rebuild failed during loss recovery: {recovery_error}");
                }
            } else {
                eprintln!("hardware decoder flush failed during loss recovery: {error}");
            }
        }
        self.waiting_for_keyframe = true;
    }

    pub fn pump_window(&mut self) -> bool {
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
        let decoded = self.drain_decoded()?;
        self.decoder.end_streaming()?;
        Ok(decoded)
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
