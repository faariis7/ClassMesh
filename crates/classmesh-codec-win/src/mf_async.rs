#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use std::mem::ManuallyDrop;
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use classmesh_video::distributor::SharedEncodedFrame;
use classmesh_video::{Codec, EncodedFrameMeta};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::{
    IMFMediaEvent, IMFMediaEventGenerator, IMFMediaType, IMFSample, IMFTransform,
    METransformDrainComplete, METransformHaveOutput, METransformNeedInput,
    MF_E_NO_EVENTS_AVAILABLE, MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE,
    MF_EVENT_FLAG_NO_WAIT, MF_LOW_LATENCY, MF_MT_AVG_BITRATE, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE,
    MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE,
    MF_TRANSFORM_ASYNC_UNLOCK, MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample,
    MFMediaType_Video, MFSampleExtension_CleanPoint, MFT_MESSAGE_COMMAND_DRAIN,
    MFT_MESSAGE_COMMAND_FLUSH, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFVideoFormat_H264, MFVideoFormat_NV12,
    MFVideoInterlace_Progressive,
};
use windows::core::Interface;

use crate::mf::{
    MfDxgiDeviceManager, MfEncoderActivation, MfH264EncoderConfig, create_dxgi_texture_sample,
};

const MAX_EVENTS_PER_POLL: usize = 128;
const ERROR_TIMEOUT_HRESULT: i32 = 0x8007_05B4_u32 as i32;

/// Bounded wait policy for asynchronous Media Foundation hardware transforms.
///
/// Hardware/driver bugs must not be able to park the ClassMesh media worker forever while waiting
/// for `METransformNeedInput` or `METransformDrainComplete`. The encoder polls the async event queue
/// with `MF_EVENT_FLAG_NO_WAIT`, sleeps briefly when no event is available, and fails with
/// `HRESULT_FROM_WIN32(ERROR_TIMEOUT)` once the corresponding deadline expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfAsyncWaitConfig {
    pub input_timeout: Duration,
    pub drain_timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for MfAsyncWaitConfig {
    fn default() -> Self {
        Self {
            input_timeout: Duration::from_secs(2),
            drain_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(1),
        }
    }
}

#[derive(Debug)]
struct PendingInput {
    sample_time_100ns: i64,
    frame_id: u64,
    timestamp_us: u64,
    surface: ID3D11Texture2D,
}

/// One H.264 access unit plus the NV12 surface that is now safe to recycle.
///
/// Returning surface ownership at the encoded-output boundary prevents the GPU converter from
/// overwriting a texture while an asynchronous hardware MFT may still be reading it.
pub struct MfEncodedOutput {
    pub frame: SharedEncodedFrame,
    pub recycled_surface: ID3D11Texture2D,
}

impl fmt::Debug for MfEncodedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MfEncodedOutput")
            .field("meta", &self.frame.meta)
            .field("codec", &self.frame.codec)
            .field("bytes", &self.frame.data.len())
            .finish_non_exhaustive()
    }
}

/// Error from submitting a surface.
///
/// `rejected_surface` is `Some` only when Media Foundation did not accept the input, so the caller
/// may safely return that texture to its bounded pool. Once `ProcessInput` succeeds, ownership stays
/// inside the encoder until an encoded output, drain, or explicit abort proves the texture is no
/// longer in use. In that case this field is `None` even if a later asynchronous event fails.
pub struct MfSubmitError {
    pub error: windows::core::Error,
    pub rejected_surface: Option<ID3D11Texture2D>,
}

impl MfSubmitError {
    fn rejected(error: windows::core::Error, surface: ID3D11Texture2D) -> Self {
        Self {
            error,
            rejected_surface: Some(surface),
        }
    }

    fn accepted(error: windows::core::Error) -> Self {
        Self {
            error,
            rejected_surface: None,
        }
    }

    /// Returns true when Media Foundation already accepted the submitted texture.
    ///
    /// When this is true the caller must not recycle its previous texture handle. Reclaim pending
    /// surfaces through encoded output, [`MfAsyncH264Encoder::finish`], or
    /// [`MfAsyncH264Encoder::abort_and_reclaim`].
    #[must_use]
    pub const fn input_was_accepted(&self) -> bool {
        self.rejected_surface.is_none()
    }
}

impl fmt::Debug for MfSubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MfSubmitError")
            .field("error", &self.error)
            .field("input_was_accepted", &self.input_was_accepted())
            .finish_non_exhaustive()
    }
}

/// Result of a terminal encoder drain. `reclaimed_surfaces` covers inputs that did not yield an
/// output before the MFT declared the drain complete, so callers can always rebuild their pool.
#[derive(Debug)]
pub struct MfDrainResult {
    pub outputs: Vec<MfEncodedOutput>,
    pub reclaimed_surfaces: Vec<ID3D11Texture2D>,
}

/// Event-driven Media Foundation H.264 hardware encoder.
///
/// Hardware encoder MFTs are asynchronous: they request input through `METransformNeedInput` and
/// announce output through `METransformHaveOutput`. ClassMesh follows that contract instead of
/// busy-looping `ProcessInput`/`ProcessOutput`. Input NV12 surfaces are owned by this object until
/// the matching encoded sample is observed, which is the key invariant needed by a bounded GPU
/// surface pool.
pub struct MfAsyncH264Encoder {
    transform: IMFTransform,
    events: IMFMediaEventGenerator,
    _device_manager: MfDxgiDeviceManager,
    config: MfH264EncoderConfig,
    wait: MfAsyncWaitConfig,
    provides_output_samples: bool,
    output_size: u32,
    needs_input: bool,
    drained: bool,
    next_sample_index: u64,
    pending: VecDeque<PendingInput>,
}

impl fmt::Debug for MfAsyncH264Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MfAsyncH264Encoder")
            .field("config", &self.config)
            .field("wait", &self.wait)
            .field("needs_input", &self.needs_input)
            .field("drained", &self.drained)
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl MfAsyncH264Encoder {
    /// Activates an H.264 hardware MFT with the default bounded wait policy.
    ///
    /// # Errors
    /// Returns an error when the transform cannot expose the asynchronous event interface or rejects
    /// the GPU device/media-type configuration.
    pub fn new(
        activation: &MfEncoderActivation,
        device: &ID3D11Device,
        config: MfH264EncoderConfig,
    ) -> windows::core::Result<Self> {
        Self::new_with_wait_config(activation, device, config, MfAsyncWaitConfig::default())
    }

    /// Activates an H.264 hardware MFT with an explicit watchdog policy.
    ///
    /// # Errors
    /// Returns an error for an invalid wait policy or when Media Foundation rejects initialization.
    pub fn new_with_wait_config(
        activation: &MfEncoderActivation,
        device: &ID3D11Device,
        config: MfH264EncoderConfig,
        wait: MfAsyncWaitConfig,
    ) -> windows::core::Result<Self> {
        validate_config(config)?;
        validate_wait_config(wait)?;
        let transform = activation.activate_transform()?;
        let attributes = unsafe { transform.GetAttributes()? };
        unsafe {
            attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)?;
            let _ = attributes.SetUINT32(&MF_LOW_LATENCY, 1);
        }

        let events: IMFMediaEventGenerator = transform.cast()?;
        let device_manager = MfDxgiDeviceManager::new(device)?;
        unsafe {
            transform.ProcessMessage(
                MFT_MESSAGE_SET_D3D_MANAGER,
                device_manager.manager().as_raw() as usize,
            )?;
        }

        let output_type = create_h264_output_type(config)?;
        let input_type = create_nv12_input_type(config)?;
        unsafe {
            transform.SetOutputType(0, &output_type, 0)?;
            transform.SetInputType(0, &input_type, 0)?;
        }

        let (provides_output_samples, output_size) = output_stream_info(&transform)?;
        unsafe {
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        }

        Ok(Self {
            transform,
            events,
            _device_manager: device_manager,
            config,
            wait,
            provides_output_samples,
            output_size,
            needs_input: false,
            drained: false,
            next_sample_index: 0,
            pending: VecDeque::new(),
        })
    }

    #[must_use]
    pub fn pending_inputs(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub const fn wait_config(&self) -> MfAsyncWaitConfig {
        self.wait
    }

    /// Waits up to the configured input deadline for `METransformNeedInput`, submits the owned NV12
    /// surface, and then drains output events that are already ready.
    ///
    /// The wait is implemented with non-blocking Media Foundation event polling so a missing async
    /// event cannot park the media worker forever.
    pub fn encode_surface(
        &mut self,
        frame_id: u64,
        timestamp_us: u64,
        surface: ID3D11Texture2D,
    ) -> Result<Vec<MfEncodedOutput>, MfSubmitError> {
        let mut outputs = Vec::new();
        if let Err(error) = self.wait_for_input(&mut outputs) {
            return Err(MfSubmitError::rejected(error, surface));
        }

        let sample_time_100ns = self.sample_time_100ns();
        let sample = match create_dxgi_texture_sample(
            &surface,
            sample_time_100ns,
            self.config.frame_duration_100ns(),
        ) {
            Ok(sample) => sample,
            Err(error) => return Err(MfSubmitError::rejected(error, surface)),
        };

        if let Err(error) = unsafe { self.transform.ProcessInput(0, &sample, 0) } {
            return Err(MfSubmitError::rejected(error, surface));
        }

        self.needs_input = false;
        self.pending.push_back(PendingInput {
            sample_time_100ns,
            frame_id,
            timestamp_us,
            surface,
        });
        self.next_sample_index = self.next_sample_index.saturating_add(1);

        if let Err(error) = self.drain_ready(&mut outputs) {
            // `ProcessInput` already succeeded. The submitted surface stays exclusively in
            // `pending`; exposing even a cloned COM handle as recyclable would allow a caller to
            // overwrite storage while the hardware encoder may still be reading it.
            return Err(MfSubmitError::accepted(error));
        }
        Ok(outputs)
    }

    /// Non-blockingly consumes a bounded batch of queued encoder events and returns completed access
    /// units. A transform that continuously emits events therefore cannot monopolize the worker.
    ///
    /// # Errors
    /// Returns an asynchronous MFT event/status or output-processing error.
    pub fn poll_ready(&mut self) -> windows::core::Result<Vec<MfEncodedOutput>> {
        let mut outputs = Vec::new();
        self.drain_ready(&mut outputs)?;
        Ok(outputs)
    }

    /// Ends the stream, waits up to the configured drain deadline for
    /// `METransformDrainComplete`, and returns all tail output plus every input surface that is safe
    /// to recycle.
    ///
    /// # Errors
    /// Returns an asynchronous event/drain error or a timeout if the hardware transform stops
    /// making progress.
    pub fn finish(&mut self) -> windows::core::Result<MfDrainResult> {
        let mut outputs = Vec::new();
        self.drained = false;
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0)?;
            self.transform
                .ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0)?;
        }

        let deadline = Instant::now() + self.wait.drain_timeout;
        while !self.drained {
            self.drain_ready(&mut outputs)?;
            if self.drained {
                break;
            }
            wait_for_next_poll(deadline, self.wait.poll_interval, "Media Foundation drain timed out")?;
        }
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0)?;
        }

        let reclaimed_surfaces = self
            .pending
            .drain(..)
            .map(|pending| pending.surface)
            .collect();
        Ok(MfDrainResult {
            outputs,
            reclaimed_surfaces,
        })
    }

    /// Flushes the transform and returns every accepted input surface still pending.
    ///
    /// This is the recovery path after an asynchronous encoder failure. Surfaces are reclaimed only
    /// after the MFT accepts `MFT_MESSAGE_COMMAND_FLUSH`, which prevents a bounded pool from reusing
    /// GPU memory while the transform may still hold a reference to it.
    ///
    /// # Errors
    /// Returns the transform error if Media Foundation refuses the flush. In that case ownership of
    /// all pending surfaces remains with this encoder.
    pub fn abort_and_reclaim(&mut self) -> windows::core::Result<Vec<ID3D11Texture2D>> {
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0)?;
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
        self.needs_input = false;
        self.drained = false;
        Ok(self
            .pending
            .drain(..)
            .map(|pending| pending.surface)
            .collect())
    }

    fn sample_time_100ns(&self) -> i64 {
        let duration = self.config.frame_duration_100ns().max(1);
        let index = i64::try_from(self.next_sample_index).unwrap_or(i64::MAX);
        index.saturating_mul(duration)
    }

    fn wait_for_input(&mut self, outputs: &mut Vec<MfEncodedOutput>) -> windows::core::Result<()> {
        let deadline = Instant::now() + self.wait.input_timeout;
        while !self.needs_input {
            self.drain_ready(outputs)?;
            if self.needs_input {
                break;
            }
            wait_for_next_poll(
                deadline,
                self.wait.poll_interval,
                "Media Foundation encoder input timed out",
            )?;
        }
        Ok(())
    }

    fn drain_ready(&mut self, outputs: &mut Vec<MfEncodedOutput>) -> windows::core::Result<()> {
        for _ in 0..MAX_EVENTS_PER_POLL {
            match unsafe { self.events.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                Ok(event) => self.handle_event(&event, outputs)?,
                Err(error) if error.code() == MF_E_NO_EVENTS_AVAILABLE => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn handle_event(
        &mut self,
        event: &IMFMediaEvent,
        outputs: &mut Vec<MfEncodedOutput>,
    ) -> windows::core::Result<()> {
        let status = unsafe { event.GetStatus()? };
        status.ok()?;

        const NEED_INPUT: u32 = METransformNeedInput.0 as u32;
        const HAVE_OUTPUT: u32 = METransformHaveOutput.0 as u32;
        const DRAIN_COMPLETE: u32 = METransformDrainComplete.0 as u32;
        match unsafe { event.GetType()? } {
            NEED_INPUT => self.needs_input = true,
            HAVE_OUTPUT => {
                if let Some(output) = self.process_output()? {
                    outputs.push(output);
                }
            }
            DRAIN_COMPLETE => self.drained = true,
            _ => {}
        }
        Ok(())
    }

    fn process_output(&mut self) -> windows::core::Result<Option<MfEncodedOutput>> {
        let supplied_sample = if self.provides_output_samples {
            None
        } else {
            let buffer = unsafe { MFCreateMemoryBuffer(self.output_size.max(1))? };
            let sample = unsafe { MFCreateSample()? };
            unsafe { sample.AddBuffer(&buffer)? };
            Some(sample)
        };

        let mut data = [MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            pSample: ManuallyDrop::new(supplied_sample),
            dwStatus: 0,
            pEvents: ManuallyDrop::new(None),
        }];
        let mut status = 0_u32;
        let result = unsafe { self.transform.ProcessOutput(0, &mut data, &mut status) };
        let sample = ManuallyDrop::into_inner(unsafe { ptr::read(&data[0].pSample) });
        let _events = ManuallyDrop::into_inner(unsafe { ptr::read(&data[0].pEvents) });

        match result {
            Ok(()) => {}
            Err(error) if error.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
            Err(error) if error.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                let output_type = create_h264_output_type(self.config)?;
                unsafe { self.transform.SetOutputType(0, &output_type, 0)? };
                let info = output_stream_info(&self.transform)?;
                self.provides_output_samples = info.0;
                self.output_size = info.1;
                return Ok(None);
            }
            Err(error) => return Err(error),
        }

        let Some(sample) = sample else {
            return Ok(None);
        };
        let sample_time = unsafe { sample.GetSampleTime() }.ok();
        let pending = self.take_pending(sample_time)?;
        let bytes = sample_to_vec(&sample)?;
        let keyframe = unsafe { sample.GetUINT32(&MFSampleExtension_CleanPoint) }.unwrap_or(0) != 0
            || annex_b_contains_idr(&bytes);
        let frame = SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id: pending.frame_id,
                timestamp_us: pending.timestamp_us,
                keyframe,
            },
            Codec::H264,
            bytes,
        );

        Ok(Some(MfEncodedOutput {
            frame,
            recycled_surface: pending.surface,
        }))
    }

    fn take_pending(&mut self, sample_time: Option<i64>) -> windows::core::Result<PendingInput> {
        let matching = sample_time.and_then(|time| {
            self.pending
                .iter()
                .position(|pending| pending.sample_time_100ns == time)
        });
        let pending = match matching {
            Some(index) => self.pending.remove(index),
            None => self.pending.pop_front(),
        };
        pending.ok_or_else(|| invalid_argument("encoder produced output with no pending input"))
    }
}

fn output_stream_info(transform: &IMFTransform) -> windows::core::Result<(bool, u32)> {
    let info = unsafe { transform.GetOutputStreamInfo(0)? };
    let provides = info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 != 0;
    Ok((provides, info.cbSize))
}

fn create_nv12_input_type(config: MfH264EncoderConfig) -> windows::core::Result<IMFMediaType> {
    let media_type = unsafe { MFCreateMediaType()? };
    unsafe {
        media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
        media_type.SetUINT64(
            &MF_MT_FRAME_SIZE,
            pack_u32_pair(config.width, config.height),
        )?;
        media_type.SetUINT64(
            &MF_MT_FRAME_RATE,
            pack_u32_pair(config.fps_numerator, config.fps_denominator),
        )?;
        media_type.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_u32_pair(1, 1))?;
        media_type.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
    }
    Ok(media_type)
}

fn create_h264_output_type(config: MfH264EncoderConfig) -> windows::core::Result<IMFMediaType> {
    let media_type = unsafe { MFCreateMediaType()? };
    unsafe {
        media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
        media_type.SetUINT64(
            &MF_MT_FRAME_SIZE,
            pack_u32_pair(config.width, config.height),
        )?;
        media_type.SetUINT64(
            &MF_MT_FRAME_RATE,
            pack_u32_pair(config.fps_numerator, config.fps_denominator),
        )?;
        media_type.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_u32_pair(1, 1))?;
        media_type.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        media_type.SetUINT32(&MF_MT_AVG_BITRATE, config.bitrate_bps)?;
    }
    Ok(media_type)
}

fn sample_to_vec(sample: &IMFSample) -> windows::core::Result<Vec<u8>> {
    let buffer = unsafe { sample.ConvertToContiguousBuffer()? };
    let mut pointer: *mut u8 = ptr::null_mut();
    let mut length = 0_u32;
    unsafe { buffer.Lock(&mut pointer, None, Some(&mut length))? };
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec();
    let unlock = unsafe { buffer.Unlock() };
    unlock?;
    Ok(bytes)
}

fn annex_b_contains_idr(bytes: &[u8]) -> bool {
    let mut index = 0_usize;
    while index + 4 <= bytes.len() {
        let nal_start = if bytes[index..].starts_with(&[0, 0, 0, 1]) {
            Some(index + 4)
        } else if bytes[index..].starts_with(&[0, 0, 1]) {
            Some(index + 3)
        } else {
            None
        };
        if let Some(start) = nal_start {
            if start < bytes.len() && bytes[start] & 0x1f == 5 {
                return true;
            }
            index = start;
        } else {
            index = index.saturating_add(1);
        }
    }
    false
}

fn validate_config(config: MfH264EncoderConfig) -> windows::core::Result<()> {
    if config.width == 0
        || config.height == 0
        || config.fps_numerator == 0
        || config.fps_denominator == 0
        || config.bitrate_bps == 0
    {
        return Err(invalid_argument(
            "invalid async H.264 encoder configuration",
        ));
    }
    Ok(())
}

fn validate_wait_config(config: MfAsyncWaitConfig) -> windows::core::Result<()> {
    if config.input_timeout.is_zero()
        || config.drain_timeout.is_zero()
        || config.poll_interval.is_zero()
    {
        return Err(invalid_argument(
            "Media Foundation async wait durations must be non-zero",
        ));
    }
    Ok(())
}

fn wait_for_next_poll(
    deadline: Instant,
    poll_interval: Duration,
    timeout_message: &'static str,
) -> windows::core::Result<()> {
    let now = Instant::now();
    if now >= deadline {
        return Err(timeout_error(timeout_message));
    }
    let remaining = deadline.duration_since(now);
    let sleep_for = if poll_interval < remaining {
        poll_interval
    } else {
        remaining
    };
    thread::sleep(sleep_for);
    if Instant::now() >= deadline {
        return Err(timeout_error(timeout_message));
    }
    Ok(())
}

const fn pack_u32_pair(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

fn invalid_argument(message: &'static str) -> windows::core::Error {
    windows::core::Error::new(windows::core::HRESULT(0x8007_0057_u32 as i32), message)
}

fn timeout_error(message: &'static str) -> windows::core::Error {
    windows::core::Error::new(windows::core::HRESULT(ERROR_TIMEOUT_HRESULT), message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_three_and_four_byte_annex_b_idr_start_codes() {
        assert!(annex_b_contains_idr(&[0, 0, 0, 1, 0x65, 1, 2]));
        assert!(annex_b_contains_idr(&[9, 0, 0, 1, 0x65, 3]));
        assert!(!annex_b_contains_idr(&[0, 0, 0, 1, 0x41, 1, 2]));
    }

    #[test]
    fn packed_media_foundation_pairs_are_stable() {
        assert_eq!(pack_u32_pair(1920, 1080), 0x0000_0780_0000_0438);
        assert_eq!(pack_u32_pair(30, 1), 0x0000_001e_0000_0001);
    }

    #[test]
    fn accepted_submit_error_never_exposes_a_recyclable_surface() {
        let error = MfSubmitError::accepted(invalid_argument("synthetic async failure"));
        assert!(error.input_was_accepted());
        assert!(error.rejected_surface.is_none());
    }

    #[test]
    fn default_wait_policy_is_bounded_and_polling() {
        let wait = MfAsyncWaitConfig::default();
        assert_eq!(wait.input_timeout, Duration::from_secs(2));
        assert_eq!(wait.drain_timeout, Duration::from_secs(5));
        assert_eq!(wait.poll_interval, Duration::from_millis(1));
        assert!(validate_wait_config(wait).is_ok());
    }

    #[test]
    fn zero_wait_duration_is_rejected() {
        let wait = MfAsyncWaitConfig {
            input_timeout: Duration::ZERO,
            ..MfAsyncWaitConfig::default()
        };
        assert!(validate_wait_config(wait).is_err());
    }

    #[test]
    fn timeout_error_uses_win32_timeout_hresult() {
        assert_eq!(
            timeout_error("test timeout").code(),
            windows::core::HRESULT(ERROR_TIMEOUT_HRESULT)
        );
    }
}
