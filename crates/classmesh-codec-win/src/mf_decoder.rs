#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fmt;
use std::mem::ManuallyDrop;
use std::ptr::{self, null_mut, read};

use windows::Win32::Graphics::Direct3D11::{D3D11_TEXTURE2D_DESC, ID3D11Device, ID3D11Texture2D};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_NV12;
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, IMFAttributes, IMFDXGIBuffer, IMFMediaType, IMFSample, IMFTransform,
    MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY, MF_MT_MAJOR_TYPE,
    MF_MT_SUBTYPE, MF_SA_D3D11_AWARE, MF_TRANSFORM_ASYNC, MFCreateMediaType, MFCreateMemoryBuffer,
    MFCreateSample, MFMediaType_Video, MFSampleExtension_Discontinuity, MFT_CATEGORY_VIDEO_DECODER,
    MFT_ENUM_FLAG_ASYNCMFT, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_ENUM_FLAG_SYNCMFT, MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_COMMAND_DRAIN,
    MFT_MESSAGE_COMMAND_FLUSH, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_MESSAGE_TYPE,
    MFT_OUTPUT_DATA_BUFFER, MFT_OUTPUT_DATA_BUFFER_INCOMPLETE, MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE,
    MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES, MFT_OUTPUT_STREAM_PROVIDES_SAMPLES,
    MFT_REGISTER_TYPE_INFO, MFT_TRANSFORM_CLSID_Attribute, MFTEnumEx, MFVideoFormat_H264,
    MFVideoFormat_NV12,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::core::{IUnknown, Interface};

use crate::mf::MfDxgiDeviceManager;

/// One Media Foundation H.264 decoder candidate.
pub struct MfDecoderActivation {
    name: String,
    clsid: String,
    activation: IMFActivate,
}

impl fmt::Debug for MfDecoderActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MfDecoderActivation")
            .field("name", &self.name)
            .field("clsid", &self.clsid)
            .finish_non_exhaustive()
    }
}

impl MfDecoderActivation {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn clsid(&self) -> &str {
        &self.clsid
    }
}

// IMFActivate owns a cached reference and is responsible for shutting down
// the transform, including candidates that fail qualification.
struct DecoderActivationGuard(IMFActivate);

impl Drop for DecoderActivationGuard {
    fn drop(&mut self) {
        let _ = unsafe { self.0.ShutdownObject() };
    }
}

/// Enumerates H.264 decoder MFTs that advertise NV12 output.
///
/// Registration alone is insufficient. [`MfH264Decoder::new`] qualifies the activated
/// transform's synchronous I/O contract and D3D11 support before presentation.
///
/// # Errors
/// Returns the Media Foundation enumeration error.
pub fn enumerate_h264_decoders() -> windows::core::Result<Vec<MfDecoderActivation>> {
    let input_type = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };
    let output_type = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let flags = MFT_ENUM_FLAG_SYNCMFT
        | MFT_ENUM_FLAG_ASYNCMFT
        | MFT_ENUM_FLAG_HARDWARE
        | MFT_ENUM_FLAG_SORTANDFILTER;
    let mut raw_activations: *mut Option<IMFActivate> = null_mut();
    let mut activation_count = 0_u32;

    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_DECODER,
            flags,
            Some(&input_type),
            Some(&output_type),
            &mut raw_activations,
            &mut activation_count,
        )?;
    }

    let count = usize::try_from(activation_count).unwrap_or(usize::MAX);
    let mut decoders = Vec::with_capacity(count);
    if !raw_activations.is_null() {
        for index in 0..count {
            let activation = unsafe { read(raw_activations.add(index)) };
            if let Some(activation) = activation {
                decoders.push(MfDecoderActivation {
                    name: activation_string(&activation, &MFT_FRIENDLY_NAME_Attribute)
                        .unwrap_or_else(|| "Media Foundation H.264 decoder".to_owned()),
                    clsid: unsafe { activation.GetGUID(&MFT_TRANSFORM_CLSID_Attribute) }
                        .map_or_else(|_| "unknown".to_owned(), |value| format!("{value:?}")),
                    activation,
                });
            }
        }
        unsafe { CoTaskMemFree(Some(raw_activations.cast::<c_void>())) };
    }

    Ok(decoders)
}

/// GPU-resident decoded output from the H.264 decoder.
///
/// Retains the sample for as long as the presenter uses its validated D3D11 texture.
pub struct DecodedGpuFrame {
    sample: IMFSample,
    dxgi_buffer: IMFDXGIBuffer,
    texture: ID3D11Texture2D,
    subresource_index: u32,
    timestamp_100ns: Option<i64>,
    duration_100ns: Option<i64>,
}

impl fmt::Debug for DecodedGpuFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedGpuFrame")
            .field("timestamp_100ns", &self.timestamp_100ns)
            .field("duration_100ns", &self.duration_100ns)
            .finish_non_exhaustive()
    }
}

impl DecodedGpuFrame {
    #[must_use]
    pub const fn sample(&self) -> &IMFSample {
        &self.sample
    }

    #[must_use]
    pub const fn dxgi_buffer(&self) -> &IMFDXGIBuffer {
        &self.dxgi_buffer
    }

    #[must_use]
    pub const fn texture(&self) -> &ID3D11Texture2D {
        &self.texture
    }

    #[must_use]
    pub const fn subresource_index(&self) -> u32 {
        self.subresource_index
    }

    #[must_use]
    pub const fn timestamp_100ns(&self) -> Option<i64> {
        self.timestamp_100ns
    }

    #[must_use]
    pub const fn duration_100ns(&self) -> Option<i64> {
        self.duration_100ns
    }
}

/// One synchronous ProcessOutput step. The caller releases each frame before polling again.
#[derive(Debug)]
pub enum DecoderOutput {
    Frame(DecodedGpuFrame),
    Progress,
    NeedInput,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamState {
    FirstInput,
    Streaming,
    ResetRequired,
    Ending,
    Draining,
    Stopped,
}

impl StreamState {
    fn flush(
        &mut self,
        mut message: impl FnMut(MFT_MESSAGE_TYPE) -> windows::core::Result<()>,
    ) -> windows::core::Result<()> {
        if matches!(self, Self::Ending | Self::Draining | Self::Stopped) {
            return Err(classmesh_decoder_error(
                "cannot restart an ending H.264 stream",
            ));
        }
        *self = Self::ResetRequired;
        message(MFT_MESSAGE_COMMAND_FLUSH)?;
        message(MFT_MESSAGE_NOTIFY_START_OF_STREAM)?;
        *self = Self::FirstInput;
        Ok(())
    }

    fn end(
        &mut self,
        mut message: impl FnMut(MFT_MESSAGE_TYPE) -> windows::core::Result<()>,
    ) -> windows::core::Result<()> {
        let previous = std::mem::replace(self, Self::Stopped);
        if previous == Self::Stopped {
            return Ok(());
        }
        let end_input = if matches!(previous, Self::Ending | Self::Draining) {
            Ok(())
        } else {
            message(MFT_MESSAGE_NOTIFY_END_OF_STREAM)
        };
        // Release queued samples and notify the MFT even if an earlier message failed.
        let flush = message(MFT_MESSAGE_COMMAND_FLUSH);
        let end = message(MFT_MESSAGE_NOTIFY_END_STREAMING);
        end_input.and(flush).and(end)
    }

    fn begin_drain(
        &mut self,
        mut message: impl FnMut(MFT_MESSAGE_TYPE) -> windows::core::Result<()>,
    ) -> windows::core::Result<()> {
        if *self != Self::Streaming {
            return Err(classmesh_decoder_error(
                "cannot drain an inactive H.264 stream",
            ));
        }
        *self = Self::ResetRequired;
        message(MFT_MESSAGE_NOTIFY_END_OF_STREAM)?;
        *self = Self::Ending;
        message(MFT_MESSAGE_COMMAND_DRAIN)?;
        *self = Self::Draining;
        Ok(())
    }
}

/// D3D11-aware Media Foundation H.264 decoder for the student presentation path.
///
/// Input access units remain compressed CPU memory. Decoded output must be an NV12 DXGI-backed
/// sample produced by the decoder. A transform that does not provide D3D11 output samples is
/// rejected rather than silently introducing a CPU-frame fallback into the real-time path.
pub struct MfH264Decoder {
    transform: IMFTransform,
    _activation: DecoderActivationGuard,
    device: ID3D11Device,
    _device_manager: MfDxgiDeviceManager,
    decoder_name: String,
    state: StreamState,
}

impl fmt::Debug for MfH264Decoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MfH264Decoder")
            .field("decoder_name", &self.decoder_name)
            .finish_non_exhaustive()
    }
}

impl MfH264Decoder {
    /// Activates an H.264 decoder and binds it to the caller's D3D11 device.
    ///
    /// # Errors
    /// Returns an error if the transform uses asynchronous I/O, lacks D3D11 support, cannot
    /// negotiate NV12 output, or cannot supply DXGI-backed output samples.
    pub fn new(
        activation: MfDecoderActivation,
        device: &ID3D11Device,
    ) -> windows::core::Result<Self> {
        let guard = DecoderActivationGuard(activation.activation);
        let transform = unsafe { guard.0.ActivateObject::<IMFTransform>()? };
        let attributes = unsafe { transform.GetAttributes()? };
        if unsafe { attributes.GetUINT32(&MF_TRANSFORM_ASYNC) }.unwrap_or(0) != 0 {
            return Err(classmesh_decoder_error(
                "asynchronous H.264 decoder requires an event-driven input/output pump",
            ));
        }
        let device_manager = configure_decoder(&transform, &attributes, device, 0, 0)?;

        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)? };
        let decoder = Self {
            transform,
            _activation: guard,
            device: device.clone(),
            _device_manager: device_manager,
            decoder_name: activation.name,
            state: StreamState::FirstInput,
        };
        unsafe {
            decoder
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?
        };
        Ok(decoder)
    }

    #[must_use]
    pub fn decoder_name(&self) -> &str {
        &self.decoder_name
    }

    /// Submits one compressed H.264 access unit.
    ///
    /// The first keyframe should contain the SPS/PPS required by the decoder. Media Foundation may
    /// initially signal `MF_E_TRANSFORM_STREAM_CHANGE` once it learns the coded dimensions; that is
    /// handled by [`Self::poll_decoded`].
    ///
    /// # Errors
    /// Returns an error if the compressed sample cannot be allocated or accepted by the transform.
    pub fn submit_access_unit(
        &mut self,
        access_unit: &[u8],
        timestamp_us: u64,
    ) -> windows::core::Result<()> {
        if access_unit.is_empty() {
            return Err(classmesh_decoder_error("empty H.264 access unit"));
        }
        let first_input = match self.state {
            StreamState::FirstInput => true,
            StreamState::Streaming => false,
            _ => {
                return Err(classmesh_decoder_error(
                    "H.264 decoder is not accepting input",
                ));
            }
        };
        let sample = create_compressed_sample(access_unit, timestamp_us)?;
        if first_input {
            unsafe { sample.SetUINT32(&MFSampleExtension_Discontinuity, 1)? };
        }
        unsafe { self.transform.ProcessInput(0, &sample, 0) }
            .map_err(|error| prefer_device_failure(&self.device, error))?;
        self.state = StreamState::Streaming;
        Ok(())
    }

    /// Polls one frame or handles one stream change. Release the returned frame before
    /// polling again so decoder-owned surfaces can return to the MFT's pool.
    ///
    /// # Errors
    /// Returns Media Foundation output errors, a renegotiation error, or an error if decoded output
    /// is not backed by `IMFDXGIBuffer`.
    pub fn poll_decoded(&self) -> windows::core::Result<DecoderOutput> {
        match self.state {
            StreamState::FirstInput => return Ok(DecoderOutput::NeedInput),
            StreamState::Streaming | StreamState::Draining => {}
            _ => {
                return Err(classmesh_decoder_error(
                    "H.264 decoder is not producing output",
                ));
            }
        }
        let output = match process_one_output(&self.transform, &self.device, 0) {
            Err(error) if error.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                configure_nv12_output(&self.transform, 0)
                    .and_then(|()| require_decoder_owned_output(&self.transform, 0))
                    .map(|()| DecoderOutput::Progress)
            }
            result => result,
        };
        output.map_err(|error| prefer_device_failure(&self.device, error))
    }

    /// Flushes compressed and decoded state while keeping the transform alive.
    ///
    /// # Errors
    /// Returns the transform error if the flush command is rejected.
    pub fn flush(&mut self) -> windows::core::Result<()> {
        self.state
            .flush(|message| unsafe { self.transform.ProcessMessage(message, 0) })
            .map_err(|error| prefer_device_failure(&self.device, error))
    }

    /// Tells the transform to release delayed output for normal end-of-stream.
    ///
    /// # Errors
    /// Returns an error if the stream is inactive or the MFT rejects the drain.
    pub fn begin_drain(&mut self) -> windows::core::Result<()> {
        self.state
            .begin_drain(|message| unsafe { self.transform.ProcessMessage(message, 0) })
    }

    /// Ends the active decode stream.
    ///
    /// # Errors
    /// Returns the first transform lifecycle error.
    pub fn end_streaming(&mut self) -> windows::core::Result<()> {
        self.state
            .end(|message| unsafe { self.transform.ProcessMessage(message, 0) })
    }
}

impl Drop for MfH264Decoder {
    fn drop(&mut self) {
        let _ = self.end_streaming();
    }
}

fn prefer_device_failure(
    device: &ID3D11Device,
    transform_error: windows::core::Error,
) -> windows::core::Error {
    // MFTs can wrap DXGI errors in a generic Media Foundation failure.
    unsafe { device.GetDeviceRemovedReason() }
        .err()
        .unwrap_or(transform_error)
}

fn configure_decoder(
    transform: &IMFTransform,
    attributes: &IMFAttributes,
    device: &ID3D11Device,
    input_stream: u32,
    output_stream: u32,
) -> windows::core::Result<MfDxgiDeviceManager> {
    if unsafe { attributes.GetUINT32(&MF_SA_D3D11_AWARE) }.unwrap_or(0) == 0 {
        return Err(classmesh_decoder_error("H.264 decoder is not D3D11-aware"));
    }
    let _ = unsafe { attributes.SetUINT32(&MF_LOW_LATENCY, 1) };
    let device_manager = MfDxgiDeviceManager::new(device)?;
    unsafe {
        transform.ProcessMessage(
            MFT_MESSAGE_SET_D3D_MANAGER,
            device_manager.manager().as_raw() as usize,
        )?;
    }
    let input_type = create_h264_input_type()?;
    unsafe { transform.SetInputType(input_stream, &input_type, 0)? };
    configure_nv12_output(transform, output_stream)?;
    require_decoder_owned_output(transform, output_stream)?;
    Ok(device_manager)
}

fn create_h264_input_type() -> windows::core::Result<IMFMediaType> {
    let media_type = unsafe { MFCreateMediaType()? };
    unsafe {
        media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
    }
    Ok(media_type)
}

fn configure_nv12_output(
    transform: &IMFTransform,
    output_stream: u32,
) -> windows::core::Result<()> {
    for index in 0..64_u32 {
        let media_type = match unsafe { transform.GetOutputAvailableType(output_stream, index) } {
            Ok(media_type) => media_type,
            Err(_) => break,
        };
        let subtype = unsafe { media_type.GetGUID(&MF_MT_SUBTYPE) };
        if subtype.is_ok_and(|subtype| subtype == MFVideoFormat_NV12) {
            unsafe { transform.SetOutputType(output_stream, &media_type, 0)? };
            return Ok(());
        }
    }
    Err(classmesh_decoder_error(
        "H.264 decoder did not offer NV12 output",
    ))
}

fn require_decoder_owned_output(
    transform: &IMFTransform,
    output_stream: u32,
) -> windows::core::Result<()> {
    let info = unsafe { transform.GetOutputStreamInfo(output_stream)? };
    let provides = MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0;
    if info.dwFlags & provides as u32 == 0 {
        return Err(classmesh_decoder_error(
            "D3D11 H.264 decoder does not provide DXGI output samples",
        ));
    }
    Ok(())
}

fn checked_sample_time(timestamp_us: u64) -> windows::core::Result<i64> {
    timestamp_us
        .checked_mul(10)
        .and_then(|ticks| i64::try_from(ticks).ok())
        .ok_or_else(|| classmesh_decoder_error("H.264 timestamp exceeds Media Foundation limit"))
}

fn create_compressed_sample(data: &[u8], timestamp_us: u64) -> windows::core::Result<IMFSample> {
    create_compressed_sample_at(data, checked_sample_time(timestamp_us)?)
}

fn create_compressed_sample_at(
    data: &[u8],
    timestamp_100ns: i64,
) -> windows::core::Result<IMFSample> {
    let length = u32::try_from(data.len())
        .map_err(|_| classmesh_decoder_error("H.264 access unit exceeds Media Foundation limit"))?;
    let buffer = unsafe { MFCreateMemoryBuffer(length)? };
    let mut pointer: *mut u8 = ptr::null_mut();
    let mut max_length = 0_u32;
    unsafe { buffer.Lock(&mut pointer, Some(&mut max_length), None)? };
    if pointer.is_null() || max_length < length {
        let _ = unsafe { buffer.Unlock() };
        return Err(classmesh_decoder_error(
            "Media Foundation compressed buffer is smaller than requested",
        ));
    }
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), pointer, data.len()) };
    unsafe { buffer.Unlock()? };
    unsafe { buffer.SetCurrentLength(length)? };

    let sample = unsafe { MFCreateSample()? };
    unsafe {
        sample.AddBuffer(&buffer)?;
        sample.SetSampleTime(timestamp_100ns)?;
    }
    Ok(sample)
}

fn process_one_output(
    transform: &IMFTransform,
    device: &ID3D11Device,
    output_stream: u32,
) -> windows::core::Result<DecoderOutput> {
    let mut output = [MFT_OUTPUT_DATA_BUFFER {
        dwStreamID: output_stream,
        pSample: ManuallyDrop::new(None),
        dwStatus: 0,
        pEvents: ManuallyDrop::new(None),
    }];
    let mut status = 0_u32;
    let result = unsafe { transform.ProcessOutput(0, &mut output, &mut status) };
    let [output] = output;
    interpret_output(output, status, result, |sample| {
        validate_gpu_frame(sample, device)
    })
}

fn interpret_output(
    output: MFT_OUTPUT_DATA_BUFFER,
    status: u32,
    result: windows::core::Result<()>,
    validate: impl FnOnce(IMFSample) -> windows::core::Result<DecodedGpuFrame>,
) -> windows::core::Result<DecoderOutput> {
    let sample = ManuallyDrop::into_inner(output.pSample);
    let events = ManuallyDrop::into_inner(output.pEvents);

    if status != 0
        && (result.is_ok()
            || result
                .as_ref()
                .is_err_and(|error| error.code() == MF_E_TRANSFORM_STREAM_CHANGE))
    {
        return Err(classmesh_decoder_error(
            "H.264 decoder returned unsupported output stream changes",
        ));
    }

    match result {
        Ok(()) => {}
        Err(error) if error.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => {
            return Ok(DecoderOutput::NeedInput);
        }
        Err(error) => return Err(error),
    }

    const NO_SAMPLE: u32 = MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE.0 as u32;
    const INCOMPLETE: u32 = MFT_OUTPUT_DATA_BUFFER_INCOMPLETE.0 as u32;
    match (output.dwStatus, sample, events) {
        (NO_SAMPLE, None, _) => Ok(DecoderOutput::Progress),
        (0 | INCOMPLETE, Some(sample), _) => Ok(DecoderOutput::Frame(validate(sample)?)),
        (0, None, Some(events)) => {
            if unsafe { events.GetElementCount()? } == 0 {
                return Err(classmesh_decoder_error(
                    "H.264 decoder returned an empty event collection",
                ));
            }
            Ok(DecoderOutput::Progress)
        }
        _ => Err(classmesh_decoder_error(
            "H.264 decoder returned an invalid output status or sample",
        )),
    }
}

fn validate_gpu_frame(
    sample: IMFSample,
    device: &ID3D11Device,
) -> windows::core::Result<DecodedGpuFrame> {
    let dxgi_buffer = dxgi_output_buffer(&sample)?;
    let mut resource = ptr::null_mut();
    unsafe { dxgi_buffer.GetResource(&ID3D11Texture2D::IID, &mut resource)? };
    if resource.is_null() {
        return Err(classmesh_decoder_error(
            "H.264 decoder returned a null D3D11 surface",
        ));
    }
    // GetResource returns an owned reference to the requested texture interface.
    let texture = unsafe { ID3D11Texture2D::from_raw(resource) };
    let owner = unsafe { texture.GetDevice()? };
    let subresource_index = unsafe { dxgi_buffer.GetSubresourceIndex()? };
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { texture.GetDesc(&mut desc) };
    if owner.cast::<IUnknown>()? != device.cast::<IUnknown>()?
        || desc.Format != DXGI_FORMAT_NV12
        || desc.Width == 0
        || desc.Height == 0
        || desc.SampleDesc.Count != 1
        || desc.MipLevels == 0
        || subresource_index / desc.MipLevels >= desc.ArraySize
    {
        return Err(classmesh_decoder_error(
            "H.264 decoder output is not a valid NV12 surface on the presentation device",
        ));
    }
    let timestamp_100ns = unsafe { sample.GetSampleTime() }.ok();
    let duration_100ns = unsafe { sample.GetSampleDuration() }.ok();

    Ok(DecodedGpuFrame {
        sample,
        dxgi_buffer,
        texture,
        subresource_index,
        timestamp_100ns,
        duration_100ns,
    })
}

fn dxgi_output_buffer(sample: &IMFSample) -> windows::core::Result<IMFDXGIBuffer> {
    if unsafe { sample.GetBufferCount()? } != 1 {
        return Err(classmesh_decoder_error(
            "H.264 decoder must return exactly one DXGI buffer per sample",
        ));
    }
    unsafe { sample.GetBufferByIndex(0)? }.cast()
}

fn activation_string(activation: &IMFActivate, key: &windows::core::GUID) -> Option<String> {
    let length = unsafe { activation.GetStringLength(key) }.ok()?;
    let mut utf16 = vec![0_u16; usize::try_from(length).ok()?.saturating_add(1)];
    unsafe { activation.GetString(key, &mut utf16, None) }.ok()?;
    Some(String::from_utf16_lossy(
        &utf16[..usize::try_from(length).ok()?],
    ))
}

fn classmesh_decoder_error(message: &'static str) -> windows::core::Error {
    windows::core::Error::new(windows::core::HRESULT(0x8000_4005_u32 as i32), message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_no_sample_without_events_is_progress() {
        let output = MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            pSample: ManuallyDrop::new(None),
            dwStatus: MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE.0 as u32,
            pEvents: ManuallyDrop::new(None),
        };
        let result = interpret_output(output, 0, Ok(()), |_| panic!("no sample to validate"));
        assert!(matches!(result.unwrap(), DecoderOutput::Progress));
    }

    #[test]
    fn unexpected_success_status_cannot_be_treated_as_progress() {
        use windows::Win32::Media::MediaFoundation::{
            MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE, MFT_OUTPUT_DATA_BUFFER_STREAM_END,
        };
        for status in [
            0,
            MFT_OUTPUT_DATA_BUFFER_INCOMPLETE.0,
            MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE.0,
            MFT_OUTPUT_DATA_BUFFER_STREAM_END.0,
            MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE.0 | MFT_OUTPUT_DATA_BUFFER_INCOMPLETE.0,
        ] {
            let output = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: ManuallyDrop::new(None),
                dwStatus: status as u32,
                pEvents: ManuallyDrop::new(None),
            };
            assert!(interpret_output(output, 0, Ok(()), |_| unreachable!()).is_err());
        }
    }

    #[test]
    fn no_sample_status_rejects_a_returned_sample() {
        let _platform = crate::mf::MfPlatform::startup().unwrap();
        let sample = unsafe { MFCreateSample() }.unwrap();
        let output = MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            pSample: ManuallyDrop::new(Some(sample)),
            dwStatus: MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE.0 as u32,
            pEvents: ManuallyDrop::new(None),
        };
        assert!(interpret_output(output, 0, Ok(()), |_| unreachable!()).is_err());
    }

    #[test]
    fn output_collection_releases_its_elements_on_success_and_failure() {
        use std::sync::Arc;
        use windows::Win32::Media::MediaFoundation::MFCreateCollection;

        #[windows::core::implement()]
        struct OwnedEvent {
            _lifetime: Arc<()>,
        }

        let _platform = crate::mf::MfPlatform::startup().unwrap();
        for accepted in [true, false] {
            let lifetime = Arc::new(());
            let released = Arc::downgrade(&lifetime);
            let event: IUnknown = OwnedEvent {
                _lifetime: lifetime,
            }
            .into();
            let collection = unsafe { MFCreateCollection() }.unwrap();
            unsafe { collection.AddElement(&event) }.unwrap();
            drop(event);
            assert!(released.upgrade().is_some());

            let output = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: ManuallyDrop::new(None),
                dwStatus: 0,
                pEvents: ManuallyDrop::new(Some(collection)),
            };
            let result = if accepted {
                Ok(())
            } else {
                Err(classmesh_decoder_error("injected output failure"))
            };
            assert_eq!(
                interpret_output(output, 0, result, |_| unreachable!()).is_ok(),
                accepted
            );
            assert!(released.upgrade().is_none());
        }
    }

    #[test]
    fn empty_access_unit_error_is_stable() {
        let error = classmesh_decoder_error("empty H.264 access unit");
        assert_eq!(error.code(), windows::core::HRESULT(0x8000_4005_u32 as i32));
    }

    #[test]
    fn compressed_sample_rejects_timestamps_that_would_alias() {
        let _platform = crate::mf::MfPlatform::startup().unwrap();
        let max_timestamp_us = (i64::MAX as u64) / 10;
        let sample = create_compressed_sample(&[1], max_timestamp_us).unwrap();
        assert_eq!(unsafe { sample.GetSampleTime() }.unwrap(), i64::MAX - 7);
        assert!(create_compressed_sample(&[1], max_timestamp_us + 1).is_err());
    }

    #[test]
    fn native_media_foundation_memory_sample_is_not_gpu_output() {
        let _platform = crate::mf::MfPlatform::startup().unwrap();
        let sample = create_compressed_sample(&[1, 2, 3], 123).unwrap();
        assert_eq!(unsafe { sample.GetSampleTime() }.unwrap(), 1_230);
        assert!(dxgi_output_buffer(&sample).is_err());
    }

    #[test]
    fn flush_restarts_stream_and_a_failed_restart_keeps_the_stream_invalid() {
        let mut state = StreamState::Streaming;
        let mut calls = Vec::new();
        let result = state.flush(|message| {
            calls.push(message);
            if message == MFT_MESSAGE_NOTIFY_START_OF_STREAM {
                return Err(classmesh_decoder_error("start rejected"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(state == StreamState::ResetRequired);
        assert_eq!(
            calls,
            [
                MFT_MESSAGE_COMMAND_FLUSH,
                MFT_MESSAGE_NOTIFY_START_OF_STREAM
            ]
        );
        state.flush(|_| Ok(())).unwrap();
        assert!(state == StreamState::FirstInput);
    }

    #[test]
    fn drain_ends_input_before_output_and_stop_discards_idempotently() {
        let mut state = StreamState::Streaming;
        let mut calls = Vec::new();
        let mut record = |message| {
            calls.push(message);
            Ok(())
        };
        state.begin_drain(&mut record).unwrap();
        assert!(state == StreamState::Draining);
        assert!(state.flush(&mut record).is_err());
        state.end(&mut record).unwrap();
        state.end(&mut record).unwrap();
        assert!(state == StreamState::Stopped);
        assert_eq!(
            calls,
            [
                MFT_MESSAGE_NOTIFY_END_OF_STREAM,
                MFT_MESSAGE_COMMAND_DRAIN,
                MFT_MESSAGE_COMMAND_FLUSH,
                MFT_MESSAGE_NOTIFY_END_STREAMING,
            ]
        );
    }

    #[test]
    fn abort_still_flushes_and_ends_streaming_if_eos_fails() {
        let mut state = StreamState::Streaming;
        let mut calls = Vec::new();
        let result = state.end(|message| {
            calls.push(message);
            if message == MFT_MESSAGE_NOTIFY_END_OF_STREAM {
                return Err(classmesh_decoder_error("EOS rejected"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(state == StreamState::Stopped);
        assert_eq!(
            calls,
            [
                MFT_MESSAGE_NOTIFY_END_OF_STREAM,
                MFT_MESSAGE_COMMAND_FLUSH,
                MFT_MESSAGE_NOTIFY_END_STREAMING,
            ]
        );
    }
}

#[path = "mf_decoder_async.rs"]
mod asynchronous;
pub use asynchronous::{AsyncDecoderPoll, AsyncDecoderSubmit, MfAsyncH264Decoder};
