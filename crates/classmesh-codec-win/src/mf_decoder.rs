#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fmt;
use std::mem::ManuallyDrop;
use std::ptr::{self, null_mut, read};

use windows::Win32::Graphics::Direct3D11::ID3D11Device;
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, IMFDXGIBuffer, IMFMediaType, IMFSample, IMFTransform,
    MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY, MF_MT_MAJOR_TYPE,
    MF_MT_SUBTYPE, MF_SA_D3D11_AWARE, MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample,
    MFMediaType_Video, MFT_CATEGORY_VIDEO_DECODER, MFT_ENUM_FLAG_ASYNCMFT, MFT_ENUM_FLAG_HARDWARE,
    MFT_ENUM_FLAG_SORTANDFILTER, MFT_ENUM_FLAG_SYNCMFT, MFT_FRIENDLY_NAME_Attribute,
    MFT_MESSAGE_COMMAND_FLUSH, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFT_REGISTER_TYPE_INFO, MFT_TRANSFORM_CLSID_Attribute,
    MFTEnumEx, MFVideoFormat_H264, MFVideoFormat_NV12,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::core::Interface;

use crate::mf::{MfDxgiDeviceManager, microseconds_to_100ns};

const MAX_OUTPUTS_PER_POLL: usize = 32;

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

    fn activate_transform(&self) -> windows::core::Result<IMFTransform> {
        unsafe { self.activation.ActivateObject::<IMFTransform>() }
    }
}

/// Enumerates H.264 decoder MFTs that advertise NV12 output.
///
/// Both proxy/synchronous and true hardware/asynchronous transforms are considered. ClassMesh does
/// not trust registration alone: [`MfH264Decoder::new`] requires the activated transform to report
/// D3D11 awareness before it may enter the GPU presentation path.
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
/// The Media Foundation sample and its `IMFDXGIBuffer` are retained together so a renderer can
/// later obtain the underlying D3D11 texture without a CPU readback.
pub struct DecodedGpuFrame {
    sample: IMFSample,
    dxgi_buffer: IMFDXGIBuffer,
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
    pub const fn timestamp_100ns(&self) -> Option<i64> {
        self.timestamp_100ns
    }

    #[must_use]
    pub const fn duration_100ns(&self) -> Option<i64> {
        self.duration_100ns
    }
}

/// D3D11-aware Media Foundation H.264 decoder for the student presentation path.
///
/// Input access units remain compressed CPU memory. Decoded output must be an NV12 DXGI-backed
/// sample produced by the decoder. A transform that does not provide D3D11 output samples is
/// rejected rather than silently introducing a CPU-frame fallback into the real-time path.
pub struct MfH264Decoder {
    transform: IMFTransform,
    _device_manager: MfDxgiDeviceManager,
    decoder_name: String,
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
    /// Returns an error if the transform is not D3D11-aware, cannot negotiate NV12 output, or does
    /// not provide its own DXGI-backed output samples.
    pub fn new(
        activation: &MfDecoderActivation,
        device: &ID3D11Device,
    ) -> windows::core::Result<Self> {
        let transform = activation.activate_transform()?;
        let attributes = unsafe { transform.GetAttributes()? };
        let d3d11_aware = unsafe { attributes.GetUINT32(&MF_SA_D3D11_AWARE) }.unwrap_or(0) != 0;
        if !d3d11_aware {
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
        unsafe { transform.SetInputType(0, &input_type, 0)? };
        configure_nv12_output(&transform)?;
        require_decoder_owned_output(&transform)?;

        unsafe {
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        }

        Ok(Self {
            transform,
            _device_manager: device_manager,
            decoder_name: activation.name.clone(),
        })
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
        &self,
        access_unit: &[u8],
        timestamp_us: u64,
    ) -> windows::core::Result<()> {
        if access_unit.is_empty() {
            return Err(classmesh_decoder_error("empty H.264 access unit"));
        }
        let sample = create_compressed_sample(access_unit, timestamp_us)?;
        unsafe { self.transform.ProcessInput(0, &sample, 0) }
    }

    /// Pulls all currently available decoded frames, up to a bounded per-call batch.
    ///
    /// # Errors
    /// Returns Media Foundation output errors, a renegotiation error, or an error if decoded output
    /// is not backed by `IMFDXGIBuffer`.
    pub fn poll_decoded(&self) -> windows::core::Result<Vec<DecodedGpuFrame>> {
        let mut frames = Vec::new();
        for _ in 0..MAX_OUTPUTS_PER_POLL {
            match process_one_output(&self.transform) {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break,
                Err(error) if error.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    configure_nv12_output(&self.transform)?;
                    require_decoder_owned_output(&self.transform)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(frames)
    }

    /// Flushes compressed and decoded state while keeping the transform alive.
    ///
    /// # Errors
    /// Returns the transform error if the flush command is rejected.
    pub fn flush(&self) -> windows::core::Result<()> {
        unsafe { self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0) }
    }

    /// Ends the active decode stream.
    ///
    /// # Errors
    /// Returns the first transform lifecycle error.
    pub fn end_streaming(&self) -> windows::core::Result<()> {
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0)?;
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0)
        }
    }
}

fn create_h264_input_type() -> windows::core::Result<IMFMediaType> {
    let media_type = unsafe { MFCreateMediaType()? };
    unsafe {
        media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
    }
    Ok(media_type)
}

fn configure_nv12_output(transform: &IMFTransform) -> windows::core::Result<()> {
    for index in 0..64_u32 {
        let media_type = match unsafe { transform.GetOutputAvailableType(0, index) } {
            Ok(media_type) => media_type,
            Err(_) => break,
        };
        let subtype = unsafe { media_type.GetGUID(&MF_MT_SUBTYPE) };
        if subtype.is_ok_and(|subtype| subtype == MFVideoFormat_NV12) {
            unsafe { transform.SetOutputType(0, &media_type, 0)? };
            return Ok(());
        }
    }
    Err(classmesh_decoder_error(
        "H.264 decoder did not offer NV12 output",
    ))
}

fn require_decoder_owned_output(transform: &IMFTransform) -> windows::core::Result<()> {
    let info = unsafe { transform.GetOutputStreamInfo(0)? };
    if info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 == 0 {
        return Err(classmesh_decoder_error(
            "D3D11 H.264 decoder does not provide DXGI output samples",
        ));
    }
    Ok(())
}

fn create_compressed_sample(data: &[u8], timestamp_us: u64) -> windows::core::Result<IMFSample> {
    let length = u32::try_from(data.len())
        .map_err(|_| classmesh_decoder_error("H.264 access unit exceeds Media Foundation limit"))?;
    let buffer = unsafe { MFCreateMemoryBuffer(length)? };
    let mut pointer: *mut u8 = ptr::null_mut();
    let mut max_length = 0_u32;
    unsafe { buffer.Lock(&mut pointer, Some(&mut max_length), None)? };
    if max_length < length {
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
        sample.SetSampleTime(microseconds_to_100ns(timestamp_us))?;
    }
    Ok(sample)
}

fn process_one_output(transform: &IMFTransform) -> windows::core::Result<Option<DecodedGpuFrame>> {
    let mut output = [MFT_OUTPUT_DATA_BUFFER {
        dwStreamID: 0,
        pSample: ManuallyDrop::new(None),
        dwStatus: 0,
        pEvents: ManuallyDrop::new(None),
    }];
    let mut status = 0_u32;
    let result = unsafe { transform.ProcessOutput(0, &mut output, &mut status) };
    let sample = ManuallyDrop::into_inner(unsafe { ptr::read(&output[0].pSample) });
    let _events = ManuallyDrop::into_inner(unsafe { ptr::read(&output[0].pEvents) });

    match result {
        Ok(()) => {}
        Err(error) if error.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
        Err(error) => return Err(error),
    }

    let sample = sample.ok_or_else(|| {
        classmesh_decoder_error("H.264 decoder reported output without an IMFSample")
    })?;
    let buffer = unsafe { sample.GetBufferByIndex(0)? };
    let dxgi_buffer: IMFDXGIBuffer = buffer.cast()?;
    let timestamp_100ns = unsafe { sample.GetSampleTime() }.ok();
    let duration_100ns = unsafe { sample.GetSampleDuration() }.ok();

    Ok(Some(DecodedGpuFrame {
        sample,
        dxgi_buffer,
        timestamp_100ns,
        duration_100ns,
    }))
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
    fn decoder_output_batch_is_bounded() {
        assert_eq!(MAX_OUTPUTS_PER_POLL, 32);
    }

    #[test]
    fn empty_access_unit_error_is_stable() {
        let error = classmesh_decoder_error("empty H.264 access unit");
        assert_eq!(error.code(), windows::core::HRESULT(0x8000_4005_u32 as i32));
    }
}
