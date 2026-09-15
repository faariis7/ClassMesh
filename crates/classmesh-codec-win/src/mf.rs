#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fmt;
use std::ptr::{null_mut, read};

use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, IMFDXGIDeviceManager, IMFMediaType, IMFSample, IMFTransform, MF_LOW_LATENCY,
    MF_MT_ALL_SAMPLES_INDEPENDENT, MF_MT_AVG_BITRATE, MF_MT_FIXED_SIZE_SAMPLES, MF_MT_FRAME_RATE,
    MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_PIXEL_ASPECT_RATIO,
    MF_MT_SUBTYPE, MF_TRANSFORM_ASYNC, MF_TRANSFORM_ASYNC_UNLOCK, MF_VERSION,
    MFCreateDXGIDeviceManager, MFCreateDXGISurfaceBuffer, MFCreateMediaType, MFCreateSample,
    MFMediaType_Video, MFSTARTUP_FULL, MFShutdown, MFStartup, MFT_CATEGORY_VIDEO_ENCODER,
    MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER, MFT_FRIENDLY_NAME_Attribute,
    MFT_MESSAGE_COMMAND_FLUSH, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_REGISTER_TYPE_INFO,
    MFT_TRANSFORM_CLSID_Attribute, MFTEnumEx, MFVideoFormat_H264, MFVideoFormat_NV12,
    MFVideoInterlace_Progressive,
};
use windows::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::core::Interface;

use crate::{EncoderCandidate, EncoderVendor};

/// Owns the COM apartment and Media Foundation startup lifetime for one Worker thread.
///
/// Media Foundation must outlive every transform, sample and device-manager object created through
/// this module. Construct this guard on the interactive Worker thread before probing encoders.
#[derive(Debug)]
pub struct MfPlatform {
    com_initialized: bool,
    mf_started: bool,
}

impl MfPlatform {
    /// Starts a multithreaded COM apartment and the full Media Foundation platform.
    ///
    /// # Errors
    /// Returns the underlying Windows error if COM or Media Foundation startup fails.
    pub fn startup() -> windows::core::Result<Self> {
        // SAFETY: COM initialization is balanced by `CoUninitialize` in Drop on this same thread.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;

        // SAFETY: MF_VERSION is the SDK-supported version and shutdown is balanced in Drop.
        if let Err(error) = unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL) } {
            // SAFETY: COM initialization above succeeded on this thread.
            unsafe { CoUninitialize() };
            return Err(error);
        }

        Ok(Self {
            com_initialized: true,
            mf_started: true,
        })
    }
}

impl Drop for MfPlatform {
    fn drop(&mut self) {
        if self.mf_started {
            // SAFETY: paired with the successful MFStartup call in `startup`.
            let _ = unsafe { MFShutdown() };
            self.mf_started = false;
        }
        if self.com_initialized {
            // SAFETY: paired with the successful CoInitializeEx call in `startup` and expected to
            // be dropped on the same Worker thread.
            unsafe { CoUninitialize() };
            self.com_initialized = false;
        }
    }
}

/// An H.264 hardware encoder activation returned by Media Foundation.
pub struct MfEncoderActivation {
    candidate: EncoderCandidate,
    activation: IMFActivate,
}

impl fmt::Debug for MfEncoderActivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MfEncoderActivation")
            .field("candidate", &self.candidate)
            .finish_non_exhaustive()
    }
}

impl MfEncoderActivation {
    #[must_use]
    pub const fn candidate(&self) -> &EncoderCandidate {
        &self.candidate
    }

    /// Activates the underlying Media Foundation transform.
    ///
    /// # Errors
    /// Returns the activation error reported by Media Foundation.
    pub fn activate_transform(&self) -> windows::core::Result<IMFTransform> {
        // SAFETY: IMFActivate owns the registered MFT activation and the requested interface is the
        // transform interface advertised by MFTEnumEx.
        unsafe { self.activation.ActivateObject::<IMFTransform>() }
    }
}

/// Enumerates hardware H.264 encoder MFTs in Media Foundation preference order.
///
/// `MfPlatform` must already be alive on the current thread. Software-only transforms are excluded
/// deliberately; ClassMesh evaluates a software fallback separately from the GPU-native path.
///
/// # Errors
/// Returns the Media Foundation enumeration error.
pub fn enumerate_h264_hardware_encoders() -> windows::core::Result<Vec<MfEncoderActivation>> {
    let output_type = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };
    let flags = MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER;
    let mut raw_activations: *mut Option<IMFActivate> = null_mut();
    let mut activation_count = 0_u32;

    // SAFETY: output pointers are valid and initialized. Media Foundation allocates the returned
    // array with CoTaskMemAlloc; each array element is moved out below before the array is freed.
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            flags,
            None,
            Some(&output_type),
            &mut raw_activations,
            &mut activation_count,
        )?;
    }

    let count = usize::try_from(activation_count).unwrap_or(usize::MAX);
    let mut encoders = Vec::with_capacity(count);
    if !raw_activations.is_null() {
        for index in 0..count {
            // SAFETY: MFTEnumEx returned an array containing `activation_count` Option<IMFActivate>
            // entries. `read` transfers ownership out of the raw array without double-dropping.
            let activation = unsafe { read(raw_activations.add(index)) };
            if let Some(activation) = activation {
                let candidate = candidate_from_activation(&activation);
                encoders.push(MfEncoderActivation {
                    candidate,
                    activation,
                });
            }
        }
        // SAFETY: all COM interface values were moved out above, so only the array allocation
        // itself remains to be released.
        unsafe { CoTaskMemFree(Some(raw_activations.cast::<c_void>())) };
    }

    Ok(encoders)
}

/// Media Foundation device-manager wrapper for sharing a D3D11 device with hardware transforms.
#[derive(Debug)]
pub struct MfDxgiDeviceManager {
    reset_token: u32,
    manager: IMFDXGIDeviceManager,
}

impl MfDxgiDeviceManager {
    /// Creates a DXGI device manager and binds it to the capture/processing D3D11 device.
    ///
    /// # Errors
    /// Returns the Media Foundation or device-manager error.
    pub fn new(device: &ID3D11Device) -> windows::core::Result<Self> {
        let mut reset_token = 0_u32;
        let mut manager = None;
        // SAFETY: both output pointers are valid. The returned manager is owned by the wrapper.
        unsafe { MFCreateDXGIDeviceManager(&mut reset_token, &mut manager) }?;
        let manager = manager.expect("MFCreateDXGIDeviceManager succeeded without a manager");
        // SAFETY: `device` is a live D3D11 device and the reset token belongs to this manager.
        unsafe { manager.ResetDevice(device, reset_token) }?;
        Ok(Self {
            reset_token,
            manager,
        })
    }

    #[must_use]
    pub const fn reset_token(&self) -> u32 {
        self.reset_token
    }

    #[must_use]
    pub const fn manager(&self) -> &IMFDXGIDeviceManager {
        &self.manager
    }
}

/// Stable ClassMesh configuration for one low-latency H.264 presentation rendition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfH264EncoderConfig {
    pub width: u32,
    pub height: u32,
    pub fps_numerator: u32,
    pub fps_denominator: u32,
    pub bitrate_bps: u32,
}

impl MfH264EncoderConfig {
    #[must_use]
    pub const fn presentation_1080p30() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps_numerator: 30,
            fps_denominator: 1,
            bitrate_bps: 5_000_000,
        }
    }

    #[must_use]
    pub const fn frame_duration_100ns(self) -> i64 {
        if self.fps_numerator == 0 {
            return 0;
        }
        let numerator = 10_000_000_u64.saturating_mul(self.fps_denominator as u64);
        let ticks = numerator / self.fps_numerator as u64;
        if ticks > i64::MAX as u64 {
            i64::MAX
        } else {
            ticks as i64
        }
    }
}

/// Configured Media Foundation H.264 transform backed by the same D3D11 device as capture.
///
/// The input contract is NV12 `ID3D11Texture2D`. BGRA desktop duplication frames must be converted
/// on the GPU before calling `submit_nv12_texture`; ClassMesh intentionally never performs a CPU
/// bitmap conversion in this path.
pub struct MfH264Encoder {
    transform: IMFTransform,
    _device_manager: MfDxgiDeviceManager,
    config: MfH264EncoderConfig,
}

impl fmt::Debug for MfH264Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MfH264Encoder")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl MfH264Encoder {
    /// Activates and configures a hardware H.264 MFT for GPU-native NV12 input.
    ///
    /// # Errors
    /// Returns the first Media Foundation or transform configuration error.
    pub fn new(
        activation: &MfEncoderActivation,
        device: &ID3D11Device,
        config: MfH264EncoderConfig,
    ) -> windows::core::Result<Self> {
        validate_encoder_config(config)?;
        let transform = activation.activate_transform()?;
        let device_manager = MfDxgiDeviceManager::new(device)?;

        // Async hardware MFTs are locked until callers explicitly opt into asynchronous operation.
        if activation.candidate().advertised_async {
            // SAFETY: this attribute store belongs to the newly activated transform and is mutated
            // before any streaming messages or samples are submitted.
            let attributes = unsafe { transform.GetAttributes()? };
            unsafe { attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)? };
        }

        // Low-latency is an intent. Some vendor MFTs may ignore the attribute, but the attribute
        // store itself should accept it and capability benchmarking later verifies real behavior.
        if let Ok(attributes) = unsafe { transform.GetAttributes() } {
            let _ = unsafe { attributes.SetUINT32(&MF_LOW_LATENCY, 1) };
        }

        // SAFETY: Media Foundation expects the raw IMFDXGIDeviceManager pointer as ulParam and the
        // wrapper outlives the transform for the whole encoder lifetime.
        unsafe {
            transform.ProcessMessage(
                MFT_MESSAGE_SET_D3D_MANAGER,
                device_manager.manager().as_raw() as usize,
            )?;
        }

        let output_type = create_h264_output_type(config)?;
        let input_type = create_nv12_input_type(config)?;

        // Some hardware encoders require output type before input type. Both stream IDs are zero for
        // standard one-in/one-out video encoder MFTs returned by MFTEnumEx.
        unsafe {
            transform.SetOutputType(0, &output_type, 0)?;
            transform.SetInputType(0, &input_type, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        }

        Ok(Self {
            transform,
            _device_manager: device_manager,
            config,
        })
    }

    #[must_use]
    pub const fn config(&self) -> MfH264EncoderConfig {
        self.config
    }

    /// Submits one GPU-resident NV12 texture to the encoder.
    ///
    /// # Errors
    /// Returns the Media Foundation error if the sample cannot be wrapped or accepted by the MFT.
    pub fn submit_nv12_texture(
        &self,
        texture: &ID3D11Texture2D,
        timestamp_us: u64,
    ) -> windows::core::Result<()> {
        let timestamp_100ns = microseconds_to_100ns(timestamp_us);
        let sample = create_dxgi_texture_sample(
            texture,
            timestamp_100ns,
            self.config.frame_duration_100ns(),
        )?;
        // SAFETY: the transform is configured for stream zero and the sample wraps an NV12 texture
        // from the same D3D11 device lineage provided to the device manager.
        unsafe { self.transform.ProcessInput(0, &sample, 0) }
    }

    /// Flushes queued transform state without destroying the encoder.
    ///
    /// # Errors
    /// Returns the transform error if the flush command fails.
    pub fn flush(&self) -> windows::core::Result<()> {
        // SAFETY: this is a control message on a live configured transform.
        unsafe { self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0) }
    }

    /// Signals end-of-stream and releases streaming resources held by the MFT.
    ///
    /// # Errors
    /// Returns the first transform error.
    pub fn end_streaming(&self) -> windows::core::Result<()> {
        // SAFETY: both messages are valid lifecycle messages for a configured transform.
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0)?;
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0)
        }
    }
}

/// Wraps a GPU-native D3D11 texture in an IMFSample without copying it to CPU memory.
///
/// The timestamp and duration use Media Foundation's 100-nanosecond timebase.
///
/// # Errors
/// Returns the Media Foundation error if the DXGI buffer/sample cannot be created or timestamped.
pub fn create_dxgi_texture_sample(
    texture: &ID3D11Texture2D,
    timestamp_100ns: i64,
    duration_100ns: i64,
) -> windows::core::Result<IMFSample> {
    // SAFETY: `texture` is a live D3D11 texture. The returned media buffer retains the COM surface
    // reference, so the caller does not need to keep a separate texture clone for sample lifetime.
    let buffer = unsafe { MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, texture, 0, false)? };
    // SAFETY: Media Foundation is expected to be started by an MfPlatform guard.
    let sample = unsafe { MFCreateSample()? };
    // SAFETY: both COM objects are live and owned for the duration of these calls.
    unsafe {
        sample.AddBuffer(&buffer)?;
        sample.SetSampleTime(timestamp_100ns)?;
        sample.SetSampleDuration(duration_100ns)?;
    }
    Ok(sample)
}

fn create_nv12_input_type(config: MfH264EncoderConfig) -> windows::core::Result<IMFMediaType> {
    // SAFETY: Media Foundation is expected to be started and the returned media type is owned.
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
        media_type.SetUINT32(&MF_MT_FIXED_SIZE_SAMPLES, 1)?;
        media_type.SetUINT32(&MF_MT_ALL_SAMPLES_INDEPENDENT, 1)?;
    }
    Ok(media_type)
}

fn create_h264_output_type(config: MfH264EncoderConfig) -> windows::core::Result<IMFMediaType> {
    // SAFETY: Media Foundation is expected to be started and the returned media type is owned.
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

fn validate_encoder_config(config: MfH264EncoderConfig) -> windows::core::Result<()> {
    if config.width == 0
        || config.height == 0
        || config.fps_numerator == 0
        || config.fps_denominator == 0
        || config.bitrate_bps == 0
    {
        return Err(windows::core::Error::new(
            windows::core::HRESULT(0x8007_0057_u32 as i32),
            "invalid H.264 encoder configuration",
        ));
    }
    Ok(())
}

#[must_use]
pub const fn microseconds_to_100ns(value_us: u64) -> i64 {
    let ticks = value_us.saturating_mul(10);
    if ticks > i64::MAX as u64 {
        i64::MAX
    } else {
        ticks as i64
    }
}

#[must_use]
const fn pack_u32_pair(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

fn candidate_from_activation(activation: &IMFActivate) -> EncoderCandidate {
    let name = activation_string(activation, &MFT_FRIENDLY_NAME_Attribute)
        .unwrap_or_else(|| "Hardware H.264 MFT".to_owned());
    // SAFETY: reading an IMFAttributes GUID/UINT32 is valid for this activation object. Missing
    // optional attributes are represented as fallback metadata rather than fatal probe errors.
    let clsid = unsafe { activation.GetGUID(&MFT_TRANSFORM_CLSID_Attribute) }
        .map_or_else(|_| "unknown".to_owned(), |value| format!("{value:?}"));
    let advertised_async = unsafe { activation.GetUINT32(&MF_TRANSFORM_ASYNC) }.unwrap_or(0) != 0;

    EncoderCandidate {
        vendor: vendor_from_name(&name),
        name,
        clsid,
        advertised_hardware: true,
        advertised_async,
    }
}

fn activation_string(activation: &IMFActivate, key: &windows::core::GUID) -> Option<String> {
    // SAFETY: both attribute reads operate on a live IMFActivate attribute store.
    let len = unsafe { activation.GetStringLength(key) }.ok()?;
    let mut utf16 = vec![0_u16; usize::try_from(len).ok()?.saturating_add(1)];
    unsafe { activation.GetString(key, &mut utf16, None) }.ok()?;
    Some(String::from_utf16_lossy(
        &utf16[..usize::try_from(len).ok()?],
    ))
}

fn vendor_from_name(name: &str) -> EncoderVendor {
    let normalized = name.to_ascii_lowercase();
    if normalized.contains("intel") {
        EncoderVendor::Intel
    } else if normalized.contains("nvidia") || normalized.contains("nvenc") {
        EncoderVendor::Nvidia
    } else if normalized.contains("amd") || normalized.contains("advanced micro devices") {
        EncoderVendor::Amd
    } else if normalized.contains("microsoft") {
        EncoderVendor::Microsoft
    } else {
        EncoderVendor::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_vendor_is_inferred_without_platform_calls() {
        assert_eq!(
            vendor_from_name("Intel H.264 Encoder MFT"),
            EncoderVendor::Intel
        );
        assert_eq!(vendor_from_name("NVIDIA NVENC H264"), EncoderVendor::Nvidia);
        assert_eq!(vendor_from_name("AMD Video Encoder"), EncoderVendor::Amd);
        assert_eq!(
            vendor_from_name("Microsoft H264 Video Encoder MFT"),
            EncoderVendor::Microsoft
        );
        assert_eq!(vendor_from_name("Vendor X Encoder"), EncoderVendor::Other);
    }

    #[test]
    fn timestamp_conversion_saturates() {
        assert_eq!(microseconds_to_100ns(123), 1_230);
        assert_eq!(microseconds_to_100ns(u64::MAX), i64::MAX);
    }

    #[test]
    fn media_foundation_pair_packing_matches_attribute_layout() {
        assert_eq!(pack_u32_pair(1920, 1080), 0x0000_0780_0000_0438);
        assert_eq!(pack_u32_pair(30, 1), 0x0000_001e_0000_0001);
    }

    #[test]
    fn presentation_frame_duration_is_about_thirty_fps() {
        let config = MfH264EncoderConfig::presentation_1080p30();
        assert_eq!(config.frame_duration_100ns(), 333_333);
    }
}
