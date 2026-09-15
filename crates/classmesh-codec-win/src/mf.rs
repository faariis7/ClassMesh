use std::ffi::c_void;
use std::fmt;
use std::ptr::{null_mut, read};

use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, IMFDXGIDeviceManager, IMFSample, IMFTransform, MF_TRANSFORM_ASYNC,
    MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_FRIENDLY_NAME_Attribute, MFT_REGISTER_TYPE_INFO, MFT_TRANSFORM_CLSID_Attribute,
    MFCreateDXGIDeviceManager, MFCreateDXGISurfaceBuffer, MFCreateSample, MFMediaType_Video,
    MFSTARTUP_FULL, MFShutdown, MFStartup, MFVideoFormat_H264, MF_VERSION, MFTEnumEx,
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
    let buffer = unsafe {
        MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, texture, 0, false)?
    };
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

#[must_use]
pub const fn microseconds_to_100ns(value_us: u64) -> i64 {
    let ticks = value_us.saturating_mul(10);
    if ticks > i64::MAX as u64 {
        i64::MAX
    } else {
        ticks as i64
    }
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
        assert_eq!(vendor_from_name("Intel H.264 Encoder MFT"), EncoderVendor::Intel);
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
}
