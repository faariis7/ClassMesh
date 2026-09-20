use std::fmt;
use std::time::Instant;

use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11CreateDevice, ID3D11Device,
    ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_MODE_ROTATION_ROTATE90, DXGI_MODE_ROTATION_ROTATE180, DXGI_MODE_ROTATION_ROTATE270,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_DEVICE_REMOVED, DXGI_ERROR_DEVICE_RESET,
    DXGI_ERROR_NOT_FOUND, DXGI_ERROR_UNSUPPORTED, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    IDXGIAdapter1, IDXGIDevice, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
};
use windows::core::Interface;

use crate::{
    AdapterCapabilityIdentity, CaptureBackend, CaptureFactory, CaptureFailure, CapturedFrameMeta,
    DisplayDescriptor, DisplayId,
};

pub struct DxgiFrame {
    texture: ID3D11Texture2D,
    duplication: IDXGIOutputDuplication,
    release_pending: bool,
}

impl DxgiFrame {
    #[must_use]
    pub const fn texture(&self) -> &ID3D11Texture2D {
        &self.texture
    }
}

impl fmt::Debug for DxgiFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DxgiFrame")
            .field("release_pending", &self.release_pending)
            .finish_non_exhaustive()
    }
}

impl Drop for DxgiFrame {
    fn drop(&mut self) {
        if self.release_pending {
            // SAFETY: this frame was produced by a successful AcquireNextFrame call on the same
            // duplication object and each frame wrapper releases exactly once.
            let _ = unsafe { self.duplication.ReleaseFrame() };
            self.release_pending = false;
        }
    }
}

#[derive(Debug, Default)]
pub struct DxgiCaptureFactory;

impl CaptureFactory<DxgiCaptureBackend> for DxgiCaptureFactory {
    fn create(&mut self, target: DisplayId) -> Result<DxgiCaptureBackend, CaptureFailure> {
        DxgiCaptureBackend::open(target)
    }
}

pub struct DxgiCaptureBackend {
    descriptor: DisplayDescriptor,
    device: ID3D11Device,
    duplication: IDXGIOutputDuplication,
    next_frame_id: u64,
    clock: Instant,
}

impl fmt::Debug for DxgiCaptureBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DxgiCaptureBackend")
            .field("descriptor", &self.descriptor)
            .field("next_frame_id", &self.next_frame_id)
            .finish_non_exhaustive()
    }
}

impl DxgiCaptureBackend {
    pub fn open(target: DisplayId) -> Result<Self, CaptureFailure> {
        let (adapter, descriptor, output) = find_output(target)?;
        let device = create_device(&adapter)?;
        // SAFETY: `output` is a live DXGI output that belongs to the selected adapter, and `device`
        // was created on that same adapter. Desktop Duplication owns its COM references.
        let duplication = unsafe { output.DuplicateOutput(&device) }.map_err(map_windows_error)?;

        Ok(Self {
            descriptor,
            device,
            duplication,
            next_frame_id: 1,
            clock: Instant::now(),
        })
    }

    /// Returns the D3D11 device that owns the duplication resources.
    ///
    /// Downstream GPU processing and hardware encoding must use this same adapter/device lineage to
    /// keep desktop frames GPU-native and avoid cross-adapter copies or CPU readback.
    #[must_use]
    pub const fn device(&self) -> &ID3D11Device {
        &self.device
    }
}

impl CaptureBackend for DxgiCaptureBackend {
    type Frame = DxgiFrame;

    fn display(&self) -> &DisplayDescriptor {
        &self.descriptor
    }

    fn acquire(
        &mut self,
        timeout_ms: u32,
    ) -> Result<(CapturedFrameMeta, Self::Frame), CaptureFailure> {
        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        // SAFETY: both output pointers are valid for the duration of the call. Desktop Duplication
        // permits exactly one outstanding acquired frame, represented by the returned `DxgiFrame`.
        unsafe {
            self.duplication
                .AcquireNextFrame(timeout_ms, &mut frame_info, &mut resource)
        }
        .map_err(map_windows_error)?;

        let Some(resource) = resource else {
            // SAFETY: AcquireNextFrame succeeded, so a frame is outstanding and must be released.
            let _ = unsafe { self.duplication.ReleaseFrame() };
            return Err(CaptureFailure::Fatal);
        };

        let texture = match resource.cast::<ID3D11Texture2D>() {
            Ok(texture) => texture,
            Err(_) => {
                // SAFETY: same successful-acquire obligation as above.
                let _ = unsafe { self.duplication.ReleaseFrame() };
                return Err(CaptureFailure::Fatal);
            }
        };

        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.saturating_add(1);
        let capture_timestamp_us =
            u64::try_from(self.clock.elapsed().as_micros()).unwrap_or(u64::MAX);
        let meta = CapturedFrameMeta {
            frame_id,
            capture_timestamp_us,
            width: self.descriptor.width,
            height: self.descriptor.height,
            accumulated_frames: frame_info.AccumulatedFrames,
            pointer_visible: frame_info.PointerPosition.Visible.as_bool(),
        };

        Ok((
            meta,
            DxgiFrame {
                texture,
                duplication: self.duplication.clone(),
                release_pending: true,
            },
        ))
    }
}

pub fn query_adapter_capability_identity(
    target: DisplayId,
) -> Result<AdapterCapabilityIdentity, CaptureFailure> {
    let (adapter, _, _) = find_output(target)?;
    let driver_version =
        unsafe { adapter.CheckInterfaceSupport(&IDXGIDevice::IID) }.map_err(map_windows_error)?;
    Ok(AdapterCapabilityIdentity {
        adapter_luid_low: target.adapter_luid_low,
        adapter_luid_high: target.adapter_luid_high,
        driver_version: format_umd_driver_version(driver_version),
    })
}

fn format_umd_driver_version(raw: i64) -> String {
    let raw = raw as u64;
    let low = raw as u32;
    let high = (raw >> 32) as u32;
    format!(
        "{}.{}.{}.{}",
        (high >> 16) & 0xffff,
        high & 0xffff,
        (low >> 16) & 0xffff,
        low & 0xffff
    )
}

pub fn enumerate_displays() -> Result<Vec<DisplayDescriptor>, CaptureFailure> {
    // SAFETY: the generic interface type is a valid DXGI factory interface and no raw pointers are
    // supplied by the caller.
    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }.map_err(map_windows_error)?;
    let mut displays = Vec::new();
    let mut adapter_index = 0_u32;

    loop {
        // SAFETY: DXGI validates the adapter index and returns DXGI_ERROR_NOT_FOUND at the end.
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(adapter) => adapter,
            Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => break,
            Err(error) => return Err(map_windows_error(error)),
        };
        // SAFETY: adapter is a live COM interface returned by this factory.
        let adapter_desc = unsafe { adapter.GetDesc1() }.map_err(map_windows_error)?;
        let mut output_index = 0_u32;
        loop {
            // SAFETY: DXGI validates the output index and returns DXGI_ERROR_NOT_FOUND at the end.
            let output = match unsafe { adapter.EnumOutputs(output_index) } {
                Ok(output) => output,
                Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(error) => return Err(map_windows_error(error)),
            };
            // SAFETY: output is a live interface returned by the selected adapter.
            let output_desc = unsafe { output.GetDesc() }.map_err(map_windows_error)?;
            if output_desc.AttachedToDesktop.as_bool() {
                displays.push(descriptor_from_dxgi(
                    adapter_desc.AdapterLuid.LowPart,
                    adapter_desc.AdapterLuid.HighPart,
                    output_index,
                    &output_desc,
                ));
            }
            output_index = output_index.saturating_add(1);
        }
        adapter_index = adapter_index.saturating_add(1);
    }

    Ok(displays)
}

fn find_output(
    target: DisplayId,
) -> Result<(IDXGIAdapter1, DisplayDescriptor, IDXGIOutput1), CaptureFailure> {
    // SAFETY: see `enumerate_displays`.
    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }.map_err(map_windows_error)?;
    let mut adapter_index = 0_u32;

    loop {
        // SAFETY: DXGI validates enumeration indexes.
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(adapter) => adapter,
            Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => {
                return Err(CaptureFailure::MonitorRemoved);
            }
            Err(error) => return Err(map_windows_error(error)),
        };
        // SAFETY: adapter is live.
        let adapter_desc = unsafe { adapter.GetDesc1() }.map_err(map_windows_error)?;
        let luid_matches = adapter_desc.AdapterLuid.LowPart == target.adapter_luid_low
            && adapter_desc.AdapterLuid.HighPart == target.adapter_luid_high;
        if luid_matches {
            // SAFETY: DXGI validates the output index.
            let output =
                unsafe { adapter.EnumOutputs(target.output_index) }.map_err(map_windows_error)?;
            // SAFETY: output is live.
            let output_desc = unsafe { output.GetDesc() }.map_err(map_windows_error)?;
            let descriptor = descriptor_from_dxgi(
                target.adapter_luid_low,
                target.adapter_luid_high,
                target.output_index,
                &output_desc,
            );
            let output1: IDXGIOutput1 = output.cast().map_err(|_| CaptureFailure::Unsupported)?;
            return Ok((adapter, descriptor, output1));
        }
        adapter_index = adapter_index.saturating_add(1);
    }
}

fn create_device(adapter: &IDXGIAdapter1) -> Result<ID3D11Device, CaptureFailure> {
    let feature_levels = [D3D_FEATURE_LEVEL_11_0];
    let mut device = None;

    // SAFETY: the adapter is live and all optional output pointers either point to initialized
    // storage or are omitted. The feature-level slice remains valid for the call.
    unsafe {
        D3D11CreateDevice(
            adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&feature_levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            None,
        )
    }
    .map_err(map_windows_error)?;

    device.ok_or(CaptureFailure::Unsupported)
}

fn descriptor_from_dxgi(
    adapter_luid_low: u32,
    adapter_luid_high: i32,
    output_index: u32,
    desc: &windows::Win32::Graphics::Dxgi::DXGI_OUTPUT_DESC,
) -> DisplayDescriptor {
    let width = desc
        .DesktopCoordinates
        .right
        .saturating_sub(desc.DesktopCoordinates.left)
        .unsigned_abs();
    let height = desc
        .DesktopCoordinates
        .bottom
        .saturating_sub(desc.DesktopCoordinates.top)
        .unsigned_abs();
    let primary = desc.DesktopCoordinates.left == 0 && desc.DesktopCoordinates.top == 0;
    let rotation_degrees = if desc.Rotation == DXGI_MODE_ROTATION_ROTATE90 {
        90
    } else if desc.Rotation == DXGI_MODE_ROTATION_ROTATE180 {
        180
    } else if desc.Rotation == DXGI_MODE_ROTATION_ROTATE270 {
        270
    } else {
        0
    };

    DisplayDescriptor {
        id: DisplayId {
            adapter_luid_low,
            adapter_luid_high,
            output_index,
        },
        name: utf16_name(&desc.DeviceName),
        width,
        height,
        primary,
        rotation_degrees,
    }
}

fn utf16_name(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

fn map_windows_error(error: windows::core::Error) -> CaptureFailure {
    let code = error.code();
    if code == DXGI_ERROR_WAIT_TIMEOUT {
        CaptureFailure::Timeout
    } else if code == DXGI_ERROR_ACCESS_LOST {
        CaptureFailure::AccessLost
    } else if code == DXGI_ERROR_DEVICE_REMOVED {
        CaptureFailure::DeviceRemoved
    } else if code == DXGI_ERROR_DEVICE_RESET {
        CaptureFailure::DeviceReset
    } else if code == DXGI_ERROR_UNSUPPORTED {
        CaptureFailure::Unsupported
    } else if code.0 == i32::from_le_bytes([0x05, 0x00, 0x07, 0x80]) {
        CaptureFailure::AccessDenied
    } else {
        CaptureFailure::Fatal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_umd_driver_version_parts() {
        let high = (31_u64 << 16) | 0;
        let low = (15_u64 << 16) | 5123;
        let raw = ((high << 32) | low) as i64;
        assert_eq!(format_umd_driver_version(raw), "31.0.15.5123");
    }
}
