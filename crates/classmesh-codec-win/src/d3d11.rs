#![allow(unsafe_code)]

use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_SDK_VERSION,
    D3D11CreateDevice, ID3D11Device,
};
use windows::Win32::Graphics::Dxgi::IDXGIAdapter;

/// Creates a hardware D3D11 device suitable for Media Foundation video decode/render diagnostics.
///
/// ClassMesh deliberately does not fall back to WARP here. A teacher-presentation receiver that
/// cannot obtain a real hardware video device must remain diagnosable rather than silently moving
/// the real-time path onto the CPU.
///
/// # Errors
/// Returns the D3D11 device-creation error or an explicit failure if Windows reports success without
/// returning a device.
pub fn create_default_video_device() -> windows::core::Result<ID3D11Device> {
    let feature_levels = [D3D_FEATURE_LEVEL_11_0];
    let mut device = None;
    let flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;

    unsafe {
        D3D11CreateDevice(
            None::<&IDXGIAdapter>,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE::default(),
            flags,
            Some(&feature_levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            None,
        )?;
    }

    device.ok_or_else(|| {
        windows::core::Error::new(
            windows::core::HRESULT(0x8000_4005_u32 as i32),
            "D3D11CreateDevice succeeded without returning a device",
        )
    })
}
