#![allow(unsafe_code)]

use std::fmt;
use std::mem::ManuallyDrop;
use std::ptr;

use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV, D3D11_TEXTURE2D_DESC, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_STREAM,
    D3D11_VIDEO_USAGE_PLAYBACK_NORMAL, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11Device, ID3D11DeviceContext, ID3D11RenderTargetView,
    ID3D11Texture2D, ID3D11VideoContext, ID3D11VideoDevice, ID3D11VideoProcessor,
    ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_ALPHA_MODE_IGNORE, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_NV12, DXGI_FORMAT_UNKNOWN,
    DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_MWA_NO_ALT_ENTER, DXGI_PRESENT, DXGI_SCALING_STRETCH,
    DXGI_SWAP_CHAIN_DESC1, DXGI_SWAP_CHAIN_FLAG, DXGI_SWAP_EFFECT_FLIP_DISCARD,
    DXGI_USAGE_RENDER_TARGET_OUTPUT, IDXGIFactory2, IDXGISwapChain1,
};
use windows::core::Interface;

const DXGI_ERROR_DEVICE_REMOVED_HR: i32 = 0x887A_0005_u32 as i32;
const DXGI_ERROR_DEVICE_HUNG_HR: i32 = 0x887A_0006_u32 as i32;
const DXGI_ERROR_DEVICE_RESET_HR: i32 = 0x887A_0007_u32 as i32;
const DXGI_ERROR_DRIVER_INTERNAL_ERROR_HR: i32 = 0x887A_0020_u32 as i32;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentMetrics {
    pub presented_frames: u64,
    pub processor_rebuilds: u64,
    pub swap_chain_resizes: u64,
    pub suspend_events: u64,
    pub skipped_while_suspended: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentOutcome {
    Presented,
    SkippedSuspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeOutcome {
    Unchanged,
    Suspended,
    Resized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DxgiFailureClass {
    DeviceLost,
    Other,
}

#[must_use]
pub fn classify_dxgi_error(error: &windows::core::Error) -> DxgiFailureClass {
    match error.code().0 {
        DXGI_ERROR_DEVICE_REMOVED_HR
        | DXGI_ERROR_DEVICE_HUNG_HR
        | DXGI_ERROR_DEVICE_RESET_HR
        | DXGI_ERROR_DRIVER_INTERNAL_ERROR_HR => DxgiFailureClass::DeviceLost,
        _ => DxgiFailureClass::Other,
    }
}

struct VideoPipeline {
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    source_width: u32,
    source_height: u32,
}

impl fmt::Debug for VideoPipeline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VideoPipeline")
            .field("source_width", &self.source_width)
            .field("source_height", &self.source_height)
            .finish_non_exhaustive()
    }
}

/// GPU-native NV12 presenter for the student presentation window.
///
/// Decoded Media Foundation surfaces remain on the same D3D11 device. A D3D11 Video Processor
/// converts/scales NV12 directly into a flip-discard BGRA swap-chain backbuffer; the path performs
/// no staging readback, CPU color conversion, or bitmap allocation.
pub struct FlipPresenter {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext,
    swap_chain: IDXGISwapChain1,
    output_width: u32,
    output_height: u32,
    suspended: bool,
    pipeline: Option<VideoPipeline>,
    metrics: PresentMetrics,
}

impl fmt::Debug for FlipPresenter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlipPresenter")
            .field("output_width", &self.output_width)
            .field("output_height", &self.output_height)
            .field("suspended", &self.suspended)
            .field("pipeline", &self.pipeline)
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

impl FlipPresenter {
    /// Creates a two-buffer flip-discard swap chain attached to `hwnd` using the same D3D11 device
    /// as the hardware decoder.
    ///
    /// # Errors
    /// Returns an error for zero geometry, missing D3D11 video-processing support, or DXGI swap
    /// chain creation failure.
    pub fn new(
        hwnd: HWND,
        device: &ID3D11Device,
        output_width: u32,
        output_height: u32,
    ) -> windows::core::Result<Self> {
        if output_width == 0 || output_height == 0 {
            return Err(invalid_argument(
                "presentation window dimensions must be non-zero",
            ));
        }

        let context = unsafe { device.GetImmediateContext()? };
        let video_device: ID3D11VideoDevice = device.cast()?;
        let video_context: ID3D11VideoContext = context.cast()?;
        let factory: IDXGIFactory2 = unsafe { CreateDXGIFactory1()? };
        let descriptor = DXGI_SWAP_CHAIN_DESC1 {
            Width: output_width,
            Height: output_height,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            Stereo: false.into(),
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            BufferCount: 2,
            Scaling: DXGI_SCALING_STRETCH,
            SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
            AlphaMode: DXGI_ALPHA_MODE_IGNORE,
            Flags: 0,
        };
        let swap_chain =
            unsafe { factory.CreateSwapChainForHwnd(device, hwnd, &descriptor, None, None)? };
        unsafe { factory.MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER)? };

        Ok(Self {
            device: device.clone(),
            context,
            video_device,
            video_context,
            swap_chain,
            output_width,
            output_height,
            suspended: false,
            pipeline: None,
            metrics: PresentMetrics::default(),
        })
    }

    #[must_use]
    pub const fn metrics(&self) -> PresentMetrics {
        self.metrics
    }

    #[must_use]
    pub const fn output_size(&self) -> (u32, u32) {
        (self.output_width, self.output_height)
    }

    #[must_use]
    pub const fn is_suspended(&self) -> bool {
        self.suspended
    }

    /// Updates the flip-model buffers to the current client size.
    ///
    /// A zero width or height means the HWND is minimized. In that state ClassMesh deliberately
    /// suspends presentation without calling `ResizeBuffers(0, 0)` and without treating the media
    /// stream as failed. Restoring the window resizes the swap chain and rebuilds the video
    /// processor lazily on the next decoded frame.
    ///
    /// # Errors
    /// Returns the underlying DXGI error if `ResizeBuffers` fails. Device-removed/reset failures
    /// can be identified with [`classify_dxgi_error`].
    pub fn resize_output(
        &mut self,
        output_width: u32,
        output_height: u32,
    ) -> windows::core::Result<ResizeOutcome> {
        if output_width == 0 || output_height == 0 {
            if !self.suspended {
                self.metrics.suspend_events = self.metrics.suspend_events.saturating_add(1);
            }
            self.suspended = true;
            return Ok(ResizeOutcome::Suspended);
        }

        if !self.suspended
            && output_width == self.output_width
            && output_height == self.output_height
        {
            return Ok(ResizeOutcome::Unchanged);
        }

        // The presenter does not cache a backbuffer view between frames. Dropping the video
        // processor here ensures no pipeline-owned object can indirectly retain swap-chain-size
        // assumptions across ResizeBuffers.
        self.pipeline = None;
        unsafe {
            self.context.Flush();
            self.swap_chain.ResizeBuffers(
                2,
                output_width,
                output_height,
                DXGI_FORMAT_UNKNOWN,
                DXGI_SWAP_CHAIN_FLAG(0),
            )?;
        }
        self.output_width = output_width;
        self.output_height = output_height;
        self.suspended = false;
        self.metrics.swap_chain_resizes = self.metrics.swap_chain_resizes.saturating_add(1);
        Ok(ResizeOutcome::Resized)
    }

    /// Presents one decoder-owned NV12 D3D11 texture.
    ///
    /// `subresource_index` is the Media Foundation `IMFDXGIBuffer` subresource index. The presenter
    /// derives the correct texture-array slice rather than assuming every decoder returns slice 0.
    ///
    /// # Errors
    /// Returns an error if the decoded surface is not NV12, geometry is invalid, D3D11 video
    /// processing rejects the surface, or DXGI fails to present the frame.
    pub fn present_nv12(
        &mut self,
        texture: &ID3D11Texture2D,
        subresource_index: u32,
    ) -> windows::core::Result<PresentOutcome> {
        if self.suspended {
            self.metrics.skipped_while_suspended =
                self.metrics.skipped_while_suspended.saturating_add(1);
            return Ok(PresentOutcome::SkippedSuspended);
        }

        let source_desc = texture_desc(texture);
        if source_desc.Width == 0
            || source_desc.Height == 0
            || source_desc.Format != DXGI_FORMAT_NV12
            || source_desc.SampleDesc.Count != 1
        {
            return Err(invalid_argument(
                "decoded presentation surface must be a non-multisampled NV12 texture",
            ));
        }

        self.ensure_pipeline(source_desc.Width, source_desc.Height)?;
        let pipeline = self
            .pipeline
            .as_ref()
            .expect("video pipeline is created before presenting");
        let backbuffer = unsafe { self.swap_chain.GetBuffer::<ID3D11Texture2D>(0)? };
        let render_target = create_render_target(&self.device, &backbuffer)?;
        let input_view = create_input_view(
            &self.video_device,
            &pipeline.enumerator,
            texture,
            subresource_index,
            source_desc.MipLevels,
        )?;
        let output_view =
            create_output_view(&self.video_device, &pipeline.enumerator, &backbuffer)?;

        let source_rect = RECT {
            left: 0,
            top: 0,
            right: i32::try_from(source_desc.Width).unwrap_or(i32::MAX),
            bottom: i32::try_from(source_desc.Height).unwrap_or(i32::MAX),
        };
        let destination_rect = fit_rect(
            source_desc.Width,
            source_desc.Height,
            self.output_width,
            self.output_height,
        );
        let output_rect = RECT {
            left: 0,
            top: 0,
            right: i32::try_from(self.output_width).unwrap_or(i32::MAX),
            bottom: i32::try_from(self.output_height).unwrap_or(i32::MAX),
        };

        unsafe {
            self.context
                .ClearRenderTargetView(&render_target, &[0.0, 0.0, 0.0, 1.0]);
            self.video_context.VideoProcessorSetStreamSourceRect(
                &pipeline.processor,
                0,
                true,
                Some(&source_rect),
            );
            self.video_context.VideoProcessorSetStreamDestRect(
                &pipeline.processor,
                0,
                true,
                Some(&destination_rect),
            );
            self.video_context.VideoProcessorSetOutputTargetRect(
                &pipeline.processor,
                true,
                Some(&output_rect),
            );
        }

        let mut streams = [D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            OutputIndex: 0,
            InputFrameOrField: 0,
            PastFrames: 0,
            FutureFrames: 0,
            ppPastSurfaces: ptr::null_mut(),
            pInputSurface: ManuallyDrop::new(Some(input_view)),
            ppFutureSurfaces: ptr::null_mut(),
            ppPastSurfacesRight: ptr::null_mut(),
            pInputSurfaceRight: ManuallyDrop::new(None),
            ppFutureSurfacesRight: ptr::null_mut(),
        }];
        let blit = unsafe {
            self.video_context
                .VideoProcessorBlt(&pipeline.processor, &output_view, 0, &streams)
        };
        let _ = ManuallyDrop::into_inner(unsafe { ptr::read(&streams[0].pInputSurface) });
        unsafe {
            ptr::write(&mut streams[0].pInputSurface, ManuallyDrop::new(None));
        }
        blit?;

        unsafe { self.swap_chain.Present(1, DXGI_PRESENT(0)) }.ok()?;
        self.metrics.presented_frames = self.metrics.presented_frames.saturating_add(1);
        Ok(PresentOutcome::Presented)
    }

    fn ensure_pipeline(
        &mut self,
        source_width: u32,
        source_height: u32,
    ) -> windows::core::Result<()> {
        if self.pipeline.as_ref().is_some_and(|pipeline| {
            pipeline.source_width == source_width && pipeline.source_height == source_height
        }) {
            return Ok(());
        }

        let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: DXGI_RATIONAL {
                Numerator: 30,
                Denominator: 1,
            },
            InputWidth: source_width,
            InputHeight: source_height,
            OutputFrameRate: DXGI_RATIONAL {
                Numerator: 30,
                Denominator: 1,
            },
            OutputWidth: self.output_width,
            OutputHeight: self.output_height,
            Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
        };
        let enumerator = unsafe { self.video_device.CreateVideoProcessorEnumerator(&content)? };
        let processor = unsafe { self.video_device.CreateVideoProcessor(&enumerator, 0)? };
        unsafe {
            self.video_context.VideoProcessorSetStreamFrameFormat(
                &processor,
                0,
                D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            );
            self.video_context
                .VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false);
        }
        self.pipeline = Some(VideoPipeline {
            enumerator,
            processor,
            source_width,
            source_height,
        });
        self.metrics.processor_rebuilds = self.metrics.processor_rebuilds.saturating_add(1);
        Ok(())
    }
}

fn texture_desc(texture: &ID3D11Texture2D) -> D3D11_TEXTURE2D_DESC {
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { texture.GetDesc(&mut desc) };
    desc
}

fn create_render_target(
    device: &ID3D11Device,
    texture: &ID3D11Texture2D,
) -> windows::core::Result<ID3D11RenderTargetView> {
    let mut view = None;
    unsafe { device.CreateRenderTargetView(texture, None, Some(&mut view))? };
    view.ok_or_else(|| invalid_argument("D3D11 returned no swap-chain render-target view"))
}

fn create_input_view(
    video_device: &ID3D11VideoDevice,
    enumerator: &ID3D11VideoProcessorEnumerator,
    texture: &ID3D11Texture2D,
    subresource_index: u32,
    mip_levels: u32,
) -> windows::core::Result<ID3D11VideoProcessorInputView> {
    let mip_levels = mip_levels.max(1);
    let mip_slice = subresource_index % mip_levels;
    let array_slice = subresource_index / mip_levels;
    let desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
        FourCC: 0,
        ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
        Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
            Texture2D: D3D11_TEX2D_VPIV {
                MipSlice: mip_slice,
                ArraySlice: array_slice,
            },
        },
    };
    let mut view = None;
    unsafe {
        video_device.CreateVideoProcessorInputView(texture, enumerator, &desc, Some(&mut view))?;
    }
    view.ok_or_else(|| invalid_argument("D3D11 returned no decoder video input view"))
}

fn create_output_view(
    video_device: &ID3D11VideoDevice,
    enumerator: &ID3D11VideoProcessorEnumerator,
    texture: &ID3D11Texture2D,
) -> windows::core::Result<ID3D11VideoProcessorOutputView> {
    let desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
        ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
        Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
            Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
        },
    };
    let mut view = None;
    unsafe {
        video_device.CreateVideoProcessorOutputView(texture, enumerator, &desc, Some(&mut view))?;
    }
    view.ok_or_else(|| invalid_argument("D3D11 returned no swap-chain video output view"))
}

fn fit_rect(source_width: u32, source_height: u32, output_width: u32, output_height: u32) -> RECT {
    let source_aspect = f64::from(source_width) / f64::from(source_height.max(1));
    let output_aspect = f64::from(output_width) / f64::from(output_height.max(1));
    let (width, height) = if source_aspect > output_aspect {
        let height = (f64::from(output_width) / source_aspect).round() as u32;
        (output_width, height.max(1))
    } else {
        let width = (f64::from(output_height) * source_aspect).round() as u32;
        (width.max(1), output_height)
    };
    let left = output_width.saturating_sub(width) / 2;
    let top = output_height.saturating_sub(height) / 2;
    RECT {
        left: i32::try_from(left).unwrap_or(i32::MAX),
        top: i32::try_from(top).unwrap_or(i32::MAX),
        right: i32::try_from(left.saturating_add(width)).unwrap_or(i32::MAX),
        bottom: i32::try_from(top.saturating_add(height)).unwrap_or(i32::MAX),
    }
}

fn invalid_argument(message: &'static str) -> windows::core::Error {
    windows::core::Error::new(windows::core::HRESULT(0x8007_0057_u32 as i32), message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_rect_letterboxes_wide_source() {
        let rect = fit_rect(1920, 1080, 1024, 768);
        assert_eq!(rect.left, 0);
        assert_eq!(rect.right, 1024);
        assert_eq!(rect.top, 96);
        assert_eq!(rect.bottom, 672);
    }

    #[test]
    fn fit_rect_pillarboxes_tall_source() {
        let rect = fit_rect(1080, 1920, 1280, 720);
        assert_eq!(rect.top, 0);
        assert_eq!(rect.bottom, 720);
        assert!(rect.left > 0);
        assert!(rect.right < 1280);
    }

    #[test]
    fn classifies_device_loss_hresult_values() {
        for code in [
            DXGI_ERROR_DEVICE_REMOVED_HR,
            DXGI_ERROR_DEVICE_HUNG_HR,
            DXGI_ERROR_DEVICE_RESET_HR,
            DXGI_ERROR_DRIVER_INTERNAL_ERROR_HR,
        ] {
            let error = windows::core::Error::from_hresult(windows::core::HRESULT(code));
            assert_eq!(classify_dxgi_error(&error), DxgiFailureClass::DeviceLost);
        }
        let other =
            windows::core::Error::from_hresult(windows::core::HRESULT(0x8000_4005_u32 as i32));
        assert_eq!(classify_dxgi_error(&other), DxgiFailureClass::Other);
    }
}
