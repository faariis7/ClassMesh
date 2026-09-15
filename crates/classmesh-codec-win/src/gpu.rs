#![allow(unsafe_code)]

use std::mem::ManuallyDrop;
use std::ptr;

use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV, D3D11_TEXTURE2D_DESC,
    D3D11_USAGE_DEFAULT, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_CONTENT_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
    D3D11_VPIV_DIMENSION_TEXTURE2D, D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11Device,
    ID3D11DeviceContext, ID3D11Texture2D, ID3D11VideoContext, ID3D11VideoDevice,
    ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView,
    ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_NV12, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::core::Interface;

/// Fixed geometry/rate for a GPU BGRA→NV12 conversion stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuNv12Config {
    pub source_width: u32,
    pub source_height: u32,
    pub target_width: u32,
    pub target_height: u32,
    pub fps_numerator: u32,
    pub fps_denominator: u32,
}

impl GpuNv12Config {
    #[must_use]
    pub const fn presentation_1080p30(source_width: u32, source_height: u32) -> Self {
        Self {
            source_width,
            source_height,
            target_width: 1920,
            target_height: 1080,
            fps_numerator: 30,
            fps_denominator: 1,
        }
    }

    fn validate(self) -> windows::core::Result<()> {
        if self.source_width == 0
            || self.source_height == 0
            || self.target_width == 0
            || self.target_height == 0
            || self.fps_numerator == 0
            || self.fps_denominator == 0
            || self.target_width % 2 != 0
            || self.target_height % 2 != 0
        {
            return Err(invalid_argument(
                "invalid GPU NV12 conversion configuration",
            ));
        }
        Ok(())
    }
}

/// GPU-only desktop color converter/scaler using the D3D11 Video Processor.
///
/// The source is expected to be a Desktop Duplication BGRA texture. ClassMesh first copies it into
/// a reusable GPU texture with neutral bind flags, then asks the Video Processor to scale and
/// convert that texture into a caller-owned NV12 render target. There is no `Map`, staging readback,
/// `Bitmap`, or CPU pixel conversion in this path.
pub struct GpuBgraToNv12Converter {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    input_copy: ID3D11Texture2D,
    config: GpuNv12Config,
    source_rect: RECT,
    target_rect: RECT,
}

impl std::fmt::Debug for GpuBgraToNv12Converter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuBgraToNv12Converter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl GpuBgraToNv12Converter {
    /// Builds a video-processor conversion stage on the same D3D11 device used for capture.
    ///
    /// # Errors
    /// Returns an error when the geometry is invalid or the selected adapter does not expose the
    /// D3D11 video-processing interfaces required for the GPU-native path.
    pub fn new(device: &ID3D11Device, config: GpuNv12Config) -> windows::core::Result<Self> {
        config.validate()?;

        let context = unsafe { device.GetImmediateContext()? };
        let video_device: ID3D11VideoDevice = device.cast()?;
        let video_context: ID3D11VideoContext = context.cast()?;

        let content_desc = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: DXGI_RATIONAL {
                Numerator: config.fps_numerator,
                Denominator: config.fps_denominator,
            },
            InputWidth: config.source_width,
            InputHeight: config.source_height,
            OutputFrameRate: DXGI_RATIONAL {
                Numerator: config.fps_numerator,
                Denominator: config.fps_denominator,
            },
            OutputWidth: config.target_width,
            OutputHeight: config.target_height,
            Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
        };

        let enumerator = unsafe { video_device.CreateVideoProcessorEnumerator(&content_desc)? };
        let processor = unsafe { video_device.CreateVideoProcessor(&enumerator, 0)? };
        let input_copy = create_input_copy(device, config.source_width, config.source_height)?;

        unsafe {
            video_context.VideoProcessorSetStreamFrameFormat(
                &processor,
                0,
                D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            );
            video_context.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false);
        }

        let source_rect = RECT {
            left: 0,
            top: 0,
            right: i32::try_from(config.source_width).unwrap_or(i32::MAX),
            bottom: i32::try_from(config.source_height).unwrap_or(i32::MAX),
        };
        let target_rect = RECT {
            left: 0,
            top: 0,
            right: i32::try_from(config.target_width).unwrap_or(i32::MAX),
            bottom: i32::try_from(config.target_height).unwrap_or(i32::MAX),
        };

        unsafe {
            video_context.VideoProcessorSetStreamSourceRect(
                &processor,
                0,
                true,
                Some(&source_rect),
            );
            video_context.VideoProcessorSetStreamDestRect(&processor, 0, true, Some(&target_rect));
            video_context.VideoProcessorSetOutputTargetRect(&processor, true, Some(&target_rect));
        }

        Ok(Self {
            device: device.clone(),
            context,
            video_device,
            video_context,
            enumerator,
            processor,
            input_copy,
            config,
            source_rect,
            target_rect,
        })
    }

    #[must_use]
    pub const fn config(&self) -> GpuNv12Config {
        self.config
    }

    /// Allocates an NV12 render target compatible with this converter and the Media Foundation
    /// encoder input path. The caller owns the texture so it can manage a bounded in-flight pool.
    ///
    /// # Errors
    /// Returns the D3D11 allocation error.
    pub fn create_output_texture(&self) -> windows::core::Result<ID3D11Texture2D> {
        create_nv12_target(
            &self.device,
            self.config.target_width,
            self.config.target_height,
        )
    }

    /// Converts one Desktop Duplication frame into a caller-owned NV12 texture entirely on the GPU.
    ///
    /// A GPU-to-GPU copy into `input_copy` intentionally isolates the Video Processor from Desktop
    /// Duplication resource bind flags. This avoids a driver-dependent input-view failure without
    /// introducing CPU readback. The destination must have been allocated by
    /// [`Self::create_output_texture`] for this converter.
    ///
    /// # Errors
    /// Returns an error if source/destination geometry or format is incompatible, or if the video
    /// processor rejects the input/output view or blit.
    pub fn convert(
        &mut self,
        source: &ID3D11Texture2D,
        destination_nv12: &ID3D11Texture2D,
    ) -> windows::core::Result<()> {
        validate_source(source, self.config)?;
        validate_destination(destination_nv12, self.config)?;

        unsafe {
            self.context.CopyResource(&self.input_copy, source);
        }

        let input_view = self.create_input_view(&self.input_copy)?;
        let output_view = self.create_output_view(destination_nv12)?;

        // Keep explicit rectangles current. They are cheap state calls and make future dynamic
        // resizing/recovery less error-prone if the processor state is reset by a driver.
        unsafe {
            self.video_context.VideoProcessorSetStreamSourceRect(
                &self.processor,
                0,
                true,
                Some(&self.source_rect),
            );
            self.video_context.VideoProcessorSetStreamDestRect(
                &self.processor,
                0,
                true,
                Some(&self.target_rect),
            );
            self.video_context.VideoProcessorSetOutputTargetRect(
                &self.processor,
                true,
                Some(&self.target_rect),
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

        let result = unsafe {
            self.video_context
                .VideoProcessorBlt(&self.processor, &output_view, 0, &streams)
        };

        // `D3D11_VIDEO_PROCESSOR_STREAM` stores COM interfaces in ManuallyDrop fields. Release the
        // temporary input view exactly once regardless of blit success.
        let _ = ManuallyDrop::into_inner(unsafe { ptr::read(&streams[0].pInputSurface) });
        unsafe {
            ptr::write(&mut streams[0].pInputSurface, ManuallyDrop::new(None));
        }

        result
    }

    fn create_input_view(
        &self,
        texture: &ID3D11Texture2D,
    ) -> windows::core::Result<ID3D11VideoProcessorInputView> {
        let desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPIV {
                    MipSlice: 0,
                    ArraySlice: 0,
                },
            },
        };
        let mut view = None;
        unsafe {
            self.video_device.CreateVideoProcessorInputView(
                texture,
                &self.enumerator,
                &desc,
                Some(&mut view),
            )?;
        }
        view.ok_or_else(|| invalid_argument("D3D11 returned no video-processor input view"))
    }

    fn create_output_view(
        &self,
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
            self.video_device.CreateVideoProcessorOutputView(
                texture,
                &self.enumerator,
                &desc,
                Some(&mut view),
            )?;
        }
        view.ok_or_else(|| invalid_argument("D3D11 returned no video-processor output view"))
    }
}

fn create_input_copy(
    device: &ID3D11Device,
    width: u32,
    height: u32,
) -> windows::core::Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: 0,
        CPUAccessFlags: 0,
        MiscFlags: 0,
    };
    create_texture(device, &desc)
}

fn create_nv12_target(
    device: &ID3D11Device,
    width: u32,
    height: u32,
) -> windows::core::Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_NV12,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: D3D11_BIND_RENDER_TARGET.0 as u32,
        CPUAccessFlags: 0,
        MiscFlags: 0,
    };
    create_texture(device, &desc)
}

fn create_texture(
    device: &ID3D11Device,
    desc: &D3D11_TEXTURE2D_DESC,
) -> windows::core::Result<ID3D11Texture2D> {
    let mut texture = None;
    unsafe {
        device.CreateTexture2D(desc, None, Some(&mut texture))?;
    }
    texture.ok_or_else(|| invalid_argument("D3D11 returned no texture"))
}

fn validate_source(texture: &ID3D11Texture2D, config: GpuNv12Config) -> windows::core::Result<()> {
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { texture.GetDesc(&mut desc) };
    if desc.Width != config.source_width
        || desc.Height != config.source_height
        || desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM
        || desc.SampleDesc.Count != 1
    {
        return Err(invalid_argument(
            "source texture does not match the configured Desktop Duplication BGRA surface",
        ));
    }
    Ok(())
}

fn validate_destination(
    texture: &ID3D11Texture2D,
    config: GpuNv12Config,
) -> windows::core::Result<()> {
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { texture.GetDesc(&mut desc) };
    if desc.Width != config.target_width
        || desc.Height != config.target_height
        || desc.Format != DXGI_FORMAT_NV12
        || desc.SampleDesc.Count != 1
    {
        return Err(invalid_argument(
            "destination texture does not match the configured NV12 encoder surface",
        ));
    }
    Ok(())
}

fn invalid_argument(message: &'static str) -> windows::core::Error {
    windows::core::Error::new(windows::core::HRESULT(0x8007_0057_u32 as i32), message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_config_targets_even_nv12_geometry() {
        let config = GpuNv12Config::presentation_1080p30(2560, 1440);
        assert_eq!(config.target_width, 1920);
        assert_eq!(config.target_height, 1080);
        assert_eq!(config.fps_numerator, 30);
        assert_eq!(config.fps_denominator, 1);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn odd_nv12_target_is_rejected_before_touching_d3d() {
        let config = GpuNv12Config {
            source_width: 1920,
            source_height: 1080,
            target_width: 1279,
            target_height: 720,
            fps_numerator: 30,
            fps_denominator: 1,
        };
        assert!(config.validate().is_err());
    }
}
