use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use classmesh_codec_win::mf_decoder::DecodedGpuFrame;
use classmesh_render_win::{FlipPresenter, PresentOutcome};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{E_FAIL, HWND};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_MAP_FLAG_DO_NOT_WAIT, D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::DXGI_ERROR_WAS_STILL_DRAWING;
use windows::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, CreateWindowExW, DestroyWindow, DispatchMessageW, IsWindow, MSG, PM_REMOVE,
    PeekMessageW, TranslateMessage, WINDOW_EX_STYLE, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::{Error, w};

use super::super::Failure;
use super::{At, POLL_INTERVAL};

const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;
const MAP_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct Presentation {
    presenter: FlipPresenter,
    readback: Readback,
    phases: [FrameEvidence; 2],
    window: LabWindow,
}

impl Presentation {
    pub(super) fn new(device: &ID3D11Device) -> Result<Self, Failure> {
        let window = LabWindow(
            unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("STATIC"),
                    w!("ClassMesh async H.264 qualification"),
                    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    WIDTH as i32,
                    HEIGHT as i32,
                    None,
                    None,
                    None,
                    None,
                )
            }
            .at("create_presentation_window")?,
        );
        let presenter =
            FlipPresenter::new(window.0, device, WIDTH, HEIGHT).at("create_flip_presenter")?;
        let readback = Readback::new(device).at("create_bgra_readback")?;
        Ok(Self {
            presenter,
            readback,
            phases: Default::default(),
            window,
        })
    }

    pub(super) fn pump(&self) -> Result<(), Failure> {
        let mut msg = MSG::default();
        for _ in 0..32 {
            if !unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
                break;
            }
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if !unsafe { IsWindow(Some(self.window.0)) }.as_bool() {
            return Err(Failure::new(
                "presentation_window_closed",
                "qualification window closed during playback",
            ));
        }
        Ok(())
    }

    pub(super) fn frame(&mut self, frame: &DecodedGpuFrame, phase: usize) -> Result<(), Failure> {
        let mut evidence = None;
        let outcome = self.presenter.present_nv12_observed(
            frame.texture(),
            frame.subresource_index(),
            |backbuffer| {
                evidence = Some(self.readback.capture(backbuffer));
                Ok(())
            },
        );
        // The synchronous observer uses a bounded Map. Preserve its distinct stage.
        let evidence = evidence.transpose().at("bgra_backbuffer_readback")?;
        if outcome.at("present_nv12")? != PresentOutcome::Presented {
            return Err(Failure::new(
                "present_nv12",
                "D3D11 presenter skipped the frame",
            ));
        }
        let (hash, min, max) = evidence.ok_or_else(|| {
            Failure::new("bgra_backbuffer_readback", "missing back-buffer evidence")
        })?;
        let evidence = &mut self.phases[phase];
        evidence.frames += 1;
        if max >= 24 && max - min >= 16 {
            evidence.nonblank += 1;
            evidence.distinct.insert(hash);
        }
        Ok(())
    }

    pub(super) fn verify(&self, report: &mut Value) -> Result<(), Failure> {
        report["presentation_frames"] = json!(self.phases.each_ref().map(|phase| json!({
            "presented": phase.frames,
            "nonblank": phase.nonblank,
            "distinct_nonblank": phase.distinct.len(),
            "sample_bgra_sha256": phase.distinct.iter().take(2).collect::<Vec<_>>(),
        })));
        report["presentation_pipeline_rebuilds"] =
            json!(self.presenter.metrics().processor_rebuilds);
        if self.phases.iter().any(|phase| phase.distinct.len() < 2)
            || self.presenter.metrics().processor_rebuilds < 2
        {
            return Err(Failure::new(
                "presentation_content",
                "each size must produce at least two distinct nonblank BGRA frames and rebuild the video processor",
            ));
        }
        report["presentation"] = json!("passed");
        Ok(())
    }
}

struct LabWindow(HWND);

impl Drop for LabWindow {
    fn drop(&mut self) {
        let _ = unsafe { DestroyWindow(self.0) };
    }
}

#[derive(Default)]
struct FrameEvidence {
    frames: u32,
    nonblank: u32,
    distinct: BTreeSet<String>,
}

struct Readback {
    context: ID3D11DeviceContext,
    staging: ID3D11Texture2D,
}

impl Readback {
    fn new(device: &ID3D11Device) -> windows::core::Result<Self> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: WIDTH,
            Height: HEIGHT,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            ..Default::default()
        };
        let mut staging = None;
        unsafe { device.CreateTexture2D(&desc, None, Some(&mut staging))? };
        Ok(Self {
            context: unsafe { device.GetImmediateContext()? },
            staging: staging.ok_or_else(|| Error::new(E_FAIL, "missing BGRA staging texture"))?,
        })
    }

    fn capture(&self, backbuffer: &ID3D11Texture2D) -> windows::core::Result<(String, u8, u8)> {
        unsafe {
            self.context.CopyResource(&self.staging, backbuffer);
            self.context.Flush();
        }
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        let deadline = Instant::now() + MAP_TIMEOUT;
        loop {
            let result = unsafe {
                self.context.Map(
                    &self.staging,
                    0,
                    D3D11_MAP_READ,
                    D3D11_MAP_FLAG_DO_NOT_WAIT.0 as u32,
                    Some(&mut mapped),
                )
            };
            match result {
                Ok(()) => break,
                Err(error)
                    if error.code() == DXGI_ERROR_WAS_STILL_DRAWING
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(error) => return Err(error),
            }
        }
        let result = sample_bgra(&mapped);
        unsafe { self.context.Unmap(&self.staging, 0) };
        result
    }
}

fn sample_bgra(mapped: &D3D11_MAPPED_SUBRESOURCE) -> windows::core::Result<(String, u8, u8)> {
    let pitch = mapped.RowPitch as usize;
    if mapped.pData.is_null() || pitch < WIDTH as usize * 4 {
        return Err(Error::new(E_FAIL, "invalid mapped BGRA data or pitch"));
    }
    // Map returned a live BGRA resource matching the fixed staging descriptor.
    // Read only pixels inside mapped rows, before the owning context unmaps.
    let mut digest = Sha256::new();
    let (mut min, mut max) = (u8::MAX, 0_u8);
    for row in 1..=24 {
        let y = row * HEIGHT as usize / 25;
        for column in 1..=32 {
            let x = column * WIDTH as usize / 33;
            let pixel = unsafe {
                mapped
                    .pData
                    .cast::<[u8; 4]>()
                    .byte_add(y * pitch + x * 4)
                    .read()
            };
            let [b, g, r, _] = pixel;
            let luma = ((29 * u16::from(b) + 150 * u16::from(g) + 77 * u16::from(r)) >> 8) as u8;
            min = min.min(luma);
            max = max.max(luma);
            digest.update([b >> 3, g >> 3, r >> 3]);
        }
    }
    Ok((format!("{:x}", digest.finalize()), min, max))
}
