#![allow(unsafe_code)]

use classmesh_codec_win::mf_decoder::DecodedGpuFrame;
use classmesh_render_win::{FlipPresenter, PresentMetrics};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow,
    DispatchMessageW, IDC_ARROW, LoadCursorW, MSG, PM_REMOVE, PeekMessageW, PostQuitMessage,
    RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WM_DESTROY, WM_QUIT, WNDCLASSW,
    WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::w;

const WINDOW_CLASS: windows::core::PCWSTR = w!("ClassMeshMediaReceiverWindow");
const WINDOW_TITLE: windows::core::PCWSTR = w!("ClassMesh Student Presentation");

/// Diagnostic student presentation window backed by the ClassMesh D3D11 flip presenter.
///
/// The window and GPU presenter live on the same interactive Worker thread. Decoded NV12 surfaces
/// are passed directly from Media Foundation to D3D11 without CPU readback.
pub struct PresentationWindow {
    hwnd: HWND,
    presenter: FlipPresenter,
    closed: bool,
}

impl std::fmt::Debug for PresentationWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PresentationWindow")
            .field("hwnd", &self.hwnd.0)
            .field("closed", &self.closed)
            .field("presenter", &self.presenter)
            .finish()
    }
}

impl PresentationWindow {
    /// Creates a visible presentation window and binds a flip-model presenter to the decoder's
    /// D3D11 device.
    ///
    /// # Errors
    /// Returns a Win32 or DXGI/D3D11 error if the window or GPU presentation target cannot be
    /// created.
    pub fn new(
        device: &ID3D11Device,
        width: u32,
        height: u32,
    ) -> windows::core::Result<Self> {
        let module = unsafe { GetModuleHandleW(None)? };
        let cursor = unsafe { LoadCursorW(None, IDC_ARROW)? };
        let window_class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: module.into(),
            hCursor: cursor,
            lpszClassName: WINDOW_CLASS,
            ..Default::default()
        };

        // RegisterClassW returns zero when this process already registered the class. That case is
        // harmless for the diagnostic because CreateWindowExW below still resolves the class.
        let _ = unsafe { RegisterClassW(&window_class) };
        let width_i32 = i32::try_from(width).unwrap_or(i32::MAX);
        let height_i32 = i32::try_from(height).unwrap_or(i32::MAX);
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                WINDOW_CLASS,
                WINDOW_TITLE,
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                width_i32,
                height_i32,
                None,
                None,
                Some(module.into()),
                None,
            )?
        };
        let presenter = FlipPresenter::new(hwnd, device, width, height)?;

        Ok(Self {
            hwnd,
            presenter,
            closed: false,
        })
    }

    /// Presents one Media Foundation GPU frame and keeps it entirely on the D3D11 path.
    ///
    /// # Errors
    /// Returns an error when Media Foundation cannot expose the decoder surface as an
    /// `ID3D11Texture2D`, when the subresource index cannot be queried, or when D3D11/DXGI fails to
    /// present the frame.
    pub fn present(&mut self, frame: &DecodedGpuFrame) -> windows::core::Result<()> {
        let texture: ID3D11Texture2D = unsafe { frame.dxgi_buffer().GetResource()? };
        let subresource_index = unsafe { frame.dxgi_buffer().GetSubresourceIndex()? };
        self.presenter.present_nv12(&texture, subresource_index)
    }

    /// Drains pending Win32 messages without blocking media receive/decode.
    ///
    /// Returns `false` after the presentation window has closed.
    pub fn pump_messages(&mut self) -> bool {
        let mut message = MSG::default();
        while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() } {
            if message.message == WM_QUIT {
                self.closed = true;
                break;
            }
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        !self.closed
    }

    #[must_use]
    pub const fn metrics(&self) -> PresentMetrics {
        self.presenter.metrics()
    }
}

impl Drop for PresentationWindow {
    fn drop(&mut self) {
        if !self.closed {
            let _ = unsafe { DestroyWindow(self.hwnd) };
            self.closed = true;
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_DESTROY {
        unsafe { PostQuitMessage(0) };
        return LRESULT(0);
    }
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}
