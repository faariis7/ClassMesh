#![allow(unsafe_code)]

use classmesh_codec_win::mf_decoder::DecodedGpuFrame;
use classmesh_render_win::{
    DxgiFailureClass, FlipPresenter, PresentMetrics, ResizeOutcome, classify_dxgi_error,
};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow,
    DispatchMessageW, IDC_ARROW, IsWindow, LoadCursorW, MSG, PM_REMOVE, PeekMessageW,
    RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WM_QUIT, WM_SIZE, WNDCLASSW,
    WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::{Interface, w};

const WINDOW_CLASS: windows::core::PCWSTR = w!("ClassMeshMediaReceiverWindow");
const WINDOW_TITLE: windows::core::PCWSTR = w!("ClassMesh Student Presentation");

/// Diagnostic student presentation window backed by the ClassMesh D3D11 flip presenter.
///
/// The window and GPU presenter live on the same interactive Worker thread. Decoded NV12 surfaces
/// are passed directly from Media Foundation to D3D11 without CPU readback.
pub struct PresentationWindow {
    hwnd: HWND,
    presenter: Option<FlipPresenter>,
    closed: bool,
    client_size: (u32, u32),
    device_lost: bool,
}

impl std::fmt::Debug for PresentationWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PresentationWindow")
            .field("hwnd", &self.hwnd.0)
            .field("closed", &self.closed)
            .field("client_size", &self.client_size)
            .field("device_lost", &self.device_lost)
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
    pub fn new(device: &ID3D11Device, width: u32, height: u32) -> windows::core::Result<Self> {
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
        let presenter = match FlipPresenter::new(hwnd, device, width, height) {
            Ok(presenter) => presenter,
            Err(error) => {
                // The PresentationWindow owner does not exist yet, so its Drop
                // cannot close this HWND on a failed D3D11/DXGI initialization.
                let _ = unsafe { DestroyWindow(hwnd) };
                return Err(error);
            }
        };

        Ok(Self {
            hwnd,
            presenter: Some(presenter),
            closed: false,
            client_size: (width, height),
            device_lost: false,
        })
    }

    /// Rebinds the existing HWND to a freshly-created D3D11 device after device loss.
    ///
    /// Flip-model swap chains must not overlap on the same HWND. ClassMesh therefore releases the
    /// old presenter and its swap chain *before* constructing the replacement. The HWND itself
    /// remains alive, so recovery does not flash a replacement window or require a teacher
    /// reconnect. If replacement construction fails, the window remains alive with no presenter and
    /// the device-loss signal stays asserted so the caller can retry recovery.
    ///
    /// If the HWND is currently minimized, the replacement is immediately put back into suspended
    /// state after construction.
    ///
    /// # Errors
    /// Returns a D3D11/DXGI error if the new flip-model presenter cannot be constructed.
    pub fn recover_device(&mut self, device: &ID3D11Device) -> windows::core::Result<()> {
        let (client_width, client_height) = self.client_size;
        let fallback_size = self
            .presenter
            .as_ref()
            .map_or((1280, 720), FlipPresenter::output_size);
        let initial_width = if client_width == 0 {
            fallback_size.0
        } else {
            client_width
        };
        let initial_height = if client_height == 0 {
            fallback_size.1
        } else {
            client_height
        };

        self.device_lost = true;
        let stale_presenter = self.presenter.take();
        drop(stale_presenter);

        let mut replacement = FlipPresenter::new(self.hwnd, device, initial_width, initial_height)?;
        if client_width == 0 || client_height == 0 {
            let _ = replacement.resize_output(0, 0)?;
        }
        self.presenter = Some(replacement);
        self.device_lost = false;
        Ok(())
    }

    /// Presents one Media Foundation GPU frame and keeps it entirely on the D3D11 path.
    ///
    /// While minimized the underlying presenter intentionally skips GPU presentation and returns
    /// success so window lifecycle does not become media/decode failure. The presenter's own
    /// metrics keep the skipped-frame count separate from successful swap-chain presents.
    ///
    /// # Errors
    /// Returns an error when Media Foundation cannot expose the decoder surface as an
    /// `ID3D11Texture2D`, when the subresource index cannot be queried, when recovery has left the
    /// window temporarily without GPU presentation resources, or when D3D11/DXGI fails to present
    /// the frame.
    pub fn present(&mut self, frame: &DecodedGpuFrame) -> windows::core::Result<()> {
        let mut texture: Option<ID3D11Texture2D> = None;
        unsafe {
            frame
                .dxgi_buffer()
                .GetResource(&ID3D11Texture2D::IID, &mut texture as *mut _ as *mut _)?;
        }
        let texture = texture.ok_or_else(|| {
            windows::core::Error::new(
                windows::core::HRESULT(0x8000_4005_u32 as i32),
                "Media Foundation returned a null D3D11 decode surface",
            )
        })?;
        let subresource_index = unsafe { frame.dxgi_buffer().GetSubresourceIndex()? };
        let Some(presenter) = self.presenter.as_mut() else {
            self.device_lost = true;
            return Err(windows::core::Error::new(
                windows::core::HRESULT(0x8000_4005_u32 as i32),
                "presentation GPU resources are unavailable during recovery",
            ));
        };
        match presenter.present_nv12(&texture, subresource_index) {
            Ok(_) => Ok(()),
            Err(error) => {
                if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                    self.device_lost = true;
                }
                Err(error)
            }
        }
    }

    /// Drains pending Win32 messages without blocking media receive/decode.
    ///
    /// `WM_SIZE` is consumed as a renderer lifecycle signal. Zero client dimensions suspend
    /// presentation while the window is minimized; restoring/resizing the window performs a
    /// bounded `ResizeBuffers` and lazily rebuilds the video processor on the next frame.
    ///
    /// Returns `false` after the presentation window has closed.
    pub fn pump_messages(&mut self) -> bool {
        let mut message = MSG::default();
        while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() } {
            if message.message == WM_QUIT {
                self.closed = true;
                break;
            }
            if message.message == WM_SIZE && message.hwnd == self.hwnd {
                let (width, height) = client_size_from_lparam(message.lParam);
                self.client_size = (width, height);
                if let Some(presenter) = self.presenter.as_mut() {
                    match presenter.resize_output(width, height) {
                        Ok(ResizeOutcome::Resized) => {
                            eprintln!("student presentation resized to {width}x{height}");
                        }
                        Ok(ResizeOutcome::Suspended) => {
                            eprintln!(
                                "student presentation suspended while the window is minimized"
                            );
                        }
                        Ok(ResizeOutcome::Unchanged) => {}
                        Err(error) => {
                            if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                                self.device_lost = true;
                            }
                            eprintln!(
                                "student presentation swap-chain resize failed at {width}x{height}: {error}"
                            );
                        }
                    }
                } else {
                    self.device_lost = true;
                }
            }
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            // DefWindowProcW destroys this HWND on WM_CLOSE synchronously.
            // No process/thread-wide WM_QUIT should be posted: the Worker may
            // later open another presentation on the same interactive thread.
            if !unsafe { IsWindow(Some(self.hwnd)).as_bool() } {
                self.closed = true;
                break;
            }
        }
        !self.closed
    }

    /// Returns and clears the pending device-loss signal raised by present or resize.
    pub fn take_device_lost(&mut self) -> bool {
        std::mem::take(&mut self.device_lost)
    }

    #[must_use]
    pub fn metrics(&self) -> PresentMetrics {
        self.presenter
            .as_ref()
            .map_or_else(PresentMetrics::default, FlipPresenter::metrics)
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

fn client_size_from_lparam(lparam: LPARAM) -> (u32, u32) {
    let packed = lparam.0 as usize;
    let width = u32::try_from(packed & 0xffff).unwrap_or(0);
    let height = u32::try_from((packed >> 16) & 0xffff).unwrap_or(0);
    (width, height)
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // WM_DESTROY is scoped to this presentation HWND. Do not call
    // PostQuitMessage: it would poison the Worker thread for later sessions.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_client_size_from_wm_size_lparam() {
        let packed = (720usize << 16) | 1280usize;
        assert_eq!(
            client_size_from_lparam(LPARAM(packed as isize)),
            (1280, 720)
        );
    }

    #[test]
    fn destroying_receiver_window_does_not_post_global_thread_quit() {
        // A Worker can close one presentation and start another on the same
        // interactive thread. Its HWND must not terminate that thread's queue.
        std::thread::spawn(|| {
            let module = unsafe { GetModuleHandleW(None).unwrap() };
            let class = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: module.into(),
                lpszClassName: WINDOW_CLASS,
                ..Default::default()
            };
            let _ = unsafe { RegisterClassW(&class) };
            let hwnd = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    WINDOW_CLASS,
                    WINDOW_TITLE,
                    WS_OVERLAPPEDWINDOW,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    320,
                    180,
                    None,
                    None,
                    Some(module.into()),
                    None,
                )
                .unwrap()
            };
            unsafe { DestroyWindow(hwnd).unwrap() };
            let mut message = MSG::default();
            let mut posted_quit = false;
            while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() } {
                posted_quit |= message.message == WM_QUIT;
            }
            assert!(
                !posted_quit,
                "closing one presentation must not quit the Worker thread"
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn closing_receiver_window_is_observed_without_global_quit() {
        std::thread::spawn(|| {
            let module = unsafe { GetModuleHandleW(None).unwrap() };
            let class = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: module.into(),
                lpszClassName: WINDOW_CLASS,
                ..Default::default()
            };
            let _ = unsafe { RegisterClassW(&class) };
            let hwnd = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    WINDOW_CLASS,
                    WINDOW_TITLE,
                    WS_OVERLAPPEDWINDOW,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    320,
                    180,
                    None,
                    None,
                    Some(module.into()),
                    None,
                )
                .unwrap()
            };
            let mut receiver = PresentationWindow {
                hwnd,
                presenter: None,
                closed: false,
                client_size: (320, 180),
                device_lost: false,
            };
            unsafe {
                windows::Win32::UI::WindowsAndMessaging::PostMessageW(
                    Some(hwnd),
                    windows::Win32::UI::WindowsAndMessaging::WM_CLOSE,
                    WPARAM(0),
                    LPARAM(0),
                )
                .unwrap()
            };
            assert!(
                !receiver.pump_messages(),
                "closing HWND must stop the presentation"
            );
            assert!(receiver.closed);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn failed_presenter_initialization_destroys_its_new_window() {
        use classmesh_codec_win::d3d11::create_default_video_device;
        use windows::Win32::UI::WindowsAndMessaging::{EnumThreadWindows, GetClassNameW};
        use windows::core::BOOL;
        use windows_sys::Win32::System::Threading::GetCurrentThreadId;

        unsafe extern "system" fn count_window(hwnd: HWND, state: LPARAM) -> BOOL {
            let mut class = [0u16; 64];
            let len = unsafe { GetClassNameW(hwnd, &mut class) };
            let expected: Vec<u16> = "ClassMeshMediaReceiverWindow".encode_utf16().collect();
            if len > 0 && class[..len as usize] == expected {
                let count = unsafe { &mut *(state.0 as *mut usize) };
                *count += 1;
            }
            BOOL(1)
        }

        fn thread_window_count() -> usize {
            let mut count = 0usize;
            let thread_id = unsafe { GetCurrentThreadId() };
            let _ = unsafe {
                EnumThreadWindows(
                    thread_id,
                    Some(count_window),
                    LPARAM((&raw mut count) as isize),
                )
            };
            count
        }

        // Use a dedicated Win32 thread so unrelated test windows cannot mask
        // the leaked HWND. Zero output width fails inside FlipPresenter::new,
        // after PresentationWindow::new has already created its HWND.
        std::thread::spawn(|| {
            let device = create_default_video_device().expect("D3D11 test device");
            let before = thread_window_count();
            assert!(PresentationWindow::new(&device, 0, 720).is_err());
            assert_eq!(
                thread_window_count(),
                before,
                "failed presenter initialization must not leave a live HWND"
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn zero_wm_size_dimensions_are_preserved_for_minimize() {
        assert_eq!(client_size_from_lparam(LPARAM(0)), (0, 0));
    }
}
