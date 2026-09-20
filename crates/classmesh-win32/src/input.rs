use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::io;
use std::mem::size_of;

use windows_sys::Win32::System::StationsAndDesktops::{
    GetThreadDesktop, GetUserObjectInformationW, UOI_IO,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL,
    MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP,
    MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK,
    MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, SendInput,
};

pub const ABSOLUTE_COORDINATE_MAX: i32 = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputKey {
    pub virtual_key: u16,
    pub scan_code: u16,
    pub extended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAction {
    MouseMove {
        x: i32,
        y: i32,
        absolute: bool,
    },
    MouseButton {
        button: MouseButton,
        down: bool,
    },
    MouseWheel {
        delta: i32,
        horizontal: bool,
    },
    Key {
        virtual_key: u32,
        scan_code: u32,
        down: bool,
        extended: bool,
    },
    ReleaseAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDesktopUnavailable {
    NotInputDesktop,
    ProbeFailed,
}

#[derive(Debug)]
pub enum InputError {
    AbsoluteCoordinateOutOfRange {
        x: i32,
        y: i32,
    },
    KeyCodeOutOfRange {
        virtual_key: u32,
        scan_code: u32,
    },
    MissingKeyCode,
    DesktopUnavailable(InputDesktopUnavailable),
    SendInput {
        requested: u32,
        inserted: u32,
        source: io::Error,
    },
}

impl Display for InputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AbsoluteCoordinateOutOfRange { x, y } => write!(
                formatter,
                "absolute mouse coordinates ({x}, {y}) must be within 0..={ABSOLUTE_COORDINATE_MAX}"
            ),
            Self::KeyCodeOutOfRange {
                virtual_key,
                scan_code,
            } => write!(
                formatter,
                "input key codes exceed u16 range: virtual_key={virtual_key}, scan_code={scan_code}"
            ),
            Self::MissingKeyCode => {
                write!(
                    formatter,
                    "input key requires a scan code or virtual-key code"
                )
            }
            Self::DesktopUnavailable(InputDesktopUnavailable::NotInputDesktop) => {
                write!(formatter, "Worker desktop is not the current input desktop")
            }
            Self::DesktopUnavailable(InputDesktopUnavailable::ProbeFailed) => {
                write!(formatter, "Worker could not verify the current input desktop")
            }
            Self::SendInput {
                requested,
                inserted,
                source,
            } => write!(
                formatter,
                "SendInput inserted {inserted} of {requested} requested events: {source}"
            ),
        }
    }
}

impl std::error::Error for InputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SendInput { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl InputError {
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::AbsoluteCoordinateOutOfRange { .. } => "worker.input.absolute_out_of_range",
            Self::KeyCodeOutOfRange { .. } => "worker.input.key_code_out_of_range",
            Self::MissingKeyCode => "worker.input.missing_key_code",
            Self::DesktopUnavailable(InputDesktopUnavailable::NotInputDesktop) => {
                "worker.input.desktop_unavailable"
            }
            Self::DesktopUnavailable(InputDesktopUnavailable::ProbeFailed) => {
                "worker.input.desktop_probe_failed"
            }
            Self::SendInput { .. } => "worker.input.send_rejected",
        }
    }
}

#[derive(Debug, Default)]
pub struct InputInjector {
    pressed_keys: BTreeSet<InputKey>,
    pressed_buttons: BTreeSet<MouseButton>,
}

impl InputInjector {
    pub fn apply(&mut self, action: InputAction) -> Result<(), InputError> {
        ensure_input_desktop()?;
        match action {
            InputAction::MouseMove { x, y, absolute } => {
                let input = mouse_move_input(x, y, absolute)?;
                send_inputs(std::slice::from_ref(&input))
            }
            InputAction::MouseButton { button, down } => {
                let input = mouse_button_input(button, down);
                send_inputs(std::slice::from_ref(&input))?;
                if down {
                    self.pressed_buttons.insert(button);
                } else {
                    self.pressed_buttons.remove(&button);
                }
                Ok(())
            }
            InputAction::MouseWheel { delta, horizontal } => {
                let input = mouse_wheel_input(delta, horizontal);
                send_inputs(std::slice::from_ref(&input))
            }
            InputAction::Key {
                virtual_key,
                scan_code,
                down,
                extended,
            } => {
                let key = validate_key(virtual_key, scan_code, extended)?;
                let input = key_input(key, down);
                send_inputs(std::slice::from_ref(&input))?;
                if down {
                    self.pressed_keys.insert(key);
                } else {
                    self.pressed_keys.remove(&key);
                }
                Ok(())
            }
            InputAction::ReleaseAll => self.release_all(),
        }
    }

    pub fn release_all(&mut self) -> Result<(), InputError> {
        if self.pressed_keys.is_empty() && self.pressed_buttons.is_empty() {
            return Ok(());
        }

        let mut inputs = Vec::with_capacity(self.pressed_keys.len() + self.pressed_buttons.len());
        inputs.extend(
            self.pressed_keys
                .iter()
                .copied()
                .map(|key| key_input(key, false)),
        );
        inputs.extend(
            self.pressed_buttons
                .iter()
                .copied()
                .map(|button| mouse_button_input(button, false)),
        );
        send_inputs(&inputs)?;
        self.pressed_keys.clear();
        self.pressed_buttons.clear();
        Ok(())
    }

    #[must_use]
    pub fn pressed_key_count(&self) -> usize {
        self.pressed_keys.len()
    }

    #[must_use]
    pub fn pressed_button_count(&self) -> usize {
        self.pressed_buttons.len()
    }
}

fn validate_key(virtual_key: u32, scan_code: u32, extended: bool) -> Result<InputKey, InputError> {
    let original_virtual_key = virtual_key;
    let virtual_key = u16::try_from(virtual_key).map_err(|_| InputError::KeyCodeOutOfRange {
        virtual_key,
        scan_code,
    })?;
    let scan_code = u16::try_from(scan_code).map_err(|_| InputError::KeyCodeOutOfRange {
        virtual_key: original_virtual_key,
        scan_code,
    })?;
    if virtual_key == 0 && scan_code == 0 {
        return Err(InputError::MissingKeyCode);
    }
    Ok(InputKey {
        virtual_key,
        scan_code,
        extended,
    })
}

fn mouse_move_input(x: i32, y: i32, absolute: bool) -> Result<INPUT, InputError> {
    let mut flags = MOUSEEVENTF_MOVE;
    if absolute {
        if !(0..=ABSOLUTE_COORDINATE_MAX).contains(&x)
            || !(0..=ABSOLUTE_COORDINATE_MAX).contains(&y)
        {
            return Err(InputError::AbsoluteCoordinateOutOfRange { x, y });
        }
        flags |= MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
    }

    Ok(mouse_input(x, y, 0, flags))
}

fn mouse_button_input(button: MouseButton, down: bool) -> INPUT {
    let (flags, mouse_data) = match (button, down) {
        (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
        (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
        (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
        (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
        (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
        (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
        (MouseButton::X1, true) => (MOUSEEVENTF_XDOWN, 1),
        (MouseButton::X1, false) => (MOUSEEVENTF_XUP, 1),
        (MouseButton::X2, true) => (MOUSEEVENTF_XDOWN, 2),
        (MouseButton::X2, false) => (MOUSEEVENTF_XUP, 2),
    };
    mouse_input(0, 0, mouse_data, flags)
}

fn mouse_wheel_input(delta: i32, horizontal: bool) -> INPUT {
    let flags = if horizontal {
        MOUSEEVENTF_HWHEEL
    } else {
        MOUSEEVENTF_WHEEL
    };
    mouse_input(0, 0, delta as u32, flags)
}

fn mouse_input(dx: i32, dy: i32, mouse_data: u32, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn key_input(key: InputKey, down: bool) -> INPUT {
    let mut flags = 0;
    let (virtual_key, scan_code) = if key.scan_code == 0 {
        (key.virtual_key, 0)
    } else {
        flags |= KEYEVENTF_SCANCODE;
        (0, key.scan_code)
    };
    if key.extended {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    if !down {
        flags |= KEYEVENTF_KEYUP;
    }

    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: virtual_key,
                wScan: scan_code,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn ensure_input_desktop() -> Result<(), InputError> {
    // SAFETY: GetCurrentThreadId has no preconditions. GetThreadDesktop returns a borrowed
    // desktop handle for this thread; it must not be closed by the caller. UOI_IO writes
    // a BOOL-sized value into the provided initialized stack slot.
    let thread_id = unsafe { GetCurrentThreadId() };
    let desktop = unsafe { GetThreadDesktop(thread_id) };
    if desktop.is_null() {
        return Err(InputError::DesktopUnavailable(
            InputDesktopUnavailable::ProbeFailed,
        ));
    }

    let mut is_input_desktop = 0_i32;
    let mut bytes_needed = 0_u32;
    let ok = unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_IO,
            (&mut is_input_desktop as *mut i32).cast(),
            u32::try_from(size_of::<i32>()).expect("BOOL size fits u32"),
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        return Err(InputError::DesktopUnavailable(
            InputDesktopUnavailable::ProbeFailed,
        ));
    }
    if is_input_desktop == 0 {
        return Err(InputError::DesktopUnavailable(
            InputDesktopUnavailable::NotInputDesktop,
        ));
    }
    Ok(())
}

fn send_inputs(inputs: &[INPUT]) -> Result<(), InputError> {
    if inputs.is_empty() {
        return Ok(());
    }

    let requested = u32::try_from(inputs.len()).expect("input batch length fits u32");
    let input_size = i32::try_from(size_of::<INPUT>()).expect("INPUT size fits i32");
    // SAFETY: inputs is a valid contiguous slice of initialized INPUT structures and
    // remains alive for the duration of the synchronous SendInput call.
    let inserted = unsafe { SendInput(requested, inputs.as_ptr(), input_size) };
    if inserted != requested {
        return Err(InputError::SendInput {
            requested,
            inserted,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_mouse_requires_normalized_virtual_desktop_range() {
        assert!(mouse_move_input(0, ABSOLUTE_COORDINATE_MAX, true).is_ok());
        assert!(matches!(
            mouse_move_input(-1, 0, true),
            Err(InputError::AbsoluteCoordinateOutOfRange { .. })
        ));
        assert!(matches!(
            mouse_move_input(0, ABSOLUTE_COORDINATE_MAX + 1, true),
            Err(InputError::AbsoluteCoordinateOutOfRange { .. })
        ));
        assert!(mouse_move_input(-50, 120, false).is_ok());
    }

    #[test]
    fn scan_code_is_preferred_and_key_codes_are_bounded() {
        let key = validate_key(0x41, 0x1e, true).expect("key should validate");
        let input = key_input(key, true);
        // SAFETY: INPUT is initialized with the keyboard union variant above.
        let keyboard = unsafe { input.Anonymous.ki };
        assert_eq!(keyboard.wVk, 0);
        assert_eq!(keyboard.wScan, 0x1e);
        assert_ne!(keyboard.dwFlags & KEYEVENTF_SCANCODE, 0);
        assert_ne!(keyboard.dwFlags & KEYEVENTF_EXTENDEDKEY, 0);

        assert!(matches!(
            validate_key(0, 0, false),
            Err(InputError::MissingKeyCode)
        ));
        assert!(matches!(
            validate_key(u32::from(u16::MAX) + 1, 0, false),
            Err(InputError::KeyCodeOutOfRange { .. })
        ));
    }

    #[test]
    fn input_diagnostic_codes_are_stable_and_value_free() {
        assert_eq!(
            InputError::DesktopUnavailable(InputDesktopUnavailable::NotInputDesktop)
                .diagnostic_code(),
            "worker.input.desktop_unavailable"
        );
        assert_eq!(
            InputError::DesktopUnavailable(InputDesktopUnavailable::ProbeFailed)
                .diagnostic_code(),
            "worker.input.desktop_probe_failed"
        );
        assert_eq!(
            InputError::MissingKeyCode.diagnostic_code(),
            "worker.input.missing_key_code"
        );
    }

    #[test]
    fn mouse_button_mapping_is_stable() {
        let x1 = mouse_button_input(MouseButton::X1, true);
        // SAFETY: INPUT is initialized with the mouse union variant above.
        let x1_mouse = unsafe { x1.Anonymous.mi };
        assert_eq!(x1_mouse.mouseData, 1);
        assert_eq!(x1_mouse.dwFlags, MOUSEEVENTF_XDOWN);

        let x2 = mouse_button_input(MouseButton::X2, false);
        // SAFETY: INPUT is initialized with the mouse union variant above.
        let x2_mouse = unsafe { x2.Anonymous.mi };
        assert_eq!(x2_mouse.mouseData, 2);
        assert_eq!(x2_mouse.dwFlags, MOUSEEVENTF_XUP);
    }
}
