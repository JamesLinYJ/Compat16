use super::super::events::{decode_character, decode_key, decode_mouse};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    WM_CHAR, WM_KEYDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_SYSKEYUP,
};
use graphics::{HostEvent, MouseButton, WindowHandle};

fn window() -> WindowHandle {
    WindowHandle::from_raw(17).unwrap()
}

#[test]
fn key_conversion_preserves_virtual_key_and_repeat_count() {
    assert_eq!(
        decode_key(window(), WM_KEYDOWN, 0x41, 3),
        Some(HostEvent::KeyDown {
            window: window(),
            key: 0x41,
            repeat_count: 3,
        }),
    );
    assert_eq!(
        decode_key(window(), WM_SYSKEYUP, 0x12, 1),
        Some(HostEvent::KeyUp {
            window: window(),
            key: 0x12,
            repeat_count: 1,
        }),
    );
    assert_eq!(decode_key(window(), 0x0102, 0x41, 1), None);
}

#[test]
fn character_conversion_preserves_utf16_unit_scan_code_and_repeat_count() {
    let character_parameter = 2u32 | (0x32u32 << 16);
    assert_eq!(
        decode_character(window(), WM_CHAR, 0x4e2d, character_parameter as isize),
        Some(HostEvent::Character {
            window: window(),
            character: 0x4e2d,
            scan: 0x32,
            repeat_count: 2,
        }),
    );
    assert_eq!(decode_character(window(), WM_KEYDOWN, 0x41, 1), None);
}

#[test]
fn mouse_conversion_sign_extends_each_packed_coordinate() {
    let packed = (u32::from(i16::MIN as u16) << 16) | u32::from((-2i16) as u16);
    assert_eq!(
        decode_mouse(window(), WM_MOUSEMOVE, 0, packed as isize),
        Some(HostEvent::MouseMove {
            window: window(),
            x: -2,
            y: i16::MIN,
        }),
    );
    assert_eq!(
        decode_mouse(window(), WM_LBUTTONUP, 0, packed as isize),
        Some(HostEvent::MouseButton {
            window: window(),
            button: MouseButton::Left,
            down: false,
            x: -2,
            y: i16::MIN,
        }),
    );
}
