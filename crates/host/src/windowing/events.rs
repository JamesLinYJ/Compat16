use windows_sys::Win32::UI::WindowsAndMessaging::{
    WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEMOVE,
    WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};
use graphics::{HostEvent, MouseButton, WindowHandle};

pub(super) fn decode_key(
    window: WindowHandle,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> Option<HostEvent> {
    let key = w_param as u16;
    let repeat_count = l_param as u32 as u16;
    match message {
        WM_KEYDOWN | WM_SYSKEYDOWN => Some(HostEvent::KeyDown {
            window,
            key,
            repeat_count,
        }),
        WM_KEYUP | WM_SYSKEYUP => Some(HostEvent::KeyUp {
            window,
            key,
            repeat_count,
        }),
        _ => None,
    }
}

pub(super) fn decode_character(
    window: WindowHandle,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> Option<HostEvent> {
    (message == windows_sys::Win32::UI::WindowsAndMessaging::WM_CHAR).then_some(
        HostEvent::Character {
            window,
            character: w_param as u16,
            scan: ((l_param as u32 >> 16) & 0xff) as u8,
            repeat_count: l_param as u32 as u16,
        },
    )
}

pub(super) fn decode_mouse(
    window: WindowHandle,
    message: u32,
    _w_param: usize,
    l_param: isize,
) -> Option<HostEvent> {
    let x = signed_point_word(l_param, 0);
    let y = signed_point_word(l_param, 16);
    match message {
        WM_MOUSEMOVE => Some(HostEvent::MouseMove { window, x, y }),
        WM_LBUTTONDOWN => Some(HostEvent::MouseButton {
            window,
            button: MouseButton::Left,
            down: true,
            x,
            y,
        }),
        WM_LBUTTONUP => Some(HostEvent::MouseButton {
            window,
            button: MouseButton::Left,
            down: false,
            x,
            y,
        }),
        WM_MBUTTONDOWN => Some(HostEvent::MouseButton {
            window,
            button: MouseButton::Middle,
            down: true,
            x,
            y,
        }),
        WM_MBUTTONUP => Some(HostEvent::MouseButton {
            window,
            button: MouseButton::Middle,
            down: false,
            x,
            y,
        }),
        WM_RBUTTONDOWN => Some(HostEvent::MouseButton {
            window,
            button: MouseButton::Right,
            down: true,
            x,
            y,
        }),
        WM_RBUTTONUP => Some(HostEvent::MouseButton {
            window,
            button: MouseButton::Right,
            down: false,
            x,
            y,
        }),
        _ => None,
    }
}

fn signed_point_word(l_param: isize, shift: u32) -> i16 {
    ((l_param as u32 >> shift) as u16) as i16
}
