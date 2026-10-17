//! Native delivery of synthesized Win16 keyboard and mouse input.
//!
//! The guest extra-info dword is widened to the native `ULONG_PTR` slot.
//! It is not loaded or stored as a pointer.

use runtime::{Win16InjectedKey, Win16InjectedMouse};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{keybd_event, mouse_event};

pub(super) fn inject_keyboard(event: Win16InjectedKey) {
    // SAFETY: keybd_event consumes four scalars. extra_info is zero-extended
    // from the guest DWORD and is not a host address.
    unsafe {
        keybd_event(
            event.virtual_key,
            event.scan,
            event.flags,
            event.extra_info as usize,
        );
    }
}

pub(super) fn inject_mouse(event: Win16InjectedMouse) {
    // SAFETY: mouse_event consumes five scalars. The button count fits in a
    // signed 32-bit value because the guest register image is 16 bits wide.
    // extra_info is zero-extended from the guest DWORD and is not a host address.
    unsafe {
        mouse_event(
            u32::from(event.flags),
            event.dx,
            event.dy,
            i32::from(event.buttons),
            event.extra_info as usize,
        );
    }
}
