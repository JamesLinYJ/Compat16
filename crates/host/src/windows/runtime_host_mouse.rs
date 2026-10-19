//! Host mouse services kept separate from the USER and window adapter.

use std::thread;
use std::time::Duration;

use super::win16_common::get_async_key_state;
use super::*;
use windows_sys::Win32::Foundation::POINT;
use windows_sys::Win32::UI::WindowsAndMessaging::GetCursorPos;

const VK_LBUTTON: i32 = 0x01;
const VK_ESCAPE: i32 = 0x1b;
const DRAG_POLL_WAIT: Duration = Duration::from_millis(10);

pub(super) fn mouse_available(host: &WindowsHost) -> bool {
    host.mouse_input_enabled
        // SAFETY: GetSystemMetrics has no pointer arguments or ownership requirements.
        &&  (crate::windows::win32_safe::system_metrics(SM_MOUSEPRESENT)) != 0
}

pub(super) fn take_mouse_input(host: &mut WindowsHost) -> Result<Option<MouseInput>, RuntimeError> {
    if !mouse_available(host) || host.vga_window.is_active() {
        return Ok(None);
    }
    Ok(host.mouse_inputs.pop_front())
}

pub(super) fn set_mouse_position(
    host: &mut WindowsHost,
    x: u16,
    y: u16,
) -> Result<(), RuntimeError> {
    // INT 33h function 04h replaces queued samples for the old guest position.
    host.mouse_inputs.clear();
    host.last_mouse_input = Some(MouseInput {
        x: i32::from(x),
        y: i32::from(y),
        buttons: host.last_mouse_buttons,
    });
    Ok(())
}

/// Sample the screen pointer and the logical left button and Escape key.
///
/// `wait_for_change` sleeps until the sample differs from the previous poll.
/// This does not pump the guest queue and does not call `SetCapture`. The
/// guest HWND stays in the runtime.
pub(super) fn drag_poll(
    host: &mut WindowsHost,
    wait_for_change: bool,
) -> Result<runtime::Win16DragSample, RuntimeError> {
    let mut sample = read_drag_sample()?;
    if wait_for_change {
        while host.last_drag_sample == Some(sample) {
            thread::sleep(DRAG_POLL_WAIT);
            sample = read_drag_sample()?;
        }
    }
    host.last_drag_sample = Some(sample);
    Ok(sample)
}

fn read_drag_sample() -> Result<runtime::Win16DragSample, RuntimeError> {
    let mut point = POINT::default();
    // SAFETY: GetCursorPos writes one caller-owned POINT and retains no pointer.
    if unsafe { GetCursorPos(&mut point) } == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "host cursor position is unavailable",
        ));
    }
    Ok(runtime::Win16DragSample {
        x: narrow_screen(point.x),
        y: narrow_screen(point.y),
        left_down: key_down(VK_LBUTTON),
        escape_down: key_down(VK_ESCAPE),
    })
}

fn key_down(virtual_key: i32) -> bool {
    get_async_key_state(virtual_key) < 0
}

fn narrow_screen(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}
