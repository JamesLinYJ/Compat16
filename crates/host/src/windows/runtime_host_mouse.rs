//! Host mouse services kept separate from the USER and window adapter.

use super::*;

pub(super) fn mouse_available(host: &WindowsHost) -> bool {
    host.mouse_input_enabled
        // SAFETY: GetSystemMetrics has no pointer arguments or ownership requirements.
        && unsafe { GetSystemMetrics(SM_MOUSEPRESENT) } != 0
}

pub(super) fn take_mouse_input(
    host: &mut WindowsHost,
) -> Result<Option<MouseInput>, RuntimeError> {
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
