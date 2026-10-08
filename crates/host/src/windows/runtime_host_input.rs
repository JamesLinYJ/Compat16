//! Keyboard and event-pump forwarding for the native Windows adapter.

use super::*;

pub(super) fn read_bios_key(host: &mut WindowsHost) -> Result<KeyStroke, RuntimeError> {
    host.key(true)
        .map_err(|error| console_input_runtime_error("console input", error))?
        .ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "blocking console input returned no key"))
}

pub(super) fn try_read_bios_key(
    host: &mut WindowsHost,
) -> Result<Option<KeyStroke>, RuntimeError> {
    host.key(false)
        .map_err(|error| console_input_runtime_error("nonblocking console input", error))
}

pub(super) fn pump_events(host: &mut WindowsHost) -> Result<(), RuntimeError> {
    if host.vga_window.is_active() {
        host.pump_vga_events()
    } else {
        host.pump_console_input(false)
            .map_err(|error| console_input_runtime_error("console event input", error))
    }
}
