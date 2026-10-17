//! Decoding of catalogued Win16 export calls into owned runtime requests.

use super::{Win16ExportDescriptor, Win16ExportId};
use crate::{ReturnAddressWidth, SelectorTable, Win16CallFrame, Win16Error};
use guest_core::GuestMemory;
use super::request::*;

#[path = "call_helpers.rs"]
pub(super) mod call_helpers;
use call_helpers::*;

#[path = "call_guid_compare.rs"]
mod guid_compare_calls;
#[path = "call_gdi.rs"]
mod gdi_calls;
#[path = "call_gdi_services.rs"]
mod gdi_services_calls;
#[path = "call_gdi_spool.rs"]
mod gdi_spool_calls;
#[path = "call_gdi_device.rs"]
mod gdi_device_calls;
#[path = "call_gdi_objects.rs"]
mod gdi_objects_calls;
#[path = "call_gdi_drawing.rs"]
mod gdi_drawing_calls;
#[path = "call_gdi_primitives.rs"]
mod gdi_primitives_calls;
#[path = "call_user_paint.rs"]
mod user_paint_calls;
#[path = "call_user_hooks.rs"]
mod user_hooks_calls;
#[path = "call_user_drawing.rs"]
mod user_drawing_calls;
#[path = "call_user_messages.rs"]
mod user_messages;
#[path = "call_user_cursor_accelerator.rs"]
mod user_cursor_accelerator_calls;
#[path = "call_user_clipboard.rs"]
mod user_clipboard;
#[path = "call_user_text.rs"]
mod user_text;
#[path = "call_resources.rs"]
mod resource_calls;
#[path = "call_file_io.rs"]
mod file_io_calls;
#[path = "call_file_control.rs"]
mod file_control_calls;
#[path = "call_toolhelp.rs"]
mod toolhelp_calls;
#[path = "call_kernel_services.rs"]
mod kernel_service_calls;
#[path = "call_kernel_locale.rs"]
mod kernel_locale;
#[path = "call_kernel_heap.rs"]
mod kernel_heap_calls;
#[path = "call_kernel_atoms.rs"]
mod kernel_atom_calls;
#[path = "call_kernel_runtime.rs"]
mod kernel_runtime_calls;
#[path = "call_kernel_selectors.rs"]
mod kernel_selector_calls;
#[path = "call_kernel_modules.rs"]
mod kernel_module_calls;
#[path = "call_profile.rs"]
mod profile_calls;
#[path = "call_win16_services.rs"]
mod win16_service_calls;
#[path = "call_user_system.rs"]
mod user_system_calls;
#[path = "call_user_comm.rs"]
mod call_user_comm;
#[path = "call_user_resources.rs"]
mod user_resource_calls;
#[path = "call_user_atoms.rs"]
mod user_atom_calls;
#[path = "call_menus.rs"]
mod call_menus;
#[path = "call_window_ops.rs"]
mod call_window_ops;
#[path = "call_window_properties.rs"]
mod call_window_properties;
#[path = "call_request_routes.rs"]
mod call_request_routes;
#[path = "call_requests_kernel.rs"]
mod call_requests_kernel;
#[path = "call_requests_user.rs"]
mod call_requests_user;
#[path = "call_user_string_format.rs"]
mod call_user_string_format;
#[path = "call_requests_gdi.rs"]
mod call_requests_gdi;
#[path = "call_requests_libraries.rs"]
mod call_requests_libraries;
#[path = "call_requests.rs"]
mod requests;

/// Decode a call's scalar frame and copy all required far strings/buffers.
pub fn decode_export_call(
    descriptor: &Win16ExportDescriptor,
    frame: Win16CallFrame,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<DecodedWin16Call, Win16Error> {
    if descriptor.id == Win16ExportId::UserWsprintf {
        return call_user_string_format::decode_wsprintf(descriptor, frame, selectors, memory);
    }
    let (arguments, stack_cleanup) =
        decode_fixed_stack_frame(descriptor, frame, selectors, memory)?;

    let request = requests::decode(descriptor, &arguments, selectors, memory)?;

    Ok(DecodedWin16Call {
        export: descriptor.id,
        request,
        stack_cleanup,
    })
}

#[path = "input_event.rs"]
mod input_event;
#[path = "call_register_context.rs"]
mod register_context;
pub use register_context::decode_export_call_with_register_context;

/// The entry frame uses a four-byte far return for NE-imported far calls.
/// Kept here as a convenience for thunk integration code that needs to build
/// the matching frame from a guest SS:SP pair.
pub const FAR_EXPORT_RETURN_WIDTH: ReturnAddressWidth = ReturnAddressWidth::Far;

#[cfg(test)]
#[path = "call_open_file_tests.rs"]
mod open_file_tests;

#[cfg(test)]
#[path = "call_input_event_tests.rs"]
mod input_event_tests;
