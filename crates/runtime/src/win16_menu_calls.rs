//! Win16 menu calls marshalled through the native USER worker.

use guest_core::Registers;
use guest_core::memory::Memory;
use win16_abi::exports::menu_abi as flags;
use win16_abi::{MAX_WIN16_STRING_BYTES, Win16ReturnKind, Win16UserMenuRequest};

use super::{Win16State, guest_ranges::GuestOutputRange, windows::WindowReturn};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostRect, Win16MenuItem,
    Win16MenuItemContent, Win16MenuItemIdentity, Win16MenuOperation,
    Win16WindowOperation,
};

#[path = "win16_menu_calls/completion.rs"]
mod completion;
#[path = "win16_menu_calls/creation.rs"]
mod creation;
#[path = "win16_menu_calls/operations.rs"]
mod operations;

#[path = "win16_menu_templates.rs"]
mod templates;

#[derive(Clone, Copy)]
pub(in crate::win16_runtime) enum MenuCallKind {
    Handle,
    Boolean,
    ItemFlags,
    ItemId,
    ItemCount,
    ContextHelpId,
    CheckMarkDimensions,
    MenuRect,
    MenuString,
    Void,
    Popup,
}

/// Return-side data for a suspended menu API. Output pointers are retained
/// only for GetMenuString/GetMenuItemRect after the full destination has been
/// preflighted in guest memory.
pub(super) struct MenuCall {
    pub(in crate::win16_runtime) kind: MenuCallKind,
    pub(in crate::win16_runtime) return_kind: Win16ReturnKind,
    pub(in crate::win16_runtime) output: Option<GuestOutputRange>,
}

impl Win16State {
    pub(super) fn begin_menu_api(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        request: Win16UserMenuRequest,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        use Win16UserMenuRequest as Request;

        match request {
            request @ (Request::CreateMenu
            | Request::CreatePopupMenu
            | Request::LoadMenu { .. }
            | Request::LoadMenuIndirect { .. }) => {
                self.begin_menu_creation(registers, memory, host, request, return_to, return_kind)
            }
            request => {
                self.begin_menu_operations(registers, memory, host, request, return_to, return_kind)
            }
        }
    }
}
