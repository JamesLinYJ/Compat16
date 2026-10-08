//! Decoder routing from the project-owned typed catalog module identity.

use super::super::Win16ExportId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DecodeRoute {
    Kernel,
    User,
    Gdi,
    Libraries,
}

pub(super) fn route(id: Win16ExportId) -> DecodeRoute {
    // `module()` is exhaustive metadata emitted by the same catalog macro as
    // the ID enum; it is never a guest-provided DLL name or permission check.
    match id.module() {
        "KERNEL" => DecodeRoute::Kernel,
        "USER" => DecodeRoute::User,
        "GDI" => DecodeRoute::Gdi,
        "DDEML" => DecodeRoute::Libraries,
        _ => DecodeRoute::Libraries,
    }
}
