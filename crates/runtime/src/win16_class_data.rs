//! Guest class WORD/LONG access for USER.129–132.
//!
//! Microsoft Windows 3.1 SDK Guide to Programming, section 16.2.4, defines
//! cbClsExtra as byte storage shared by the windows of a registered class.
//! Only guest registrations own that layout here; native class storage and
//! native pointer-sized metadata never enter these accessors.

use win16_abi::{Win16ClassDataRequest, exports::class_data::{
    GCL_WNDPROC, GCW_ATOM, GCW_CBCLSEXTRA, GCW_CBWNDEXTRA, GCW_HBRBACKGROUND,
    GCW_HCURSOR, GCW_HICON, GCW_STYLE,
}};

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeHost};

#[derive(Clone, Copy)]
enum DataWidth { Word, Long }

impl DataWidth {
    fn bytes(self) -> usize {
        match self { Self::Word => 2, Self::Long => 4 }
    }

    fn api(self, writing: bool) -> &'static str {
        match (self, writing) {
            (Self::Word, false) => "GetClassWord",
            (Self::Word, true) => "SetClassWord",
            (Self::Long, false) => "GetClassLong",
            (Self::Long, true) => "SetClassLong",
        }
    }
}

impl Win16State {
    pub(super) fn access_class_data(
        &mut self,
        request: Win16ClassDataRequest,
        host: &mut impl RuntimeHost,
    ) -> u32 {
        let (window, index, width, replacement) = match request {
            Win16ClassDataRequest::GetClassWord { window, index } =>
                (window, index, DataWidth::Word, None),
            Win16ClassDataRequest::SetClassWord { window, index, value } =>
                (window, index, DataWidth::Word, Some(u32::from(value))),
            Win16ClassDataRequest::GetClassLong { window, index } =>
                (window, index, DataWidth::Long, None),
            Win16ClassDataRequest::SetClassLong { window, index, value } =>
                (window, index, DataWidth::Long, Some(value as u32)),
        };
        if window == 0 || !self.window_handles.contains_key(&window) { return 0; }

        let mut unsupported = |reason| {
            report_unsupported(host, window, index, width, replacement.is_some(), reason);
            0
        };
        let Some(class) = self.window_host_class(window) else {
            return unsupported("has no exact guest class identity");
        };

        if index >= 0 {
            let Some(bytes) = self.window_classes.guest_class_extra_mut(class) else {
                return unsupported("has no guest-owned class extra-data contract");
            };
            let offset = index as usize;
            let Some(end) = offset.checked_add(width.bytes()) else { return 0; };
            let Some(slot) = bytes.get_mut(offset..end) else { return 0; };
            // Unaligned offsets and overlapping WORD/LONG accesses are byte
            // operations. Validate the entire span before changing any byte.
            let mut old = [0_u8; 4];
            old[..width.bytes()].copy_from_slice(slot);
            if let Some(value) = replacement {
                slot.copy_from_slice(&value.to_le_bytes()[..width.bytes()]);
            }
            return u32::from_le_bytes(old);
        }

        let Some((atom, info)) = self.window_classes.guest_class_info(class) else {
            // Predefined aliases may have native metadata and procedure gates,
            // but their private fields are not a registered Win16 class layout.
            return unsupported("has no guest registration metadata contract");
        };
        if replacement.is_some() {
            // Even scalar-looking fields can affect native class behavior,
            // resource ownership, allocation sizes, or saved procedure chains.
            return unsupported("requires an implemented class-metadata mutation");
        }
        match (width, index) {
            (DataWidth::Word, GCW_STYLE) => u32::from(info.style),
            (DataWidth::Word, GCW_CBCLSEXTRA) => u32::from(info.cb_cls_extra as u16),
            (DataWidth::Word, GCW_CBWNDEXTRA) => u32::from(info.cb_wnd_extra as u16),
            (DataWidth::Word, GCW_ATOM) => u32::from(atom),
            (DataWidth::Word, GCW_HBRBACKGROUND) => u32::from(info.hbr_background),
            (DataWidth::Word, GCW_HCURSOR) => u32::from(info.h_cursor),
            (DataWidth::Word, GCW_HICON) => u32::from(info.h_icon),
            // The window's own saved/subclassed procedure may differ. This is
            // the class procedure copied at RegisterClass, always a guest FAR.
            (DataWidth::Long, GCL_WNDPROC) => info.lpfn_wnd_proc,
            // HMODULE's owner/instance semantics, MENUNAME pointer lifetime,
            // and cross-width reads need separate Win16 contracts.
            _ => unsupported("has no supported guest class field at this width"),
        }
    }
}

fn report_unsupported(
    host: &mut impl RuntimeHost,
    window: u16,
    index: i16,
    width: DataWidth,
    writing: bool,
    reason: &str,
) {
    let api = width.api(writing);
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
        "Win16 {api} index {index} for guest HWND 0x{window:04X} {reason}; returned zero",
    )));
}

#[cfg(test)]
#[path = "win16_class_data_tests.rs"]
mod tests;
