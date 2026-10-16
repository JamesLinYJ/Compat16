//! Guest class WORD/LONG access for USER.129–132.
//!
//! The SDK describes GCW_* fields under the WORD accessors and GCL_WNDPROC /
//! GCL_MENUNAME under the LONG accessors. A shared constants table does not
//! establish zero-extension or truncation for other width/index combinations.
//! Those combinations remain explicit gaps: the Win16 USER GetWC2 / SetWC2
//! routines can observe or overwrite adjacent fields, which needs its own
//! checked representation and resource translation rather than discarding bits.
//!
//! Microsoft Windows 3.1 SDK Guide to Programming, section 16.2.4, defines
//! cbClsExtra as byte storage shared by the windows of a registered class.
//! Only guest registrations own that layout here; native class storage and
//! native pointer-sized metadata never enter these accessors.

use guest_core::memory::Memory;
use win16_abi::{Win16ClassDataRequest, exports::class_data::{
    GCL_MENUNAME, GCL_WNDPROC, GCW_ATOM, GCW_CBCLSEXTRA, GCW_CBWNDEXTRA, GCW_HBRBACKGROUND,
    GCW_HCURSOR, GCW_HICON, GCW_HMODULE, GCW_STYLE,
}};

use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

#[derive(Clone, Copy, Eq, PartialEq)]
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

/// One SDK class field, including the width of its documented accessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClassField {
    Style,
    WndProc,
    CbClsExtra,
    CbWndExtra,
    HModule,
    HIcon,
    HCursor,
    HbrBackground,
    MenuName,
    Atom,
}

impl ClassField {
    fn for_index(index: i16) -> Option<Self> {
        Some(match index {
            GCL_MENUNAME => Self::MenuName,
            GCW_HBRBACKGROUND => Self::HbrBackground,
            GCW_HCURSOR => Self::HCursor,
            GCW_HICON => Self::HIcon,
            GCW_HMODULE => Self::HModule,
            GCW_CBWNDEXTRA => Self::CbWndExtra,
            GCW_CBCLSEXTRA => Self::CbClsExtra,
            GCL_WNDPROC => Self::WndProc,
            GCW_STYLE => Self::Style,
            GCW_ATOM => Self::Atom,
            _ => return None,
        })
    }

    /// The shared constants table alone does not define cross-width access.
    fn declared_width(self) -> DataWidth {
        match self {
            Self::WndProc | Self::MenuName => DataWidth::Long,
            _ => DataWidth::Word,
        }
    }
}

impl Win16State {
    pub(super) fn access_class_data(
        &mut self,
        request: Win16ClassDataRequest,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
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
        if window == 0 || !self.window_handles.contains_key(&window) { return Ok(0); }

        let writing = replacement.is_some();
        let mut unsupported = |reason| {
            report_unsupported(host, window, index, width, writing, reason);
            0
        };
        let Some(class) = self.window_host_class(window) else {
            return Ok(unsupported("has no exact guest class identity"));
        };

        if index >= 0 {
            let Some(bytes) = self.window_classes.guest_class_extra_mut(class) else {
                return Ok(unsupported("has no guest-owned class extra-data contract"));
            };
            let offset = index as usize;
            let Some(end) = offset.checked_add(width.bytes()) else { return Ok(0); };
            let Some(slot) = bytes.get_mut(offset..end) else { return Ok(0); };
            // Unaligned offsets and overlapping WORD/LONG accesses are byte
            // operations. Validate the entire span before changing any byte.
            let mut old = [0_u8; 4];
            old[..width.bytes()].copy_from_slice(slot);
            if let Some(value) = replacement {
                slot.copy_from_slice(&value.to_le_bytes()[..width.bytes()]);
            }
            return Ok(u32::from_le_bytes(old));
        }

        let Some((atom, info, instance)) = self.window_classes.guest_class_info(class) else {
            // Predefined aliases may have native metadata and procedure gates,
            // but their private fields are not a registered Win16 class layout.
            return Ok(unsupported("has no guest registration metadata contract"));
        };
        let Some(field) = ClassField::for_index(index) else {
            return Ok(unsupported("has no supported guest class field"));
        };
        if field.declared_width() != width {
            return Ok(unsupported("has no supported guest class field at this width"));
        }
        let module = if field == ClassField::HModule {
            let Some(module) = self.module_handle_for_instance(instance) else {
                return Ok(unsupported("has no live owning module"));
            };
            module
        } else { 0 };
        let Some(value) = replacement else {
            return Ok(read_class_field(atom, &info, module, field));
        };
        if field == ClassField::HModule {
            // NT 3.5 `PRIVATE/MVDM/WOW16/USER/WINMISC1.ASM` special-cases this
            // index in SetClassWord (Bug #5138, Designer 2.0) and returns the
            // current module handle without replacing it. Cross-width LONG
            // access was rejected above; it does not have this WORD guard.
            return Ok(u32::from(module));
        }
        match field {
            ClassField::HIcon => self.set_class_icon(window, class, value, host),
            ClassField::HCursor => self.set_class_cursor(window, class, value, host),
            ClassField::HbrBackground => self.set_class_background(window, class, value, host),
            ClassField::WndProc =>
                self.set_class_window_procedure(window, class, value, memory),
            ClassField::MenuName => self.set_class_menu_name(class, value, memory),
            // Allocation sizes, class style and the registration atom still
            // need their own mutation contracts and native synchronization.
            _ => {
                report_class_field_gap(host, window, field);
                Ok(0)
            }
        }
    }
}

fn read_class_field(
    atom: u16,
    info: &win16_abi::WndClass16,
    module: u16,
    field: ClassField,
) -> u32 {
    match field {
        // These values become WORD returns at the checked accessor boundary.
        ClassField::Style => u32::from(info.style),
        ClassField::CbClsExtra => u32::from(info.cb_cls_extra as u16),
        ClassField::CbWndExtra => u32::from(info.cb_wnd_extra as u16),
        ClassField::HModule => u32::from(module),
        ClassField::HIcon => u32::from(info.h_icon),
        ClassField::HCursor => u32::from(info.h_cursor),
        ClassField::HbrBackground => u32::from(info.hbr_background),
        ClassField::Atom => u32::from(atom),
        // The window's own saved/subclassed procedure may differ. This is the
        // current registered class procedure, always a guest FAR.
        ClassField::WndProc => info.lpfn_wnd_proc,
        ClassField::MenuName => info.lpsz_menu_name,
    }
}

/// Report a class field whose replacement the runtime does not implement. The
/// index is re-derived from the field so the message names the exact
/// `WINDOWS.H` constant the caller used.
fn report_class_field_gap(host: &mut impl RuntimeHost, window: u16, field: ClassField) {
    let index = match field {
        ClassField::Style => GCW_STYLE,
        ClassField::WndProc => GCL_WNDPROC,
        ClassField::CbClsExtra => GCW_CBCLSEXTRA,
        ClassField::CbWndExtra => GCW_CBWNDEXTRA,
        ClassField::HModule => GCW_HMODULE,
        ClassField::HIcon => GCW_HICON,
        ClassField::HCursor => GCW_HCURSOR,
        ClassField::HbrBackground => GCW_HBRBACKGROUND,
        ClassField::MenuName => GCL_MENUNAME,
        ClassField::Atom => GCW_ATOM,
    };
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, format!(
        "Win16 SetClassWord/SetClassLong index {index} for guest HWND 0x{window:04X} \
         requires an implemented class-metadata mutation; returned zero",
    )));
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
