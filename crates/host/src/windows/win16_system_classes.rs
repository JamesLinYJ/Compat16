//! Predefined USER class templates. Native storage stays separate from guest.

use windows_sys::Win32::UI::WindowsAndMessaging::{GetClassInfoExW, WNDCLASSEXW};
use runtime::{RuntimeError, Win16HostSystemClass, Win16HostProcedure};
use std::cell::RefCell;
use std::rc::Rc;
use super::win16_window_worker::WorkerState;

pub(super) const CLASSES: [Win16HostSystemClass; 6] = [
    Win16HostSystemClass::Button, Win16HostSystemClass::Edit, Win16HostSystemClass::Static,
    Win16HostSystemClass::ListBox, Win16HostSystemClass::ComboBox, Win16HostSystemClass::ScrollBar,
];

pub(super) fn name(class: Win16HostSystemClass) -> &'static [u8] {
    match class {
        Win16HostSystemClass::Button => b"BUTTON\0",
        Win16HostSystemClass::Edit => b"EDIT\0",
        Win16HostSystemClass::Static => b"STATIC\0",
        Win16HostSystemClass::ListBox => b"LISTBOX\0",
        Win16HostSystemClass::ComboBox => b"COMBOBOX\0",
        Win16HostSystemClass::ScrollBar => b"SCROLLBAR\0",
        Win16HostSystemClass::MdiClient => b"MDICLIENT\0",
    }
}

/// Host-private values crossing only the USER worker/client boundary. The
/// client adopts borrowed resources before constructing runtime's DTO.
pub(super) struct NativeSystemClassInfo {
    pub style: u16, pub class_extra: i16, pub window_extra: i16,
    pub procedure: Win16HostProcedure,
    pub icon: usize, pub cursor: usize, pub background: usize,
}

pub(super) fn native_template(class: Win16HostSystemClass) -> Option<WNDCLASSEXW> {
    let name = name(class);
    let wide = name.iter().map(|byte| u16::from(*byte)).collect::<Vec<_>>();
    let mut unicode = WNDCLASSEXW { cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        ..WNDCLASSEXW::default() };
    // SAFETY: The class name is terminated owned UTF-16 data. USER writes the
    // complete Unicode structure; NULL instance selects a system class.
    if unsafe { GetClassInfoExW(std::ptr::null_mut(), wide.as_ptr(), &mut unicode) } == 0 {
        return None;
    }
    Some(unicode)
}

/// Reserve enough native storage for any supported superclass. RegisterClass
/// has no superclass parameter: guest code may save a class proc separately
/// and invoke it only during NCCREATE. Reserving capacity does not guess that
/// procedure's family or copy any native state into guest extra bytes.
pub(super) fn native_reserves() -> Option<(i32, i32)> {
    let mut class_extra = 0;
    // Dialog state is likewise host-only.
    let mut window_extra = windows_sys::Win32::UI::WindowsAndMessaging::DLGWINDOWEXTRA as i32;
    for class in CLASSES {
        let native = native_template(class)?;
        if native.cbClsExtra < 0 || native.cbWndExtra < 0 { return None; }
        class_extra = class_extra.max(native.cbClsExtra);
        window_extra = window_extra.max(native.cbWndExtra);
    }
    Some((class_extra, window_extra))
}

pub(super) fn query(
    state: &Rc<RefCell<WorkerState>>, kind: Win16HostSystemClass,
) -> Result<Option<NativeSystemClassInfo>, RuntimeError> {
    let Some(unicode) = native_template(kind) else { return Ok(None); };
    let (Ok(class_extra), Ok(mut window_extra)) = (
        i16::try_from(unicode.cbClsExtra), i16::try_from(unicode.cbWndExtra),
    ) else { return Ok(None); };
    if class_extra < 0 || window_extra < 0 { return Ok(None); }
    // Guest sidecars reserve actual bytes. These capacities are a compatibility
    // policy, not a claim that modern native private layouts match Win3.1.
    // The documented EDIT exception is fixed: Win3.1 reserved six bytes (XP
    // wow32/wuwind.c, Get/SetWindowWord), with a different native handle width.
    if kind == Win16HostSystemClass::Edit { window_extra = 6; }
    let Some(procedure) = super::win16_native_procedures::capture_system_class(
        state, kind, &unicode,
    )? else { return Ok(None); };
    Ok(Some(NativeSystemClassInfo {
        style: unicode.style as u16, class_extra, window_extra, procedure,
        icon: unicode.hIcon as usize, cursor: unicode.hCursor as usize,
        background: unicode.hbrBackground as usize,
    }))
}
