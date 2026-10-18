//! Win16 OEM bitmap names interpreted independently of the host EXE version.

use windows_sys::Win32::UI::WindowsAndMessaging::{
    OBM_CLOSE, OBM_DNARROW, OBM_LFARROW, OBM_OLD_CLOSE, OBM_OLD_DNARROW, OBM_OLD_LFARROW,
    OBM_OLD_REDUCE, OBM_OLD_RESTORE, OBM_OLD_RGARROW, OBM_OLD_UPARROW, OBM_OLD_ZOOM, OBM_REDUCE,
    OBM_RESTORE, OBM_RGARROW, OBM_UPARROW, OBM_ZOOM,
};

pub(super) fn native_resource_id(resource_id: u16) -> u16 {
    // USER's LoadBmp maps these pairs to the same OBI glyph. The OLD names
    // are rejected for a host EXE expecting Windows 4.0+, even when the Win16
    // caller expects 3.1. Resolve that namespace here without changing the
    // host process version or replacing a failed GDI allocation with success.
    // Reference: NT USER/CLIENT/CLRES.C, MapOemBmp and MR_FAILFOR40; OLD_CLOSE
    // falls through to CLOSE in the same routine.
    let native = match u32::from(resource_id) {
        OBM_OLD_CLOSE => OBM_CLOSE,
        OBM_OLD_DNARROW => OBM_DNARROW,
        OBM_OLD_LFARROW => OBM_LFARROW,
        OBM_OLD_REDUCE => OBM_REDUCE,
        OBM_OLD_RESTORE => OBM_RESTORE,
        OBM_OLD_RGARROW => OBM_RGARROW,
        OBM_OLD_UPARROW => OBM_UPARROW,
        OBM_OLD_ZOOM => OBM_ZOOM,
        value => value,
    };
    native as u16
}

#[cfg(test)]
#[path = "win16_gdi_oem_bitmap_tests.rs"]
mod tests;
