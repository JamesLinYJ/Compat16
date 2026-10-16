//! Window-thread implementations of USER paint and borrowed-DC operations.
//!
//! The shared window worker owns HWNDs and its Win16Dcs clone. These helpers
//! never keep a worker-state borrow across a native call: BeginPaint, GetDC,
//! EndPaint, and ReleaseDC can synchronously reenter USER callbacks.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DrawingRect, Win16HostDc,
    Win16HostPaintInfo, Win16HostRect, Win16HostWindow,
};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, GetDC, GetWindowDC, ReleaseDC, PAINTSTRUCT,
};

use super::super::win16_gdi::{Win16Dcs, Win16NativePaintInfo, WindowDcLease};
use super::win16_window_worker::WorkerState;

fn window_context(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
) -> Option<(Win16Dcs, HWND)> {
    let hwnd = super::win16_window_identity::resolve_user_window(state, window)?;
    let dcs = { state.borrow().dcs.clone() };
    Some((dcs, hwnd))
}

fn native_paint_info(paint: &PAINTSTRUCT) -> Win16NativePaintInfo {
    Win16NativePaintInfo {
        erase: paint.fErase,
        rect: Win16DrawingRect {
            left: paint.rcPaint.left,
            top: paint.rcPaint.top,
            right: paint.rcPaint.right,
            bottom: paint.rcPaint.bottom,
        },
        restore: paint.fRestore,
        inc_update: paint.fIncUpdate,
        reserved: paint.rgbReserved,
    }
}

fn host_paint_info(paint: Win16NativePaintInfo) -> Win16HostPaintInfo {
    let mut reserved = [0_u8; 16];
    reserved.copy_from_slice(&paint.reserved[..16]);
    Win16HostPaintInfo {
        erase: paint.erase != 0,
        rect: Win16HostRect {
            left: paint.rect.left,
            top: paint.rect.top,
            right: paint.rect.right,
            bottom: paint.rect.bottom,
        },
        restore: paint.restore != 0,
        inc_update: paint.inc_update != 0,
        reserved,
    }
}

/// Run BeginPaint on the HWND-owning worker and save its native session data
/// beside the shared opaque HDC identity.
pub(super) fn begin_paint(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
) -> Result<Option<(Win16HostDc, Win16HostPaintInfo)>, RuntimeError> {
    let Some((dcs, hwnd)) = window_context(state, window) else { return Ok(None); };
    let mut paint = PAINTSTRUCT::default();
    // SAFETY: `hwnd` is a live native window from this worker's HWND map and
    // `paint` is writable for the duration of the synchronous native call.
    let hdc = unsafe { BeginPaint(hwnd, &mut paint) };
    if hdc.is_null() { return Ok(None); }
    // BeginPaint can synchronously enter the guest, which may destroy this
    // HWND. Do not publish its borrowed HDC under a retired owner, or issue
    // EndPaint against a different window that reused the same HWND bits.
    if super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd) {
        return Ok(None);
    }

    let saved = native_paint_info(&paint);
    let token = match dcs.adopt_paint_dc(window, hdc as usize, saved) {
        Ok(Some(token)) => token,
        Ok(None) => {
            // SAFETY: This is the exact PAINTSTRUCT produced by BeginPaint,
            // and cleanup runs immediately on the same owning worker thread.
            unsafe { EndPaint(hwnd, &paint); }
            return Ok(None);
        }
        Err(error) => {
            // SAFETY: This is the exact PAINTSTRUCT produced by BeginPaint,
            // and cleanup runs immediately on the same owning worker thread.
            unsafe { EndPaint(hwnd, &paint); }
            return Err(error);
        }
    };
    Ok(Some((token, host_paint_info(saved))))
}

/// End a BeginPaint session through the shared HDC table. The visible fields
/// and first 16 reserved bytes come from the guest PAINTSTRUCT; the native
/// reserved tail remains from the original BeginPaint session.
pub(super) fn end_paint(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    dc: Win16HostDc,
    info: Win16HostPaintInfo,
) -> Result<bool, RuntimeError> {
    let Some((dcs, hwnd)) = window_context(state, window) else { return Ok(false); };
    let Some(hdc) = dcs.window_dc_native(dc, window, WindowDcLease::Paint) else {
        return Ok(false);
    };
    let Some(mut paint) = dcs.native_paint_info(dc, window) else {
        dcs.cancel_window_dc_release(dc, window, WindowDcLease::Paint);
        return Ok(false);
    };
    paint.erase = info.erase as i32;
    paint.rect = Win16DrawingRect {
        left: info.rect.left,
        top: info.rect.top,
        right: info.rect.right,
        bottom: info.rect.bottom,
    };
    paint.restore = info.restore as i32;
    paint.inc_update = info.inc_update as i32;
    paint.reserved[..16].copy_from_slice(&info.reserved);
    let native = PAINTSTRUCT {
        hdc,
        fErase: paint.erase,
        rcPaint: RECT {
            left: paint.rect.left,
            top: paint.rect.top,
            right: paint.rect.right,
            bottom: paint.rect.bottom,
        },
        fRestore: paint.restore,
        fIncUpdate: paint.inc_update,
        rgbReserved: paint.reserved,
    };
    // SAFETY: `hwnd` is the lease owner, `hdc` was validated for this exact
    // paint token, and `native` is a live native-format PAINTSTRUCT.
    if unsafe { EndPaint(hwnd, &native) } == 0 {
        dcs.cancel_window_dc_release(dc, window, WindowDcLease::Paint);
        return Ok(false);
    }
    if !dcs.forget_window_dc(dc, window, WindowDcLease::Paint) {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 EndPaint succeeded but its host DC token changed"));
    }
    Ok(true)
}

/// Acquire a client or whole-window DC on the owner thread. Screen DCs use
/// the existing non-window path and are handled outside this helper.
pub(super) fn acquire_window_dc(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    whole_window: bool,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    let Some((dcs, hwnd)) = window_context(state, window) else { return Ok(None); };
    // SAFETY: `hwnd` is a valid native window owned by this worker; these
    // APIs return a borrowed DC that is recorded in the shared table below.
    let hdc = unsafe {
        if whole_window { GetWindowDC(hwnd) } else { GetDC(hwnd) }
    };
    record_window_dc(state, window, whole_window, dcs, hwnd, hdc)
}

pub(super) fn acquire_window_dc_ex(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    region: Option<&super::super::win16_gdi_objects::Win16RegionLease>,
    flags: u32,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    let Some((dcs, hwnd)) = window_context(state, window) else { return Ok(None); };
    let hdc = super::super::win16_get_dc_ex::acquire_native(hwnd, region, flags);
    record_window_dc(state, window, flags & 1 != 0, dcs, hwnd, hdc)
}

fn record_window_dc(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    whole_window: bool,
    dcs: Win16Dcs,
    hwnd: HWND,
    hdc: windows_sys::Win32::Graphics::Gdi::HDC,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    if hdc.is_null() { return Ok(None); }
    // A synchronous callback may retire or replace the owner. USER owns this
    // borrowed DC; cleanup against recycled HWND bits would affect a different
    // window, so only a still-matching owner permits registration or release.
    if super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd) {
        return Ok(None);
    }
    match dcs.adopt_window_dc(window, whole_window, hdc as usize) {
        Ok(Some(token)) => Ok(Some(token)),
        Ok(None) => {
            // SAFETY: `hdc` was just acquired for this exact HWND and the
            // release remains on the window-owning worker thread.
            unsafe { ReleaseDC(hwnd, hdc); }
            Ok(None)
        }
        Err(error) => {
            // SAFETY: `hdc` was just acquired for this exact HWND and the
            // release remains on the window-owning worker thread.
            unsafe { ReleaseDC(hwnd, hdc); }
            Err(error)
        }
    }
}

/// Release a client or whole-window DC only after validating its owner and
/// lease kind in the common host HDC table.
pub(super) fn release_window_dc(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    dc: Win16HostDc,
) -> Result<bool, RuntimeError> {
    let Some((dcs, hwnd)) = window_context(state, window) else { return Ok(false); };
    for lease in [WindowDcLease::Client, WindowDcLease::WholeWindow] {
        let Some(hdc) = dcs.window_dc_native(dc, window, lease) else { continue; };
        // SAFETY: The common HDC table verified this borrowed lease belongs
        // to `window`; both acquisition and release use this worker thread.
        if unsafe { ReleaseDC(hwnd, hdc) } == 0 {
            dcs.cancel_window_dc_release(dc, window, lease);
            return Ok(false);
        }
        if !dcs.forget_window_dc(dc, window, lease) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 ReleaseDC succeeded but its host DC token changed"));
        }
        return Ok(true);
    }
    Ok(false)
}
