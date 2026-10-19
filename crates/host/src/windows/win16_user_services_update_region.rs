//! Native USER update-region calls owned by the window worker.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use runtime::{
    RuntimeError, Win16HostGdiObject, Win16HostRect, Win16HostUpdateOperation as Operation,
    Win16HostUpdateResult as ResultValue, Win16HostWindow,
};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    GetUpdateRect, GetUpdateRgn, HRGN, InvalidateRect, InvalidateRgn, LockWindowUpdate,
    RedrawWindow, ValidateRect, ValidateRgn,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{ScrollWindow, ScrollWindowEx};

use super::super::win16_gdi_objects::Win16RegionLease;
use super::win16_window_worker::WorkerState;

#[path = "win16_user_services_scroll_dc.rs"]
mod scroll_dc;

enum WindowTarget {
    Resolved(HWND),
    Stale,
}

/// Resolve a token through the shared cookie-aware identity table so a recycled
/// HWND cannot redirect this USER operation to a replacement native window.
fn window_target(
    state: &Rc<RefCell<WorkerState>>,
    window: Option<Win16HostWindow>,
) -> WindowTarget {
    let Some(window) = window else {
        // Preserve the native API's NULL argument; never substitute a desktop HWND.
        return WindowTarget::Resolved(std::ptr::null_mut());
    };
    match super::win16_window_identity::resolve_user_window(state, window) {
        Some(hwnd) => WindowTarget::Resolved(hwnd),
        None => WindowTarget::Stale,
    }
}

fn native_rect(rect: Win16HostRect) -> RECT {
    RECT {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn host_rect(rect: RECT) -> Win16HostRect {
    Win16HostRect {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn native_region(
    regions: &BTreeMap<Win16HostGdiObject, Option<Win16RegionLease>>,
    token: Win16HostGdiObject,
) -> Option<HRGN> {
    // A deleted/tombstoned non-NULL identity is failure. Only the operation's
    // explicit `None` branch below is allowed to become native NULL.
    regions
        .get(&token)?
        .as_ref()
        .map(Win16RegionLease::native)
        .filter(|region| !region.is_null())
}

fn failure_result(operation: &Operation) -> ResultValue {
    match operation {
        Operation::UpdateWindow { .. }
        | Operation::InvalidateRect { .. }
        | Operation::InvalidateRgn { .. }
        | Operation::ValidateRect { .. }
        | Operation::ValidateRgn { .. }
        | Operation::ScrollWindow { .. } => ResultValue::Void { succeeded: false },
        Operation::GetUpdateRect { .. } => ResultValue::Rect {
            value: 0,
            rect: None,
        },
        Operation::GetUpdateRgn { .. }
        | Operation::ExcludeUpdateRgn { .. }
        | Operation::RedrawWindow { .. }
        | Operation::LockWindowUpdate { .. } => ResultValue::Word(0),
        Operation::ScrollWindowEx { .. } | Operation::ScrollDC { .. } => ResultValue::Rect {
            value: 0,
            rect: None,
        },
    }
}

/// Execute a pointer-free Win16 USER operation on the HWND-owning worker.
/// Region leases stay in the caller's owned operation frame through native
/// reentrancy; a missing non-null token is ordinary API failure, never NULL.
pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation: Operation,
    regions: &BTreeMap<Win16HostGdiObject, Option<Win16RegionLease>>,
) -> Result<ResultValue, RuntimeError> {
    match &operation {
        Operation::UpdateWindow { window } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            // SAFETY: `hwnd` is the copied worker-owned HWND (or NULL, preserved
            // from the guest API); no Rust borrow is held across WM_PAINT delivery.
            let succeeded = (crate::windows::win32_safe::update_window(hwnd)) != 0;
            Ok(ResultValue::Void { succeeded })
        }
        Operation::InvalidateRect {
            window,
            rect,
            erase,
        } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let rect = (*rect).map(native_rect);
            let rect_ptr = rect
                .as_ref()
                .map_or(std::ptr::null(), |rect| rect as *const RECT);
            // SAFETY: `rect_ptr` is NULL for guest NULL or points to this call's
            // owned RECT; `hwnd` is copied and no worker-state borrow is held.
            let succeeded = unsafe { InvalidateRect(hwnd, rect_ptr, *erase as i32) } != 0;
            Ok(ResultValue::Void { succeeded })
        }
        Operation::InvalidateRgn {
            window,
            region,
            erase,
        } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let region = match region {
                Some(token) => match native_region(regions, *token) {
                    Some(region) => region,
                    None => return Ok(failure_result(&operation)),
                },
                None => std::ptr::null_mut(),
            };
            // SAFETY: non-NULL regions come from a live operation-scoped lease;
            // NULL is passed only for a guest NULL region argument.
            let succeeded = unsafe { InvalidateRgn(hwnd, region, *erase as i32) } != 0;
            Ok(ResultValue::Void { succeeded })
        }
        Operation::ValidateRect { window, rect } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let rect = (*rect).map(native_rect);
            let rect_ptr = rect
                .as_ref()
                .map_or(std::ptr::null(), |rect| rect as *const RECT);
            // SAFETY: `rect_ptr` is NULL or references the owned local RECT;
            // `hwnd` is copied and the worker-state borrow has ended.
            let succeeded = unsafe { ValidateRect(hwnd, rect_ptr) } != 0;
            Ok(ResultValue::Void { succeeded })
        }
        Operation::ValidateRgn { window, region } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let region = match region {
                Some(token) => match native_region(regions, *token) {
                    Some(region) => region,
                    None => return Ok(failure_result(&operation)),
                },
                None => std::ptr::null_mut(),
            };
            // SAFETY: a non-NULL region is operation-leased; NULL retains the
            // Win16 API's NULL-region meaning. Erase/child drawing may reenter,
            // and no worker-state borrow or guest pointer crosses this call.
            let succeeded = unsafe { ValidateRgn(hwnd, region) } != 0;
            Ok(ResultValue::Void { succeeded })
        }
        Operation::GetUpdateRect {
            window,
            rect_is_null,
            erase,
        } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let mut rect = RECT::default();
            let rect_ptr = if *rect_is_null {
                std::ptr::null_mut()
            } else {
                &mut rect
            };
            let has_native_window = !hwnd.is_null();
            // SAFETY: output storage is a live local RECT or NULL as requested;
            // any erase-triggered WM_ERASEBKGND reenters with no RefCell borrow held.
            let value = unsafe { GetUpdateRect(hwnd, rect_ptr, *erase as i32) };
            Ok(ResultValue::Rect {
                value: (value != 0) as u16,
                // The SDK guarantees the empty zero RECT for a valid window
                // with no update region. It does not specify writes for NULL
                // HWND plus FALSE, so do not copy back initialized scratch.
                rect: (!*rect_is_null && (has_native_window || value != 0))
                    .then(|| host_rect(rect)),
            })
        }
        Operation::GetUpdateRgn {
            window,
            region,
            erase,
        } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let Some(region) = native_region(regions, *region) else {
                return Ok(failure_result(&operation));
            };
            // SAFETY: `region` is protected by its operation-scoped lease and
            // `hwnd` is copied; the native API mutates only that retained HRGN.
            let value = unsafe { GetUpdateRgn(hwnd, region, *erase as i32) };
            Ok(ResultValue::Word(value as u16))
        }
        Operation::ExcludeUpdateRgn { dc, window } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let dcs = { state.borrow().dcs.clone() };
            Ok(ResultValue::Word(
                dcs.exclude_update_region(*dc, hwnd)?.unwrap_or(0),
            ))
        }
        Operation::RedrawWindow {
            window,
            rect,
            region,
            flags,
        } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let rect = (*rect).map(native_rect);
            let rect_ptr = rect
                .as_ref()
                .map_or(std::ptr::null(), |rect| rect as *const RECT);
            let region = match region {
                Some(token) => match native_region(regions, *token) {
                    Some(region) => region,
                    None => return Ok(failure_result(&operation)),
                },
                None => std::ptr::null_mut(),
            };
            // SAFETY: optional arguments are NULL only when the guest supplied
            // NULL; otherwise rect is owned locally and HRGN is operation-leased.
            // RDW_UPDATENOW/RDW_ERASENOW may synchronously reenter guest code;
            // no worker-state borrow is held across the native call.
            let succeeded = unsafe { RedrawWindow(hwnd, rect_ptr, region, u32::from(*flags)) } != 0;
            Ok(ResultValue::Word(succeeded as u16))
        }
        Operation::LockWindowUpdate { window } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            // SAFETY: `hwnd` is the copied worker HWND or the native NULL value.
            let succeeded = unsafe { LockWindowUpdate(hwnd) } != 0;
            Ok(ResultValue::Word(succeeded as u16))
        }
        Operation::ScrollWindow {
            window,
            dx,
            dy,
            scroll_rect,
            clip_rect,
        } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let scroll_rect = (*scroll_rect).map(native_rect);
            let clip_rect = (*clip_rect).map(native_rect);
            let scroll_ptr = scroll_rect
                .as_ref()
                .map_or(std::ptr::null(), |rect| rect as *const RECT);
            let clip_ptr = clip_rect
                .as_ref()
                .map_or(std::ptr::null(), |rect| rect as *const RECT);
            // SAFETY: optional pointers reference owned local RECT values or are
            // NULL by guest choice; no worker-state borrow crosses native USER.
            let succeeded =
                unsafe { ScrollWindow(hwnd, i32::from(*dx), i32::from(*dy), scroll_ptr, clip_ptr) }
                    != 0;
            Ok(ResultValue::Void { succeeded })
        }
        Operation::ScrollDC { .. } => {
            let dcs = { state.borrow().dcs.clone() };
            scroll_dc::execute(&dcs, &operation, regions)
        }
        Operation::ScrollWindowEx {
            window,
            dx,
            dy,
            scroll_rect,
            clip_rect,
            update_region,
            update_rect_is_null,
            flags,
        } => {
            let WindowTarget::Resolved(hwnd) = window_target(state, *window) else {
                return Ok(failure_result(&operation));
            };
            let scroll_rect = (*scroll_rect).map(native_rect);
            let clip_rect = (*clip_rect).map(native_rect);
            let scroll_ptr = scroll_rect
                .as_ref()
                .map_or(std::ptr::null(), |rect| rect as *const RECT);
            let clip_ptr = clip_rect
                .as_ref()
                .map_or(std::ptr::null(), |rect| rect as *const RECT);
            let region = match update_region {
                Some(token) => match native_region(regions, *token) {
                    Some(region) => region,
                    None => return Ok(failure_result(&operation)),
                },
                None => std::ptr::null_mut(),
            };
            let mut update_rect = RECT::default();
            let update_ptr = if *update_rect_is_null {
                std::ptr::null_mut()
            } else {
                &mut update_rect
            };
            // SAFETY: input RECTs are owned locals or NULL, output RECT is a
            // writable local or NULL, HRGN is leased, and no worker borrow is held.
            // SW_SCROLLCHILDREN and SW_ERASE|SW_INVALIDATE may synchronously
            // dispatch child or erase callbacks. The Win16 manual leaves output
            // state on ERROR unspecified, so failed scratch output is not returned.
            let native_value = unsafe {
                ScrollWindowEx(
                    hwnd,
                    i32::from(*dx),
                    i32::from(*dy),
                    scroll_ptr,
                    clip_ptr,
                    region,
                    update_ptr,
                    u32::from(*flags),
                )
            };
            let value = native_value as u16;
            Ok(ResultValue::Rect {
                value,
                rect: (!*update_rect_is_null && native_value != 0).then(|| host_rect(update_rect)),
            })
        }
    }
}
