//! Native ScrollDC with an HDC lease and independent update-region storage.

use super::{Operation, ResultValue, RuntimeError, Win16HostGdiObject, Win16RegionLease,
    failure_result, host_rect, native_rect, native_region};
use crate::windows::win16_gdi::Win16Dcs;
use std::collections::BTreeMap;
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::UI::WindowsAndMessaging::ScrollDC;

pub(super) fn execute(
    dcs: &Win16Dcs,
    operation: &Operation,
    regions: &BTreeMap<Win16HostGdiObject, Option<Win16RegionLease>>,
) -> Result<ResultValue, RuntimeError> {
    let Operation::ScrollDC { dc, dx, dy, scroll_rect, clip_rect,
        update_region, update_rect_is_null } = operation else {
        return Err(RuntimeError::new(runtime::DiagnosticKind::InternalInvariant,
            "ScrollDC adapter received a different USER operation"));
    };
    let Some(dc) = dcs.lease_dc(*dc)? else {
        return Ok(failure_result(operation));
    };
    let scroll_rect = (*scroll_rect).map(native_rect);
    let clip_rect = (*clip_rect).map(native_rect);
    let scroll_ptr = scroll_rect.as_ref().map_or(std::ptr::null(), |rect| rect as *const RECT);
    let clip_ptr = clip_rect.as_ref().map_or(std::ptr::null(), |rect| rect as *const RECT);
    let region = match update_region {
        Some(token) => match native_region(regions, *token) {
            Some(region) => region,
            None => return Ok(failure_result(operation)),
        },
        None => std::ptr::null_mut(),
    };
    let mut update_rect = RECT::default();
    let update_ptr = if *update_rect_is_null {
        std::ptr::null_mut()
    } else {
        &mut update_rect
    };
    // Preserve the DC's existing mapping. ScrollDC takes device-unit
    // deltas and logical input rectangles; native USER supplies client
    // coordinates for its output. Do not map or offset them again.
    // SAFETY: input/output RECTs are owned locals or guest-requested
    // NULL; the independent region snapshot and HDC lease stay alive
    // through the call, with no shared table lock or worker borrow held.
    let native_value = unsafe {
        ScrollDC(
            dc.native(), i32::from(*dx), i32::from(*dy), scroll_ptr, clip_ptr,
            region, update_ptr,
        )
    };
    // Neither SDK defines failure output. Do not publish initialized
    // scratch; the zero result also suppresses region snapshot commit.
    let value = (native_value != 0) as u16;
    Ok(ResultValue::Rect {
        value,
        rect: (!*update_rect_is_null && native_value != 0)
            .then(|| host_rect(update_rect)),
    })
}

#[cfg(test)]
#[path = "win16_scroll_dc_native_tests.rs"]
mod scroll_dc_tests;
