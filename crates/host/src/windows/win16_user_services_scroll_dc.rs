//! Native ScrollDC with an HDC lease and independent update-region storage.
//!
//! A null scroll or clip rectangle selects the whole client area. Scroll
//! distances are signed 16-bit device units, and the update rectangle is
//! returned in client coordinates. Windows 3.1 stores those edges in a
//! `RECT` of signed ints. An edge that does not fit fails the call: the
//! device bits are copied back and the region snapshot is not committed.

use super::{
    Operation, ResultValue, RuntimeError, Win16HostGdiObject, Win16RegionLease, failure_result,
    host_rect, native_rect, native_region,
};
use crate::windows::win16_gdi::Win16Dcs;
use std::collections::BTreeMap;
use windows_sys::Win32::Foundation::{POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BITMAP, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, GetClipBox, GetCurrentObject,
    GetObjectW, GetRgnBox, HDC, HGDIOBJ, HRGN, LPtoDP, MM_TEXT, NULLREGION, OBJ_BITMAP, RGN_ERROR,
    RestoreDC, SRCCOPY, SaveDC, SelectObject, SetMapMode, SetViewportOrgEx, SetWindowOrgEx,
};
use windows_sys::Win32::UI::WindowsAndMessaging::ScrollDC;

pub(super) fn execute(
    dcs: &Win16Dcs,
    operation: &Operation,
    regions: &BTreeMap<Win16HostGdiObject, Option<Win16RegionLease>>,
) -> Result<ResultValue, RuntimeError> {
    let Operation::ScrollDC {
        dc,
        dx,
        dy,
        scroll_rect,
        clip_rect,
        update_region,
        update_rect_is_null,
    } = operation
    else {
        return Err(RuntimeError::new(
            runtime::DiagnosticKind::InternalInvariant,
            "ScrollDC adapter received a different USER operation",
        ));
    };
    let Some(dc) = dcs.lease_dc(*dc)? else {
        return Ok(failure_result(operation));
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
    // A published update rectangle or region has to fit a Win16 RECT before
    // the scroll may stand. Capture the clip-box bits first so a later
    // rejection can put them back. Null outputs are not stored, so that
    // call keeps the native scroll.
    let record_output = !*update_rect_is_null || !region.is_null();
    let backup = if record_output {
        match capture_clip_bits(dc.native()) {
            Some(backup) => Some(backup),
            None => return Ok(failure_result(operation)),
        }
    } else {
        None
    };
    // Preserve the DC's existing mapping. ScrollDC takes device-unit
    // deltas and logical input rectangles; native USER supplies client
    // coordinates for its output. Do not map or offset them again.
    // SAFETY: input/output RECTs are owned locals or guest-requested
    // NULL; the independent region snapshot and HDC lease stay alive
    // through the call, with no shared table lock or worker borrow held.
    let native_value = unsafe {
        ScrollDC(
            dc.native(),
            i32::from(*dx),
            i32::from(*dy),
            scroll_ptr,
            clip_ptr,
            region,
            update_ptr,
        )
    };
    // Neither SDK defines failure output. Do not publish initialized
    // scratch; the zero result also suppresses region snapshot commit.
    if native_value == 0 {
        return Ok(failure_result(operation));
    }
    let published = (!*update_rect_is_null).then_some(update_rect);
    if !output_fits(published, region) {
        if let Some(backup) = &backup
            && !backup.restore()
        {
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::HostFailure,
                "ScrollDC could not restore device bits after an update rectangle outside the signed 16-bit range",
            ));
        }
        return Ok(failure_result(operation));
    }
    Ok(ResultValue::Rect {
        value: 1,
        rect: (!*update_rect_is_null).then(|| host_rect(update_rect)),
    })
}

fn signed_rect_fits(rect: RECT) -> bool {
    [rect.left, rect.top, rect.right, rect.bottom]
        .into_iter()
        .all(|edge| i16::try_from(edge).is_ok())
}

fn output_fits(update: Option<RECT>, region: HRGN) -> bool {
    update.is_none_or(signed_rect_fits) && (region.is_null() || region_box_fits(region))
}

fn region_box_fits(region: HRGN) -> bool {
    let mut bounds = RECT::default();
    // SAFETY: `region` is the operation-leased snapshot and `bounds` is a
    // caller-owned RECT. No guest address is passed.
    let kind = unsafe { GetRgnBox(region, &mut bounds) };
    kind == NULLREGION || (kind != RGN_ERROR && signed_rect_fits(bounds))
}

struct DeviceArea {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

impl DeviceArea {
    fn empty() -> Self {
        Self {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.width <= 0 || self.height <= 0
    }
}

fn inflate_one(area: DeviceArea) -> DeviceArea {
    DeviceArea {
        x: area.x.saturating_sub(1),
        y: area.y.saturating_sub(1),
        width: area.width.saturating_add(2),
        height: area.height.saturating_add(2),
    }
}

fn device_area(corners: [POINT; 2]) -> Option<DeviceArea> {
    let left = corners[0].x.min(corners[1].x);
    let right = corners[0].x.max(corners[1].x);
    let top = corners[0].y.min(corners[1].y);
    let bottom = corners[0].y.max(corners[1].y);
    Some(DeviceArea {
        x: left,
        y: top,
        width: right.checked_sub(left)?,
        height: bottom.checked_sub(top)?,
    })
}

fn intersect_surface(area: DeviceArea, width: i32, height: i32) -> Option<DeviceArea> {
    if width <= 0 || height <= 0 {
        return None;
    }
    let right = area.x.checked_add(area.width)?;
    let bottom = area.y.checked_add(area.height)?;
    let left = area.x.max(0);
    let top = area.y.max(0);
    let right = right.min(width);
    let bottom = bottom.min(height);
    let width = right.checked_sub(left)?;
    let height = bottom.checked_sub(top)?;
    if width <= 0 || height <= 0 {
        return Some(DeviceArea::empty());
    }
    Some(DeviceArea {
        x: left,
        y: top,
        width,
        height,
    })
}

struct MappingGuard {
    dc: HDC,
    saved: i32,
}

impl MappingGuard {
    fn restore(mut self) -> bool {
        let saved = self.saved;
        self.saved = 0;
        if saved == 0 {
            return false;
        }
        // SAFETY: `saved` is the state identifier returned by SaveDC for this
        // leased HDC. RestoreDC writes only that DC's saved attributes.
        unsafe { RestoreDC(self.dc, saved) != 0 }
    }
}

impl Drop for MappingGuard {
    fn drop(&mut self) {
        if self.saved != 0 {
            // SAFETY: `saved` is the identifier from SaveDC on this HDC.
            unsafe { RestoreDC(self.dc, self.saved) };
            self.saved = 0;
        }
    }
}

fn with_device_space(dc: HDC, copy: impl FnOnce() -> bool) -> bool {
    // SAFETY: SaveDC records the leased DC and returns a state id. It does
    // not take a guest address.
    let saved = unsafe { SaveDC(dc) };
    if saved == 0 {
        return false;
    }
    let guard = MappingGuard { dc, saved };
    // SAFETY: MM_TEXT with zero window and viewport origins makes logical
    // points equal device pixels for the copy. The copy runs before the
    // guard restores the previous mapping, so ScrollDC sees the original DC.
    let mapped = unsafe {
        SetMapMode(dc, MM_TEXT) != 0
            && SetWindowOrgEx(dc, 0, 0, std::ptr::null_mut()) != 0
            && SetViewportOrgEx(dc, 0, 0, std::ptr::null_mut()) != 0
    };
    let copied = mapped && copy();
    guard.restore() && copied
}

struct PixelBackup {
    source: HDC,
    memory: HDC,
    bitmap: HGDIOBJ,
    previous: HGDIOBJ,
    area: DeviceArea,
}

impl PixelBackup {
    fn empty(source: HDC) -> Self {
        Self {
            source,
            memory: std::ptr::null_mut(),
            bitmap: std::ptr::null_mut(),
            previous: std::ptr::null_mut(),
            area: DeviceArea::empty(),
        }
    }

    fn save_from_source(&self) -> bool {
        copy_device_rect(self.source, self.memory, self.area, false)
    }

    fn restore(&self) -> bool {
        if self.area.is_empty() {
            return true;
        }
        copy_device_rect(self.source, self.memory, self.area, true)
    }
}

impl Drop for PixelBackup {
    fn drop(&mut self) {
        if self.memory.is_null() {
            return;
        }
        // SAFETY: The backup DC and bitmap were created for this call. The
        // previous object is reselected before either handle is deleted.
        unsafe {
            if !self.previous.is_null() && self.previous as usize != usize::MAX {
                SelectObject(self.memory, self.previous);
            }
            if !self.bitmap.is_null() {
                crate::windows::win32_safe::delete_object(self.bitmap);
            }
            crate::windows::win32_safe::delete_dc(self.memory);
        }
        self.memory = std::ptr::null_mut();
        self.bitmap = std::ptr::null_mut();
    }
}

fn copy_device_rect(window: HDC, memory: HDC, area: DeviceArea, to_window: bool) -> bool {
    if area.is_empty() {
        return true;
    }
    with_device_space(window, || {
        // SAFETY: Both HDCs are process-owned and live for this call. The
        // rectangle is a device-pixel area of the leased DC. SRCCOPY reads
        // those pixels and writes the backup, or the reverse on restore.
        unsafe {
            if to_window {
                BitBlt(
                    window,
                    area.x,
                    area.y,
                    area.width,
                    area.height,
                    memory,
                    0,
                    0,
                    SRCCOPY,
                ) != 0
            } else {
                BitBlt(
                    memory,
                    0,
                    0,
                    area.width,
                    area.height,
                    window,
                    area.x,
                    area.y,
                    SRCCOPY,
                ) != 0
            }
        }
    })
}

fn surface_size(dc: HDC) -> Option<(i32, i32)> {
    // SAFETY: GetCurrentObject queries the leased DC and returns the selected
    // bitmap handle. An invalid DC yields NULL.
    let selected = unsafe { GetCurrentObject(dc, OBJ_BITMAP as u32) };
    if selected.is_null() {
        return None;
    }
    let mut bitmap = BITMAP::default();
    let size = i32::try_from(std::mem::size_of::<BITMAP>()).ok()?;
    // SAFETY: GetObjectW writes into the caller-owned BITMAP of the byte
    // count passed with it. `selected` is the DC's current bitmap.
    let written = unsafe { GetObjectW(selected, size, std::ptr::from_mut(&mut bitmap).cast()) };
    (written == size && bitmap.bmWidth > 0 && bitmap.bmHeight > 0)
        .then_some((bitmap.bmWidth, bitmap.bmHeight))
}

fn capture_clip_bits(dc: HDC) -> Option<PixelBackup> {
    let mut logical = RECT::default();
    // SAFETY: GetClipBox writes a caller-owned RECT. The HDC lease is live.
    let kind = unsafe { GetClipBox(dc, &mut logical) };
    if kind == RGN_ERROR {
        return None;
    }
    if kind == NULLREGION {
        return Some(PixelBackup::empty(dc));
    }
    let mut corners = [
        POINT {
            x: logical.left,
            y: logical.top,
        },
        POINT {
            x: logical.right,
            y: logical.bottom,
        },
    ];
    // SAFETY: LPtoDP converts the two owned corners in place. The DC mapping
    // is unchanged. No guest address is passed.
    if unsafe { LPtoDP(dc, corners.as_mut_ptr(), 2) } == 0 {
        return None;
    }
    let mut area = device_area(corners)?;
    if let Some((width, height)) = surface_size(dc) {
        // LPtoDP of a clip-box corner can be one pixel off. Grow the box,
        // then keep only the selected bitmap so the copy stays on the surface.
        area = intersect_surface(inflate_one(area), width, height)?;
    }
    if area.is_empty() {
        return Some(PixelBackup::empty(dc));
    }
    // SAFETY: CreateCompatibleDC/CreateCompatibleBitmap allocate private GDI
    // objects from the leased DC. The caller deletes them if selection fails.
    let memory = unsafe { CreateCompatibleDC(dc) };
    if memory.is_null() {
        return None;
    }
    let created = unsafe { CreateCompatibleBitmap(dc, area.width, area.height) };
    if created.is_null() {
        crate::windows::win32_safe::delete_dc(memory);
        return None;
    }
    let bitmap = created.cast();
    // SAFETY: `bitmap` is the private bitmap just created. SelectObject does
    // not take a guest address. Failure leaves the stock selection in place.
    let previous = unsafe { SelectObject(memory, bitmap) };
    if previous.is_null() || previous as usize == usize::MAX {
        crate::windows::win32_safe::delete_object(bitmap);
        crate::windows::win32_safe::delete_dc(memory);
        return None;
    }
    let backup = PixelBackup {
        source: dc,
        memory,
        bitmap,
        previous,
        area,
    };
    if !backup.save_from_source() {
        return None;
    }
    Some(backup)
}

#[cfg(test)]
#[path = "win16_scroll_dc_native_tests.rs"]
mod scroll_dc_tests;
