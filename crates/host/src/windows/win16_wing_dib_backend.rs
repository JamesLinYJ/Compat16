//! WinG DIB-format queries and creation over the private shared-section owner.

use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16GdiDeviceOperation as Operation,
    Win16GdiDeviceResult as ResultValue, Win16HostDibSection,
};
use windows_sys::Win32::Graphics::Gdi::{
    GetDC, GetDeviceCaps, ReleaseDC, BITSPIXEL, PLANES,
};

use super::{
    win16_gdi::Win16Dcs,
    win16_gdi_objects::Win16Objects,
    win16_wing_dib_header::BitmapInfoHeaderWire,
    win16_wing_dib_storage::Win16DibSectionOwner,
};

/// Handles only the two DIB-section operations; the existing GDI adapter
/// remains the owner of every other Win16 GDI device operation.
pub(super) fn execute(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    operation: &Operation,
) -> Result<Option<ResultValue>, RuntimeError> {
    match operation {
        Operation::RecommendWinGDibFormat => {
            Ok(Some(ResultValue::DibHeader(recommend_format()?)))
        }
        Operation::CreateWinGDibSection { dc, info, image_bytes } => {
            Ok(Some(ResultValue::DibSection(create_section(
                dcs, objects, *dc, info, *image_bytes,
            )?)))
        }
        _ => Ok(None),
    }
}

fn create_section(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    dc: runtime::Win16HostDc,
    info: &[u8],
    image_bytes: u32,
) -> Result<Option<Win16HostDibSection>, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(None); };
    let Some(created) = Win16DibSectionOwner::create(
        dc_use.native(), info, image_bytes,
    )? else { return Ok(None); };
    let Some(object) = objects.adopt_dib_section(
        created.bitmap, std::sync::Arc::clone(&created.owner),
    )? else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "created WinG DIB section returned no registered bitmap identity",
        ));
    };
    Ok(Some(Win16HostDibSection {
        object,
        extent: created.owner.extent(),
        header: created.header,
        memory: created.memory,
    }))
}

fn recommend_format() -> Result<Option<[u8; 40]>, RuntimeError> {
    // Use an actually supported display bit depth, not a historical-speed
    // guess. A positive one-scanline BI_RGB DIB is a host-supported suggestion.
    let dc = unsafe { GetDC(ptr::null_mut()) };
    if dc.is_null() { return Ok(None); }
    let planes = unsafe { GetDeviceCaps(dc, PLANES as i32) };
    let bits_per_plane = unsafe { GetDeviceCaps(dc, BITSPIXEL as i32) };
    let released = unsafe { ReleaseDC(ptr::null_mut(), dc) } != 0;
    if !released {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "ReleaseDC failed after WinG display-format query",
        ));
    }
    let Some(bits) = planes.checked_mul(bits_per_plane)
        .and_then(|bits| u16::try_from(bits).ok())
        .filter(|bits| matches!(*bits, 1 | 4 | 8 | 16 | 24 | 32))
    else { return Ok(None); };

    Ok(Some(BitmapInfoHeaderWire::new(40, 1, 1, 1, bits, 0, 0, 0, 0, 0, 0)
        .into_bytes()))
}
