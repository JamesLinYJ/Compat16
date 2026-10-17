//! Pins WinG DIB owners across synchronous GDI operations that touch pixels.

use std::sync::Arc;

use runtime::{
    RuntimeError, Win16DrawingOperation, Win16GdiBitmapOperation,
    Win16GdiDeviceOperation, Win16HostDc, Win16HostGdiObject, Win16HostMetafileOperation,
};
use windows_sys::Win32::Graphics::Gdi::{GetCurrentObject, HGDIOBJ, OBJ_BITMAP};

use super::{
    win16_gdi::Win16Dcs,
    win16_gdi_objects::Win16Objects,
    win16_wing_dib_storage::{Win16DibNativeUse, Win16DibSectionOwner},
};

pub(super) fn with_drawing<R>(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    operation: Win16DrawingOperation,
    run: impl FnOnce(&mut Win16Objects, Win16DrawingOperation) -> Result<R, RuntimeError>,
) -> Result<R, RuntimeError> {
    let (dc_tokens, count) = drawing_dcs(&operation);
    with_selected(dcs, objects, dc_tokens, count, |objects| run(objects, operation))
}

pub(super) fn with_bitmap_transfer<R>(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    operation: Win16GdiBitmapOperation,
    run: impl FnOnce(&mut Win16Objects, Win16GdiBitmapOperation) -> Result<R, RuntimeError>,
) -> Result<R, RuntimeError> {
    use Win16GdiBitmapOperation as Op;
    match &operation {
        Op::SetBitmapBits { bitmap, .. }
        | Op::GetBitmapBits { bitmap, .. }
        | Op::SetDibits { bitmap, .. }
        | Op::GetDibits { bitmap, .. } => {
            let bitmap = *bitmap;
            with_bitmap(objects, bitmap, |objects| run(objects, operation))
        }
        Op::SetDibitsToDevice { dc, .. } => {
            let tokens = [Some(*dc), None];
            with_selected(dcs, objects, tokens, 1, |objects| run(objects, operation))
        }
    }
}

pub(super) fn with_device_operation<R>(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    operation: Win16GdiDeviceOperation,
    run: impl FnOnce(&mut Win16Objects, Win16GdiDeviceOperation) -> Result<R, RuntimeError>,
) -> Result<R, RuntimeError> {
    use Win16GdiDeviceOperation as Op;
    let mut tokens = [None, None];
    let count = match &operation {
        Op::DibColorTable { dc, .. } | Op::UpdateColors { dc } => {
            tokens[0] = Some(*dc);
            1
        }
        Op::WinGStretchBlt { destination, source, .. } => {
            tokens[0] = Some(*destination);
            tokens[1] = Some(*source);
            2
        }
        _ => 0,
    };
    with_selected(dcs, objects, tokens, count, |objects| run(objects, operation))
}

pub(super) fn with_metafile<R>(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    operation: Win16HostMetafileOperation,
    run: impl FnOnce(&mut Win16Objects, Win16HostMetafileOperation) -> Result<R, RuntimeError>,
) -> Result<R, RuntimeError> {
    let (tokens, count) = match &operation {
        Win16HostMetafileOperation::Play { dc, .. } | Win16HostMetafileOperation::PlayRecord { dc, .. } => ([Some(*dc), None], 1),
        _ => ([None, None], 0),
    };
    with_selected(dcs, objects, tokens, count, |objects| run(objects, operation))
}

fn with_bitmap<R>(
    objects: &mut Win16Objects,
    bitmap: Win16HostGdiObject,
    run: impl FnOnce(&mut Win16Objects) -> Result<R, RuntimeError>,
) -> Result<R, RuntimeError> {
    let Some(owner) = objects.dib_owner(bitmap) else { return run(objects); };
    let _native_use = owner.pin_native()?;
    run(objects)
}

fn with_selected<R>(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    tokens: [Option<Win16HostDc>; 2],
    count: usize,
    run: impl FnOnce(&mut Win16Objects) -> Result<R, RuntimeError>,
) -> Result<R, RuntimeError> {
    let mut dc_uses = Vec::new();
    dc_uses.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
        runtime::DiagnosticKind::ResourceExhausted,
        "reserve WinG DIB source and destination DC leases",
        error,
    ))?;
    let mut owners: Vec<Arc<Win16DibSectionOwner>> = Vec::new();
    owners.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
        runtime::DiagnosticKind::ResourceExhausted,
        "reserve WinG DIB operation owners",
        error,
    ))?;

    for index in 0..count {
        let Some(token) = tokens[index] else { continue; };
        if tokens[..index].iter().any(|previous| *previous == Some(token)) { continue; }
        let Some(dc_use) = dcs.lease_dc(token)? else { continue; };
        // Only pixel-reading/writing operations enter this helper. Query the
        // actual current bitmap so SaveDC/RestoreDC and intervening selections
        // cannot make a cached guest-side selection map stale.
        let selected: HGDIOBJ = unsafe { GetCurrentObject(dc_use.native(), OBJ_BITMAP as u32) };
        if !selected.is_null() {
            if let Some(owner) = objects.dib_owner_for_native(selected) {
                if !owners.iter().any(|current| Arc::ptr_eq(current, &owner)) {
                    owners.push(owner);
                }
            }
        }
        dc_uses.push(dc_use);
    }

    let mut uses: Vec<Win16DibNativeUse> = Vec::new();
    uses.try_reserve_exact(owners.len()).map_err(|error| RuntimeError::with_source(
        runtime::DiagnosticKind::ResourceExhausted,
        "reserve WinG DIB native-use pins",
        error,
    ))?;
    for owner in owners {
        uses.push(owner.pin_native()?);
    }
    run(objects)
}

fn drawing_dcs(operation: &Win16DrawingOperation) -> ([Option<Win16HostDc>; 2], usize) {
    use Win16DrawingOperation as Op;
    let mut tokens = [None, None];
    let count = match operation {
        Op::StretchDibits { dc, .. }
        | Op::LineTo { dc, .. }
        | Op::Rectangle { dc, .. }
        | Op::SetLayout { dc, .. }
        | Op::TextOut { dc, .. }
        | Op::SetPixel { dc, .. }
        | Op::GetPixel { dc, .. }
        | Op::PatBlt { dc, .. }
        | Op::Polyline { dc, .. }
        | Op::ExtTextOut { dc, .. }
        | Op::Arc { dc, .. }
        | Op::Ellipse { dc, .. }
        | Op::FloodFill { dc, .. }
        | Op::Pie { dc, .. }
        | Op::RoundRect { dc, .. }
        | Op::Polygon { dc, .. }
        | Op::FillRgn { dc, .. }
        | Op::FrameRgn { dc, .. }
        | Op::InvertRgn { dc, .. }
        | Op::PaintRgn { dc, .. }
        | Op::Chord { dc, .. }
        | Op::ExtFloodFill { dc, .. }
        | Op::PolyPolygon { dc, .. }
        | Op::PolyBezier { dc, .. }
        | Op::PolyBezierTo { dc, .. }
        | Op::FillPath { dc }
        | Op::StrokeAndFillPath { dc }
        | Op::StrokePath { dc }
        | Op::UserFillRect { dc, .. }
        | Op::UserInvertRect { dc, .. }
        | Op::UserFrameRect { dc, .. }
        | Op::UserDrawIcon { dc, .. }
        | Op::UserDrawFocusRect { dc, .. }
        | Op::UserTabbedTextOut { dc, .. }
        | Op::UserDrawText { dc, .. } => {
            tokens[0] = Some(*dc);
            1
        }
        Op::BitBlt { destination, source, .. }
        | Op::StretchBlt { destination, source, .. } => {
            tokens[0] = Some(*destination);
            if let Some(source) = source {
                tokens[1] = Some(*source);
                2
            } else { 1 }
        }
        _ => 0,
    };
    (tokens, count)
}
