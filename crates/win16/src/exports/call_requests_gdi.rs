//! Export decoder arms owned by the Gdi API module group.

use super::*;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16ApiRequest>, Win16Error> {
    if let Some(request) = super::gdi_services_calls::decode(descriptor.id, arguments, selectors, memory)? {
        return Ok(Some(Win16ApiRequest::GdiServices(request)));
    }
    if let Some(request) = super::super::call_print_queue::decode(descriptor.ordinal(), arguments)? {
        return Ok(Some(Win16ApiRequest::PrintQueue(request)));
    }
    let request = match descriptor.id {
        Win16ExportId::GdiCreateCompatibleDc
        | Win16ExportId::GdiDeleteDc
        | Win16ExportId::GdiDeleteObject
        | Win16ExportId::GdiUnrealizeObject
        | Win16ExportId::GdiGetObject
        | Win16ExportId::GdiGetDeviceCaps
        | Win16ExportId::GdiGetStockObject
        | Win16ExportId::GdiEnumFonts
        | Win16ExportId::GdiEnumFontFamilies
        | Win16ExportId::GdiLineDda
        | Win16ExportId::GdiMulDiv
        | Win16ExportId::GdiSelectObject
        | Win16ExportId::GdiSetBkColor
        | Win16ExportId::GdiSetBkMode
        | Win16ExportId::GdiSetMapMode
        | Win16ExportId::GdiSetRop2
        | Win16ExportId::GdiSetTextColor
        | Win16ExportId::GdiLineTo
        | Win16ExportId::GdiMoveTo
        | Win16ExportId::GdiRectangle
        | Win16ExportId::GdiTextOut
        | Win16ExportId::GdiBitBlt
        | Win16ExportId::GdiCreateSolidBrush
        | Win16ExportId::GdiGetTextExtent
        | Win16ExportId::GdiCreateDc
        | Win16ExportId::GdiCreateIc
        | Win16ExportId::GdiGetOutlineTextMetrics
        | Win16ExportId::GdiGetTextMetrics
        | Win16ExportId::GdiGetTextFace => {
            gdi_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::GdiCreatePen
        | Win16ExportId::GdiCreatePenIndirect
        | Win16ExportId::GdiCreateFont
        | Win16ExportId::GdiCreateFontIndirect
        | Win16ExportId::GdiCreateBitmap
        | Win16ExportId::GdiCreateBitmapIndirect
        | Win16ExportId::GdiCreateHatchBrush
        | Win16ExportId::GdiCreatePatternBrush
        | Win16ExportId::GdiCreateDibPatternBrush
        | Win16ExportId::GdiCreateBrushIndirect
        | Win16ExportId::GdiCreateCompatibleBitmap => {
            gdi_objects_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::GdiSetStretchBltMode
        | Win16ExportId::GdiGetStretchBltMode
        | Win16ExportId::GdiSetWindowExt
        | Win16ExportId::GdiSetWindowOrg
        | Win16ExportId::GdiSetViewportOrg
        | Win16ExportId::GdiSetViewportExt
        | Win16ExportId::GdiOffsetWindowOrg
        | Win16ExportId::GdiOffsetViewportOrg
        | Win16ExportId::GdiScaleWindowExt
        | Win16ExportId::GdiScaleViewportExt
        | Win16ExportId::GdiExcludeClipRect
        | Win16ExportId::GdiIntersectClipRect
        | Win16ExportId::GdiPatBlt
        | Win16ExportId::GdiSaveDc
        | Win16ExportId::GdiSetPixel
        | Win16ExportId::GdiStretchBlt
        | Win16ExportId::GdiPolyline
        | Win16ExportId::GdiRestoreDc
        | Win16ExportId::GdiDptoLp
        | Win16ExportId::GdiGetClipBox
        | Win16ExportId::GdiGetPixel
        | Win16ExportId::GdiLptoDp
        | Win16ExportId::GdiRectVisibleOld
        | Win16ExportId::GdiRectVisible
        | Win16ExportId::GdiGetTextCharacterExtra
        | Win16ExportId::GdiSetTextCharacterExtra
        | Win16ExportId::GdiSetTextJustification
        | Win16ExportId::GdiGetTextAlign
        | Win16ExportId::GdiSetTextAlign
        | Win16ExportId::GdiExtTextOut
        | Win16ExportId::GdiGetCurrentPositionEx
        | Win16ExportId::GdiGetTextExtentPoint
        | Win16ExportId::GdiGetViewportExtEx
        | Win16ExportId::GdiGetViewportOrgEx
        | Win16ExportId::GdiGetWindowExtEx
        | Win16ExportId::GdiGetWindowOrgEx
        | Win16ExportId::GdiSetViewportExtEx
        | Win16ExportId::GdiSetViewportOrgEx
        | Win16ExportId::GdiSetWindowExtEx
        | Win16ExportId::GdiSetWindowOrgEx
        | Win16ExportId::GdiOffsetViewportOrgEx
        | Win16ExportId::GdiOffsetWindowOrgEx
        | Win16ExportId::GdiScaleViewportExtEx
        | Win16ExportId::GdiScaleWindowExtEx
        | Win16ExportId::GdiMoveToEx
        | Win16ExportId::GdiGetCurrentPosition
        | Win16ExportId::GdiGetViewportExt
        | Win16ExportId::GdiGetViewportOrg
        | Win16ExportId::GdiGetWindowExt
        | Win16ExportId::GdiGetWindowOrg => {
            gdi_drawing_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::GdiGetBkColor
        | Win16ExportId::GdiGetNearestColor
        | Win16ExportId::GdiGetBkMode
        | Win16ExportId::GdiGetMapMode
        | Win16ExportId::GdiGetPolyFillMode
        | Win16ExportId::GdiGetRop2
        | Win16ExportId::GdiGetTextColor
        | Win16ExportId::GdiSetPolyFillMode
        | Win16ExportId::GdiSetArcDirection
        | Win16ExportId::GdiGetArcDirection
        | Win16ExportId::GdiSetBrushOrg
        | Win16ExportId::GdiGetBrushOrg
        | Win16ExportId::GdiGetBrushOrgEx
        | Win16ExportId::GdiGetDcOrg
        | Win16ExportId::GdiCreateEllipticRgn
        | Win16ExportId::GdiCreateEllipticRgnIndirect
        | Win16ExportId::GdiCreatePolygonRgn
        | Win16ExportId::GdiCreateRectRgn
        | Win16ExportId::GdiCreateRectRgnIndirect
        | Win16ExportId::GdiCreateRoundRectRgn
        | Win16ExportId::GdiCreatePolyPolygonRgn
        | Win16ExportId::GdiArc
        | Win16ExportId::GdiEllipse
        | Win16ExportId::GdiFloodFill
        | Win16ExportId::GdiPie
        | Win16ExportId::GdiRoundRect
        | Win16ExportId::GdiOffsetClipRgn
        | Win16ExportId::GdiPolygon
        | Win16ExportId::GdiFillRgn
        | Win16ExportId::GdiFrameRgn
        | Win16ExportId::GdiInvertRgn
        | Win16ExportId::GdiPaintRgn
        | Win16ExportId::GdiSelectClipRgn
        | Win16ExportId::GdiCombineRgn
        | Win16ExportId::GdiEqualRgn
        | Win16ExportId::GdiOffsetRgn
        | Win16ExportId::GdiPtVisible
        | Win16ExportId::GdiGetRgnBox
        | Win16ExportId::GdiPtInRegion
        | Win16ExportId::GdiSetRectRgn
        | Win16ExportId::GdiGetClipRgn
        | Win16ExportId::GdiRectInRegion
        | Win16ExportId::GdiRectInRegionEhh
        | Win16ExportId::GdiPolyPolygon
        | Win16ExportId::GdiPolyBezier
        | Win16ExportId::GdiPolyBezierTo
        | Win16ExportId::GdiAbortPath
        | Win16ExportId::GdiBeginPath
        | Win16ExportId::GdiCloseFigure
        | Win16ExportId::GdiEndPath
        | Win16ExportId::GdiFillPath
        | Win16ExportId::GdiFlattenPath
        | Win16ExportId::GdiPathToRegion
        | Win16ExportId::GdiStrokeAndFillPath
        | Win16ExportId::GdiStrokePath
        | Win16ExportId::GdiWidenPath
        | Win16ExportId::GdiGetPath
        | Win16ExportId::GdiSelectClipPath
        | Win16ExportId::GdiExtSelectClipRgn
        | Win16ExportId::GdiExtFloodFill
        | Win16ExportId::GdiChord => {
            gdi_primitives_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::GdiEscape
        | Win16ExportId::GdiStretchDibits
        | Win16ExportId::GdiSetDibits
        | Win16ExportId::GdiGetDibits
        | Win16ExportId::GdiCreateDibitmap
        | Win16ExportId::GdiSetDibitsToDevice
        | Win16ExportId::GdiDeviceGetBitmapBits
        | Win16ExportId::GdiDeviceSetBitmapBits
        | Win16ExportId::GdiDeviceCreateDiscardableBitmap
        | Win16ExportId::GdiDeviceCreatePalette
        | Win16ExportId::GdiDeviceSelectPalette
        | Win16ExportId::GdiDeviceRealizePalette
        | Win16ExportId::GdiDeviceGetPaletteEntries
        | Win16ExportId::GdiDeviceSetPaletteEntries
        | Win16ExportId::GdiDeviceRealizeDefaultPalette
        | Win16ExportId::GdiDeviceUpdateColors
        | Win16ExportId::GdiDeviceAnimatePalette
        | Win16ExportId::GdiDeviceResizePalette
        | Win16ExportId::GdiDeviceGetNearestPaletteIndex
        | Win16ExportId::GdiDeviceSetSystemPaletteUse
        | Win16ExportId::GdiDeviceGetSystemPaletteUse
        | Win16ExportId::GdiDeviceGetSystemPaletteEntries
        | Win16ExportId::GdiDeviceResetDc
        | Win16ExportId::GdiDeviceStartDoc
        | Win16ExportId::GdiDeviceEndDoc
        | Win16ExportId::GdiDeviceStartPage
        | Win16ExportId::GdiDeviceEndPage
        | Win16ExportId::GdiDeviceSetAbortProc
        | Win16ExportId::GdiDeviceAbortDoc
        | Win16ExportId::GdiDeviceGetBitmapDimension
        | Win16ExportId::GdiDeviceSetBitmapDimension
        | Win16ExportId::GdiDeviceGetBitmapDimensionEx
        | Win16ExportId::GdiDeviceSetBitmapDimensionEx
        | Win16ExportId::GdiDeviceCreateHalftonePalette
        | Win16ExportId::GdiDeviceSetDibColorTable
        | Win16ExportId::GdiDeviceGetDibColorTable => Win16ApiRequest::GdiDevice(
            gdi_device_calls::decode(
                descriptor.module().as_bytes(),
                descriptor.ordinal(),
                &arguments,
                selectors,
                memory,
            )?
            .ok_or(Win16Error::InvalidRange)?,
        ),
        _ => return Ok(None),
    };
    Ok(Some(request))
}
