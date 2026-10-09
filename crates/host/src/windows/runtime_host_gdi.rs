//! GDI host operations kept separate from the RuntimeHost forwarding table.

use super::*;

pub(super) fn create_dc(
    host: &mut WindowsHost,
    driver: Option<&[u8]>,
    device: Option<&[u8]>,
    output: Option<&[u8]>,
    devmode: Option<&runtime::Win16HostDevMode>,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    host.win16_dcs.create_dc(driver, device, output, devmode)
}

pub(super) fn create_ic(
    host: &mut WindowsHost,
    driver: Option<&[u8]>,
    device: Option<&[u8]>,
    output: Option<&[u8]>,
    devmode: Option<&runtime::Win16HostDevMode>,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    host.win16_dcs.create_ic(driver, device, output, devmode)
}

pub(super) fn get_text_metrics(
    host: &mut WindowsHost,
    dc: Win16HostDc,
) -> Result<Option<runtime::Win16HostTextMetrics>, RuntimeError> {
    host.win16_dcs.get_text_metrics(dc)
}

pub(super) fn get_text_face(
    host: &mut WindowsHost,
    dc: Win16HostDc,
    count: i16,
    output: Option<Vec<u8>>,
) -> Result<Option<runtime::Win16HostTextFace>, RuntimeError> {
    host.win16_dcs.get_text_face(dc, count, output)
}

pub(super) fn execute_drawing(
    host: &mut WindowsHost,
    operation: runtime::Win16DrawingOperation,
) -> Result<runtime::Win16DrawingResult, RuntimeError> {
    use runtime::{Win16DrawingOperation as Operation, Win16DrawingResult as ResultValue};
    use windows_sys::Win32::Graphics::Gdi::{DT_MODIFYSTRING, ETO_GLYPH_INDEX};

    match &operation {
        Operation::ExtTextOut { options, .. } if options & ETO_GLYPH_INDEX != 0 => {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "ExtTextOut glyph indices cannot be read from a Win16 ANSI byte buffer",
            ));
            return Ok(ResultValue::Bool(false));
        }
        Operation::UserDrawText { flags, rect, .. } if flags & DT_MODIFYSTRING != 0 => {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "DrawText string modification has no Win16 output-buffer contract",
            ));
            return Ok(ResultValue::DrawText {
                height: 0,
                rect: *rect,
            });
        }
        _ => {}
    }
    let maps_byte_spacing = matches!(
        &operation,
        Operation::ExtTextOut {
            spacing: Some(_),
            ..
        }
    );
    let dcs = &host.win16_dcs;
    let images = &host.win16_images;
    let result = win16_wing_dib_use::with_drawing(
        dcs,
        &mut host.win16_objects,
        operation,
        |objects, operation| win16_drawing::execute(dcs, objects, images, operation),
    );
    match result {
        Err(error) if maps_byte_spacing && error.kind() == Kind::CompatibilityGap => {
            host.report_diagnostic(
                &Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "ExtTextOut cannot map byte spacing for the selected code page",
                )
                .with_cause(error),
            );
            Ok(ResultValue::Bool(false))
        }
        result => result,
    }
}

pub(super) fn create_object(
    host: &mut WindowsHost,
    operation: runtime::Win16GdiObjectOperation,
) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
    win16_gdi_object_factories::create(&mut host.win16_objects, &host.win16_dcs, operation)
}

pub(super) fn execute_bitmap_transfer(
    host: &mut WindowsHost,
    operation: runtime::Win16GdiBitmapOperation,
) -> Result<runtime::Win16GdiBitmapResult, RuntimeError> {
    let dcs = &host.win16_dcs;
    let work = &host.win16_format_work;
    win16_wing_dib_use::with_bitmap_transfer(
        dcs,
        &mut host.win16_objects,
        operation,
        |objects, operation| win16_gdi_bitmap_transfer::execute(dcs, objects, operation, work),
    )
}

pub(super) fn execute_device(
    host: &mut WindowsHost,
    operation: runtime::Win16GdiDeviceOperation,
) -> Result<runtime::Win16GdiDeviceResult, RuntimeError> {
    if let Some(result) =
        win16_wing_dib_backend::execute(&host.win16_dcs, &mut host.win16_objects, &operation)?
    {
        return Ok(result);
    }
    let dcs = &host.win16_dcs;
    win16_wing_dib_use::with_device_operation(
        dcs,
        &mut host.win16_objects,
        operation,
        |objects, operation| win16_gdi_device::execute(dcs, objects, operation),
    )
}

pub(super) fn create_compatible_dc(
    host: &mut WindowsHost,
    source: Option<Win16HostDc>,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    host.win16_dcs.create_compatible(source)
}

pub(super) fn acquire_screen_dc(
    host: &mut WindowsHost,
    whole_window: bool,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    host.win16_dcs.acquire_screen(whole_window)
}

pub(super) fn release_screen_dc(
    host: &mut WindowsHost,
    dc: Win16HostDc,
) -> Result<bool, RuntimeError> {
    Ok(host.win16_dcs.release_screen(dc))
}

pub(super) fn cleanup_dc(host: &mut WindowsHost, dc: Win16HostDc) -> Result<bool, RuntimeError> {
    Ok(host.win16_dcs.cleanup(dc))
}

pub(super) fn cleanup_dc_state(
    host: &mut WindowsHost,
    dc: Win16HostDc,
) -> Result<runtime::Win16HostGdiCleanup, RuntimeError> {
    Ok(host.win16_dcs.cleanup_state(dc))
}

pub(super) fn delete_dc(host: &mut WindowsHost, dc: Win16HostDc) -> Result<bool, RuntimeError> {
    Ok(host.win16_dcs.delete(dc))
}

pub(super) fn device_caps(
    host: &mut WindowsHost,
    dc: Win16HostDc,
    index: i16,
) -> Result<Option<i16>, RuntimeError> {
    host.win16_dcs.device_caps(dc, index)
}

pub(super) fn enum_fonts(
    host: &mut WindowsHost,
    dc: Win16HostDc,
    face: Option<&[u8]>,
) -> Result<Vec<Win16HostFontRecord>, RuntimeError> {
    host.win16_dcs.enum_fonts(dc, face)
}

pub(super) fn stock_object(
    host: &mut WindowsHost,
    index: i16,
) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
    host.win16_objects.stock(index)
}

pub(super) fn select_object(
    host: &mut WindowsHost,
    dc: Win16HostDc,
    object: Win16HostGdiObject,
) -> Result<Option<Win16SelectObjectResult>, RuntimeError> {
    let Some(dc_use) = host.win16_dcs.lease_dc(dc)? else {
        return Ok(None);
    };
    host.win16_objects.select(dc_use.native(), object)
}

pub(super) fn delete_object(
    host: &mut WindowsHost,
    object: Win16HostGdiObject,
) -> Result<bool, RuntimeError> {
    host.win16_objects.delete_owned(object)
}

pub(super) fn cleanup_gdi_object(
    host: &mut WindowsHost,
    object: Win16HostGdiObject,
) -> Result<runtime::Win16HostGdiCleanup, RuntimeError> {
    host.win16_objects.cleanup_owned(object)
}
