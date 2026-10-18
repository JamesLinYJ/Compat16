//! Opt-in native pixel context; publishes no native handle or memory address.
use super::super::{WindowsHost, win16_io_trace::Win16IoTrace};
use runtime::{Diagnostic, DiagnosticKind, RuntimeError, RuntimeHost, Win16DrawingOperation};
use windows_sys::Win32::Graphics::Gdi::{
    BITMAP, GetCurrentObject, GetObjectType, GetObjectW, OBJ_BITMAP,
};

pub(super) fn observe(
    host: &mut WindowsHost,
    operation: &Win16DrawingOperation,
) -> Result<(), RuntimeError> {
    let Win16DrawingOperation::GetPixel { dc, x, y } = operation else {
        return Ok(());
    };
    if !host
        .win16_io_trace
        .as_ref()
        .is_some_and(Win16IoTrace::is_complete)
    {
        return Ok(());
    }
    let Some(lease) = host.win16_dcs.lease_dc(*dc)? else {
        return Ok(());
    };
    // SAFETY: The native HDC is pinned for these synchronous metadata queries.
    let kind = unsafe { GetObjectType(lease.native().cast()) };
    let selected = unsafe { GetCurrentObject(lease.native(), OBJ_BITMAP as u32) };
    let mut bitmap = BITMAP::default();
    let size = std::mem::size_of::<BITMAP>() as i32;
    let facts = (!selected.is_null()
        && unsafe { GetObjectW(selected, size, std::ptr::from_mut(&mut bitmap).cast()) } == size)
        .then_some((
            bitmap.bmWidth,
            bitmap.bmHeight,
            bitmap.bmWidthBytes,
            bitmap.bmPlanes,
            bitmap.bmBitsPixel,
            !bitmap.bmBits.is_null(),
        ));
    drop(lease);
    if let Some(trace) = host.win16_io_trace.as_mut()
        && let Err(error) = trace.native_pixel(dc.0, *x, *y, kind, facts)
    {
        host.win16_io_trace = None;
        host.report_diagnostic(
            &Diagnostic::warning(
                DiagnosticKind::HostFailure,
                "Win16 pixel trace write failed; tracing has been disabled",
            )
            .with_cause(error),
        );
    }
    Ok(())
}
