//! Read-only replacements for the bounded Win16 printer Escape queries.

use super::super::win16_gdi::Win16Dcs;
use runtime::{
    RuntimeError, Win16EscapeQuery as Query, Win16GdiDeviceResult as Value, Win16HostDc,
};
use windows_sys::Win32::Graphics::Gdi::{
    DT_PLOTTER, DT_RASPRINTER, GetDeviceCaps, PHYSICALHEIGHT, PHYSICALOFFSETX, PHYSICALOFFSETY,
    PHYSICALWIDTH, QUERYESCSUPPORT, SCALINGFACTORX, SCALINGFACTORY, TECHNOLOGY,
};
use windows_sys::Win32::Storage::Xps::Escape;

pub(super) fn query_support(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    query: Query,
) -> Result<Value, RuntimeError> {
    let Some(lease) = dcs.lease_dc(dc)? else {
        return Ok(Value::Bool(false));
    };
    let supported = if query == Query::QuerySupport {
        let queried_escape = QUERYESCSUPPORT as i32;
        // SAFETY: Exact DC lease plus one owned native i32 input. This fixed
        // self-query has no output and cannot dispatch a guest-selected driver
        // command. In particular no guest FAR pointer reaches native Escape.
        unsafe {
            Escape(
                lease.native(),
                QUERYESCSUPPORT as i32,
                size_of::<i32>() as i32,
                (&queried_escape as *const i32).cast(),
                std::ptr::null_mut(),
            ) > 0
        }
    } else {
        // SAFETY: All queried indices are selected below, and the exact DC
        // identity remains leased across the complete synchronous read.
        query_caps(query, |index| unsafe {
            GetDeviceCaps(lease.native(), index)
        })
        .is_some()
    };
    Ok(Value::Bool(supported))
}

pub(super) fn query_point(
    dcs: &Win16Dcs,
    dc: Win16HostDc,
    query: Query,
) -> Result<Value, RuntimeError> {
    let failure = || Value::Point {
        success: false,
        x: 0,
        y: 0,
    };
    let Some(lease) = dcs.lease_dc(dc)? else {
        return Ok(failure());
    };
    // SAFETY: GetDeviceCaps reads only the live leased DC using known indices.
    Ok(
        match query_caps(query, |index| unsafe {
            GetDeviceCaps(lease.native(), index)
        }) {
            Some((x, y)) => Value::Point {
                success: true,
                x,
                y,
            },
            None => failure(),
        },
    )
}

fn query_caps(query: Query, mut caps: impl FnMut(i32) -> i32) -> Option<(i32, i32)> {
    let indices = match query {
        Query::PhysicalPageSize => (PHYSICALWIDTH, PHYSICALHEIGHT),
        Query::PrintingOffset => (PHYSICALOFFSETX, PHYSICALOFFSETY),
        Query::ScalingFactor => (SCALINGFACTORX, SCALINGFACTORY),
        Query::QuerySupport => return None,
    };
    // Microsoft documents these six GetDeviceCaps indices as replacements
    // for escapes 12/13/14, with device units and unmodified scaling exponents:
    // https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-getdevicecaps
    // Conservative conversion policy: require a printing device with a real
    // physical page. Zero offsets (borderless) and zero exponents are valid,
    // so neither can be used on its own as a device-support test. This does
    // not claim equivalence to every historical driver's support decisions.
    let technology = caps(TECHNOLOGY as i32);
    if technology != DT_RASPRINTER as i32 && technology != DT_PLOTTER as i32 {
        return None;
    }
    let width = caps(PHYSICALWIDTH as i32);
    let height = caps(PHYSICALHEIGHT as i32);
    if width <= 0 || height <= 0 {
        return None;
    }
    let (x, y) = if query == Query::PhysicalPageSize {
        (width, height)
    } else {
        (caps(indices.0 as i32), caps(indices.1 as i32))
    };
    // Support and execution share exactly the same representability policy.
    // Never advertise a conversion that would truncate the signed POINT16.
    i16::try_from(x).ok()?;
    i16::try_from(y).ok()?;
    Some((x, y))
}

#[cfg(test)]
#[path = "win16_gdi_escape_tests.rs"]
mod tests;
