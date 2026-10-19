//! Snapshot native pens and brushes before scheduling any guest callbacks.

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostGdiObjectRecord as Record, Win16HostLogBrush,
    Win16HostLogPen,
};
use windows_sys::Win32::Graphics::Gdi::{
    BS_DIBPATTERN, BS_HATCHED, BS_INDEXED, BS_NULL, BS_PATTERN, BS_SOLID, EnumObjects, HDC,
    HGDIOBJ, LOGBRUSH, LOGPEN, OBJ_BITMAP, OBJ_BRUSH, OBJ_PEN,
};

use super::Win16Objects;

struct Enumeration<'a> {
    objects: &'a mut Win16Objects,
    object_type: i32,
    records: Vec<Record>,
    failure: Option<RuntimeError>,
}

impl Win16Objects {
    pub(in crate::windows) fn enum_objects(
        &mut self,
        dc: HDC,
        object_type: i16,
    ) -> Result<Vec<Record>, RuntimeError> {
        if !matches!(i32::from(object_type), OBJ_PEN | OBJ_BRUSH) {
            return Ok(Vec::new());
        }
        let mut enumeration = Enumeration {
            objects: self,
            object_type: i32::from(object_type),
            records: Vec::new(),
            failure: None,
        };
        // SAFETY: The caller retains the DC lease. GDI supplies native POD
        // records synchronously; the context and object table remain live,
        // and collect_object never executes guest code or retains pointers.
        unsafe {
            EnumObjects(
                dc,
                enumeration.object_type,
                Some(collect_object),
                (&mut enumeration as *mut Enumeration<'_>) as isize,
            );
        }
        match enumeration.failure {
            Some(error) => Err(error),
            None => Ok(enumeration.records),
        }
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn collect_object(object: *mut core::ffi::c_void, context: isize) -> i32 {
    // SAFETY: Only enum_objects installs this callback and supplies context.
    let state = unsafe { &mut *(context as *mut Enumeration<'_>) };
    if state.failure.is_some() {
        return 0;
    }
    let result = collect_record(state, object).and_then(|record| {
        state.records.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain native GDI enumeration record",
                error,
            )
        })?;
        state.records.push(record);
        Ok(())
    });
    if let Err(error) = result {
        state.failure = Some(error);
        return 0;
    }
    1
}

fn collect_record(
    state: &mut Enumeration<'_>,
    object: *mut core::ffi::c_void,
) -> Result<Record, RuntimeError> {
    if object.is_null() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "native GDI enumeration supplied a null object record",
        ));
    }
    match state.object_type {
        OBJ_PEN => {
            // SAFETY: EnumObjects was called with OBJ_PEN; GDI owns a LOGPEN
            // for this callback. Copy it before the native callback returns.
            let pen = unsafe { object.cast::<LOGPEN>().read_unaligned() };
            Ok(Record::Pen(Win16HostLogPen {
                style: pen.lopnStyle as u16,
                width_x: pen.lopnWidth.x as i16,
                width_y: pen.lopnWidth.y as i16,
                color: pen.lopnColor,
            }))
        }
        OBJ_BRUSH => {
            // SAFETY: The selected native enumeration supplies LOGBRUSH.
            let brush = unsafe { object.cast::<LOGBRUSH>().read_unaligned() };
            let pattern = match brush.lbStyle {
                BS_PATTERN | BS_DIBPATTERN => {
                    // WOW's output LOGBRUSH conversion treats both styles as
                    // bitmap handles. Validate that contract before interning;
                    // a driver-supplied DIB address must never become a token.
                    let bitmap = brush.lbHatch as HGDIOBJ;
                    if bitmap.is_null() || { crate::windows::win32_safe::get_object_type(bitmap) }
                        != OBJ_BITMAP as u32
                    {
                        return Err(RuntimeError::new(
                            Kind::CompatibilityGap,
                            "native enumerated brush pattern is not a bitmap handle",
                        ));
                    }
                    Some(state.objects.intern_borrowed(bitmap)?)
                }
                BS_SOLID | BS_NULL | BS_HATCHED | BS_INDEXED => None,
                _ => {
                    return Err(RuntimeError::new(
                        Kind::CompatibilityGap,
                        "native enumerated brush style has no Win16 object layout",
                    ));
                }
            };
            Ok(Record::Brush {
                brush: Win16HostLogBrush {
                    style: brush.lbStyle as u16,
                    color: brush.lbColor,
                    hatch: if brush.lbStyle == BS_HATCHED {
                        brush.lbHatch as u16 as u32
                    } else {
                        0
                    },
                },
                pattern,
            })
        }
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native GDI enumeration has an invalid object type",
        )),
    }
}
