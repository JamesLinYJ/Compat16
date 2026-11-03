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
    /// A host style, hatch, or width does not fit in the Win16 field.
    unrepresentable: bool,
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
            unrepresentable: false,
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
        if let Some(error) = enumeration.failure {
            return Err(error);
        }
        // A value outside the Win16 field must not be wrapped into a callback
        // record. Drop every snapshot so the caller returns zero and does not
        // write guest memory.
        if enumeration.unrepresentable {
            return Ok(Vec::new());
        }
        Ok(enumeration.records)
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn collect_object(object: *mut core::ffi::c_void, context: isize) -> i32 {
    // SAFETY: Only enum_objects installs this callback and supplies context.
    let state = unsafe { &mut *(context as *mut Enumeration<'_>) };
    if state.failure.is_some() || state.unrepresentable {
        return 0;
    }
    let record = match collect_record(state, object) {
        Ok(Some(record)) => record,
        Ok(None) => {
            state.unrepresentable = true;
            return 0;
        }
        Err(error) => {
            state.failure = Some(error);
            return 0;
        }
    };
    if let Err(error) = state.records.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain native GDI enumeration record",
            error,
        )
    }) {
        state.failure = Some(error);
        return 0;
    }
    state.records.push(record);
    1
}

fn collect_record(
    state: &mut Enumeration<'_>,
    object: *mut core::ffi::c_void,
) -> Result<Option<Record>, RuntimeError> {
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
            // Win16 LOGPEN stores style as a UINT and the width point as
            // signed ints. Truncating a wider host field would deliver a
            // different pen to the guest callback.
            let Some(style) = u16::try_from(pen.lopnStyle).ok() else {
                return Ok(None);
            };
            let Some(width_x) = i16::try_from(pen.lopnWidth.x).ok() else {
                return Ok(None);
            };
            let Some(width_y) = i16::try_from(pen.lopnWidth.y).ok() else {
                return Ok(None);
            };
            Ok(Some(Record::Pen(Win16HostLogPen {
                style,
                width_x,
                width_y,
                color: pen.lopnColor,
            })))
        }
        OBJ_BRUSH => {
            // SAFETY: The selected native enumeration supplies LOGBRUSH.
            let brush = unsafe { object.cast::<LOGBRUSH>().read_unaligned() };
            // Win16 LOGBRUSH stores style as a UINT and lbHatch as a signed
            // int. Check those fields before interning a pattern bitmap.
            let Some(style) = u16::try_from(brush.lbStyle).ok() else {
                return Ok(None);
            };
            let hatch = if brush.lbStyle == BS_HATCHED {
                let Some(hatch) = i16::try_from(brush.lbHatch)
                    .ok()
                    .and_then(|hatch| u16::try_from(hatch).ok())
                else {
                    return Ok(None);
                };
                u32::from(hatch)
            } else {
                0
            };
            let pattern = match brush.lbStyle {
                BS_PATTERN | BS_DIBPATTERN => {
                    // Pattern and DIB brushes expose a bitmap handle, not the
                    // native hatch address. A driver-supplied DIB address must
                    // never become a token.
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
            Ok(Some(Record::Brush {
                brush: Win16HostLogBrush {
                    style,
                    color: brush.lbColor,
                    hatch,
                },
                pattern,
            }))
        }
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native GDI enumeration has an invalid object type",
        )),
    }
}
