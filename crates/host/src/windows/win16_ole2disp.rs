//! Native OleAut BSTR and VARIANT operations with explicit Win16 value
//! marshaling. Guest BSTRs and variants are never used as native structures.

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16AutomationValue, Win16Ole2DispConversionResult,
    Win16Ole2DispConversionValue,
};
use super::guest_text::GuestTextCodec;
use std::ptr;
use windows_sys::Win32::Foundation::{SysAllocStringLen, SysStringLen, VARIANT_BOOL};
use windows_sys::Win32::System::Com::CY;
use windows_sys::Win32::System::Variant::{
    VARENUM, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VariantChangeType,
    VariantChangeTypeEx, VariantClear, VariantInit,
};

#[path = "win16_ole2disp/convert.rs"]
mod convert;
pub(in crate::windows) use convert::execute_conversion;

const MAX_NATIVE_BSTR_UNITS: usize = 1 << 20;

pub(super) fn change_variant(
    source: Win16AutomationValue,
    target_vartype: u16,
    flags: u16,
    lcid: Option<u32>,
    codec: GuestTextCodec,
) -> Result<Win16Ole2DispConversionResult, RuntimeError> {
    let source = NativeVariant::from_value(source, codec)?;
    let mut destination = NativeVariant::empty();
    // SAFETY: The source and destination are host-owned native VARIANTs.
    // Native pointers are never derived from guest bytes.
    let result = unsafe {
        match lcid {
            Some(lcid) => VariantChangeTypeEx(
                &mut destination.value,
                &source.value,
                lcid,
                flags,
                target_vartype,
            ),
            None => VariantChangeType(&mut destination.value, &source.value, flags, target_vartype),
        }
    };
    let value = if result >= 0 {
        Some(Win16Ole2DispConversionValue::Variant(
            destination.to_value(codec)?,
        ))
    } else {
        None
    };
    Ok(Win16Ole2DispConversionResult {
        hresult: result as u32,
        value,
    })
}

struct NativeVariant {
    value: VARIANT,
    clear_on_drop: bool,
}

impl NativeVariant {
    fn empty() -> Self {
        let mut value = VARIANT::default();
        // SAFETY: `value` is a writable local native VARIANT.
        unsafe {
            VariantInit(&mut value);
        }
        Self {
            value,
            clear_on_drop: true,
        }
    }

    fn from_value(
        value: Win16AutomationValue,
        codec: GuestTextCodec,
    ) -> Result<Self, RuntimeError> {
        let mut native = Self::empty();
        let (vt, payload) = match value {
            Win16AutomationValue::Empty => (0, VARIANT_0_0_0 { llVal: 0 }),
            Win16AutomationValue::Null => (1, VARIANT_0_0_0 { llVal: 0 }),
            Win16AutomationValue::I2(value) => (2, VARIANT_0_0_0 { iVal: value }),
            Win16AutomationValue::I4(value) => (3, VARIANT_0_0_0 { lVal: value }),
            Win16AutomationValue::R4(value) => (4, VARIANT_0_0_0 { fltVal: value }),
            Win16AutomationValue::R8(value) => (5, VARIANT_0_0_0 { dblVal: value }),
            Win16AutomationValue::Currency(value) => (
                6,
                VARIANT_0_0_0 {
                    cyVal: CY { int64: value },
                },
            ),
            Win16AutomationValue::Date(value) => (7, VARIANT_0_0_0 { date: value }),
            Win16AutomationValue::Bstr(value) => {
                let bstr = allocate_native_bstr_from_ansi(&value, codec)?;
                (8, VARIANT_0_0_0 { bstrVal: bstr })
            }
            Win16AutomationValue::NullBstr => (
                8,
                VARIANT_0_0_0 {
                    bstrVal: ptr::null_mut(),
                },
            ),
            Win16AutomationValue::Error(value) => (10, VARIANT_0_0_0 { scode: value }),
            Win16AutomationValue::Bool(value) => (
                11,
                VARIANT_0_0_0 {
                    boolVal: value as VARIANT_BOOL,
                },
            ),
            Win16AutomationValue::Ui1(value) => (17, VARIANT_0_0_0 { bVal: value }),
            Win16AutomationValue::I1(value) => (16, VARIANT_0_0_0 { cVal: value }),
            Win16AutomationValue::Ui2(value) => (18, VARIANT_0_0_0 { uiVal: value }),
            Win16AutomationValue::Ui4(value) => (19, VARIANT_0_0_0 { ulVal: value }),
            Win16AutomationValue::I8(value) => (20, VARIANT_0_0_0 { llVal: value }),
            Win16AutomationValue::Ui8(value) => (21, VARIANT_0_0_0 { ullVal: value }),
            Win16AutomationValue::Int(value) => (22, VARIANT_0_0_0 { intVal: value }),
            Win16AutomationValue::UInt(value) => (23, VARIANT_0_0_0 { uintVal: value }),
            Win16AutomationValue::Dispatch { .. }
            | Win16AutomationValue::Unknown { .. }
            | Win16AutomationValue::Array(_) => {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "OleAut VARIANT pointer or array value needs a dedicated bridge",
                ));
            }
        };
        let body = VARIANT_0_0 {
            vt: vt as VARENUM,
            wReserved1: 0,
            wReserved2: 0,
            wReserved3: 0,
            Anonymous: payload,
        };
        // The union payload matches the VARTYPE selected above. BSTR ownership
        // transfers to `native`, whose Drop calls VariantClear.
        native.value.Anonymous = VARIANT_0 { Anonymous: body };
        Ok(native)
    }

    fn to_value(&self, codec: GuestTextCodec) -> Result<Win16AutomationValue, RuntimeError> {
        // SAFETY: Native OleAut populated this local VARIANT through one of its
        // documented APIs, and the copied union member is selected by `vt`.
        let body = unsafe { self.value.Anonymous.Anonymous };
        let payload = body.Anonymous;
        match body.vt {
            0 => Ok(Win16AutomationValue::Empty),
            1 => Ok(Win16AutomationValue::Null),
            2 => Ok(Win16AutomationValue::I2(unsafe { payload.iVal })),
            3 => Ok(Win16AutomationValue::I4(unsafe { payload.lVal })),
            4 => Ok(Win16AutomationValue::R4(unsafe { payload.fltVal })),
            5 => Ok(Win16AutomationValue::R8(unsafe { payload.dblVal })),
            6 => Ok(Win16AutomationValue::Currency(unsafe {
                payload.cyVal.int64
            })),
            7 => Ok(Win16AutomationValue::Date(unsafe { payload.date })),
            8 => {
                let bstr = unsafe { payload.bstrVal };
                match unsafe { unsafe_bstr_to_ansi(bstr, codec)? } {
                    Some(bytes) => Ok(Win16AutomationValue::Bstr(bytes)),
                    None => Ok(Win16AutomationValue::NullBstr),
                }
            }
            10 => Ok(Win16AutomationValue::Error(unsafe { payload.scode })),
            11 => Ok(Win16AutomationValue::Bool(unsafe { payload.boolVal })),
            17 => Ok(Win16AutomationValue::Ui1(unsafe { payload.bVal })),
            16 => Ok(Win16AutomationValue::I1(unsafe { payload.cVal })),
            18 => Ok(Win16AutomationValue::Ui2(unsafe { payload.uiVal })),
            19 => Ok(Win16AutomationValue::Ui4(unsafe { payload.ulVal })),
            20 => Ok(Win16AutomationValue::I8(unsafe { payload.llVal })),
            21 => Ok(Win16AutomationValue::Ui8(unsafe { payload.ullVal })),
            22 => Ok(Win16AutomationValue::Int(unsafe { payload.intVal })),
            23 => Ok(Win16AutomationValue::UInt(unsafe { payload.uintVal })),
            _ => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "OleAut result VARTYPE has no Win16 value marshaler",
            )),
        }
    }
}

impl Drop for NativeVariant {
    fn drop(&mut self) {
        if self.clear_on_drop {
            // SAFETY: `value` owns only native allocations created by OleAut
            // from copied values. The source is never a guest structure.
            unsafe {
                VariantClear(&mut self.value);
            }
        }
    }
}

fn allocate_native_bstr_from_ansi(
    bytes: &[u8],
    codec: GuestTextCodec,
) -> Result<windows_sys::core::BSTR, RuntimeError> {
    let wide = ansi_to_wide(bytes, codec)?;
    let length = u32::try_from(wide.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "native BSTR length exceeds DWORD",
            error,
        )
    })?;
    // SAFETY: `wide` owns the converted Win16 bytes for the call. The native
    // count is UTF-16 units, independent of the guest BSTR byte count.
    let bstr = unsafe { SysAllocStringLen(wide.as_ptr(), length) };
    if bstr.is_null() {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "OleAut could not allocate the native BSTR copy",
        ));
    }
    Ok(bstr)
}

fn ansi_to_wide(bytes: &[u8], codec: GuestTextCodec) -> Result<Vec<u16>, RuntimeError> {
    if bytes.len() > MAX_NATIVE_BSTR_UNITS {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 BSTR input exceeds the native conversion limit",
        ));
    }
    // The guest length is explicit, so embedded NUL bytes remain BSTR content.
    let wide = codec.to_wide(bytes)?;
    if wide.len() > MAX_NATIVE_BSTR_UNITS {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "native BSTR conversion exceeds its bounded unit count",
        ));
    }
    Ok(wide)
}

unsafe fn unsafe_bstr_to_ansi(
    bstr: windows_sys::core::BSTR,
    codec: GuestTextCodec,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    if bstr.is_null() {
        return Ok(None);
    }
    // SAFETY: The caller provides a live BSTR returned from the local OleAut
    // allocator; SysStringLen bounds the native UTF-16 range independently of NULs.
    let wide_count = unsafe { SysStringLen(bstr) };
    let count = usize::try_from(wide_count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "BSTR length exceeds the process address range",
            error,
        )
    })?;
    // SAFETY: This BSTR remains live and has `wide_count` readable UTF-16 units.
    let wide = unsafe { std::slice::from_raw_parts(bstr, count) };
    wide_to_ansi(wide, codec).map(Some)
}

fn wide_to_ansi(wide: &[u16], codec: GuestTextCodec) -> Result<Vec<u8>, RuntimeError> {
    if wide.len() > MAX_NATIVE_BSTR_UNITS {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "native BSTR exceeds the bounded UTF-16 unit count",
        ));
    }
    let encoded = codec.from_wide(wide)?;
    if encoded.bytes.len() > MAX_NATIVE_BSTR_UNITS * 4 {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "native BSTR conversion exceeds its bounded byte count",
        ));
    }
    Ok(encoded.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::SysFreeString;

    #[test]
    fn guest_bstr_uses_fixed_code_page_and_keeps_embedded_nuls() {
        let codec = GuestTextCodec::new(936).expect("Windows should provide code page 936");
        let guest_bytes = [0xD6, 0xD0, 0, b'A'];

        let wide = ansi_to_wide(&guest_bytes, codec).expect("decode guest BSTR");
        assert_eq!(wide, [0x4E2D, 0, b'A' as u16]);

        let bstr = allocate_native_bstr_from_ansi(&guest_bytes, codec)
            .expect("allocate host-owned BSTR");
        // SAFETY: `bstr` is owned from SysAllocStringLen and remains live here.
        let wide_length = unsafe { SysStringLen(bstr) };
        // SAFETY: The BSTR remains live until the explicit SysFreeString below.
        let round_trip = unsafe { unsafe_bstr_to_ansi(bstr, codec) };
        // SAFETY: This test owns the BSTR returned by allocate_native_bstr_from_ansi.
        unsafe { SysFreeString(bstr) };

        assert_eq!(wide_length, 3);
        assert_eq!(round_trip.expect("encode host BSTR").expect("non-null BSTR"), guest_bytes);
    }
}
