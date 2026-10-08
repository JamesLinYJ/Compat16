//! Typed native OleAut calls for the Win16 Var*From* exports.
//!
//! These are host ABI calls only. Win16 selector addresses and interface
//! proxies are not accepted by this module.

use compat_services::automation::{VT_DISPATCH, VT_TYPEMASK, VT_UNKNOWN};
use super::super::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16Ole2DispConversionInput as Input,
    Win16Ole2DispConversionOperation as Operation, Win16Ole2DispConversionResult as ResultValue,
    Win16Ole2DispConversionValue as Value, Win16Ole2DispLocale as Locale,
};
use std::ptr;
use windows_sys::Win32::Foundation::{SysFreeString, VARIANT_BOOL};
use windows_sys::Win32::System::{Com::CY, Ole};
use windows_sys::core::BSTR;

pub(in crate::windows) fn execute_conversion(
    operation: Operation,
    codec: GuestTextCodec,
) -> Result<ResultValue, RuntimeError> {
    match operation {
        Operation::VarFrom {
            ordinal,
            input,
            locale,
        } => convert_scalar(ordinal, input, locale, codec),
        Operation::VariantChangeType {
            source,
            target_vartype,
            flags,
            lcid,
        } => {
            if matches!(target_vartype & VT_TYPEMASK, VT_DISPATCH | VT_UNKNOWN) {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "VariantChangeType interface targets need an apartment-bound COM bridge",
                ));
            }
            super::change_variant(source, target_vartype, flags, lcid, codec)
        }
    }
}

fn convert_scalar(
    ordinal: u16,
    input: Input,
    locale: Option<Locale>,
    codec: GuestTextCodec,
) -> Result<ResultValue, RuntimeError> {
    match ordinal {
        43 => {
            let input = require_i4(input)?;
            let mut output = 0_i16;
            // SAFETY: `output` is a local writable SHORT; input is a copied scalar.
            let hresult = unsafe { Ole::VarI2FromI4(input, &mut output) };
            scalar_result(hresult, output, |value| Value::I2(value))
        }
        44 => {
            let input = f32::from_bits(require_r4(input)?);
            let mut output = 0_i16;
            // SAFETY: `output` is local; the raw guest float bits were copied into f32.
            let hresult = unsafe { Ole::VarI2FromR4(input, &mut output) };
            scalar_result(hresult, output, |value| Value::I2(value))
        }
        45 => {
            let input = f64::from_bits(require_r8(input)?);
            let mut output = 0_i16;
            // SAFETY: `output` is local; the raw guest float bits were copied into f64.
            let hresult = unsafe { Ole::VarI2FromR8(input, &mut output) };
            scalar_result(hresult, output, |value| Value::I2(value))
        }
        46 => {
            let input = cy_from_bits(require_currency(input)?);
            let mut output = 0_i16;
            // SAFETY: `output` is local and `CY` contains copied fixed-point bits.
            let hresult = unsafe { Ole::VarI2FromCy(input, &mut output) };
            scalar_result(hresult, output, |value| Value::I2(value))
        }
        47 => {
            let input = f64::from_bits(require_date(input)?);
            let mut output = 0_i16;
            // SAFETY: `output` is local; DATE input is copied raw IEEE-754 bits.
            let hresult = unsafe { Ole::VarI2FromDate(input, &mut output) };
            scalar_result(hresult, output, |value| Value::I2(value))
        }
        48 => {
            let input = require_string(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            let wide = terminated_wide(&input, codec)?;
            let mut output = 0_i16;
            // SAFETY: `wide` is owned, NUL-terminated UTF-16 and `output` is local.
            let hresult = unsafe { Ole::VarI2FromStr(wide.as_ptr(), lcid, flags, &mut output) };
            scalar_result(hresult, output, |value| Value::I2(value))
        }
        50 => {
            let input = require_bool(input)? as VARIANT_BOOL;
            let mut output = 0_i16;
            // SAFETY: `output` is a local writable SHORT.
            let hresult = unsafe { Ole::VarI2FromBool(input, &mut output) };
            scalar_result(hresult, output, |value| Value::I2(value))
        }
        56 => {
            let input = require_string(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            let wide = terminated_wide(&input, codec)?;
            let mut output = 0_i32;
            // SAFETY: `wide` is owned, NUL-terminated UTF-16 and `output` is local.
            let hresult = unsafe { Ole::VarI4FromStr(wide.as_ptr(), lcid, flags, &mut output) };
            scalar_result(hresult, output, |value| Value::I4(value))
        }
        61 => {
            let input = f64::from_bits(require_r8(input)?);
            let mut output = 0_f32;
            // SAFETY: `output` is local; the input preserves its guest raw bits until this call.
            let hresult = unsafe { Ole::VarR4FromR8(input, &mut output) };
            scalar_result(hresult, output.to_bits(), |bits| Value::R4Bits(bits))
        }
        64 => {
            let input = require_string(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            let wide = terminated_wide(&input, codec)?;
            let mut output = 0_f32;
            // SAFETY: `wide` is owned, NUL-terminated UTF-16 and `output` is local.
            let hresult = unsafe { Ole::VarR4FromStr(wide.as_ptr(), lcid, flags, &mut output) };
            scalar_result(hresult, output.to_bits(), |bits| Value::R4Bits(bits))
        }
        72 => {
            let input = require_string(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            let wide = terminated_wide(&input, codec)?;
            let mut output = 0_f64;
            // SAFETY: `wide` is owned, NUL-terminated UTF-16 and `output` is local.
            let hresult = unsafe { Ole::VarR8FromStr(wide.as_ptr(), lcid, flags, &mut output) };
            scalar_result(hresult, output.to_bits(), |bits| Value::R8Bits(bits))
        }
        80 => {
            let input = require_string(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            let wide = terminated_wide(&input, codec)?;
            let mut output = 0_f64;
            // SAFETY: `wide` is owned, NUL-terminated UTF-16 and `output` is local.
            let hresult = unsafe { Ole::VarDateFromStr(wide.as_ptr(), lcid, flags, &mut output) };
            scalar_result(hresult, output.to_bits(), |bits| Value::DateBits(bits))
        }
        88 => {
            let input = require_string(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            let wide = terminated_wide(&input, codec)?;
            let mut output = CY { int64: 0 };
            // SAFETY: `wide` is owned, NUL-terminated UTF-16 and `output` is local.
            let hresult = unsafe { Ole::VarCyFromStr(wide.as_ptr(), lcid, flags, &mut output) };
            // SAFETY: VarCyFromStr initialized this local CY output union.
            let bits = unsafe { output.int64 as u64 };
            scalar_result(hresult, bits, |value| Value::CurrencyBits(value))
        }
        91 => {
            let input = require_i2(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            bstr_result(codec, |output| {
                // SAFETY: output is a local BSTR slot owned by the guard.
                unsafe { Ole::VarBstrFromI2(input, lcid, flags, output) }
            })
        }
        92 => {
            let input = require_i4(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            bstr_result(codec, |output| {
                // SAFETY: output is a local BSTR slot owned by the guard.
                unsafe { Ole::VarBstrFromI4(input, lcid, flags, output) }
            })
        }
        93 => {
            let input = f32::from_bits(require_r4(input)?);
            let (lcid, flags) = locale_flags(locale)?;
            bstr_result(codec, |output| {
                // SAFETY: output is a local BSTR slot owned by the guard.
                unsafe { Ole::VarBstrFromR4(input, lcid, flags, output) }
            })
        }
        94 => {
            let input = f64::from_bits(require_r8(input)?);
            let (lcid, flags) = locale_flags(locale)?;
            bstr_result(codec, |output| {
                // SAFETY: output is a local BSTR slot owned by the guard.
                unsafe { Ole::VarBstrFromR8(input, lcid, flags, output) }
            })
        }
        95 => {
            let input = cy_from_bits(require_currency(input)?);
            let (lcid, flags) = locale_flags(locale)?;
            bstr_result(codec, |output| {
                // SAFETY: output is a local BSTR slot owned by the guard.
                unsafe { Ole::VarBstrFromCy(input, lcid, flags, output) }
            })
        }
        96 => {
            let input = f64::from_bits(require_date(input)?);
            let (lcid, flags) = locale_flags(locale)?;
            bstr_result(codec, |output| {
                // SAFETY: output is a local BSTR slot owned by the guard.
                unsafe { Ole::VarBstrFromDate(input, lcid, flags, output) }
            })
        }
        98 => {
            let input = require_bool(input)? as VARIANT_BOOL;
            let (lcid, flags) = locale_flags(locale)?;
            bstr_result(codec, |output| {
                // SAFETY: output is a local BSTR slot owned by the guard.
                unsafe { Ole::VarBstrFromBool(input, lcid, flags, output) }
            })
        }
        116 => {
            let input = require_i2(input)?;
            let mut output = 0_u8;
            // SAFETY: `output` is a local writable BYTE.
            let hresult = unsafe { Ole::VarUI1FromI2(input, &mut output) };
            scalar_result(hresult, output, |value| Value::Ui1(value))
        }
        117 => {
            let input = require_i4(input)?;
            let mut output = 0_u8;
            // SAFETY: `output` is a local writable BYTE.
            let hresult = unsafe { Ole::VarUI1FromI4(input, &mut output) };
            scalar_result(hresult, output, |value| Value::Ui1(value))
        }
        118 => {
            let input = f32::from_bits(require_r4(input)?);
            let mut output = 0_u8;
            // SAFETY: `output` is a local writable BYTE.
            let hresult = unsafe { Ole::VarUI1FromR4(input, &mut output) };
            scalar_result(hresult, output, |value| Value::Ui1(value))
        }
        119 => {
            let input = f64::from_bits(require_r8(input)?);
            let mut output = 0_u8;
            // SAFETY: `output` is a local writable BYTE.
            let hresult = unsafe { Ole::VarUI1FromR8(input, &mut output) };
            scalar_result(hresult, output, |value| Value::Ui1(value))
        }
        120 => {
            let input = cy_from_bits(require_currency(input)?);
            let mut output = 0_u8;
            // SAFETY: `output` is a local writable BYTE.
            let hresult = unsafe { Ole::VarUI1FromCy(input, &mut output) };
            scalar_result(hresult, output, |value| Value::Ui1(value))
        }
        121 => {
            let input = f64::from_bits(require_date(input)?);
            let mut output = 0_u8;
            // SAFETY: `output` is a local writable BYTE.
            let hresult = unsafe { Ole::VarUI1FromDate(input, &mut output) };
            scalar_result(hresult, output, |value| Value::Ui1(value))
        }
        122 => {
            let input = require_string(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            let wide = terminated_wide(&input, codec)?;
            let mut output = 0_u8;
            // SAFETY: `wide` is owned, NUL-terminated UTF-16 and `output` is local.
            let hresult = unsafe { Ole::VarUI1FromStr(wide.as_ptr(), lcid, flags, &mut output) };
            scalar_result(hresult, output, |value| Value::Ui1(value))
        }
        124 => {
            let input = require_bool(input)? as VARIANT_BOOL;
            let mut output = 0_u8;
            // SAFETY: `output` is a local writable BYTE.
            let hresult = unsafe { Ole::VarUI1FromBool(input, &mut output) };
            scalar_result(hresult, output, |value| Value::Ui1(value))
        }
        125 => {
            let input = require_ui1(input)?;
            let mut output = 0_i16;
            // SAFETY: `output` is a local writable SHORT.
            let hresult = unsafe { Ole::VarI2FromUI1(input, &mut output) };
            scalar_result(hresult, output, |value| Value::I2(value))
        }
        131 => {
            let input = require_ui1(input)?;
            let (lcid, flags) = locale_flags(locale)?;
            bstr_result(codec, |output| {
                // SAFETY: output is a local BSTR slot owned by the guard.
                unsafe { Ole::VarBstrFromUI1(input, lcid, flags, output) }
            })
        }
        97 | 123 => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "interface conversions require a guest-to-COM lease bridge",
        )),
        _ => Err(invariant(
            "unsupported Var*From* ordinal reached native conversion",
        )),
    }
}

fn scalar_result<T>(
    hresult: i32,
    output: T,
    convert: impl FnOnce(T) -> Value,
) -> Result<ResultValue, RuntimeError> {
    Ok(ResultValue {
        hresult: hresult as u32,
        value: (hresult >= 0).then(|| convert(output)),
    })
}

fn bstr_result(
    codec: GuestTextCodec,
    call: impl FnOnce(*mut BSTR) -> i32,
) -> Result<ResultValue, RuntimeError> {
    let mut output = NativeBstr(ptr::null());
    let hresult = call(&mut output.0);
    let value = if hresult >= 0 {
        // SAFETY: A successful VarBstrFrom* returns a BSTR owned by this guard.
        Some(Value::Bstr(unsafe {
            super::unsafe_bstr_to_ansi(output.0, codec)?
        }))
    } else {
        None
    };
    Ok(ResultValue {
        hresult: hresult as u32,
        value,
    })
}

struct NativeBstr(BSTR);

impl Drop for NativeBstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: This guard owns the BSTR returned through its local slot.
            unsafe { SysFreeString(self.0) };
        }
    }
}

fn terminated_wide(input: &[u8], codec: GuestTextCodec) -> Result<Vec<u16>, RuntimeError> {
    let mut wide = super::ansi_to_wide(input, codec)?;
    wide.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "terminate native Var*FromStr input",
            error,
        )
    })?;
    wide.push(0);
    Ok(wide)
}

fn locale_flags(locale: Option<Locale>) -> Result<(u32, u32), RuntimeError> {
    locale
        .map(|value| (value.lcid, value.dw_flags))
        .ok_or_else(|| invariant("Var*From* export is missing LCID and DWORD flags"))
}

fn cy_from_bits(bits: u64) -> CY {
    CY { int64: bits as i64 }
}

fn require_i2(input: Input) -> Result<i16, RuntimeError> {
    match input {
        Input::I2(value) => Ok(value),
        _ => Err(invariant("Var*From* expected an I2 input")),
    }
}

fn require_i4(input: Input) -> Result<i32, RuntimeError> {
    match input {
        Input::I4(value) => Ok(value),
        _ => Err(invariant("Var*From* expected an I4 input")),
    }
}

fn require_r4(input: Input) -> Result<u32, RuntimeError> {
    match input {
        Input::R4Bits(value) => Ok(value),
        _ => Err(invariant("Var*From* expected raw R4 bits")),
    }
}

fn require_r8(input: Input) -> Result<u64, RuntimeError> {
    match input {
        Input::R8Bits(value) => Ok(value),
        _ => Err(invariant("Var*From* expected raw R8 bits")),
    }
}

fn require_currency(input: Input) -> Result<u64, RuntimeError> {
    match input {
        Input::CurrencyBits(value) => Ok(value),
        _ => Err(invariant("Var*From* expected raw CY bits")),
    }
}

fn require_date(input: Input) -> Result<u64, RuntimeError> {
    match input {
        Input::DateBits(value) => Ok(value),
        _ => Err(invariant("Var*From* expected raw DATE bits")),
    }
}

fn require_bool(input: Input) -> Result<i16, RuntimeError> {
    match input {
        Input::Bool(value) => Ok(value),
        _ => Err(invariant("Var*From* expected VARIANT_BOOL")),
    }
}

fn require_ui1(input: Input) -> Result<u8, RuntimeError> {
    match input {
        Input::Ui1(value) => Ok(value),
        _ => Err(invariant("Var*From* expected a UI1 input")),
    }
}

fn require_string(input: Input) -> Result<Vec<u8>, RuntimeError> {
    match input {
        Input::AnsiString(value) => Ok(value),
        _ => Err(invariant("Var*FromStr expected an owned ANSI string")),
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
