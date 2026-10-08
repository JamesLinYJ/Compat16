//! Win16 OLE2DISP scalar and VARIANT conversion parameter slots.
//!
//! The 3.1 SDK bundle contains no OLE2DISP ABI declarations. `long long` in
//! this project spec is two DWORD stack slots; this is represented explicitly
//! so Pascal argument order and cleanup stay tied to the owned spec.

use super::*;

macro_rules! parameters {
    ($name:ident: [$($argument:ident: $kind:ident / $role:expr),* $(,)?]) => {
        pub(super) const $name: &[Win16Parameter] = &[
            $(Win16Parameter {
                name: stringify!($argument),
                kind: ArgumentKind::$kind,
                parameter_type: $role,
            },)*
        ];
    };
}

parameters!(VARIANT_CHANGE_TYPE: [destination: Dword / FAR_OUTPUT_BUFFER, source: Dword / FAR_BUFFER, flags: Word / SCALAR_WORD, target_vartype: Word / SCALAR_WORD]);
parameters!(VAR_I2_FROM_I4: [source: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_I2_FROM_R4: [source_bits: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_I2_FROM_R8: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_I2_FROM_CY: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_I2_FROM_DATE: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_I2_FROM_STR: [source: Dword / FAR_STRING, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_I2_FROM_BOOL: [source: Word / SCALAR_WORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_I4_FROM_STR: [source: Dword / FAR_STRING, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_R4_FROM_R8: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_R4_FROM_STR: [source: Dword / FAR_STRING, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_R8_FROM_STR: [source: Dword / FAR_STRING, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_DATE_FROM_STR: [source: Dword / FAR_STRING, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_CY_FROM_STR: [source: Dword / FAR_STRING, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_I2: [source: Word / SIGNED_SCALAR, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_I4: [source: Dword / SIGNED_SCALAR, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_R4: [source_bits: Dword / SCALAR_DWORD, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_R8: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_CY: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_DATE: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_DISP: [source: Dword / Win16ParameterType::FarPointer, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_BOOL: [source: Word / SCALAR_WORD, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VARIANT_CHANGE_TYPE_EX: [destination: Dword / FAR_OUTPUT_BUFFER, source: Dword / FAR_BUFFER, lcid: Dword / SCALAR_DWORD, flags: Word / SCALAR_WORD, target_vartype: Word / SCALAR_WORD]);
parameters!(VAR_UI1_FROM_I2: [source: Word / SIGNED_SCALAR, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_UI1_FROM_I4: [source: Dword / SIGNED_SCALAR, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_UI1_FROM_R4: [source_bits: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_UI1_FROM_R8: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_UI1_FROM_CY: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_UI1_FROM_DATE: [source_high: Dword / SCALAR_DWORD, source_low: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_UI1_FROM_STR: [source: Dword / FAR_STRING, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_UI1_FROM_DISP: [source: Dword / Win16ParameterType::FarPointer, lcid: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_UI1_FROM_BOOL: [source: Word / SCALAR_WORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_I2_FROM_UI1: [source: Word / SCALAR_WORD, result: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VAR_BSTR_FROM_UI1: [source: Word / SCALAR_WORD, lcid: Dword / SCALAR_DWORD, flags: Dword / SCALAR_DWORD, result: Dword / FAR_OUTPUT_BUFFER]);
