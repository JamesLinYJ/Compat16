//! OLE2DISP BSTR, VARIANT, and SAFEARRAY parameter layouts.
//!
//! The parameter slot widths are checked against `ole2disp.spec`. The bundled
//! Windows SDK 3.1 does not include an OLE2DISP header contract, so modern
//! Automation declarations are not treated as proof of historical Win16 ABI.

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

parameters!(SYS_ALLOC_STRING: [string: Dword / FAR_STRING]);
parameters!(SYS_REALLOC_STRING: [destination: Dword / FAR_OUTPUT_BUFFER, string: Dword / FAR_STRING]);
parameters!(SYS_ALLOC_STRING_LEN: [string: Dword / FAR_BUFFER, length: Word / SCALAR_WORD]);
parameters!(SYS_REALLOC_STRING_LEN: [destination: Dword / FAR_OUTPUT_BUFFER, string: Dword / FAR_BUFFER, length: Word / SCALAR_WORD]);
parameters!(SYS_FREE_STRING: [string: Dword / FAR_BUFFER]);
parameters!(SYS_STRING_LEN: [string: Dword / FAR_BUFFER]);
parameters!(VARIANT_INIT: [value: Dword / FAR_OUTPUT_BUFFER]);
parameters!(VARIANT_CLEAR: [value: Dword / FAR_BUFFER]);
parameters!(VARIANT_COPY: [destination: Dword / FAR_OUTPUT_BUFFER, source: Dword / FAR_BUFFER]);
parameters!(VARIANT_COPY_IND: [destination: Dword / FAR_OUTPUT_BUFFER, source: Dword / FAR_BUFFER]);
parameters!(SAFE_ARRAY_CREATE: [element_type: Word / SCALAR_WORD, dimensions: Word / SCALAR_WORD, bounds: Dword / FAR_BUFFER]);
parameters!(SAFE_ARRAY_ONE: [array: Dword / FAR_BUFFER]);
parameters!(SAFE_ARRAY_BOUND: [array: Dword / FAR_BUFFER, dimension: Word / SCALAR_WORD, bound: Dword / FAR_OUTPUT_BUFFER]);
parameters!(SAFE_ARRAY_ACCESS_DATA: [array: Dword / FAR_BUFFER, data: Dword / FAR_OUTPUT_BUFFER]);
parameters!(SAFE_ARRAY_ELEMENT: [array: Dword / FAR_BUFFER, indices: Dword / FAR_BUFFER, value: Dword / FAR_OUTPUT_BUFFER]);
parameters!(SAFE_ARRAY_COPY: [source: Dword / FAR_BUFFER, destination: Dword / FAR_OUTPUT_BUFFER]);
parameters!(SAFE_ARRAY_ALLOC_DESCRIPTOR: [dimensions: Word / SCALAR_WORD, descriptor: Dword / FAR_OUTPUT_BUFFER]);
