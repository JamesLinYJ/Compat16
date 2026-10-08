//! Win16 MSACM stack slots from the project-owned `MSACM` module spec.
//!
//! The SDK 3.1 reference package has no MSACM header. These private descriptors
//! therefore preserve only the declared WORD/DWORD slot widths; semantic
//! names and callback contracts remain owned by the direct ACM marshaller.

use super::*;

macro_rules! params {
    ($name:ident: [$($arg:ident: $kind:ident / $role:expr),* $(,)?]) => {
        pub(super) const $name: &[Win16Parameter] = &[
            $(Win16Parameter {
                name: stringify!($arg),
                kind: ArgumentKind::$kind,
                parameter_type: $role,
            },)*
        ];
    };
}

const W: Win16ParameterType = Win16ParameterType::Scalar;
const D: Win16ParameterType = Win16ParameterType::Scalar;
const P: Win16ParameterType = Win16ParameterType::FarPointer;

params!(DLL_ENTRY_POINT: [a0: Dword / D, a1: Word / W, a2: Word / W,
    a3: Word / W, a4: Dword / D, a5: Word / W]);
params!(METRICS: [a0: Word / W, a1: Word / W, a2: Dword / P]);
params!(DRIVER_ENUM: [a0: Dword / P, a1: Dword / P, a2: Dword / D]);
params!(DRIVER_DETAILS: [a0: Word / W, a1: Dword / P, a2: Dword / D]);
params!(DRIVER_ADD: [a0: Dword / P, a1: Word / W, a2: Dword / P,
    a3: Dword / D, a4: Dword / D]);
params!(DRIVER_REMOVE: [a0: Word / W, a1: Dword / D]);
params!(DRIVER_OPEN: [a0: Dword / P, a1: Word / W, a2: Dword / D]);
params!(DRIVER_CLOSE: [a0: Word / W, a1: Dword / D]);
params!(DRIVER_MESSAGE: [a0: Word / W, a1: Word / W, a2: Dword / D, a3: Dword / D]);
params!(DRIVER_ID: [a0: Word / W, a1: Dword / P, a2: Dword / D]);
params!(DRIVER_PRIORITY: [a0: Word / W, a1: Dword / D, a2: Dword / D]);
params!(OBJECT_DETAILS: [a0: Word / W, a1: Dword / P, a2: Dword / D]);
params!(TAG_ENUM: [a0: Word / W, a1: Dword / P, a2: Dword / P,
    a3: Dword / D, a4: Dword / D]);
params!(ONE_POINTER: [a0: Dword / P]);
params!(FORMAT_SUGGEST: [a0: Word / W, a1: Dword / P, a2: Dword / P,
    a3: Dword / D, a4: Dword / D]);
params!(STREAM_OPEN: [a0: Dword / P, a1: Word / W, a2: Dword / P,
    a3: Dword / P, a4: Dword / P, a5: Dword / D, a6: Dword / D,
    a7: Dword / D]);
params!(OBJECT_FLAGS: [a0: Word / W, a1: Dword / D]);
params!(STREAM_SIZE: [a0: Word / W, a1: Dword / D, a2: Dword / P, a3: Dword / D]);
params!(STREAM_HEADER_FLAGS: [a0: Word / W, a1: Dword / P, a2: Dword / D]);
