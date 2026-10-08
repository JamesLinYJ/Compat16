//! Private, alignment-one representations for the fixed Win16 Automation layouts.

use zerocopy::byteorder::little_endian::{I32, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct BstrLengthPrefix16Wire {
    pub(super) byte_length: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct Variant16Wire {
    pub(super) vartype: U16,
    pub(super) reserved: [U16; 3],
    pub(super) payload: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct SafeArray16HeaderWire {
    pub(super) dimensions: U16,
    pub(super) features: U16,
    pub(super) element_size: U16,
    pub(super) locks: U16,
    pub(super) handle: U32,
    pub(super) data: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct SafeArrayBound16Wire {
    pub(super) elements: U32,
    pub(super) lower_bound: I32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct DispParams16Wire {
    pub(super) arguments: U32,
    pub(super) named_dispids: U32,
    pub(super) argument_count: U16,
    pub(super) named_count: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct ExcepInfo16Wire {
    pub(super) code: U16,
    pub(super) reserved: U16,
    pub(super) source: U32,
    pub(super) description: U32,
    pub(super) help_file: U32,
    pub(super) help_context: U32,
    pub(super) reserved_pointer: U32,
    pub(super) deferred_fill: U32,
    pub(super) scode: I32,
}

const _: () = {
    assert!(core::mem::size_of::<BstrLengthPrefix16Wire>() == 4);
    assert!(core::mem::align_of::<BstrLengthPrefix16Wire>() == 1);
    assert!(core::mem::size_of::<Variant16Wire>() == 16);
    assert!(core::mem::align_of::<Variant16Wire>() == 1);
    assert!(core::mem::offset_of!(Variant16Wire, vartype) == 0);
    assert!(core::mem::offset_of!(Variant16Wire, reserved) == 2);
    assert!(core::mem::offset_of!(Variant16Wire, payload) == 8);
    assert!(core::mem::size_of::<SafeArray16HeaderWire>() == 16);
    assert!(core::mem::align_of::<SafeArray16HeaderWire>() == 1);
    assert!(core::mem::offset_of!(SafeArray16HeaderWire, dimensions) == 0);
    assert!(core::mem::offset_of!(SafeArray16HeaderWire, features) == 2);
    assert!(core::mem::offset_of!(SafeArray16HeaderWire, element_size) == 4);
    assert!(core::mem::offset_of!(SafeArray16HeaderWire, locks) == 6);
    assert!(core::mem::offset_of!(SafeArray16HeaderWire, handle) == 8);
    assert!(core::mem::offset_of!(SafeArray16HeaderWire, data) == 12);
    assert!(core::mem::size_of::<SafeArrayBound16Wire>() == 8);
    assert!(core::mem::align_of::<SafeArrayBound16Wire>() == 1);
    assert!(core::mem::offset_of!(SafeArrayBound16Wire, elements) == 0);
    assert!(core::mem::offset_of!(SafeArrayBound16Wire, lower_bound) == 4);
    assert!(core::mem::size_of::<DispParams16Wire>() == 12);
    assert!(core::mem::align_of::<DispParams16Wire>() == 1);
    assert!(core::mem::offset_of!(DispParams16Wire, arguments) == 0);
    assert!(core::mem::offset_of!(DispParams16Wire, named_dispids) == 4);
    assert!(core::mem::offset_of!(DispParams16Wire, argument_count) == 8);
    assert!(core::mem::offset_of!(DispParams16Wire, named_count) == 10);
    assert!(core::mem::size_of::<ExcepInfo16Wire>() == 32);
    assert!(core::mem::align_of::<ExcepInfo16Wire>() == 1);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, code) == 0);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, reserved) == 2);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, source) == 4);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, description) == 8);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, help_file) == 12);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, help_context) == 16);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, reserved_pointer) == 20);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, deferred_fill) == 24);
    assert!(core::mem::offset_of!(ExcepInfo16Wire, scode) == 28);
};
