//! Fixed PE32 WIN32_FIND_DATA codecs, separate from host pointer-width structs.

use zerocopy::byteorder::{LittleEndian, U16, U32};
use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{DiagnosticKind as Kind, RuntimeError, Win32HostFindData};

// windows-sys describes the native host ABI; PE32 callers instead require a
// fixed-width guest layout with explicit little-endian fields and tail bytes.
#[derive(Clone, Copy, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct FindDataA32 {
    attributes: U32<LittleEndian>,
    creation_time_low: U32<LittleEndian>,
    creation_time_high: U32<LittleEndian>,
    last_access_time_low: U32<LittleEndian>,
    last_access_time_high: U32<LittleEndian>,
    last_write_time_low: U32<LittleEndian>,
    last_write_time_high: U32<LittleEndian>,
    file_size_high: U32<LittleEndian>,
    file_size_low: U32<LittleEndian>,
    reserved0: U32<LittleEndian>,
    reserved1: U32<LittleEndian>,
    file_name: [u8; 260],
    alternate_file_name: [u8; 14],
    tail_padding: [u8; 2],
}

#[derive(Clone, Copy, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct FindDataW32 {
    attributes: U32<LittleEndian>,
    creation_time_low: U32<LittleEndian>,
    creation_time_high: U32<LittleEndian>,
    last_access_time_low: U32<LittleEndian>,
    last_access_time_high: U32<LittleEndian>,
    last_write_time_low: U32<LittleEndian>,
    last_write_time_high: U32<LittleEndian>,
    file_size_high: U32<LittleEndian>,
    file_size_low: U32<LittleEndian>,
    reserved0: U32<LittleEndian>,
    reserved1: U32<LittleEndian>,
    file_name: [U16<LittleEndian>; 260],
    alternate_file_name: [U16<LittleEndian>; 14],
}

pub(super) fn encode_ansi(data: &Win32HostFindData) -> Result<[u8; 320], RuntimeError> {
    let Win32HostFindData::Ansi {
        attributes, creation_time_low, creation_time_high,
        last_access_time_low, last_access_time_high,
        last_write_time_low, last_write_time_high,
        file_size_high, file_size_low, reserved0, reserved1,
        file_name, alternate_file_name,
    } = data else {
        return Err(invariant("ANSI find service returned wide WIN32_FIND_DATA"));
    };
    let wire = FindDataA32 {
        attributes: U32::new(*attributes),
        creation_time_low: U32::new(*creation_time_low),
        creation_time_high: U32::new(*creation_time_high),
        last_access_time_low: U32::new(*last_access_time_low),
        last_access_time_high: U32::new(*last_access_time_high),
        last_write_time_low: U32::new(*last_write_time_low),
        last_write_time_high: U32::new(*last_write_time_high),
        file_size_high: U32::new(*file_size_high),
        file_size_low: U32::new(*file_size_low),
        reserved0: U32::new(*reserved0),
        reserved1: U32::new(*reserved1),
        file_name: *file_name,
        alternate_file_name: *alternate_file_name,
        tail_padding: [0; 2],
    };
    let mut bytes = [0_u8; FindDataA32::BYTE_LEN];
    bytes.copy_from_slice(wire.as_bytes());
    Ok(bytes)
}

pub(super) fn encode_wide(data: &Win32HostFindData) -> Result<[u8; 592], RuntimeError> {
    let Win32HostFindData::Wide {
        attributes, creation_time_low, creation_time_high,
        last_access_time_low, last_access_time_high,
        last_write_time_low, last_write_time_high,
        file_size_high, file_size_low, reserved0, reserved1,
        file_name, alternate_file_name,
    } = data else {
        return Err(invariant("wide find service returned ANSI WIN32_FIND_DATA"));
    };
    let wire = FindDataW32 {
        attributes: U32::new(*attributes),
        creation_time_low: U32::new(*creation_time_low),
        creation_time_high: U32::new(*creation_time_high),
        last_access_time_low: U32::new(*last_access_time_low),
        last_access_time_high: U32::new(*last_access_time_high),
        last_write_time_low: U32::new(*last_write_time_low),
        last_write_time_high: U32::new(*last_write_time_high),
        file_size_high: U32::new(*file_size_high),
        file_size_low: U32::new(*file_size_low),
        reserved0: U32::new(*reserved0),
        reserved1: U32::new(*reserved1),
        file_name: core::array::from_fn(|index| U16::new(file_name[index])),
        alternate_file_name: core::array::from_fn(|index| U16::new(alternate_file_name[index])),
    };
    let mut bytes = [0_u8; FindDataW32::BYTE_LEN];
    bytes.copy_from_slice(wire.as_bytes());
    Ok(bytes)
}

impl FindDataA32 {
    const BYTE_LEN: usize = core::mem::size_of::<Self>();
}

impl FindDataW32 {
    const BYTE_LEN: usize = core::mem::size_of::<Self>();
}

const _: () = {
    assert!(FindDataA32::BYTE_LEN == 320);
    assert!(FindDataA32::BYTE_LEN == 44 + 260 + 14 + 2);
    assert!(core::mem::align_of::<FindDataA32>() == 1);
    assert!(core::mem::offset_of!(FindDataA32, attributes) == 0);
    assert!(core::mem::offset_of!(FindDataA32, creation_time_low) == 4);
    assert!(core::mem::offset_of!(FindDataA32, creation_time_high) == 8);
    assert!(core::mem::offset_of!(FindDataA32, last_access_time_low) == 12);
    assert!(core::mem::offset_of!(FindDataA32, last_access_time_high) == 16);
    assert!(core::mem::offset_of!(FindDataA32, last_write_time_low) == 20);
    assert!(core::mem::offset_of!(FindDataA32, last_write_time_high) == 24);
    assert!(core::mem::offset_of!(FindDataA32, file_size_high) == 28);
    assert!(core::mem::offset_of!(FindDataA32, file_size_low) == 32);
    assert!(core::mem::offset_of!(FindDataA32, reserved0) == 36);
    assert!(core::mem::offset_of!(FindDataA32, reserved1) == 40);
    assert!(core::mem::offset_of!(FindDataA32, file_name) == 44);
    assert!(core::mem::offset_of!(FindDataA32, alternate_file_name) == 304);
    assert!(core::mem::offset_of!(FindDataA32, tail_padding) == 318);
    assert!(FindDataW32::BYTE_LEN == 592);
    assert!(FindDataW32::BYTE_LEN == 44 + 520 + 28);
    assert!(core::mem::align_of::<FindDataW32>() == 1);
    assert!(core::mem::offset_of!(FindDataW32, attributes) == 0);
    assert!(core::mem::offset_of!(FindDataW32, creation_time_low) == 4);
    assert!(core::mem::offset_of!(FindDataW32, creation_time_high) == 8);
    assert!(core::mem::offset_of!(FindDataW32, last_access_time_low) == 12);
    assert!(core::mem::offset_of!(FindDataW32, last_access_time_high) == 16);
    assert!(core::mem::offset_of!(FindDataW32, last_write_time_low) == 20);
    assert!(core::mem::offset_of!(FindDataW32, last_write_time_high) == 24);
    assert!(core::mem::offset_of!(FindDataW32, file_size_high) == 28);
    assert!(core::mem::offset_of!(FindDataW32, file_size_low) == 32);
    assert!(core::mem::offset_of!(FindDataW32, reserved0) == 36);
    assert!(core::mem::offset_of!(FindDataW32, reserved1) == 40);
    assert!(core::mem::offset_of!(FindDataW32, file_name) == 44);
    assert!(core::mem::offset_of!(FindDataW32, alternate_file_name) == 564);
};

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
