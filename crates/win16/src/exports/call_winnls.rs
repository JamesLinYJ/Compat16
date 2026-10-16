//! Checked stack and guest-memory decoding for WINNLS profile APIs.

use crate::exports::Win16ExportDescriptor;
use crate::winnls_abi::{IMEPRO16_NAME_OFFSET, IMEPRO16_NAME_SIZE, IMEPRO16_SIZE};
use crate::{Access, SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

use super::request::Win16WinnlsRequest;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16WinnlsRequest, Win16Error> {
    if !descriptor.module().eq_ignore_ascii_case("WINNLS")
        || arguments.len() != descriptor.parameters.len()
    {
        return Err(Win16Error::InvalidRange);
    }

    match (descriptor.ordinal(), arguments) {
        (16, [Win16Argument::Word(hwnd), Win16Argument::Word(enable)]) => {
            Ok(Win16WinnlsRequest::EnableIme {
                hwnd: *hwnd,
                enable: *enable != 0,
            })
        }
        (18, [Win16Argument::Word(hwnd)]) => {
            Ok(Win16WinnlsRequest::GetEnableStatus { hwnd: *hwnd })
        }
        (22, [Win16Argument::Dword(profile_far)]) => {
            let (name, output) = query_profile(*profile_far, selectors, memory);
            Ok(Win16WinnlsRequest::QueryIme { name, output })
        }
        (23, [Win16Argument::Word(hwnd), Win16Argument::Dword(profile_far)]) => {
            Ok(Win16WinnlsRequest::GetIme {
                hwnd: *hwnd,
                output: writable_profile_pointer(*profile_far, selectors, memory),
            })
        }
        (24, [Win16Argument::Word(hwnd), Win16Argument::Dword(profile_far)]) => {
            Ok(Win16WinnlsRequest::SetIme {
                hwnd: *hwnd,
                name: readable_profile_name(*profile_far, selectors, memory),
            })
        }
        (25, [Win16Argument::Dword(_), Win16Argument::Dword(_)])
        | (26 | 27, [Win16Argument::Dword(_)]) => {
            Ok(Win16WinnlsRequest::UnsupportedProfileMutation)
        }
        _ => Err(Win16Error::InvalidRange),
    }
}

fn query_profile(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> (
    Option<[u8; IMEPRO16_NAME_SIZE]>,
    Option<crate::SegmentedPointer>,
) {
    let Some(output) = writable_profile_pointer(far, selectors, memory) else {
        return (None, None);
    };
    let Ok(name_pointer) = selectors.add_bytes(output, IMEPRO16_NAME_OFFSET as u32) else {
        return (None, None);
    };
    let mut first_name_byte = [0_u8; 1];
    if selectors
        .read(memory, name_pointer, &mut first_name_byte)
        .is_err()
    {
        return (None, None);
    }
    if first_name_byte[0] == 0 {
        // The target's empty-name form initializes the native profile and
        // reads no other guest fields before querying available profiles.
        return (Some([0; IMEPRO16_NAME_SIZE]), Some(output));
    }

    match readable_profile_name(far, selectors, memory) {
        Some(name) => (Some(name), Some(output)),
        None => (None, None),
    }
}

fn writable_profile_pointer(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Option<crate::SegmentedPointer> {
    if far == 0 {
        return None;
    }
    let pointer = selectors.pointer_from_far(far).ok()?;
    selectors
        .translate(pointer, Access::Write, IMEPRO16_SIZE, memory)
        .ok()?;
    Some(pointer)
}

fn readable_profile_name(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Option<[u8; IMEPRO16_NAME_SIZE]> {
    if far == 0 {
        return None;
    }
    let pointer = selectors.pointer_from_far(far).ok()?;
    let name_pointer = selectors
        .add_bytes(pointer, IMEPRO16_NAME_OFFSET as u32)
        .ok()?;
    let mut name = [0_u8; IMEPRO16_NAME_SIZE];
    selectors.read(memory, name_pointer, &mut name).ok()?;
    Some(name)
}
