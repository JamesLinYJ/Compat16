//! Typed decoder for KERNEL profile-section queries.

use guest_core::GuestMemory;

use super::call::call_helpers::{
    checked_output_buffer, dword_argument, read_nullable_far_string, word_argument,
};
use super::request::Win16KernelProfileSectionRequest;
use super::Win16ExportDescriptor;
use crate::{SelectorTable, Win16Argument, Win16Error};

/// Decode the profile-section family without depending on the top-level request enum.
pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16KernelProfileSectionRequest>, Win16Error> {
    if !descriptor.id.module().eq_ignore_ascii_case("KERNEL") {
        return Ok(None);
    }

    let request = match descriptor.id.ordinal() {
        416 => Win16KernelProfileSectionRequest::WritePrivateProfileSection {
            section: read_optional_string_argument(0, arguments, selectors, memory)?,
            entries: read_optional_multistring_argument(1, arguments, selectors, memory)?,
            filename: read_optional_string_argument(2, arguments, selectors, memory)?,
        },
        417 => Win16KernelProfileSectionRequest::WriteProfileSection {
            section: read_optional_string_argument(0, arguments, selectors, memory)?,
            entries: read_optional_multistring_argument(1, arguments, selectors, memory)?,
        },
        418 => Win16KernelProfileSectionRequest::GetPrivateProfileSection {
            section: read_optional_string_argument(0, arguments, selectors, memory)?,
            output_buffer: read_output_buffer(1, 2, arguments, selectors, memory)?,
            filename: read_optional_string_argument(3, arguments, selectors, memory)?,
        },
        419 => Win16KernelProfileSectionRequest::GetProfileSection {
            section: read_optional_string_argument(0, arguments, selectors, memory)?,
            output_buffer: read_output_buffer(1, 2, arguments, selectors, memory)?,
        },
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn read_optional_string_argument(
    index: usize,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    read_nullable_far_string(dword_argument(arguments, index)?, selectors, memory)
}

fn read_optional_multistring_argument(
    index: usize,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    read_far_multistring(dword_argument(arguments, index)?, selectors, memory)
}

fn read_output_buffer(
    pointer_index: usize,
    capacity_index: usize,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<crate::Win16OutputBuffer>, Win16Error> {
    let capacity = word_argument(arguments, capacity_index)?;
    if capacity == 0 {
        // A zero-capacity profile query does not access the guest pointer.
        return Ok(None);
    }
    checked_output_buffer(
        dword_argument(arguments, pointer_index)?,
        capacity,
        selectors,
        memory,
    ).map(Some)
}

fn read_far_multistring(
    far_pointer: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    // The shared ANSI-Z reader stops at one NUL; these profile inputs require a
    // double-NUL list. Read through SelectorTable so guest FAR data stays checked
    // and is copied before crossing into the host boundary.
    if far_pointer == 0 {
        return Ok(None);
    }

    let mut pointer = selectors.pointer_from_far(far_pointer)?;
    let mut bytes = Vec::new();
    let mut previous_was_nul = false;
    for _ in 0..super::MAX_WIN16_STRING_BYTES {
        let mut byte = [0_u8; 1];
        selectors.read(memory, pointer, &mut byte)?;
        bytes.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        bytes.push(byte[0]);
        if byte[0] == 0 && previous_was_nul {
            return Ok(Some(bytes));
        }
        previous_was_nul = byte[0] == 0;
        pointer = selectors.add_bytes(pointer, 1)?;
    }
    Err(Win16Error::InvalidRange)
}
