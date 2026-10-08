//! Guest-buffer handling for KERNEL profile-section queries.

use guest_core::memory::Memory;
use win16_abi::{Win16KernelProfileSectionRequest, Win16OutputBuffer};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

/// Execute an owned KERNEL profile-section request through the host boundary.
pub(super) fn dispatch(
    state: &Win16State,
    request: &Win16KernelProfileSectionRequest,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    match request {
        Win16KernelProfileSectionRequest::WriteProfileSection { section, entries } => {
            Ok(u32::from(host.win16_system_profile_section_write(
                section.as_deref(), entries.as_deref(),
            )?))
        }
        Win16KernelProfileSectionRequest::WritePrivateProfileSection {
            section, entries, filename,
        } => Ok(u32::from(host.win16_profile_section_write(
            section.as_deref(), entries.as_deref(), filename.as_deref(),
        )?)),
        Win16KernelProfileSectionRequest::GetProfileSection {
            section, output_buffer,
        } => {
            let capacity = output_buffer.map_or(0, |output| output.capacity);
            let (bytes, copied) = host.win16_system_profile_section(
                section.as_deref(), capacity,
            )?;
            write_section_result(state, *output_buffer, bytes, copied, memory)
        }
        Win16KernelProfileSectionRequest::GetPrivateProfileSection {
            section, output_buffer, filename,
        } => {
            let capacity = output_buffer.map_or(0, |output| output.capacity);
            let (bytes, copied) = host.win16_profile_section(
                section.as_deref(), filename.as_deref(), capacity,
            )?;
            write_section_result(state, *output_buffer, bytes, copied, memory)
        }
    }
}

fn write_section_result(
    state: &Win16State,
    output: Option<Win16OutputBuffer>,
    bytes: Vec<u8>,
    copied: u16,
    memory: &mut Memory,
) -> Result<u32, RuntimeError> {
    let Some(output) = output else {
        if !bytes.is_empty() || copied != 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "zero-capacity Win16 profile-section host result was not empty"));
        }
        return Ok(0);
    };

    let capacity = usize::from(output.capacity);
    let copied = usize::from(copied);
    if capacity == 0 && bytes.is_empty() && copied == 0 {
        return Ok(0);
    }
    if bytes.len() > capacity || copied >= capacity {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 profile-section host returned an oversized output"));
    }

    // The truncation count is a capacity sentinel, not the encoded prefix
    // length. Write only the actual terminated guest bytes; a complete DBCS
    // character may leave unused space before the reported nSize-2 count.
    let written = if capacity == 1 && copied == 0 && bytes.first() == Some(&0) {
        1
    } else {
        bytes.windows(2).position(|pair| pair == [0, 0]).map(|end| end + 2)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 profile-section host returned an unterminated MULTI_SZ"))?
    };
    let count_matches = if copied == 0 {
        bytes.first() == Some(&0) && written == capacity.min(2)
    } else {
        copied == capacity.saturating_sub(2) || written == copied + 1
    };
    if !count_matches {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 profile-section count does not describe its MULTI_SZ result"));
    }
    state.write_output(memory, output, &bytes[..written])?;
    Ok(copied as u32)
}
