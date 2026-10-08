//! DOS 3+ process environment serialization, independent of host encoding.

use crate::{DiagnosticKind, RuntimeError};
use dos_kernel::DosErrorCode;
use guest_core::{GuestMemory, real_address};

pub(crate) struct EnvironmentBlock {
    pub(crate) bytes: Vec<u8>,
    pub(crate) paragraphs: u16,
}

impl EnvironmentBlock {
    pub(crate) fn new(entries: &[Vec<u8>], program_path: &[u8]) -> Result<Self, RuntimeError> {
        // Each entry has a NUL terminator, followed by the list's extra NUL.
        // An empty list still has two NULs. DOS 3+ follows the list with a
        // string count word and the executable's full guest path.
        let mut length = 1 + usize::from(entries.is_empty()) + 2 + program_path.len() + 1;
        for entry in entries {
            if entry.contains(&0) || !entry.iter().position(|&byte| byte == b'=')
                .is_some_and(|separator| separator > 0)
            {
                return Err(RuntimeError::new(DiagnosticKind::InvalidInput,
                    "DOS environment entry must be NAME=VALUE without embedded NUL bytes"));
            }
            length = length.checked_add(entry.len()).and_then(|n| n.checked_add(1))
                .ok_or_else(|| RuntimeError::new(DiagnosticKind::InvalidInput,
                    "DOS environment size overflows the address space"))?;
        }
        // Environment traversal uses a 16-bit offset within a single segment.
        if length > usize::from(u16::MAX) {
            return Err(RuntimeError::new(DiagnosticKind::InvalidInput,
                "inherited environment exceeds the DOS 64 KiB segment limit"));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
            DiagnosticKind::ResourceExhausted, "allocate DOS process environment", error))?;
        for entry in entries {
            bytes.extend_from_slice(entry);
            bytes.push(0);
        }
        if entries.is_empty() { bytes.push(0); }
        bytes.push(0);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(program_path);
        bytes.push(0);
        Ok(Self { bytes, paragraphs: length.div_ceil(16) as u16 })
    }

    /// DOS EXEC gives each child a copy of the selected environment block.
    /// Only variable strings are inherited; the DOS 3+ trailer names the child.
    pub(crate) fn copy_for_child(
        memory: &impl GuestMemory,
        source_segment: u16,
        program_path: &[u8],
    ) -> Result<Self, DosErrorCode> {
        if source_segment == 0 || program_path.contains(&0) {
            return Err(DosErrorCode::InvalidEnvironment);
        }
        let mut bytes = Vec::new();
        let mut previous_nul = false;
        let mut complete = false;
        for offset in 0..=u16::MAX {
            let byte = memory.read_u8(real_address(source_segment, offset))
                .map_err(|_| DosErrorCode::InvalidEnvironment)?;
            bytes.try_reserve(1).map_err(|_| DosErrorCode::InsufficientMemory)?;
            bytes.push(byte);
            if byte == 0 && previous_nul {
                complete = true;
                break;
            }
            previous_nul = byte == 0;
        }
        if !complete { return Err(DosErrorCode::InvalidEnvironment); }
        let length = bytes.len().checked_add(2)
            .and_then(|size| size.checked_add(program_path.len()))
            .and_then(|size| size.checked_add(1))
            .ok_or(DosErrorCode::InvalidEnvironment)?;
        if length > usize::from(u16::MAX) {
            return Err(DosErrorCode::InvalidEnvironment);
        }
        bytes.try_reserve(length - bytes.len())
            .map_err(|_| DosErrorCode::InsufficientMemory)?;
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(program_path);
        bytes.push(0);
        Ok(Self { bytes, paragraphs: length.div_ceil(16) as u16 })
    }
}
