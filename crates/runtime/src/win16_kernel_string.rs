//! KERNEL bounded ANSI string helpers over checked guest selectors.

use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer, Win16OutputBuffer};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    pub(super) fn kernel_lstrcpyn(
        &self,
        destination: u32,
        source: &[u8],
        limit: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let capacity = i16::from_le_bytes(limit.to_le_bytes());
        if capacity <= 0 { return Ok(0); }
        let Ok(pointer) = self.selectors.pointer_from_far(destination) else { return Ok(0); };
        let capacity = capacity as u16;
        if !self.kernel_string_range_valid(pointer, usize::from(capacity), Access::Write, memory) {
            return Ok(0);
        }
        let count = source.len().min(usize::from(capacity.saturating_sub(1)));
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(count + 1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate Win16 lstrcpyn output", error,
        ))?;
        bytes.extend_from_slice(&source[..count]);
        bytes.push(0);
        self.write_output(memory, Win16OutputBuffer { pointer, capacity }, &bytes)?;
        Ok(destination)
    }

    pub(super) fn kernel_lstrcatn(
        &self,
        destination: u32,
        source: &[u8],
        limit: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let capacity = i16::from_le_bytes(limit.to_le_bytes());
        if capacity <= 0 { return Ok(destination); }
        let Ok(pointer) = self.selectors.pointer_from_far(destination) else { return Ok(0); };
        let capacity = capacity as u16;
        let length = usize::from(capacity);
        if !self.kernel_string_range_valid(pointer, length, Access::Read, memory)
            || !self.kernel_string_range_valid(pointer, length, Access::Write, memory)
        {
            return Ok(0);
        }
        let mut cursor = pointer;
        let mut destination_length = None;
        for index in 0..length {
            let mut byte = [0_u8; 1];
            self.selectors.read(memory, cursor, &mut byte).map_err(crate::runtime_error)?;
            if byte[0] == 0 {
                destination_length = Some(index);
                break;
            }
            if index + 1 < length {
                cursor = self.selectors.add_bytes(cursor, 1).map_err(crate::runtime_error)?;
            }
        }
        let Some(destination_length) = destination_length else { return Ok(0); };
        let remaining = length - destination_length;
        let count = source.len().min(remaining.saturating_sub(1));
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(count + 1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate Win16 lstrcatn output", error,
        ))?;
        bytes.extend_from_slice(&source[..count]);
        bytes.push(0);
        let mut output = pointer;
        if destination_length != 0 {
            output = self.selectors.add_bytes(pointer, destination_length as u32)
                .map_err(crate::runtime_error)?;
        }
        self.write_output(memory, Win16OutputBuffer {
            pointer: output,
            capacity: remaining as u16,
        }, &bytes)?;
        Ok(destination)
    }

    fn kernel_string_range_valid(
        &self,
        pointer: SegmentedPointer,
        length: usize,
        access: Access,
        memory: &Memory,
    ) -> bool {
        let mut current = pointer;
        let mut remaining = length;
        while remaining != 0 {
            let Ok(descriptor) = self.selectors.describe(current.selector()) else { return false; };
            let Some(available) = descriptor.limit.checked_sub(u32::from(current.offset()))
                .and_then(|bytes| bytes.checked_add(1))
                .and_then(|bytes| usize::try_from(bytes).ok())
            else { return false; };
            let chunk = remaining.min(available);
            if chunk == 0 || self.selectors.translate(current, access, chunk, memory).is_err() {
                return false;
            }
            remaining -= chunk;
            if remaining != 0 {
                let Ok(chunk) = u32::try_from(chunk) else { return false; };
                let Ok(next) = self.selectors.add_bytes(current, chunk) else { return false; };
                current = next;
            }
        }
        true
    }
}
