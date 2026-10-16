//! Checked transfers for guest text, including shared-allocation selector spans.

use guest_core::{GuestMemory, PhysAddr};
use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

struct TextChunk {
    address: PhysAddr,
    offset: usize,
    length: usize,
}

/// Prepared destination for one synchronous transfer while guest execution is
/// stopped. All ranges and rollback bytes are acquired before host I/O; callers
/// must not execute guest callbacks or change mappings before committing it.
pub(super) struct PreparedTextWrite {
    chunks: Vec<TextChunk>,
    previous: Vec<u8>,
}

impl PreparedTextWrite {
    /// Commit only the actual returned prefix, without allocating another
    /// transfer buffer after a native file operation has advanced its cursor.
    pub(super) fn commit(self, memory: &mut Memory, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes.len() > self.previous.len() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 transfer exceeded its prepared destination"));
        }
        for (index, chunk) in self.chunks.iter().enumerate() {
            let length = chunk.length.min(bytes.len().saturating_sub(chunk.offset));
            if length == 0 { break; }
            if let Err(write_error) = memory.write(chunk.address,
                &bytes[chunk.offset..chunk.offset + length])
            {
                for rollback in self.chunks[..=index].iter().rev() {
                    let length = rollback.length.min(bytes.len().saturating_sub(rollback.offset));
                    if let Err(rollback_error) = memory.write(rollback.address,
                        &self.previous[rollback.offset..rollback.offset + length])
                    {
                        return Err(RuntimeError::with_source(Kind::InternalInvariant,
                            format!("Win16 text write failed ({write_error}) and rollback failed"),
                            rollback_error));
                    }
                }
                return Err(RuntimeError::with_source(Kind::GuestFault,
                    "Win16 text transfer could not commit its guest bytes", write_error));
            }
        }
        Ok(())
    }
}

impl Win16State {
    pub(super) fn read_z_string(
        &self,
        memory: &Memory,
        far: u32,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if far == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        let descriptor = self.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
        let available = descriptor.limit.checked_sub(u32::from(pointer.offset()))
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 string begins outside its selector"))?;
        let count = usize::try_from(available).unwrap_or(usize::MAX).min(maximum);
        let bytes = self.read_text_bytes(memory, pointer, count)?;
        let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault,
                "Win16 string has no terminator within its selector")
        })?;
        Ok(Some(bytes[..end].to_vec()))
    }


    pub(super) fn validate_callback_buffer(&self, memory: &Memory, far: u32,
        access: Access, bytes: u32) -> Result<(), RuntimeError> {
        if bytes == 0 { return Ok(()); }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        self.text_chunks(memory, pointer, bytes as usize, access).map(|_| ())
    }

    fn text_chunks(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
        length: usize,
        access: Access,
    ) -> Result<Vec<TextChunk>, RuntimeError> {
        let mut chunks = Vec::new();
        let mut consumed = 0;
        while consumed < length {
            let current = self.selectors.add_bytes(pointer,
                u32::try_from(consumed).map_err(|error| RuntimeError::with_source(
                    Kind::GuestFault, "Win16 text offset exceeds the guest address space", error))?)
                .map_err(crate::runtime_error)?;
            let descriptor = self.selectors.describe(current.selector())
                .map_err(crate::runtime_error)?;
            let available = descriptor.limit.checked_sub(u32::from(current.offset()))
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                    "Win16 text extends beyond its data selector"))? as usize;
            let count = available.min(length - consumed);
            let address = self.selectors.translate(current, access, count, memory)
                .map_err(crate::runtime_error)?;
            chunks.try_reserve(1).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve Win16 text transfer ranges", error))?;
            chunks.push(TextChunk { address, offset: consumed, length: count });
            consumed += count;
        }
        Ok(chunks)
    }

    pub(super) fn read_text_bytes(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
        length: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        let chunks = self.text_chunks(memory, pointer, length, Access::Read)?;
        let mut bytes = text_buffer(length)?;
        for chunk in chunks {
            memory.read(chunk.address, &mut bytes[chunk.offset..chunk.offset + chunk.length])
                .map_err(crate::runtime_error)?;
        }
        Ok(bytes)
    }

    pub(super) fn write_text_bytes(
        &self,
        memory: &mut Memory,
        pointer: SegmentedPointer,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        self.prepare_text_write(memory, pointer, bytes.len())?.commit(memory, bytes)
    }

    pub(super) fn prepare_text_write(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
        length: usize,
    ) -> Result<PreparedTextWrite, RuntimeError> {
        // Resolve all selectors, permissions and backing ranges first. A
        // failure in a later selector must not leave an earlier one changed.
        let chunks = self.text_chunks(memory, pointer, length, Access::Write)?;
        for chunk in &chunks {
            memory.validate_read(chunk.address, chunk.length).map_err(crate::runtime_error)?;
        }
        let mut previous = text_buffer(length)?;
        for chunk in &chunks {
            memory.read(chunk.address,
                &mut previous[chunk.offset..chunk.offset + chunk.length])
                .map_err(crate::runtime_error)?;
        }
        Ok(PreparedTextWrite { chunks, previous })
    }

    /// Validate a caller-owned output range before invoking a host API that
    /// will fill it. This follows the same alias-aware selector walk and
    /// write checks as `write_text_bytes`, without changing guest memory.
    pub(super) fn preflight_text_write(
        &self,
        memory: &Memory,
        pointer: SegmentedPointer,
        length: usize,
    ) -> Result<(), RuntimeError> {
        let chunks = self.text_chunks(memory, pointer, length, Access::Write)?;
        for chunk in chunks {
            memory.validate_write(chunk.address, chunk.length)
                .map_err(crate::runtime_error)?;
        }
        Ok(())
    }

    /// Read the character sequence preceding `current`, without looking past
    /// it for a terminator. The pointers may name aliases of the same bytes.
    pub(super) fn text_prefix(
        &self,
        memory: &Memory,
        start: SegmentedPointer,
        current: SegmentedPointer,
    ) -> Result<Vec<u8>, RuntimeError> {
        let first_address = self.selectors.translate(start, Access::Read, 0, memory)
            .map_err(crate::runtime_error)?;
        let current_address = self.selectors.translate(current, Access::Read, 0, memory)
            .map_err(crate::runtime_error)?;
        let length = current_address.0.checked_sub(first_address.0)
            .filter(|&length| length <= win16_abi::MAX_WIN16_STRING_BYTES as u32)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 AnsiPrev pointers do not describe a bounded forward string range"))?
            as usize;
        // Equal physical distances alone would accept a separate allocation
        // immediately following this one. Walk within the start allocation
        // before accepting a different selector as an alias of its endpoint.
        let endpoint = self.selectors.add_bytes(start, length as u32)
            .map_err(crate::runtime_error)?;
        if self.selectors.translate(endpoint, Access::Read, 0, memory)
            .map_err(crate::runtime_error)? != current_address
        {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 AnsiPrev current pointer is outside its string allocation"));
        }
        let chunks = self.text_chunks(memory, start, length, Access::Read)?;
        for chunk in chunks {
            if first_address.0.checked_add(chunk.offset as u32) != Some(chunk.address.0) {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 AnsiPrev pointers do not share contiguous string storage"));
            }
        }
        self.read_text_bytes(memory, start, length)
    }
}

fn text_buffer(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 text transfer buffer", error))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
