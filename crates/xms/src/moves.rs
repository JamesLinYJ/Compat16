use guest_core::{GuestMemory, MemoryError, PhysAddr};

use crate::model::{MoveRequest, XmsError, BIOS_ROM_START, KIB};
use crate::service::{zeroed_vec, XmsService};

impl XmsService {
    /// Move bytes using a decoded XMS move request.
    pub fn move_block(
        &self,
        request: MoveRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<(), XmsError> {
        if request.length & 1 != 0 {
            return Err(XmsError::InvalidLength);
        }

        let source_address = self.resolve_move_address(
            request.source_handle,
            request.source_offset,
            request.length,
            false,
        )?;
        let destination_address = self.resolve_move_address(
            request.destination_handle,
            request.destination_offset,
            request.length,
            true,
        )?;
        if request.length == 0 {
            return Ok(());
        }

        let source_end = source_address
            .0
            .checked_add(request.length)
            .ok_or(XmsError::InvalidLength)?;
        let destination_end = destination_address
            .0
            .checked_add(request.length)
            .ok_or(XmsError::InvalidLength)?;

        // The original XMS implementation permits the documented forward
        // overlap and rejects the reverse direction before changing memory.
        if destination_address.0 < source_address.0 && destination_end > source_address.0 {
            return Err(XmsError::InvalidMoveOverlap);
        }
        if destination_address.0 < 0x0010_0000 && destination_end > BIOS_ROM_START {
            return Err(XmsError::InvalidLength);
        }
        if source_end > memory.len() || destination_end > memory.len() {
            let address = if source_end > memory.len() {
                source_address.0
            } else {
                destination_address.0
            };
            return Err(XmsError::Memory(MemoryError::OutOfBounds {
                address,
                length: usize::try_from(request.length).unwrap_or(usize::MAX),
            }));
        }

        let length = usize::try_from(request.length).map_err(|_| XmsError::InvalidLength)?;
        let mut contents = zeroed_vec(length)?;
        memory.read(source_address, &mut contents)?;
        memory.write(destination_address, &contents)?;
        Ok(())
    }

    /// Read and execute the packed move descriptor at `descriptor_address`.
    /// Runtime code with an A20-aware bus should prepare the descriptor first
    /// and call `handle_prepared_call` instead.
    pub fn move_from_descriptor(
        &self,
        descriptor_address: PhysAddr,
        memory: &mut impl GuestMemory,
    ) -> Result<(), XmsError> {
        let mut bytes = [0; MoveRequest::BYTE_LEN];
        memory.read(descriptor_address, &mut bytes)?;
        self.move_block(MoveRequest::decode(&bytes)?, memory)
    }

    fn resolve_move_address(
        &self,
        handle: u16,
        offset: u32,
        length: u32,
        destination: bool,
    ) -> Result<PhysAddr, XmsError> {
        if handle == 0 {
            let segment = offset >> 16;
            let real_offset = offset & 0xffff;
            let physical = segment
                .checked_mul(16)
                .and_then(|base| base.checked_add(real_offset))
                .ok_or_else(|| self.invalid_pointer_offset(destination))?;
            let capacity = self
                .config
                .arena_start
                .0
                .checked_sub(physical)
                .ok_or_else(|| self.invalid_pointer_offset(destination))?;
            if length > capacity {
                return Err(XmsError::InvalidLength);
            }
            return Ok(PhysAddr(physical));
        }

        let block = self
            .blocks
            .get(usize::from(handle - 1))
            .copied()
            .flatten()
            .ok_or_else(|| self.invalid_handle(destination))?;
        let capacity = u32::from(block.size_kb) * KIB;
        let invalid_offset = self.invalid_pointer_offset(destination);
        if offset > capacity || (offset == capacity && length != 0) {
            return Err(invalid_offset);
        }
        let remaining = capacity
            .checked_sub(offset)
            .ok_or_else(|| self.invalid_pointer_offset(destination))?;
        if length > remaining {
            return Err(XmsError::InvalidLength);
        }
        let physical = block
            .base
            .0
            .checked_add(offset)
            .ok_or_else(|| self.invalid_pointer_offset(destination))?;
        Ok(PhysAddr(physical))
    }

    fn invalid_pointer_offset(&self, destination: bool) -> XmsError {
        if destination {
            XmsError::InvalidDestinationOffset
        } else {
            XmsError::InvalidSourceOffset
        }
    }

    fn invalid_handle(&self, destination: bool) -> XmsError {
        if destination {
            XmsError::InvalidDestinationHandle
        } else {
            XmsError::InvalidSourceHandle
        }
    }
}
