//! Real-mode implementation of the caller-address contract.
//!
//! It preserves the DOS kernel's existing physical-linear and offset-wrap
//! walks. Protected selectors are deliberately rejected here; only the
//! runtime's checked address-space adapter may implement those pointers.

use guest_core::{GuestMemory, MemoryError, PhysAddr, real_address};

use crate::DosError;

use super::caller_address_space::{
    DosCallAddressSpace, DosCallerId, DosFarPointer, DosPersistentFarPointer, DosPointerAccess,
    DosSpanPolicy,
};

pub(crate) struct RealModeDosAddressSpace<'a, M: GuestMemory> {
    memory: &'a mut M,
}

impl<'a, M: GuestMemory> RealModeDosAddressSpace<'a, M> {
    pub(crate) fn new(memory: &'a mut M) -> Self {
        Self { memory }
    }

    fn real_pointer(&self, pointer: DosFarPointer) -> Result<(u16, u16), DosError> {
        match pointer {
            DosFarPointer::RealMode {
                caller,
                segment,
                offset,
            } if caller == DosCallerId::REAL_MODE => Ok((segment, offset)),
            DosFarPointer::Protected { .. } | DosFarPointer::RealMode { .. } => {
                Err(DosError::Memory(MemoryError::InvalidMapping))
            }
        }
    }

    fn validate_range(
        &self,
        pointer: DosFarPointer,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
        policy: DosSpanPolicy,
    ) -> Result<(), DosError> {
        let (segment, offset) = self.real_pointer(pointer)?;
        match policy {
            DosSpanPolicy::Linear => {
                let address = address_at(segment, offset, byte_offset, DosSpanPolicy::Linear)?;
                validate_access(self.memory, address, length, access)?;
            }
            DosSpanPolicy::OffsetWrap => {
                validate_wrapped(self.memory, segment, offset, byte_offset, length, access)?;
            }
        }
        Ok(())
    }
}

impl<M: GuestMemory> GuestMemory for RealModeDosAddressSpace<'_, M> {
    fn len(&self) -> u32 {
        self.memory.len()
    }
    fn is_empty(&self) -> bool {
        self.memory.is_empty()
    }

    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.memory.validate_read(address, length)
    }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.memory.validate_write(address, length)
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.memory.read(address, bytes)
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write(address, bytes)
    }
}

impl<M: GuestMemory> DosCallAddressSpace for RealModeDosAddressSpace<'_, M> {
    fn caller_id(&self) -> DosCallerId {
        DosCallerId::REAL_MODE
    }

    fn resolve_caller_pointer(
        &mut self,
        segment: u16,
        offset: u16,
    ) -> Result<DosFarPointer, DosError> {
        Ok(DosFarPointer::real_mode(
            DosCallerId::REAL_MODE,
            segment,
            offset,
        ))
    }

    fn validate_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
        policy: DosSpanPolicy,
    ) -> Result<(), DosError> {
        self.validate_range(pointer, byte_offset, length, access, policy)
    }

    fn read_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        output: &mut [u8],
        policy: DosSpanPolicy,
    ) -> Result<(), DosError> {
        self.validate_range(
            pointer,
            byte_offset,
            output.len(),
            DosPointerAccess::Read,
            policy,
        )?;
        let (segment, offset) = self.real_pointer(pointer)?;
        read_transfer(self.memory, segment, offset, byte_offset, output, policy)
    }

    fn write_caller_range(
        &mut self,
        pointer: DosFarPointer,
        byte_offset: usize,
        input: &[u8],
        policy: DosSpanPolicy,
    ) -> Result<(), DosError> {
        self.validate_range(
            pointer,
            byte_offset,
            input.len(),
            DosPointerAccess::Write,
            policy,
        )?;
        let (segment, offset) = self.real_pointer(pointer)?;
        write_transfer(self.memory, segment, offset, byte_offset, input, policy)
    }

    fn read_caller_terminated(
        &mut self,
        pointer: DosFarPointer,
        terminator: u8,
        maximum: usize,
        policy: DosSpanPolicy,
    ) -> Result<Vec<u8>, DosError> {
        let (segment, offset) = self.real_pointer(pointer)?;
        let mut result = Vec::new();
        for index in 0..maximum {
            let address = address_at(segment, offset, index, policy)?;
            self.memory.validate_read(address, 1)?;
            let byte = self.memory.read_u8(address)?;
            if byte == terminator {
                return Ok(result);
            }
            result
                .try_reserve(1)
                .map_err(|_| DosError::Memory(MemoryError::AllocationFailed))?;
            result.push(byte);
        }
        Err(DosError::MalformedGuestInput(
            "DOS caller string is not terminated within its bound",
        ))
    }

    fn retain_caller_pointer(
        &mut self,
        pointer: DosFarPointer,
    ) -> Result<DosPersistentFarPointer, DosError> {
        self.real_pointer(pointer)?;
        Ok(DosPersistentFarPointer::new(pointer, 0))
    }

    fn release_caller_pointer(&mut self, pointer: DosPersistentFarPointer) -> Result<(), DosError> {
        self.real_pointer(pointer.pointer())?;
        if pointer.lease() != 0 {
            return Err(DosError::Memory(MemoryError::InvalidMapping));
        }
        Ok(())
    }

    fn validate_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        length: usize,
        access: DosPointerAccess,
    ) -> Result<(), DosError> {
        self.release_check(pointer)?;
        self.validate_range(
            pointer.pointer(),
            byte_offset,
            length,
            access,
            DosSpanPolicy::Linear,
        )
    }

    fn read_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        output: &mut [u8],
    ) -> Result<(), DosError> {
        self.release_check(pointer)?;
        self.read_caller_range(
            pointer.pointer(),
            byte_offset,
            output,
            DosSpanPolicy::Linear,
        )
    }

    fn write_persistent_range(
        &mut self,
        pointer: DosPersistentFarPointer,
        byte_offset: usize,
        input: &[u8],
    ) -> Result<(), DosError> {
        self.release_check(pointer)?;
        self.write_caller_range(pointer.pointer(), byte_offset, input, DosSpanPolicy::Linear)
    }

    fn expose_dos_pointer(
        &mut self,
        segment: u16,
        offset: u16,
        length: usize,
        access: DosPointerAccess,
    ) -> Result<DosFarPointer, DosError> {
        let pointer = DosFarPointer::real_mode(DosCallerId::REAL_MODE, segment, offset);
        self.validate_range(pointer, 0, length, access, DosSpanPolicy::Linear)?;
        Ok(pointer)
    }
}

impl<M: GuestMemory> RealModeDosAddressSpace<'_, M> {
    fn release_check(&self, pointer: DosPersistentFarPointer) -> Result<(), DosError> {
        self.real_pointer(pointer.pointer())?;
        if pointer.lease() != 0 {
            return Err(DosError::Memory(MemoryError::InvalidMapping));
        }
        Ok(())
    }
}

fn validate_access(
    memory: &impl GuestMemory,
    address: PhysAddr,
    length: usize,
    access: DosPointerAccess,
) -> Result<(), DosError> {
    match access {
        DosPointerAccess::Read | DosPointerAccess::Execute => {
            memory.validate_read(address, length)?
        }
        DosPointerAccess::Write => memory.validate_write(address, length)?,
    }
    Ok(())
}

fn validate_wrapped(
    memory: &impl GuestMemory,
    segment: u16,
    offset: u16,
    byte_offset: usize,
    length: usize,
    access: DosPointerAccess,
) -> Result<(), DosError> {
    let mut remaining = length;
    let mut current = (usize::from(offset) + byte_offset % 0x1_0000) & 0xffff;
    while remaining != 0 {
        let count = remaining.min(0x1_0000 - current);
        validate_access(memory, real_address(segment, current as u16), count, access)?;
        remaining -= count;
        current = 0;
    }
    Ok(())
}

fn read_transfer(
    memory: &impl GuestMemory,
    segment: u16,
    offset: u16,
    byte_offset: usize,
    output: &mut [u8],
    policy: DosSpanPolicy,
) -> Result<(), DosError> {
    let length = output.len();
    match policy {
        DosSpanPolicy::Linear => {
            let address = address_at(segment, offset, byte_offset, policy)?;
            memory.read(address, output)?;
        }
        DosSpanPolicy::OffsetWrap => {
            let mut done = 0usize;
            let mut current = (usize::from(offset) + byte_offset % 0x1_0000) & 0xffff;
            while done < length {
                let count = (length - done).min(0x1_0000 - current);
                let address = real_address(segment, current as u16);
                let slice = &mut output[done..done + count];
                memory.read(address, slice)?;
                done += count;
                current = 0;
            }
        }
    }
    Ok(())
}

fn write_transfer(
    memory: &mut impl GuestMemory,
    segment: u16,
    offset: u16,
    byte_offset: usize,
    input: &[u8],
    policy: DosSpanPolicy,
) -> Result<(), DosError> {
    let length = input.len();
    match policy {
        DosSpanPolicy::Linear => {
            memory.write(address_at(segment, offset, byte_offset, policy)?, input)?
        }
        DosSpanPolicy::OffsetWrap => {
            let mut done = 0usize;
            let mut current = (usize::from(offset) + byte_offset % 0x1_0000) & 0xffff;
            while done < length {
                let count = (length - done).min(0x1_0000 - current);
                memory.write(
                    real_address(segment, current as u16),
                    &input[done..done + count],
                )?;
                done += count;
                current = 0;
            }
        }
    }
    Ok(())
}

fn address_at(
    segment: u16,
    offset: u16,
    delta: usize,
    policy: DosSpanPolicy,
) -> Result<PhysAddr, DosError> {
    match policy {
        DosSpanPolicy::Linear => {
            let base = real_address(segment, offset).0;
            let delta =
                u32::try_from(delta).map_err(|_| DosError::Memory(MemoryError::AddressOverflow))?;
            base.checked_add(delta)
                .map(PhysAddr)
                .ok_or(DosError::Memory(MemoryError::AddressOverflow))
        }
        DosSpanPolicy::OffsetWrap => {
            let wrapped = (usize::from(offset) + delta % 0x1_0000) & 0xffff;
            Ok(real_address(segment, wrapped as u16))
        }
    }
}
