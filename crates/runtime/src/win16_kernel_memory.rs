//! KERNEL pointer validation over the runtime's checked guest selectors.

use guest_core::memory::Memory;
use win16_abi::Access;

use super::Win16State;
use crate::RuntimeError;

impl Win16State {
    pub(super) fn kernel_is_bad_memory_pointer(
        &self,
        far_pointer: u32,
        length: u32,
        access: Access,
        memory: &Memory,
    ) -> Result<u16, RuntimeError> {
        if length == 0 { return Ok(0); }
        let Ok(length) = usize::try_from(length) else { return Ok(1); };
        let Ok(pointer) = self.selectors.pointer_from_far(far_pointer) else { return Ok(1); };
        Ok(u16::from(self.selectors.translate(pointer, access, length, memory).is_err()))
    }

    /// Validate a huge range across the 64 KiB descriptors in one owned guest
    /// allocation. Ordinary pointer probes intentionally stay within one
    /// selector; only the huge variants walk the allocation's selector chain.
    pub(super) fn kernel_is_bad_huge_memory_pointer(
        &self,
        far_pointer: u32,
        length: u32,
        access: Access,
        memory: &Memory,
    ) -> Result<u16, RuntimeError> {
        if length == 0 { return Ok(0); }
        let Ok(length) = usize::try_from(length) else { return Ok(1); };
        let Ok(pointer) = self.selectors.pointer_from_far(far_pointer) else { return Ok(1); };
        Ok(u16::from(self.toolhelp_memory_ranges(pointer, access, length, memory)?.is_none()))
    }

    pub(super) fn kernel_is_bad_code_pointer(
        &self, far_pointer: u32, memory: &Memory,
    ) -> u16 {
        let Ok(pointer) = self.selectors.pointer_from_far(far_pointer) else { return 1; };
        u16::from(self.selectors.translate(pointer, Access::Execute, 1, memory).is_err())
    }

    /// Validate a bounded, terminated string without reading outside the
    /// caller's segment or allocating a temporary host buffer.
    pub(super) fn kernel_is_bad_string_pointer(
        &self, far_pointer: u32, maximum: u16, memory: &Memory,
    ) -> u16 {
        if maximum == 0 { return 0; }
        let Ok(mut pointer) = self.selectors.pointer_from_far(far_pointer) else { return 1; };
        for index in 0..maximum {
            let mut byte = [0_u8; 1];
            if self.selectors.read(memory, pointer, &mut byte).is_err() {
                return 1;
            }
            if byte[0] == 0 { return 0; }
            if index + 1 != maximum {
                let Ok(next) = self.selectors.add_bytes(pointer, 1) else { return 1; };
                pointer = next;
            }
        }
        0
    }
}
