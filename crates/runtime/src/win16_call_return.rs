//! Checked Win16 far-call return and caller output transfer.

use guest_core::{GuestMemory, Registers, Selector};
use guest_core::memory::Memory;
use win16_abi::{Access, Win16OutputBuffer, Win16ReturnKind};
use x86_cpu::{LegacyRegisterTransfer, LegacyStackPointerTarget};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

pub(super) fn checked_return_target(
    saved: &Registers,
    return_to: (u16, u16, u32),
    value: u32,
    return_kind: Win16ReturnKind,
) -> LegacyRegisterTransfer {
    let mut registers = saved.clone();
    registers.cs = return_to.0;
    registers.set_ip(return_to.1);
    registers.set_sp(return_to.2 as u16);
    if !matches!(return_kind, Win16ReturnKind::Void) {
        registers.set_ax(value as u16);
        if matches!(return_kind, Win16ReturnKind::Dword | Win16ReturnKind::FarPointer) {
            registers.set_dx((value >> 16) as u16);
        }
    }
    LegacyRegisterTransfer {
        registers,
        stack_pointer: if return_to.2 == 0x1_0000 {
            LegacyStackPointerTarget::OnePast16BitSegment
        } else {
            LegacyStackPointerTarget::RegisterValue
        },
    }
}

impl Win16State {
    pub(super) fn write_output(
        &self,
        memory: &mut Memory,
        output: Win16OutputBuffer,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        if bytes.len() > usize::from(output.capacity) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 output exceeded the guest buffer capacity"));
        }
        let mut pointer = output.pointer;
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let segment = self.selectors.describe(pointer.selector())
                .map_err(crate::runtime_error)?;
            let available = segment.limit
                .checked_sub(u32::from(pointer.offset()))
                .and_then(|size| size.checked_add(1))
                .and_then(|size| usize::try_from(size).ok())
                .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                    "Win16 output selector has no writable space"))?;
            let chunk = available.min(remaining.len());
            self.selectors.write(memory, pointer, &remaining[..chunk])
                .map_err(crate::runtime_error)?;
            remaining = &remaining[chunk..];
            if !remaining.is_empty() {
                pointer = self.selectors.add_bytes(pointer, chunk as u32)
                    .map_err(crate::runtime_error)?;
            }
        }
        Ok(())
    }

    pub(super) fn complete_return(
        &mut self,
        registers: &mut Registers,
        return_selector: u16,
        return_offset: u16,
        return_sp: u32,
        value: u32,
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        if self.active_dispatch_call_owner.is_some() {
            if self.active_dispatch_return.is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "one Win16 service dispatch staged more than one direct caller return"));
            }
            self.active_dispatch_return = Some(checked_return_target(
                registers,
                (return_selector, return_offset, return_sp),
                value,
                return_kind,
            ));
            return Ok(None);
        }
        self.retire_far_return(return_selector, u32::from(return_offset), registers.ss);
        registers.cs = return_selector;
        registers.set_ip(return_offset);
        registers.set_sp(return_sp as u16);
        if !matches!(return_kind, Win16ReturnKind::Void) {
            registers.set_ax(value as u16);
            if matches!(return_kind, Win16ReturnKind::Dword | Win16ReturnKind::FarPointer) {
                registers.set_dx((value >> 16) as u16);
            }
        }
        Ok(None)
    }

    pub(super) fn far_return(
        &self,
        registers: &Registers,
        memory: &Memory,
        callee_pop_bytes: u16,
    ) -> Result<(u16, u16, u32), RuntimeError> {
        let stack_pointer = self.selectors.pointer_from_raw(Selector(registers.ss), registers.sp())
            .map_err(crate::runtime_error)?;
        let mut return_bytes = [0_u8; 4];
        self.selectors.read(memory, stack_pointer, &mut return_bytes)
            .map_err(crate::runtime_error)?;
        let return_offset = u16::from_le_bytes([return_bytes[0], return_bytes[1]]);
        let return_selector = u16::from_le_bytes([return_bytes[2], return_bytes[3]]);
        let return_pointer = self.selectors.pointer_from_raw(Selector(return_selector), return_offset)
            .map_err(crate::runtime_error)?;
        self.selectors.address_within(return_pointer, Access::Execute, 1, memory.len())
            .map_err(crate::runtime_error)?;
        let return_sp = u32::from(registers.sp())
            .checked_add(4 + u32::from(callee_pop_bytes))
            .filter(|value| *value <= 0x1_0000)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 service return would exceed the 16-bit stack"))?;
        Ok((return_selector, return_offset, return_sp))
    }
}
