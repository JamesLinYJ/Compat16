use crate::{DosAction, DosError};
use guest_core::{GuestMemory, PhysAddr, Registers};

use super::DosKernel;

impl DosKernel {
    pub(super) fn set_interrupt_vector(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<DosAction, DosError> {
        let address = vector_address(regs.al());
        let mut value = [0; 4];
        value[..2].copy_from_slice(&regs.dx().to_le_bytes());
        value[2..].copy_from_slice(&regs.ds.to_le_bytes());

        memory.validate_write(address, value.len())?;
        memory.write(address, &value)?;
        Ok(DosAction::Continue)
    }

    pub(super) fn get_interrupt_vector(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<DosAction, DosError> {
        let address = vector_address(regs.al());
        memory.validate_read(address, 4)?;
        let mut value = [0; 4];
        memory.read(address, &mut value)?;

        let offset = u16::from_le_bytes([value[0], value[1]]);
        let segment = u16::from_le_bytes([value[2], value[3]]);
        regs.es = segment;
        regs.set_bx(offset);
        Ok(DosAction::Continue)
    }
}

fn vector_address(vector: u8) -> PhysAddr {
    PhysAddr(u32::from(vector) * 4)
}
