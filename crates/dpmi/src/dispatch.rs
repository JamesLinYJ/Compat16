use guest_core::{GuestMemory, OwnerId, Registers};

use crate::allocator::DpmiMemory;
use crate::types::{DpmiError, DpmiHandle, ServiceDisposition, DPMI_PAGE_SIZE};

impl DpmiMemory {
    /// Route the implemented INT 31h memory subset. Register pairs follow the
    /// DPMI word convention: size and linear address are both BX:CX, while
    /// handles are SI:DI. The high word is listed first in each pair.
    ///
    /// Known-function failures are reported in AX with carry set, as DPMI
    /// requires. Unknown functions return `UnsupportedFunction` without
    /// changing the caller's registers.
    pub fn handle_int31(
        &mut self,
        owner: OwnerId,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<ServiceDisposition, DpmiError> {
        let function = regs.ax();
        match function {
            0x0501 => {
                let size = (u32::from(regs.bx()) << 16) | u32::from(regs.cx());
                match self.allocate(owner, size, memory) {
                    Ok(allocation) => {
                        regs.set_bx((allocation.linear.0 >> 16) as u16);
                        regs.set_cx(allocation.linear.0 as u16);
                        regs.set_si((allocation.handle.0 >> 16) as u16);
                        regs.set_di(allocation.handle.0 as u16);
                        regs.set_carry(false);
                    }
                    Err(error) => set_service_error(regs, &error),
                }
            }
            0x0502 => {
                let handle = DpmiHandle((u32::from(regs.si()) << 16) | u32::from(regs.di()));
                match self.free(owner, handle) {
                    Ok(()) => regs.set_carry(false),
                    Err(error) => set_service_error(regs, &error),
                }
            }
            0x0503 => {
                let size = (u32::from(regs.bx()) << 16) | u32::from(regs.cx());
                let handle = DpmiHandle((u32::from(regs.si()) << 16) | u32::from(regs.di()));
                match self.resize(owner, handle, size, memory) {
                    Ok(allocation) => {
                        regs.set_bx((allocation.linear.0 >> 16) as u16);
                        regs.set_cx(allocation.linear.0 as u16);
                        regs.set_si((allocation.handle.0 >> 16) as u16);
                        regs.set_di(allocation.handle.0 as u16);
                        regs.set_carry(false);
                    }
                    Err(error) => set_service_error(regs, &error),
                }
            }
            0x0604 => {
                regs.set_bx((DPMI_PAGE_SIZE >> 16) as u16);
                regs.set_cx(DPMI_PAGE_SIZE as u16);
                regs.set_carry(false);
            }
            _ => return Err(DpmiError::UnsupportedFunction(function)),
        }
        Ok(ServiceDisposition::Handled)
    }
}

fn set_service_error(regs: &mut Registers, error: &DpmiError) {
    regs.set_ax(error.dpmi_code());
    regs.set_carry(true);
}
