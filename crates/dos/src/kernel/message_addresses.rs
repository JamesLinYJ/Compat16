//! DOS 4+ INT 2Fh/AX=122Eh message-provider address exchange.
//!
//! MS-DOS MISC2.ASM MSG_RETRIEVAL exchanges five guest ES:DI pairs; it does
//! not read a table or execute a retriever. MS_TABLE.ASM initializes all five
//! to NULL. Utilities can then use their own embedded message classes until
//! COMMAND or another resident provider registers addresses.
//! https://github.com/microsoft/MS-DOS/blob/2d04cacc5322951f187bb17e017c12920ac8ebe2/v4.0/src/DOS/MISC2.ASM
//! https://github.com/microsoft/MS-DOS/blob/2d04cacc5322951f187bb17e017c12920ac8ebe2/v4.0/src/DOS/MS_TABLE.ASM

use super::DosKernel;
use guest_core::Registers;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Copy, Debug, Default)]
struct MessageAddress {
    segment: u16,
    offset: u16,
}

/// DOS-global state shared by EXEC contexts, independent of the selected PSP.
#[derive(Clone, Debug, Default)]
pub(super) struct DosMessageAddresses(Rc<RefCell<[MessageAddress; 5]>>);

impl DosKernel {
    /// Handle the real-mode pointer exchange without dereferencing guest data.
    /// Protected selectors require a separate address-space bridge and must
    /// never be registered through this real-mode entry.
    pub fn message_address_service(&mut self, regs: &mut Registers) -> bool {
        if regs.ax() != 0x122e || regs.dl() >= 10 {
            return false;
        }
        let index = usize::from(regs.dl() / 2);
        if regs.dl() & 1 == 0 {
            let address = self.message_addresses.0.borrow()[index];
            regs.es = address.segment;
            regs.set_di(address.offset);
        } else {
            self.message_addresses.0.borrow_mut()[index] = MessageAddress {
                segment: regs.es,
                offset: regs.di(),
            };
        }
        // MSG_RETRIEVAL's final TEST clears carry for both operations. Other
        // arithmetic flags are unspecified; preserve them at this ABI boundary.
        regs.set_carry(false);
        true
    }
}
