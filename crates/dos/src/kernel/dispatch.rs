use crate::caller_address_space::DosCallAddressSpace;
use crate::{DosAction, DosError, DosErrorCode, DosHost, DosHostError};
use guest_core::Registers;

use super::DosKernel;

impl DosKernel {
    pub(super) fn int21(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let ah = regs.ah();
        match ah {
            0x00 => Ok(DosAction::Exit(0)),
            0x01 => self.console_input(regs, host, true),
            0x02 => {
                let byte = regs.dl();
                self.console_output(regs, host, byte)
            }
            0x06 => self.direct_console_io(regs, host),
            0x07 => self.console_input(regs, host, false),
            0x08 => self.console_input(regs, host, false),
            0x09 => self.print_dollar_string(regs, memory, host),
            0x0a => self.buffered_input(regs, memory, host),
            0x0b => self.input_status(regs, host),
            0x0c => self.flush_and_input(regs, memory, host),
            0x0e => self.select_drive(regs, host),
            0x19 => {
                let drive = host.current_drive();
                if drive > 25 {
                    return Err(DosError::HostContractViolation(
                        "host returned an invalid current drive",
                    ));
                }
                regs.set_al(drive);
                Ok(DosAction::Continue)
            }
            0x1a => {
                self.set_caller_dta(memory, regs.ds, regs.dx())?;
                Ok(DosAction::Continue)
            }
            0x2f => {
                let (segment_or_selector, offset) = self.caller_dta_words(memory)?;
                regs.es = segment_or_selector;
                regs.set_bx(offset);
                Ok(DosAction::Continue)
            }
            0x2a | 0x2c => Self::get_date_time(regs, host),
            0x30 => Ok(Self::dos_version(regs)),
            0x33 => Ok(self.extended_version(regs)),
            0x25 => self.set_interrupt_vector(regs, memory),
            0x35 => self.get_interrupt_vector(regs, memory),
            0x36 => self.disk_space(regs, host),
            0x3c => self.create_file(regs, memory, host),
            0x3d => self.open_file(regs, memory, host),
            0x3e => self.close_file(regs, host),
            0x3f => self.read_file(regs, memory, host),
            0x40 => self.write_file(regs, memory, host),
            0x41 => self.delete_file(regs, memory, host),
            0x42 => self.seek_file(regs, host),
            0x39 => self.create_directory(regs, memory, host),
            0x3a => self.remove_directory(regs, memory, host),
            0x3b => self.change_directory(regs, memory, host),
            0x38 => self.get_set_country_data(regs, memory, host),
            0x43 => self.file_attributes(regs, memory, host),
            0x44 => self.ioctl(regs, host),
            0x65 => self.extended_country_information(regs, memory, host),
            0x47 => self.get_current_directory(regs, memory, host),
            0x4e => self.find_first(regs, memory, host),
            0x4f => self.find_next(regs, memory, host),
            0x45 => self.duplicate_file(regs, host),
            0x46 => self.force_duplicate_file(regs, host),
            0x48 => self.allocate_memory(regs, memory),
            0x49 => self.free_memory(regs, memory),
            0x4a => self.resize_memory(regs, memory),
            0x4b => self.execute_program(regs, memory),
            0x4c => Ok(DosAction::Exit(regs.al())),
            0x56 => self.rename_file(regs, memory, host),
            0x4d => {
                regs.set_ax(u16::from(self.last_exit_code));
                self.last_exit_code = 0;
                Ok(DosAction::Continue)
            }
            0x50 => {
                self.psp_segment = regs.bx();
                Ok(DosAction::Continue)
            }
            0x51 | 0x62 => {
                regs.set_bx(self.psp_segment);
                Ok(DosAction::Continue)
            }
            0x52 => self.list_of_lists(regs, memory, host),
            _ => {
                Self::failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
                Ok(DosAction::Continue)
            }
        }
    }
}
