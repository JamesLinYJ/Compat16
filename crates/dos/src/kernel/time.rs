//! MS-DOS INT 21h Get Date (2Ah) and Get Time (2Ch).

use crate::{DosAction, DosError, DosHost};
use guest_core::Registers;
use super::DosKernel;

impl DosKernel {
    pub(super) fn get_date_time(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let value = match host.local_date_time() {
            Ok(value) => value,
            Err(error) => {
                self.failure(regs, error);
                return Ok(DosAction::Continue);
            }
        };
        // Windows supplies the calendar; DOS's register layout and hundredth
        // precision are guest ABI details that no native SYSTEMTIME encodes.
        if regs.ah() == 0x2a {
            regs.set_cx(value.year);
            regs.set_dh(value.month);
            regs.set_dl(value.day);
            regs.set_al(value.weekday);
        } else {
            regs.set_ch(value.hour);
            regs.set_cl(value.minute);
            regs.set_dh(value.second);
            regs.set_dl(value.hundredth);
        }
        Ok(DosAction::Continue)
    }
}
