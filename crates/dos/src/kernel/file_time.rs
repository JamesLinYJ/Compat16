//! Handle-based DOS last-write timestamp queries and updates.

use crate::{DosAction, DosError, DosErrorCode, DosHost, DosHostError};
use guest_core::Registers;

use super::DosKernel;
use super::state::Handle;

impl DosKernel {
    pub(super) fn file_date_time(
        &mut self,
        regs: &mut Registers,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        // AH=57h/AL=00h reads BX's last-write timestamp; AL=01h sets it from
        // CX:DX. No caller-memory pointer or DOS access-mode check is involved.
        // MS-DOS 4 Programmer's Reference, Function 57h:
        // https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/
        if regs.al() > 1 {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return Ok(DosAction::Continue);
        }
        let status = match self.handles.get(&regs.bx()).copied() {
            Some(Handle::File(file)) if regs.al() == 1 => {
                host.file_set_write_time(file, regs.cx(), regs.dx()).map(|()| None)
            }
            Some(Handle::File(file)) => host.file_status(file).map(Some),
            // Standard objects have no timestamp contract. Report the gap
            // explicitly rather than inventing dates or successful mutations.
            Some(Handle::Standard(_)) => {
                Err(DosHostError::new(DosErrorCode::InvalidFunction))
            }
            None => Err(DosHostError::new(DosErrorCode::InvalidHandle)),
        };
        match status {
            Ok(status) => {
                if let Some(status) = status {
                    regs.set_cx(status.write_time);
                    regs.set_dx(status.write_date);
                }
                Self::success(regs);
            }
            Err(error) => Self::failure(regs, error),
        }
        Ok(DosAction::Continue)
    }
}
