//! Handle-based DOS last-write timestamp queries.

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
        // AH=57h/AL=00h reads the packed last-write time/date of BX's open
        // object. Timestamp writes and other subfunctions remain unsupported.
        // MS-DOS 4 Programmer's Reference, Function 57h:
        // https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/
        if regs.al() != 0 {
            Self::failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return Ok(DosAction::Continue);
        }
        let status = match self.handles.get(&regs.bx()).copied() {
            Some(Handle::File(file)) => host.file_status(file),
            // Standard objects have no timestamp query in our host contract.
            // Report that gap explicitly rather than inventing device dates.
            Some(Handle::Standard(_)) => {
                Err(DosHostError::new(DosErrorCode::InvalidFunction))
            }
            None => Err(DosHostError::new(DosErrorCode::InvalidHandle)),
        };
        match status {
            Ok(status) => {
                regs.set_cx(status.write_time);
                regs.set_dx(status.write_date);
                Self::success(regs);
            }
            Err(error) => Self::failure(regs, error),
        }
        Ok(DosAction::Continue)
    }
}
