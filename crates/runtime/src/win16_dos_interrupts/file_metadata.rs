//! DOS scalar metadata calls on Win16 HFILEs. These numbers are distinct
//! from DOS JFT entries even when both tables contain the same integer.

use super::Win16State;
use crate::{RuntimeError, RuntimeHost, runtime_error};
use dos_kernel::{DosErrorCode, DosHostError, DosKernel};
use guest_core::{Registers, memory::Memory};

pub(super) fn dispatch(
    state: &Win16State,
    dos: &mut DosKernel,
    regs: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<bool, RuntimeError> {
    if !matches!(regs.ah(), 0x57 | 0x68) {
        return Ok(false);
    }
    let file = state.files.get(&regs.bx()).copied();
    let spool = state
        .network_print_jobs
        .values()
        .any(|jobs| jobs.owns_hfile(regs.bx()));
    if file.is_none() && !spool {
        return Ok(false);
    }
    // Validate DOS metadata before host side effects, then publish registers
    // before refreshing it. A refresh error must never replay a completed set
    // or commit. The DOS3Call entrypoint uses this same protected adapter.
    dos.prepare_external_int21(memory).map_err(runtime_error)?;
    let result = if regs.ah() == 0x57 && regs.al() > 1 {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    } else if let Some(file) = file {
        match (regs.ah(), regs.al()) {
            (0x57, 0) => host.win16_file_write_time(file).map(Some),
            (0x57, 1) => host
                .win16_file_set_write_time(file, regs.cx(), regs.dx())
                .map(|()| None),
            (0x68, _) => host.win16_file_commit(file).map(|()| None),
            _ => unreachable!(),
        }
    } else {
        // All spool aliases, including reserved and foreign-task aliases,
        // belong to the spooler. They cannot select an equal-number DOS file.
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    };
    match result {
        Ok(stamp) => {
            if let Some((time, date)) = stamp {
                regs.set_cx(time);
                regs.set_dx(date);
            }
            // Successful 5701h/68h preserve AX and all input registers.
            regs.set_carry(false);
        }
        Err(error) => {
            regs.set_ax(error.code as u16);
            regs.set_carry(true);
        }
    }
    dos.finish_external_int21(memory, host)
        .map_err(runtime_error)?;
    Ok(true)
}
