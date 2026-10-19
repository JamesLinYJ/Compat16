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
    if !matches!(regs.ah(), 0x44 | 0x57 | 0x68) {
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
    let result = if (regs.ah() == 0x57 && regs.al() > 1)
        || (regs.ah() == 0x44 && regs.al() != 0) {
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    } else if let Some(file) = file {
        match (regs.ah(), regs.al()) {
            (0x44, 0) => match host.win16_file_ioctl_info(file) {
                Ok(info) => Ok((None, Some(info.device_information_word().ok_or_else(|| {
                    RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "host returned a drive number outside the DOS drive-letter range")
                })?))),
                Err(error) => Err(error),
            },
            (0x57, 0) => host.win16_file_write_time(file).map(|(time, date)| (Some(time), Some(date))),
            (0x57, 1) => host
                .win16_file_set_write_time(file, regs.cx(), regs.dx())
                .map(|()| (None, None)),
            (0x68, _) => host.win16_file_commit(file).map(|()| (None, None)),
            _ => unreachable!(),
        }
    } else {
        // All spool aliases, including reserved and foreign-task aliases,
        // belong to the spooler. They cannot select an equal-number DOS file.
        Err(DosHostError::new(DosErrorCode::InvalidFunction))
    };
    match result {
        Ok((cx, dx)) => {
            if let Some(cx) = cx { regs.set_cx(cx); }
            if let Some(dx) = dx { regs.set_dx(dx); }
            // Successful 5701h/68h preserve AX and all input registers.
            regs.set_carry(false);
        }
        Err(error) => {
            dos.complete_service_failure(regs, error.code as u16);
        }
    }
    dos.finish_external_int21(memory, host)
        .map_err(runtime_error)?;
    Ok(true)
}
