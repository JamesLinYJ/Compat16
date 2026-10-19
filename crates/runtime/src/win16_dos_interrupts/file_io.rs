//! Ordinary HFILE I/O through DOS scalar registers and its checked protected
//! caller view. A known HFILE must never select an equal-number DOS JFT entry.

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostFile, Win16HostFileClose,
    runtime_error,
};
use dos_kernel::{
    DosCallAddressSpace, DosErrorCode, DosFileAccess, DosHostError, DosKernel, DosPointerAccess,
    DosSeekOrigin, DosSpanPolicy,
};
use guest_core::{Registers, memory::Memory};

enum Outcome {
    Closed(Win16HostFile, Win16HostFileClose),
    Transfer(usize),
    Position(u32),
}

pub(super) fn dispatch(
    state: &mut Win16State,
    dos: &mut DosKernel,
    regs: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<bool, RuntimeError> {
    if !matches!(regs.ah(), 0x3e | 0x3f | 0x40 | 0x42) {
        return Ok(false);
    }
    let file = state.files.get(&regs.bx()).copied();
    let unsupported_spool = matches!(regs.ah(), 0x3f | 0x42)
        && state
            .network_print_jobs
            .values()
            .any(|jobs| jobs.owns_hfile(regs.bx()));
    if file.is_none() && !unsupported_spool {
        return Ok(false);
    }
    // Preserve the existing spool write/close owner route in the parent.
    // Read/seek must also claim all spool aliases before DOS fallback.
    dos.prepare_external_int21(memory).map_err(runtime_error)?;
    let result = if let Some(file) = file {
        match regs.ah() {
            0x3e => host
                .win16_dos_file_close(file)
                .map(|closed| Outcome::Closed(file, closed)),
            0x3f | 0x40 => transfer(state, file, regs, memory, host)?.map(Outcome::Transfer),
            0x42 => {
                let origin = match regs.al() {
                    0 => Some(DosSeekOrigin::Start),
                    1 => Some(DosSeekOrigin::Current),
                    2 => Some(DosSeekOrigin::End),
                    _ => None,
                };
                match origin {
                    Some(origin) => {
                        let offset = ((u32::from(regs.cx()) << 16) | u32::from(regs.dx())) as i32;
                        host.win16_dos_file_seek(file, offset, origin)
                            .map(Outcome::Position)
                    }
                    None => Err(DosHostError::new(DosErrorCode::InvalidFunction)),
                }
            }
            _ => unreachable!(),
        }
    } else {
        Err(DosHostError::new(DosErrorCode::InvalidHandle))
    };
    match result {
        Ok(Outcome::Closed(file, closed)) => {
            // A completed native close consumes every mapped alias before a
            // DOS metadata refresh can fail. Successful AH=3Eh preserves AX.
            if state.invalidate_file_close(file, closed) {
                regs.set_carry(false);
            } else {
                dos.complete_service_failure(regs, DosErrorCode::InvalidHandle as u16);
            }
        }
        Ok(Outcome::Transfer(count)) => {
            regs.set_ax(count as u16);
            regs.set_carry(false);
        }
        Ok(Outcome::Position(position)) => {
            regs.set_ax(position as u16);
            regs.set_dx((position >> 16) as u16);
            regs.set_carry(false);
        }
        Err(error) => dos.complete_service_failure(regs, error.code as u16),
    }
    dos.finish_external_int21(memory, host)
        .map_err(runtime_error)?;
    Ok(true)
}

fn transfer(
    state: &mut Win16State,
    file: Win16HostFile,
    regs: &Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<Result<usize, DosHostError>, RuntimeError> {
    let read = regs.ah() == 0x3f;
    let access = match host.win16_file_dos_access(file) {
        Ok(access) => access,
        Err(error) => return Ok(Err(error)),
    };
    // DOS access failures precede pointer validation, including CX=0. The
    // mode comes from the retained host open, never projected guest metadata.
    if matches!(
        (read, access),
        (true, DosFileAccess::WriteOnly) | (false, DosFileAccess::ReadOnly)
    ) {
        return Ok(Err(DosHostError::new(DosErrorCode::AccessDenied)));
    }
    let count = usize::from(regs.cx());
    if count == 0 {
        return match if read {
            Ok(0)
        } else {
            host.win16_dos_file_write(file, &[])
        } {
            Ok(0) => Ok(Ok(0)),
            Ok(_) => Err(contract_error()),
            Err(error) => Ok(Err(error)),
        };
    }
    let mut data = Vec::new();
    data.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate DOS HFILE transfer buffer",
            error,
        )
    })?;
    data.resize(count, 0);
    let owner = state.current_task_owner()?;
    let mut caller = state
        .dos_call_address_space(memory, owner)
        .map_err(runtime_error)?;
    let pointer = caller
        .resolve_caller_pointer(regs.ds, regs.dx())
        .map_err(runtime_error)?;
    let result = if read {
        // Full single-selector preflight precedes native cursor advancement.
        // Keep the exclusive caller view alive through the output commit.
        caller
            .validate_caller_range(
                pointer,
                0,
                count,
                DosPointerAccess::Write,
                DosSpanPolicy::Linear,
            )
            .map_err(runtime_error)?;
        match host.win16_dos_file_read(file, &mut data) {
            Ok(read) if read <= count => {
                if read != 0 {
                    caller
                        .write_caller_range(pointer, 0, &data[..read], DosSpanPolicy::Linear)
                        .map_err(runtime_error)?;
                }
                Ok(read)
            }
            Ok(_) => return Err(contract_error()),
            Err(error) => Err(error),
        }
    } else {
        // Snapshot the complete input before a write can modify the file.
        caller
            .read_caller_range(pointer, 0, &mut data, DosSpanPolicy::Linear)
            .map_err(runtime_error)?;
        drop(caller);
        host.win16_dos_file_write(file, &data)
    };
    if result.as_ref().is_ok_and(|&actual| actual > count) {
        return Err(contract_error());
    }
    Ok(result)
}

fn contract_error() -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        "host DOS HFILE transfer exceeded its caller buffer",
    )
}
