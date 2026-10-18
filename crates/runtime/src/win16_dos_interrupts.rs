//! Protected-mode routing for DOS INT 21h and its interrupt-vector lifetime.
//!
//! DOS owns the real-mode IVT and DOS metadata. This adapter keeps Win16
//! selector:offset registrations in a separate overlay and only aliases
//! default vector targets when the simulated IVT names checked ROM bytes.

use dos_kernel::{DosAction, DosErrorCode, DosKernel};
use guest_core::memory::{Memory, ROM_END, ROM_START};
use guest_core::{GuestMemory, PhysAddr, Registers, Selector, real_address};
use win16_abi::{Access, AccessRights, SegmentedPointer};

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, runtime_error};

use super::Win16State;

#[path = "win16_dos_interrupts/file_metadata.rs"]
mod file_metadata;
#[path = "win16_dos_interrupts/file_io.rs"]
mod file_io;

/// A resolved protected-mode destination for one software interrupt.
///
/// Firmware entries remain typed runtime services; guest hooks keep their
/// original checked selector identity so a freed and reused raw selector can
/// never revive a saved registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtectedInterruptTarget {
    Empty,
    Guest(SegmentedPointer),
    FirmwareService { vector: u8, entry: SegmentedPointer },
}

/// DOS calls that ask the shared filesystem adapter to resolve a relative
/// pathname need the current task's virtual drive directory installed first.
/// Scalar clock, exit, and handle services must not depend on that path state.
pub(super) fn needs_dos_directory_context(service: u8) -> bool {
    matches!(
        service,
        0x39 | 0x3a | 0x3c | 0x3d | 0x41 | 0x43 | 0x4b | 0x4e | 0x56 | 0x5a | 0x5b | 0x6c
    )
}

/// Dispatch an INT 21h service from protected-mode Win16 code.
pub(super) fn dispatch_int21(
    state: &mut Win16State,
    dos: &mut DosKernel,
    regs: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<DosAction, RuntimeError> {
    let service = regs.ah();
    if file_metadata::dispatch(state, dos, regs, memory, host)? {
        return Ok(DosAction::Continue);
    }
    if file_io::dispatch(state, dos, regs, memory, host)? {
        return Ok(DosAction::Continue);
    }
    if matches!(service, 0x0e | 0x19 | 0x3b | 0x47) {
        dos.prepare_external_int21(memory).map_err(runtime_error)?;
        let action = state
            .dispatch_dos_directory_service(dos, regs, memory, host)?
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 DOS directory service was not handled by its owner-scoped adapter",
                )
            })?;
        dos.finish_external_int21(memory, host)
            .map_err(runtime_error)?;
        return Ok(action);
    }
    let file_cdr_notice = state.capture_file_cdr_notice(regs, memory, host)?;

    // WNet-created HFILEs share the runtime HFILE allocator but are backed by
    // a spooler document rather than the DOS kernel's handle table. Claim
    // every known spool alias before forwarding AH=3E/AH=40 to DOS, where
    // a numerically equal DOS handle must never be touched. Only a live
    // current-task job can be used; foreign and reserved aliases fail closed.
    if matches!(service, 0x3e | 0x40) {
        let hfile = regs.bx();
        let owner = state.current_task_owner()?;
        if state.network_print_jobs.values().any(|jobs| jobs.owns_hfile(hfile)) {
            dos.prepare_external_int21(memory).map_err(runtime_error)?;
            if state.network_print_jobs.get(&owner)
                .is_some_and(|jobs| jobs.open_job(hfile).is_some())
            {
                let result = if service == 0x3e {
                    state.close_legacy_file(hfile, host)?
                } else {
                    let far_buffer = (u32::from(regs.ds) << 16) | u32::from(regs.dx());
                    state.write_file(hfile, far_buffer, i32::from(regs.cx()), memory, host)?
                };
                let failed = if service == 0x3e { result != 0 } else { result == u32::MAX };
                if failed {
                    // WritePrinter failures without a more specific DOS
                    // mapping are reported as access denied.
                    dos.complete_service_failure(regs, if service == 0x3e {
                        DosErrorCode::InvalidHandle as u16
                    } else {
                        DosErrorCode::AccessDenied as u16
                    });
                } else {
                    regs.set_ax(result as u16);
                    regs.set_carry(false);
                }
            } else {
                dos.complete_service_failure(regs, DosErrorCode::InvalidHandle as u16);
            }
            // Publish completed I/O and retire a successfully closed alias
            // before refresh. A metadata failure must not undo that identity
            // change or replay a completed host operation.
            dos.finish_external_int21(memory, host).map_err(runtime_error)?;
            state.finish_file_cdr_dos_operation(file_cdr_notice, regs, &DosAction::Continue)?;
            return Ok(DosAction::Continue);
        }
    }

    if service == 0x3a && state.block_dos_remove_of_virtual_current_directory(dos, regs, memory, host)? {
        state.finish_file_cdr_dos_operation(file_cdr_notice, regs, &DosAction::Continue)?;
        return Ok(DosAction::Continue);
    }

    if needs_dos_directory_context(service) {
        state.activate_dos_directory_context(host)?;
    }

    let action = match service {
        0x25 => set_protected_vector(state, dos, regs, memory, host),
        0x35 => get_protected_vector(state, dos, regs, memory, host),
        0x52 => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 protected-mode INT 21h/AH=52 requires a verified List-of-Lists projection",
        )),
        _ => match dos
            .interrupt_scalar(0x21, regs, memory, host)
            .map_err(runtime_error)?
        {
            Some(action) => Ok(action),
            None => {
                let owner = state.current_task_owner()?;
                let mut address_space = state
                    .dos_call_address_space(memory, owner)
                    .map_err(runtime_error)?;
                // The caller-aware entry preserves protected selector:offset
                // operands while canonical DOS metadata remains on the real
                // DOS bus. It also supplies the same DOS lifecycle used by
                // DOS3Call, without constructing a second INT frame.
                dos.interrupt_with_address_space(0x21, regs, &mut address_space, host)
                    .map_err(runtime_error)
            }
        },
    }?;
    state.finish_file_cdr_dos_operation(file_cdr_notice, regs, &action)?;
    Ok(action)
}

fn set_protected_vector(
    state: &mut Win16State,
    dos: &mut DosKernel,
    regs: &Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<DosAction, RuntimeError> {
    let vector = regs.al();
    let target = if regs.ds == 0 && regs.dx() == 0 {
        None
    } else {
        let pointer = state
            .selectors
            .pointer_from_raw(Selector(regs.ds), regs.dx())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "INT 21h/AH=25 received an invalid Win16 selector:offset",
                    error,
                )
            })?;
        state
            .selectors
            .translate(pointer, Access::Execute, 1, memory)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "INT 21h/AH=25 target is not executable Win16 guest memory",
                    error,
                )
            })?;
        Some(pointer)
    };

    // AH=25 changes the protected-mode overlay only; the caller's selector is
    // never passed to the real-mode DOS set-vector routine or real_address.
    dos.prepare_external_int21(memory).map_err(runtime_error)?;
    let previous = state.protected_dos_vectors.insert(vector, target);
    if let Err(error) = dos.finish_external_int21(memory, host) {
        match previous {
            Some(value) => {
                state.protected_dos_vectors.insert(vector, value);
            }
            None => {
                state.protected_dos_vectors.remove(&vector);
            }
        }
        return Err(runtime_error(error));
    }
    Ok(DosAction::Continue)
}

fn get_protected_vector(
    state: &mut Win16State,
    dos: &mut DosKernel,
    regs: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<DosAction, RuntimeError> {
    let vector = regs.al();
    let registered = state.protected_dos_vectors.get(&vector).copied();
    let (target_segment, target_offset) = match registered {
        Some(None) => {
            // An explicit AH=25 NULL overrides any non-null real IVT entry.
            dos.prepare_external_int21(memory).map_err(runtime_error)?;
            dos.finish_external_int21(memory, host)
                .map_err(runtime_error)?;
            (0, 0)
        }
        Some(Some(pointer)) => {
            validate_registered_target(state, pointer, memory)?;
            dos.prepare_external_int21(memory).map_err(runtime_error)?;
            dos.finish_external_int21(memory, host)
                .map_err(runtime_error)?;
            (pointer.selector().raw().0, pointer.offset())
        }
        None => {
            // The DOS core reads its actual IVT and performs the normal DOS
            // metadata preflight/refresh. Only the result registers are used.
            let mut shadow = regs.clone();
            let action = dos
                .interrupt(0x21, &mut shadow, memory, host)
                .map_err(runtime_error)?;
            if action != DosAction::Continue {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DOS INT 21h/AH=35 returned a non-continuing action",
                ));
            }
            let segment = shadow.es;
            let offset = shadow.bx();
            if segment == 0 && offset == 0 {
                (0, 0)
            } else {
                let alias = real_vector_alias(state, segment, offset, memory)?;
                (alias.selector().raw().0, alias.offset())
            }
        }
    };

    // AH=35 returns a guest selector, never the DOS core's real-mode segment.
    regs.es = target_segment;
    regs.set_bx(target_offset);
    Ok(DosAction::Continue)
}

/// Resolve a vector before constructing its protected-mode interrupt frame.
/// A software INT does not consult the protected overlay by executing a ROM
/// IRET byte: registered handlers retain their selector identity, while
/// default ROM entries are identified and dispatched as typed services.
pub(super) fn resolve_interrupt_target(
    state: &mut Win16State,
    vector: u8,
    memory: &mut Memory,
) -> Result<ProtectedInterruptTarget, RuntimeError> {
    let target = match state.protected_dos_vectors.get(&vector).copied() {
        Some(None) => return Ok(ProtectedInterruptTarget::Empty),
        Some(Some(pointer)) => {
            validate_registered_target(state, pointer, memory)?;
            if let Some(service) = firmware_service_for_alias(state, pointer) {
                return Ok(ProtectedInterruptTarget::FirmwareService {
                    vector: service,
                    entry: pointer,
                });
            }
            return Ok(ProtectedInterruptTarget::Guest(pointer));
        }
        None => read_real_vector(memory, vector)?,
    };

    if target.0 == 0 && target.1 == 0 {
        return Ok(ProtectedInterruptTarget::Empty);
    }
    let pointer = real_vector_alias(state, target.0, target.1, memory)?;
    if let Some(service) = crate::interrupts::service_vector(target.0, target.1) {
        Ok(ProtectedInterruptTarget::FirmwareService {
            vector: service,
            entry: pointer,
        })
    } else {
        Ok(ProtectedInterruptTarget::Guest(pointer))
    }
}

fn read_real_vector(memory: &Memory, vector: u8) -> Result<(u16, u16), RuntimeError> {
    let address = PhysAddr(u32::from(vector) * 4);
    let mut bytes = [0; 4];
    memory.read(address, &mut bytes).map_err(runtime_error)?;
    let offset = u16::from_le_bytes([bytes[0], bytes[1]]);
    let segment = u16::from_le_bytes([bytes[2], bytes[3]]);
    Ok((segment, offset))
}

fn real_vector_alias(
    state: &mut Win16State,
    segment: u16,
    offset: u16,
    memory: &Memory,
) -> Result<SegmentedPointer, RuntimeError> {
    let address = real_address(segment, offset);
    if !(ROM_START..ROM_END).contains(&address.0) {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            format!(
                "real-mode interrupt vector {segment:04X}:{offset:04X} is not backed by guest ROM"
            ),
        ));
    }

    if let Some(&selector) = state.real_mode_vector_aliases.get(&(segment, offset)) {
        let pointer = SegmentedPointer::new(selector, 0);
        validate_real_alias(state, pointer, address, memory)?;
        return Ok(pointer);
    }

    // A selector alias is created only over a checked byte in the simulated
    // ROM window. No real-mode pointer is used as a host address or executable
    // mapping outside that guest-owned region.
    let selector = state
        .selectors
        .alloc_block(address, 1, AccessRights::code(), memory)
        .map_err(runtime_error)?;
    let pointer = SegmentedPointer::new(selector, 0);
    validate_real_alias(state, pointer, address, memory)?;
    state
        .real_mode_vector_aliases
        .insert((segment, offset), selector);
    Ok(pointer)
}

fn validate_real_alias(
    state: &Win16State,
    pointer: SegmentedPointer,
    expected_address: PhysAddr,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    let descriptor = state
        .selectors
        .describe(pointer.selector())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "saved real-mode vector alias has a stale selector identity",
                error,
            )
        })?;
    if !descriptor.present
        || descriptor.base != expected_address
        || descriptor.limit != 0
        || !descriptor.rights.executable()
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "saved real-mode vector alias no longer names its checked ROM byte",
        ));
    }
    state
        .selectors
        .translate(pointer, Access::Execute, 1, memory)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "saved real-mode vector alias is not executable guest ROM",
                error,
            )
        })?;
    Ok(())
}

fn validate_registered_target(
    state: &Win16State,
    pointer: SegmentedPointer,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    state
        .selectors
        .translate(pointer, Access::Execute, 1, memory)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "registered protected-mode DOS vector has a stale or non-executable selector identity",
                error,
            )
        })?;
    Ok(())
}

fn firmware_service_for_alias(state: &Win16State, pointer: SegmentedPointer) -> Option<u8> {
    state
        .real_mode_vector_aliases
        .iter()
        .find_map(|(&(segment, offset), &selector)| {
            (selector == pointer.selector() && pointer.offset() == 0)
                .then(|| crate::interrupts::service_vector(segment, offset))
                .flatten()
        })
}

/// Identify an executable ROM service alias at the current guest CS:IP.
/// The raw selector lookup is followed by validation of the saved generation;
/// a descriptor reused by guest code cannot become a firmware entry.
pub(super) fn firmware_service_at(
    state: &Win16State,
    selector: u16,
    offset: u16,
    memory: &Memory,
) -> Result<Option<u8>, RuntimeError> {
    if offset != 0 {
        return Ok(None);
    }
    for (&(segment, real_offset), &identity) in &state.real_mode_vector_aliases {
        if identity.raw().0 != selector {
            continue;
        }
        validate_real_alias(
            state,
            SegmentedPointer::new(identity, 0),
            real_address(segment, real_offset),
            memory,
        )?;
        return Ok(crate::interrupts::service_vector(segment, real_offset));
    }
    Ok(None)
}

#[cfg(test)]
mod create_new_tests {
    use super::needs_dos_directory_context;

    #[test]
    fn create_new_installs_current_task_directory_context() {
        assert!(needs_dos_directory_context(0x5b));
        assert!(needs_dos_directory_context(0x5a));
        assert!(needs_dos_directory_context(0x6c));
        for service in [0x3e, 0x3f, 0x40, 0x42, 0x45, 0x46] {
            assert!(!needs_dos_directory_context(service));
        }
    }
}

#[cfg(test)]
#[path = "win16_dos_create_new_tests.rs"]
mod protected_create_new_tests;

#[cfg(test)]
#[path = "win16_dos_timestamp_tests.rs"]
mod dos_timestamp_tests;

#[cfg(test)]
#[path = "win16_dos_commit_tests.rs"]
mod commit_tests;

#[cfg(test)]
#[path = "win16_dos_extended_open_tests.rs"]
mod dos_extended_open_tests;

#[cfg(test)]
#[path = "win16_dos_temporary_file_tests.rs"]
mod dos_temporary_file_tests;

#[cfg(test)]
#[path = "win16_dos_spool_tests.rs"]
mod spool_tests;

#[cfg(test)]
#[path = "win16_dos_search_tests.rs"]
mod dos_search_tests;

#[cfg(test)]
#[path = "win16_dos_write_access_tests.rs"]
mod dos_write_access_tests;
