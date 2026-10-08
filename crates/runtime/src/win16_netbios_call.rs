//! Runtime projection of the KERNEL NetBIOSCall register service.
//!
//! Win16 SDK 3.0 documents this export as the register equivalent of INT 5Ch.
//! The guest NCB and pointed-to status records use the WFW 3.1 16-bit wire
//! layouts; neither selector FAR values nor guest memory addresses cross the
//! host boundary.

use guest_core::memory::Memory;
use guest_core::{GuestMemory, Registers, Selector};
use win16_abi::{Access, SegmentedPointer};
use zerocopy::{FromBytes, IntoBytes};

use super::netbios_wire::{
    NCB16_BYTES, NCBASTAT, NCBCHAINSEND, NCBCHAINSENDNA, NCBDGRECV, NCBDGRECVBC,
    NCBDGSEND, NCBDGSENDBC, NCBENUM, NCBFINDNAME, NCBRECV, NCBRECVANY, NCBACTION,
    NCBSEND, NCBSENDNA, NCBSSTAT, Ncb16Wire, ACTION_HEADER_BYTES,
};
use super::netbios_validation::{self, NetbiosCallValidation};
use super::{
    Win16State,
    guest_ranges::{GuestOutputRange, commit_guest_writes},
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const NRC_BUFLEN: u8 = 0x01;
const NRC_BADDR: u8 = 0x07;

/// Execute one checked synchronous NetBIOS register call and preserve all
/// service registers except the FAR-return control state.
pub(super) fn execute(
    state: &mut Win16State,
    registers: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
    return_to: (u16, u16, u32),
) -> Result<(), RuntimeError> {
    let ncb_pointer = state
        .selectors
        .pointer_from_raw(Selector(registers.es), registers.bx())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "KERNEL NetBIOSCall has an invalid ES:BX NCB pointer",
                error,
            )
        })?;
    require_single_selector(state, ncb_pointer, NCB16_BYTES, memory)?;
    let ncb_output = GuestOutputRange::capture(state, memory, ncb_pointer, NCB16_BYTES)?;
    let ncb_bytes = ncb_output.read(state, memory)?;
    let ncb = Ncb16Wire::read_from_bytes(&ncb_bytes).map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "captured Win16 NCB has an invalid fixed layout",
        )
    })?;
    let asynchronous = ncb.is_asynchronous();
    let command = ncb.command_code();
    if command == super::netbios_wire::NCBRESET {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 NCBRESET LSN/count resource semantics have no verified native translation",
        ));
    }
    if asynchronous && ncb.post.get() != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 asynchronous POST calling convention and continuation contract are unverified",
        ));
    }
    if ncb.command_code() == super::netbios_wire::NCBCANCEL {
        let result = match super::netbios_async::cancel_target(state, memory, host, &ncb) {
            Ok(result) => result,
            Err(error) if error.kind() == Kind::GuestFault => {
                return complete_guest_status(
                    state, registers, memory, &ncb_output, ncb, NRC_BADDR, return_to,
                );
            }
            Err(error) => return Err(error),
        };
        netbios_validation::validate_result(&NetbiosCallValidation::from_ncb(&ncb), &result)?;
        commit_result_to_guest(state, memory, &ncb_output, None, ncb, &result)?;
        registers.set_al(result.function_return);
        return state.complete_kernel_register_return(registers, return_to);
    }

    if matches!(command, NCBCHAINSEND | NCBCHAINSENDNA) {
        let second_length = usize::from(u16::from_le_bytes([ncb.callname[0], ncb.callname[1]]));
        if usize::from(ncb.length.get()) + second_length > usize::from(u16::MAX) {
            return complete_guest_status(
                state, registers, memory, &ncb_output, ncb, NRC_BUFLEN, return_to,
            );
        }
    }
    if command == NCBACTION && ncb.length.get() < ACTION_HEADER_BYTES {
        // The Windows extension requires the fixed eight-byte ACTION_HEADER.
        // Returning the native documented buffer-length status here avoids
        // giving an undersized owned allocation to an API that writes it.
        return complete_guest_status(
            state, registers, memory, &ncb_output, ncb, NRC_BUFLEN, return_to,
        );
    }
    let (payload, output_range, buffer_capacity, native_length, host_command, call_name) =
        match prepare_payload(state, memory, &ncb) {
            Ok(prepared) => prepared,
            Err(error) if error.kind() == Kind::GuestFault => {
                return complete_guest_status(
                    state, registers, memory, &ncb_output, ncb, NRC_BADDR, return_to,
                );
            }
            Err(error) => return Err(error),
        };
    let call = crate::Win16HostNetbiosCall {
        command: host_command,
        asynchronous,
        lsn: ncb.lsn,
        num: ncb.num,
        length: ncb.length.get(),
        native_length,
        call_name,
        name: ncb.name,
        receive_timeout: ncb.rto,
        send_timeout: ncb.sto,
        lana_num: ncb.lana_num,
        payload,
    };
    // Keep only the result-shape contract before transferring the owned
    // request to the host. The payload bytes may be large and are never cloned.
    let mut validation = NetbiosCallValidation::from_call(&call, buffer_capacity);
    // A chain-send is flattened into an owned native SEND buffer, while the
    // guest NCB retains its own first-buffer length and command identity.
    validation.command = command;
    validation.length = ncb.length.get();
    if asynchronous {
        state.submit_netbios_async(
            registers,
            memory,
            host,
            call,
            validation,
            ncb,
            ncb_output,
            output_range,
            return_to,
        )
    } else {
        let mut result = host.win16_netbios_call(call)?;
        if matches!(command, NCBCHAINSEND | NCBCHAINSENDNA) {
            result.length = ncb.length.get();
        }
        netbios_validation::validate_result(&validation, &result)?;
        commit_result_to_guest(
            state,
            memory,
            &ncb_output,
            output_range.as_ref(),
            ncb,
            &result,
        )?;

        // The Windows SDK describes NetBIOSCall as the register equivalent
        // of INT 5Ch. Its completion byte is the function return in AL.
        registers.set_al(result.function_return);
        state.complete_kernel_register_return(registers, return_to)
    }
}

fn complete_guest_status(
    state: &mut Win16State,
    registers: &mut Registers,
    memory: &mut Memory,
    ncb_output: &GuestOutputRange,
    ncb: Ncb16Wire,
    status: u8,
    return_to: (u16, u16, u32),
) -> Result<(), RuntimeError> {
    let result = result_for_ncb(ncb, status);
    commit_result_to_guest(state, memory, ncb_output, None, ncb, &result)?;
    registers.set_al(status);
    state.complete_kernel_register_return(registers, return_to)
}

pub(super) fn result_for_ncb(
    ncb: Ncb16Wire,
    status: u8,
) -> crate::Win16HostNetbiosResult {
    crate::Win16HostNetbiosResult {
        function_return: status,
        retcode: status,
        lsn: ncb.lsn,
        num: ncb.num,
        length: ncb.length.get(),
        cmd_cplt: status,
        call_name: None,
        payload: crate::Win16HostNetbiosOutput::None,
    }
}

pub(super) fn commit_result_to_guest(
    state: &Win16State,
    memory: &mut Memory,
    ncb_output: &GuestOutputRange,
    output_range: Option<&GuestOutputRange>,
    mut ncb: Ncb16Wire,
    result: &crate::Win16HostNetbiosResult,
) -> Result<(), RuntimeError> {
    if matches!(
        netbios_validation::classify_result(result)?,
        netbios_validation::NetbiosResultClass::FunctionOnly(_)
    ) {
        // NRC_INVDDID is a function return only. The NCB status bytes and
        // every other guest field remain exactly as submitted.
        return Ok(());
    }
    ncb.retcode = result.retcode;
    ncb.lsn = result.lsn;
    ncb.num = result.num;
    ncb.set_length(result.length);
    ncb.cmd_cplt = result.cmd_cplt;
    if let Some(call_name) = result.call_name {
        ncb.callname = call_name;
    }
    let mut updated_ncb = [0u8; NCB16_BYTES];
    ncb.write_to(&mut updated_ncb).map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 NCB result did not fit its fixed wire record",
        )
    })?;

    let output_bytes = match &result.payload {
        crate::Win16HostNetbiosOutput::Bytes { bytes }
        | crate::Win16HostNetbiosOutput::FindName { bytes }
        | crate::Win16HostNetbiosOutput::LanaEnum { bytes }
        | crate::Win16HostNetbiosOutput::AdapterStatus { bytes }
        | crate::Win16HostNetbiosOutput::SessionStatus { bytes } => Some(bytes),
        crate::Win16HostNetbiosOutput::None => None,
    };
    let mut writes = Vec::new();
    writes.try_reserve_exact(2).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve NetBIOS guest output transaction",
            error,
        )
    })?;
    // NetBIOS writes its payload before the NCB completion fields. Keeping the
    // NCB write last also defines the result when guest ranges alias.
    match (output_range, output_bytes) {
        (Some(range), Some(bytes)) => {
            let mut output = Vec::new();
            output.try_reserve_exact(bytes.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain NetBIOS guest output for commit",
                    error,
                )
            })?;
            output.extend_from_slice(bytes);
            writes.push((range.try_clone()?, output));
        }
        (Some(_), None) => {}
        (None, Some(bytes)) if bytes.is_empty() => {}
        (None, None) => {}
        _ => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "NetBIOS host returned output without a captured guest buffer",
            ));
        }
    }
    let mut ncb_write = Vec::new();
    ncb_write.try_reserve_exact(NCB16_BYTES).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy NetBIOS NCB result", error)
    })?;
    ncb_write.extend_from_slice(&updated_ncb);
    writes.push((ncb_output.try_clone()?, ncb_write));
    commit_guest_writes(state, memory, writes)
}

pub(super) fn prepare_payload(
    state: &Win16State,
    memory: &Memory,
    ncb: &Ncb16Wire,
) -> Result<
    (
        crate::Win16HostNetbiosPayload,
        Option<GuestOutputRange>,
        Option<u16>,
        u16,
        u8,
        [u8; 16],
    ),
    RuntimeError,
> {
    let command = ncb.command_code();
    if matches!(command, NCBASTAT | NCBSSTAT) {
        let buffer = ncb.buffer_far_value();
        if buffer == 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "NetBIOS status NCB has a null output buffer",
            ));
        }
        let pointer = state.selectors.pointer_from_far(buffer).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "NetBIOS status NCB has an invalid guest buffer selector",
                error,
            )
        })?;
        let capacity = ncb.length.get();
        let range = capture_single_output(state, memory, pointer, usize::from(capacity))?;
        let payload = if command == NCBASTAT {
            crate::Win16HostNetbiosPayload::AdapterStatus { capacity }
        } else {
            crate::Win16HostNetbiosPayload::SessionStatus { capacity }
        };
        return Ok((
            payload,
            Some(range),
            Some(capacity),
            capacity,
            command,
            ncb.callname,
        ));
    }

    if command == NCBFINDNAME {
        let buffer = ncb.buffer_far_value();
        if buffer == 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "NCBFINDNAME has a null output buffer",
            ));
        }
        let pointer = state.selectors.pointer_from_far(buffer).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "NCBFINDNAME has an invalid guest output selector",
                error,
            )
        })?;
        let capacity = ncb.length.get();
        let range = capture_single_output(state, memory, pointer, usize::from(capacity))?;
        return Ok((
            crate::Win16HostNetbiosPayload::FindName { capacity },
            Some(range),
            Some(capacity),
            capacity,
            command,
            ncb.callname,
        ));
    }

    if command == NCBENUM {
        let buffer = ncb.buffer_far_value();
        if buffer == 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "NCBENUM has a null LANA_ENUM output buffer",
            ));
        }
        let pointer = state.selectors.pointer_from_far(buffer).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "NCBENUM has an invalid guest output selector",
                error,
            )
        })?;
        let capacity = ncb.length.get();
        let range = capture_single_output(state, memory, pointer, usize::from(capacity))?;
        return Ok((
            crate::Win16HostNetbiosPayload::LanaEnum { capacity },
            Some(range),
            Some(capacity),
            capacity,
            command,
            ncb.callname,
        ));
    }

    if command == NCBACTION {
        let far = ncb.buffer_far_value();
        if far == 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "NCBACTION has a null ACTION_HEADER buffer",
            ));
        }
        let pointer = state.selectors.pointer_from_far(far).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "NCBACTION has an invalid guest ACTION_HEADER selector",
                error,
            )
        })?;
        let capacity = usize::from(ncb.length.get());
        let range = capture_single_output(state, memory, pointer, capacity)?;
        let mut bytes = allocate_bytes(capacity, "copy Win16 NCBACTION input")?;
        require_one_selector_access(state, pointer, capacity, Access::Read, memory)?;
        let address = state
            .selectors
            .translate(pointer, Access::Read, capacity, memory)
            .map_err(crate::runtime_error)?;
        memory.read(address, &mut bytes).map_err(crate::runtime_error)?;
        return Ok((
            crate::Win16HostNetbiosPayload::Bytes {
                bytes,
                access: crate::Win16HostNetbiosBufferAccess::ReadWrite,
            },
            Some(range),
            Some(ncb.length.get()),
            ncb.length.get(),
            command,
            ncb.callname,
        ));
    }

    if matches!(command, NCBCHAINSEND | NCBCHAINSENDNA) {
        let first_length = usize::from(ncb.length.get());
        let second_length = usize::from(u16::from_le_bytes([ncb.callname[0], ncb.callname[1]]));
        let total_length = first_length + second_length;
        let first_far = ncb.buffer_far_value();
        if first_far == 0 && first_length != 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "NCBCHAINSEND has a null first buffer",
            ));
        }
        let second_far = u32::from_le_bytes([
            ncb.callname[2],
            ncb.callname[3],
            ncb.callname[4],
            ncb.callname[5],
        ]);
        if second_far == 0 && second_length != 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "NCBCHAINSEND has a null second buffer",
            ));
        }
        let mut bytes = allocate_bytes(total_length, "copy both Win16 chain-send buffers")?;
        if first_length != 0 {
            let first = state.selectors.pointer_from_far(first_far).map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "NCBCHAINSEND first buffer has an invalid selector",
                    error,
                )
            })?;
            require_one_selector_access(state, first, first_length, Access::Read, memory)?;
            let address = state
                .selectors
                .translate(first, Access::Read, first_length, memory)
                .map_err(crate::runtime_error)?;
            memory
                .read(address, &mut bytes[..first_length])
                .map_err(crate::runtime_error)?;
        }
        if second_length != 0 {
            let second = state.selectors.pointer_from_far(second_far).map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "NCBCHAINSEND second buffer has an invalid selector",
                    error,
                )
            })?;
            require_one_selector_access(state, second, second_length, Access::Read, memory)?;
            let address = state
                .selectors
                .translate(second, Access::Read, second_length, memory)
                .map_err(crate::runtime_error)?;
            memory
                .read(address, &mut bytes[first_length..])
                .map_err(crate::runtime_error)?;
        }
        return Ok((
            crate::Win16HostNetbiosPayload::Bytes {
                bytes,
                access: crate::Win16HostNetbiosBufferAccess::Read,
            },
            None,
            Some(ncb.length.get()),
            total_length as u16,
            if command == NCBCHAINSEND {
                NCBSEND
            } else {
                NCBSENDNA
            },
            [0; 16],
        ));
    }

    let access = match command {
        NCBSEND | NCBDGSEND | NCBDGSENDBC | NCBSENDNA => crate::Win16HostNetbiosBufferAccess::Read,
        NCBRECV | NCBRECVANY | NCBDGRECV | NCBDGRECVBC => {
            crate::Win16HostNetbiosBufferAccess::Write
        }
        _ => {
            return Ok((
                crate::Win16HostNetbiosPayload::None,
                None,
                None,
                ncb.length.get(),
                command,
                ncb.callname,
            ));
        }
    };
    let far = ncb.buffer_far_value();
    if far == 0 {
        if ncb.length.get() != 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "NetBIOS data NCB has a null buffer",
            ));
        }
        return Ok((
            crate::Win16HostNetbiosPayload::None,
            None,
            Some(0),
            0,
            command,
            ncb.callname,
        ));
    }
    let pointer = state.selectors.pointer_from_far(far).map_err(|error| {
        RuntimeError::with_source(
            Kind::GuestFault,
            "NetBIOS data buffer has an invalid guest selector",
            error,
        )
    })?;
    let capacity = usize::from(ncb.length.get());
    let range = if matches!(access, crate::Win16HostNetbiosBufferAccess::Write) {
        Some(capture_single_output(state, memory, pointer, capacity)?)
    } else {
        None
    };
    let mut bytes = allocate_bytes(capacity, "copy guest NetBIOS input")?;
    if matches!(access, crate::Win16HostNetbiosBufferAccess::Read) {
        require_one_selector_access(state, pointer, capacity, Access::Read, memory)?;
        let address = state
            .selectors
            .translate(pointer, Access::Read, capacity, memory)
            .map_err(crate::runtime_error)?;
        memory
            .read(address, &mut bytes)
            .map_err(crate::runtime_error)?;
    } else {
        // Output-only NCB buffers are capacity, not input. A zeroed owned
        // buffer avoids reading bytes the native operation is allowed to replace.
        require_one_selector_access(state, pointer, capacity, Access::Write, memory)?;
    }
    Ok((
        crate::Win16HostNetbiosPayload::Bytes { bytes, access },
        range,
        Some(ncb.length.get()),
        ncb.length.get(),
        command,
        ncb.callname,
    ))
}

fn capture_single_output(
    state: &Win16State,
    memory: &Memory,
    pointer: SegmentedPointer,
    length: usize,
) -> Result<GuestOutputRange, RuntimeError> {
    require_one_selector_access(state, pointer, length, Access::Write, memory)?;
    GuestOutputRange::capture(state, memory, pointer, length)
}

fn require_one_selector_access(
    state: &Win16State,
    pointer: SegmentedPointer,
    length: usize,
    access: Access,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    state
        .selectors
        .translate(pointer, access, length, memory)
        .map_err(crate::runtime_error)?;
    let descriptor = state
        .selectors
        .describe(pointer.selector())
        .map_err(crate::runtime_error)?;
    let end = u32::from(pointer.offset())
        .checked_add(u32::try_from(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "NetBIOS buffer length exceeds DWORD",
                error,
            )
        })?)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::GuestFault,
                "NetBIOS buffer end overflows its selector",
            )
        })?;
    if end > descriptor.limit.saturating_add(1) {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "NetBIOS buffer crosses its Win16 selector limit",
        ));
    }
    Ok(())
}

fn require_single_selector(
    state: &Win16State,
    pointer: SegmentedPointer,
    length: usize,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    require_one_selector_access(state, pointer, length, Access::Read, memory)?;
    require_one_selector_access(state, pointer, length, Access::Write, memory)
}

fn allocate_bytes(length: usize, operation: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, operation, error))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
