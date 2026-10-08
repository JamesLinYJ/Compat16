//! Guest result projection and Win16 MCI parameter-block writeback.

use guest_core::{Registers, memory::Memory};
use win16_abi::{
    Access, Win16MciGuestRange, Win16MciOutputBuffer, Win16MciParameters, Win16MciRequest,
    Win16ReturnKind,
};

use super::Win16State;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostMciOutput,
    Win16HostMciResult,
};

const MCI_OPEN: u16 = 0x0803;
const MCI_CLOSE: u16 = 0x0804;

pub(super) fn complete(
    state: &mut Win16State,
    request: Win16MciRequest,
    result: Win16HostMciResult,
    registers: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
) -> Result<Option<u8>, RuntimeError> {
    preflight_output_ranges(state, &request, &result, memory)?;
    let value = match &request {
        Win16MciRequest::SendCommand {
            device_id,
            message,
            parameters,
            parameter_output,
            reserved_device_id,
            ..
        } => {
            if result.return_value == 0 {
                match (*message, parameters) {
                    (MCI_OPEN, Win16MciParameters::Open { .. }) => {
                        let Win16HostMciOutput::Device {
                            device,
                            device_type,
                        } = result.output
                        else {
                            return Err(invariant(
                                "successful MCI_OPEN omitted its owned device identity",
                            ));
                        };
                        let creator = match state.current_task_handle() {
                            Ok(creator) => creator,
                            Err(error) => {
                                state.retain_orphan_mci_device(device);
                                return Err(error.with_context(
                                    "successful MCI_OPEN identity retained after creator lookup failed",
                                ));
                            }
                        };
                        let Some(guest) = reserved_device_id else {
                            state.retain_orphan_mci_device(device);
                            return Err(invariant(
                                "successful MCI_OPEN has no reserved guest alias; host identity retained",
                            ));
                        };
                        let guest = state.commit_reserved_mci_device(
                            *guest,
                            device,
                            device_type,
                            creator,
                        )?;
                        let range = parameter_output.ok_or_else(|| {
                            invariant("successful MCI_OPEN has no captured device-ID output range")
                        })?;
                        write_guest_range(state, range, &guest.to_le_bytes(), memory)?;
                    }
                    (MCI_CLOSE, _) => {
                        if *device_id == u16::MAX {
                            state.retire_all_mci_devices();
                        } else {
                            state.retire_mci_device(*device_id);
                        }
                    }
                    (_, Win16MciParameters::Status { .. })
                    | (_, Win16MciParameters::GetDeviceCaps { .. }) => {
                        let value = scalar_output(result.output)?;
                        let range = parameter_output.ok_or_else(|| {
                            invariant("successful MCI scalar command has no captured output range")
                        })?;
                        write_guest_range(state, range, &value.to_le_bytes(), memory)?;
                    }
                    (_, Win16MciParameters::Info { output, .. })
                    | (_, Win16MciParameters::SystemInfo { output, .. })
                        if matches!(result.output, Win16HostMciOutput::Bytes(_)) =>
                    {
                        write_output(state, *output, result.output, memory)?;
                    }
                    (_, Win16MciParameters::SystemInfo { output, .. }) => {
                        let scalar = scalar_output(result.output)?;
                        let range = output.range.ok_or_else(|| {
                            invariant("successful numeric MCI_SYSINFO has no captured output range")
                        })?;
                        write_guest_range(state, range, &scalar.to_le_bytes(), memory)?;
                    }
                    (0x0843, Win16MciParameters::Rectangle { output: true, .. }) => {
                        let Win16HostMciOutput::Rectangle(rect) = result.output else {
                            return Err(invariant("successful MCI_WHERE returned no rectangle"));
                        };
                        let mut bytes = [0_u8; 8];
                        for (slot, value) in bytes.chunks_exact_mut(2).zip(rect) {
                            slot.copy_from_slice(&value.to_le_bytes());
                        }
                        let range = parameter_output.ok_or_else(|| {
                            invariant("successful MCI_WHERE has no captured RECT output range")
                        })?;
                        write_guest_range(state, range, &bytes, memory)?;
                    }
                    _ => {}
                }
            } else if *message == MCI_OPEN {
                state.release_reserved_from_request(&request);
            }
            result.return_value
        }
        Win16MciRequest::SendString {
            output,
            reserved_device_id,
            ..
        } => {
            if result.return_value == 0 {
                finish_string_effects(
                    state,
                    &request,
                    *reserved_device_id,
                    Some(*output),
                    result.output,
                    memory,
                    host,
                )?;
            } else {
                state.release_reserved_from_request(&request);
            }
            result.return_value
        }
        Win16MciRequest::GetDeviceId { .. }
        | Win16MciRequest::GetDeviceIdFromElement { .. } => match result.output {
            Win16HostMciOutput::All => u32::from(u16::MAX),
            Win16HostMciOutput::Device {
                device,
                device_type,
            } => {
                let creator = match state.current_task_handle() {
                    Ok(creator) => creator,
                    Err(error) => {
                        state.retain_orphan_mci_device(device);
                        return Err(error.with_context(
                            "MCI lookup identity retained after creator lookup failed",
                        ));
                    }
                };
                let alias = match state.retain_mci_device(device, device_type, creator) {
                    Ok(alias) => alias,
                    Err(error) => {
                        state.retain_orphan_mci_device(device);
                        return Err(error.with_context(
                            "MCI lookup identity retained for task cleanup after alias mapping failed",
                        ));
                    }
                };
                u32::from(alias)
            }
            Win16HostMciOutput::None | Win16HostMciOutput::Scalar(0) => 0,
            _ => return Err(invariant("MCI device lookup returned the wrong host value")),
        },
        Win16MciRequest::GetErrorString { output, .. } => {
            if result.return_value != 0 {
                write_output(state, *output, result.output, memory)?;
            }
            result.return_value
        }
        Win16MciRequest::SetDriverData { .. } | Win16MciRequest::DriverNotify { .. } => {
            result.return_value
        }
        Win16MciRequest::SetYieldProc {
            device_id,
            procedure,
            procedure_pointer,
            data,
        } => {
            let Win16HostMciOutput::YieldProc {
                installed,
                data: native_data,
                registration,
            } = result.output
            else {
                return Err(invariant("mciSetYieldProc returned no registration receipt"));
            };
            if result.return_value != 0
                && (installed != (*procedure != 0)
                    || native_data != *data
                    || (installed != registration.is_some()))
            {
                return Err(invariant(
                    "mciSetYieldProc result disagrees with its exact native registration receipt",
                ));
            }
            if result.return_value != 0 {
                if let Some(entry) = state.resolve_mci_device(*device_id) {
                    if *procedure == 0 {
                        state.retain_mci_yield_source(entry.host);
                        state.mci.yield_procedures.remove(&entry.host);
                    } else {
                        let registration = registration.ok_or_else(|| {
                            invariant("successful MCI yield registration omitted its host identity")
                        })?;
                        state.mci.yield_procedures.insert(
                            entry.host,
                            super::Win16MciYieldProcedure {
                                procedure: *procedure,
                                pointer: procedure_pointer.ok_or_else(|| {
                                    invariant("successful MCI yield registration lost its captured selector")
                                })?,
                                registration,
                            },
                        );
                    }
                }
            }
            result.return_value
        }
        Win16MciRequest::GetDriverData { .. } | Win16MciRequest::DriverYield { .. } => {
            scalar_output(result.output)?
        }
        Win16MciRequest::Execute {
            reserved_device_id, ..
        } => {
            if result.return_value == 0 {
                finish_string_effects(
                    state,
                    &request,
                    *reserved_device_id,
                    None,
                    result.output,
                    memory,
                    host,
                )?;
                1
            } else {
                state.release_reserved_from_request(&request);
                0
            }
        }
        Win16MciRequest::GetYieldProc {
            data_output,
            device_id,
        } => {
            let Win16HostMciOutput::YieldProc {
                installed,
                data,
                registration,
            } = result.output else {
                return Err(invariant("mciGetYieldProc returned the wrong host value"));
            };
            if let Some(range) = data_output {
                write_guest_range(state, *range, &data.to_le_bytes(), memory)?;
            }
            if installed {
                state
                    .resolve_mci_device(*device_id)
                    .and_then(|entry| state.mci.yield_procedures.get(&entry.host))
                    .filter(|procedure| Some(procedure.registration) == registration)
                    .map_or(0, |procedure| procedure.procedure)
            } else {
                0
            }
        }
        Win16MciRequest::GetCreatorTask { .. } => scalar_output(result.output)?,
        Win16MciRequest::LoadCommandResource { .. }
        | Win16MciRequest::FreeCommandResource { .. } => result.return_value,
    };
    state.complete_return(
        registers,
        return_to.0,
        return_to.1,
        return_to.2,
        value,
        return_kind,
    )
}

fn preflight_output_ranges(
    state: &Win16State,
    request: &Win16MciRequest,
    result: &Win16HostMciResult,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    if result.return_value == 0 {
        match request {
            Win16MciRequest::SendCommand {
                message,
                parameters,
                parameter_output,
                ..
            } => match (*message, parameters, &result.output) {
                (MCI_OPEN, Win16MciParameters::Open { .. }, Win16HostMciOutput::Device { .. }) => {
                    preflight_guest_range(state, *parameter_output, 2, false, memory)?;
                }
                (_, Win16MciParameters::Status { .. } | Win16MciParameters::GetDeviceCaps { .. }, Win16HostMciOutput::Scalar(_)) => {
                    preflight_guest_range(state, *parameter_output, 4, false, memory)?;
                }
                (_, Win16MciParameters::Info { output, .. }, Win16HostMciOutput::Bytes(bytes))
                | (_, Win16MciParameters::SystemInfo { output, .. }, Win16HostMciOutput::Bytes(bytes)) => {
                    preflight_output_buffer(state, *output, bytes.len(), true, memory)?;
                }
                (_, Win16MciParameters::SystemInfo { output, .. }, Win16HostMciOutput::Scalar(_)) => {
                    if let Some(range) = output.range {
                        preflight_guest_range(state, Some(range), 4, false, memory)?;
                    } else {
                        return Err(invariant(
                            "successful numeric MCI_SYSINFO omitted its captured output range",
                        ));
                    }
                }
                (0x0843, Win16MciParameters::Rectangle { output: true, .. }, Win16HostMciOutput::Rectangle(_)) => {
                    preflight_guest_range(state, *parameter_output, 8, false, memory)?;
                }
                _ => {}
            },
            Win16MciRequest::SendString { output, .. } => {
                match &result.output {
                    Win16HostMciOutput::StringCommand {
                        bytes,
                        unsupported_owner: false,
                        ..
                    }
                    | Win16HostMciOutput::Bytes(bytes) => {
                        preflight_output_buffer(state, *output, bytes.len(), true, memory)?;
                    }
                    _ => {}
                }
            }
            Win16MciRequest::GetYieldProc { data_output, .. } => {
                if let Some(range) = data_output {
                    preflight_guest_range(state, Some(*range), 4, false, memory)?;
                }
            }
            Win16MciRequest::Execute { .. }
            | Win16MciRequest::GetDeviceId { .. }
            | Win16MciRequest::GetDeviceIdFromElement { .. }
            | Win16MciRequest::LoadCommandResource { .. }
            | Win16MciRequest::GetErrorString { .. }
            | Win16MciRequest::SetDriverData { .. }
            | Win16MciRequest::GetDriverData { .. }
            | Win16MciRequest::DriverYield { .. }
            | Win16MciRequest::DriverNotify { .. }
            | Win16MciRequest::FreeCommandResource { .. }
            | Win16MciRequest::SetYieldProc { .. }
            | Win16MciRequest::GetCreatorTask { .. } => {}
        }
    } else if let Win16MciRequest::GetErrorString { output, .. } = request {
        if output.far != 0 && output.capacity != 0 {
            if let Win16HostMciOutput::Bytes(bytes) = &result.output {
                preflight_output_buffer(state, *output, bytes.len(), true, memory)?;
            }
        }
    }
    Ok(())
}

fn preflight_output_buffer(
    state: &Win16State,
    output: Win16MciOutputBuffer,
    byte_count: usize,
    exact_length: bool,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    if output.far == 0 || output.capacity == 0 {
        return Ok(());
    }
    let range = output
        .range
        .ok_or_else(|| invariant("MCI output buffer lost its captured selector generation"))?;
    preflight_guest_range(state, Some(range), byte_count, exact_length, memory)
}

fn preflight_guest_range(
    state: &Win16State,
    range: Option<Win16MciGuestRange>,
    byte_count: usize,
    exact_length: bool,
    memory: &Memory,
) -> Result<(), RuntimeError> {
    let range = range.ok_or_else(|| invariant("MCI result omitted its captured output range"))?;
    let range_length = usize::try_from(range.length).unwrap_or(usize::MAX);
    if byte_count > range_length || (exact_length && byte_count != range_length) {
        return Err(invariant("MCI result length does not match its captured guest output span"));
    }
    state
        .selectors
        .translate(range.pointer, Access::Write, range_length, memory)
        .map_err(crate::runtime_error)?;
    Ok(())
}

fn finish_string_effects(
    state: &mut Win16State,
    request: &Win16MciRequest,
    reserved_device_id: Option<u16>,
    output: Option<Win16MciOutputBuffer>,
    result: Win16HostMciOutput,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let (bytes, opened, closed, closed_all, unsupported_owner) = match result {
        Win16HostMciOutput::StringCommand {
            bytes,
            opened,
            closed,
            closed_all,
            unsupported_owner,
        } => (bytes, opened, closed, closed_all, unsupported_owner),
        Win16HostMciOutput::Bytes(bytes) => (bytes, None, None, false, false),
        _ => return Err(invariant("MCI string call returned no owner receipt")),
    };
    if unsupported_owner {
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            "MCI string OPEN could not retain the native device by a stable alias",
        ));
        return Err(invariant(
            "native MCI string OPEN succeeded without a retained owner receipt",
        ));
    }
    if let Some((device, device_type)) = opened {
        let Some(reserved) = reserved_device_id else {
            state.retain_orphan_mci_device(device);
            return Err(invariant(
                "MCI string OPEN has no reserved guest device alias; host identity retained",
            ));
        };
        let creator = match state.current_task_handle() {
            Ok(creator) => creator,
            Err(error) => {
                state.retain_orphan_mci_device(device);
                return Err(error.with_context(
                    "MCI string OPEN identity retained after creator lookup failed",
                ));
            }
        };
        let _guest = state.commit_reserved_mci_device(
            reserved,
            device,
            device_type,
            creator,
        )?;
    } else {
        state.release_reserved_from_request(request);
    }
    if let Some(device) = closed {
        state.retire_mci_host_device_with_sources(device);
    }
    if closed_all {
        state.retire_all_mci_devices();
    }
    if let Some(output) = output {
        write_output(state, output, Win16HostMciOutput::Bytes(bytes), memory)?;
    }
    Ok(())
}

fn write_output(
    state: &Win16State,
    output: Win16MciOutputBuffer,
    value: Win16HostMciOutput,
    memory: &mut Memory,
) -> Result<(), RuntimeError> {
    if output.far == 0 || output.capacity == 0 {
        return Ok(());
    }
    let Win16HostMciOutput::Bytes(bytes) = value else {
        return Err(invariant(
            "MCI string operation returned no owned output bytes",
        ));
    };
    let range = output
        .range
        .ok_or_else(|| invariant("MCI output buffer has no captured selector generation"))?;
    if bytes.len() > usize::try_from(range.length).unwrap_or(usize::MAX) {
        return Err(invariant(
            "MCI host output exceeds the checked guest buffer",
        ));
    }
    if bytes.len() != usize::try_from(range.length).unwrap_or(usize::MAX) {
        return Err(invariant(
            "MCI host string output did not preserve the captured output extent",
        ));
    }
    write_guest_range(state, range, &bytes, memory)
}

fn write_guest_range(
    state: &Win16State,
    range: Win16MciGuestRange,
    bytes: &[u8],
    memory: &mut Memory,
) -> Result<(), RuntimeError> {
    if bytes.len() > usize::try_from(range.length).unwrap_or(usize::MAX) {
        return Err(invariant("MCI writeback exceeds its captured guest span"));
    }
    state
        .selectors
        .translate(
            range.pointer,
            Access::Write,
            usize::try_from(range.length).unwrap_or(usize::MAX),
            memory,
        )
        .map_err(crate::runtime_error)?;
    state
        .selectors
        .write(memory, range.pointer, bytes)
        .map_err(crate::runtime_error)
}

fn scalar_output(value: Win16HostMciOutput) -> Result<u32, RuntimeError> {
    match value {
        Win16HostMciOutput::Scalar(value) => Ok(value),
        _ => Err(invariant("MCI host operation returned a non-scalar value")),
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
