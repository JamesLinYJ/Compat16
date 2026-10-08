//! Provider validation and checked publication of PE32 Win32 service gates.

use guest_core::{PhysAddr, memory::Memory};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::{
    win32_import_catalog::{self, Win32ImportDescriptor},
    win32_import_host::{
        Win32HostImportCall, Win32HostImportResult, Win32HostServiceIdentity, Win32ImportSymbol,
    },
    win32_import_state::{
        Win32GateReservation, Win32ImportState, Win32ServiceGate, Win32SystemModuleIdentity,
    },
};

const SERVICE_GATE_MARKER: [u8; 2] = [0x0f, 0x0b];
pub(crate) const ERROR_PROC_NOT_FOUND: u32 = 127;

/// Resolve one catalogued export from an exact provider generation. Windows
/// resolves forwarders; the host returns only an opaque official-identity token.
pub(crate) fn resolve_service_gate<F>(
    state: &mut Win32ImportState,
    provider: Win32SystemModuleIdentity,
    symbol: Win32ImportSymbol,
    memory: &mut Memory,
    mut host: F,
) -> Result<
    (
        Option<(Win32ImportDescriptor, Win32ServiceGate)>,
        Option<u32>,
    ),
    RuntimeError,
>
where
    F: FnMut(Win32HostImportCall) -> Result<Win32HostImportResult, RuntimeError>,
{
    let (host_module, _) = state.module(provider)?;
    let descriptor = match &symbol {
        Win32ImportSymbol::Name(name) => win32_import_catalog::lookup(name),
        Win32ImportSymbol::Ordinal(ordinal) => win32_import_catalog::lookup_ordinal(*ordinal),
    };
    let Some(descriptor) = descriptor else {
        return Ok((None, Some(ERROR_PROC_NOT_FOUND)));
    };

    let resolved = match host(Win32HostImportCall::ResolveSystemExport {
        module: host_module,
        symbol,
        service: Win32HostServiceIdentity::from_catalog(
            descriptor.service as u16,
            descriptor.service.family(),
            descriptor.export,
        ),
    }) {
        Ok(result) => result,
        Err(primary) => return Err(primary),
    };
    let last_error = resolved.last_error;
    let export = match resolved.value {
        crate::Win32HostImportValue::ResolvedExport(value) => value,
        _ => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "system export identity lookup returned an incompatible result DTO",
            ));
        }
    };
    let Some(export) = export else {
        return Ok((
            None,
            Some(last_error.filter(|code| *code != 0).unwrap_or(ERROR_PROC_NOT_FOUND)),
        ));
    };
    let reservation = match state.reserve_service_gate(provider, descriptor.service, export)? {
        Ok(gate) if gate.export == export => {
            return Ok((Some((*descriptor, gate)), last_error));
        }
        Ok(_) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "existing PE32 service gate has a different host export identity",
            ));
        }
        Err(reservation) => reservation,
    };

    let gate_address = match reservation.address(state) {
        Ok(address) => address,
        Err(primary) => return Err(cancel_gate_preserving(state, reservation, primary)),
    };
    let address = PhysAddr(gate_address);
    if let Err(error) = memory.validate_ram_range(address, SERVICE_GATE_MARKER.len(), true) {
        let primary = crate::runtime_error(error).with_context("reserve PE32 Win32 service gate");
        return Err(poison_gate_preserving(state, reservation, primary));
    }
    if let Err(error) = memory.write_physical(address, &SERVICE_GATE_MARKER) {
        let primary = crate::runtime_error(error).with_context("write PE32 Win32 service gate");
        return Err(poison_gate_preserving(state, reservation, primary));
    }
    match state.publish_service_gate(reservation) {
        Ok(gate) => Ok((Some((*descriptor, gate)), last_error)),
        Err(primary) => Err(primary.with_context("publish PE32 Win32 service gate")),
    }
}

fn cancel_gate_preserving(
    state: &mut Win32ImportState,
    reservation: Win32GateReservation,
    primary: RuntimeError,
) -> RuntimeError {
    match state.cancel_gate_reservation(reservation) {
        Ok(()) => primary,
        Err(cleanup) => combine(primary, cleanup, "cancel unused PE32 service gate"),
    }
}

fn poison_gate_preserving(
    state: &mut Win32ImportState,
    reservation: Win32GateReservation,
    primary: RuntimeError,
) -> RuntimeError {
    match state.poison_service_gate(reservation) {
        Ok(()) => primary,
        Err(cleanup) => combine(primary, cleanup, "retain poisoned PE32 service gate"),
    }
}

fn combine(primary: RuntimeError, cleanup: RuntimeError, context: &'static str) -> RuntimeError {
    primary.with_cleanup(context, cleanup)
}
