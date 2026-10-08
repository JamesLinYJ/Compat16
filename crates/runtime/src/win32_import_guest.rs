//! Checked Win32 service-gate entry on the PE32 guest instruction boundary.

use guest_core::memory::Memory;
use x86_cpu::Cpu;

use crate::pe32_call::Pe32CallNonce;
use crate::win32_import_catalog;
use crate::win32_import_state::{
    Win32ImportState, Win32ProviderInvocationPin, Win32ServiceGate,
    Win32SystemModuleIdentity,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ModuleImage, Win32HostImportCall,
    Win32HostImportResult, Win32HostImportValue, Win32HostServiceIdentity,
    Win32HostServiceOperation, Win32ImportString, Win32ImportSymbol,
};

#[path = "win32_import_guest/files.rs"]
mod files;
#[path = "win32_import_guest/find_data.rs"]
mod find_data;
#[path = "win32_import_guest/loader.rs"]
mod loader;
#[path = "win32_import_guest/memory.rs"]
mod memory;
#[path = "win32_import_guest/paths.rs"]
mod paths;
#[path = "win32_import_guest/provider_names.rs"]
mod provider_names;
#[path = "win32_import_guest/queries.rs"]
mod queries;
#[path = "win32_import_guest/system.rs"]
mod system;

pub(crate) use loader::{
    acquire_system_provider, acquire_system_provider_path, release_system_provider,
};

const CODE_SELECTOR: u16 = 0x0008;
const STACK_SELECTOR: u16 = 0x0010;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Win32GuestReturn {
    pub(crate) eax: Option<u32>,
    pub(crate) edx: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuestProcedureLookup {
    NotGuestModule,
    Missing,
    Found(u32),
}

pub(crate) enum GuestModuleLoadProbe {
    NotFound(u32),
    SystemDirectory { resolved_path: Vec<u8> },
    GuestPe32 {
        file: Win16ModuleImage,
        basename: Vec<u8>,
    },
    Failure(u32),
}

pub(crate) struct Win32ServiceRequest {
    gate: Win32ServiceGate,
    nonce: Pe32CallNonce,
    stack_pointer: u32,
    return_address: u32,
    stack_start: u32,
    stack_top: u32,
    arguments: Vec<u32>,
}

/// The PE loader owns guest module identities; this narrow seam lets the
/// KERNEL32 adapter share those identities without giving the CPU or host a
/// module-table pointer.
pub(crate) trait Win32GuestModuleResolver {
    fn guest_module_handle(
        &mut self,
        name: &Win32ImportString,
    ) -> Result<Option<u32>, RuntimeError>;
    fn retain_guest_module(
        &mut self,
        name: &Win32ImportString,
    ) -> Result<Option<u32>, RuntimeError>;
    fn probe_guest_module(
        &mut self,
        name: &Win32ImportString,
        host: &mut impl RuntimeHost,
    ) -> Result<GuestModuleLoadProbe, RuntimeError>;
    fn load_guest_module(
        &mut self,
        state: &mut Win32ImportState,
        file: Win16ModuleImage,
        basename: Vec<u8>,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError>;
    fn active_service_nonce(&self) -> Option<Pe32CallNonce>;
    fn release_guest_module(
        &mut self,
        state: &mut Win32ImportState,
        handle: u32,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<bool>, RuntimeError>;
    fn resolve_guest_procedure(
        &mut self,
        handle: u32,
        symbol: &Win32ImportSymbol,
    ) -> Result<GuestProcedureLookup, RuntimeError>;
    fn guest_module_path(
        &mut self,
        handle: u32,
        wide: bool,
    ) -> Result<Option<Win32ImportString>, RuntimeError>;
}

/// Capture every stack operand before pausing this exact guest call frame.
pub(crate) fn capture_service_request(
    state: &Win32ImportState,
    cpu: &Cpu,
    memory: &mut Memory,
    eip: u32,
    nonce: Pe32CallNonce,
    stack_start: u32,
    stack_top: u32,
) -> Result<Win32ServiceRequest, RuntimeError> {
    let gate = state
        .service_gate(eip)
        .ok_or_else(|| invariant("PE32 service request has no exact published provider gate"))?;
    let descriptor = win32_import_catalog::descriptor_for_service(gate.service);
    let arguments = stack_arguments(
        cpu,
        memory,
        descriptor.parameters.len(),
        stack_start,
        stack_top,
    )?;
    let return_address = memory::read_u32(memory, cpu.regs.esp)?;
    Ok(Win32ServiceRequest {
        gate,
        nonce,
        stack_pointer: cpu.regs.esp,
        return_address,
        stack_start,
        stack_top,
        arguments,
    })
}

/// Validate and consume a previously captured request, then restore its caller
/// by applying the stdcall return only after the service has completed.
pub(crate) fn execute_service_request(
    state: &mut Win32ImportState,
    request: Win32ServiceRequest,
    cpu: &mut Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
    modules: &mut impl Win32GuestModuleResolver,
) -> Result<(), RuntimeError> {
    if modules.active_service_nonce() != Some(request.nonce)
        || state.service_gate(request.gate.address) != Some(request.gate)
        || cpu.regs.cs != CODE_SELECTOR
        || cpu.regs.eip != request.gate.address
        || cpu.regs.ss != STACK_SELECTOR
        || cpu.regs.esp != request.stack_pointer
        || request.stack_start >= request.stack_top
        || request.stack_pointer < request.stack_start
        || request.stack_pointer >= request.stack_top
    {
        return Err(invariant(
            "owned PE32 service request no longer matches its frame/gate",
        ));
    }
    let gate = request.gate;
    let return_address = request.return_address;
    let args = request.arguments;
    let result = execute_typed_service_call(state, gate, cpu, memory, host, modules, &args)?;
    let argument_bytes = u32::try_from(args.len())
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or_else(|| exhausted("PE32 stdcall argument bytes"))?;
    let next_stack = cpu
        .regs
        .esp
        .checked_add(4)
        .and_then(|value| value.checked_add(argument_bytes))
        .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "PE32 stdcall stack wraps"))?;
    cpu.regs.eip = return_address;
    cpu.regs.esp = next_stack;
    if let Some(eax) = result.eax {
        cpu.regs.eax = eax;
    }
    if let Some(edx) = result.edx {
        cpu.regs.edx = edx;
    }
    Ok(())
}

/// Invoke the exact typed service behind a live gate without fabricating a
/// guest CPU return frame. Direct PE32 gates and KERNEL CallProc share this
/// entry, so its exact-generation pin spans dispatch and every Result cleanup path.
pub(crate) fn execute_typed_service_call(
    state: &mut Win32ImportState,
    gate: Win32ServiceGate,
    cpu: &mut Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
    modules: &mut impl Win32GuestModuleResolver,
    args: &[u32],
) -> Result<Win32GuestReturn, RuntimeError> {
    if state.service_gate(gate.address) != Some(gate) {
        return Err(invariant(
            "typed service call does not own its live provider gate",
        ));
    }
    let descriptor = win32_import_catalog::descriptor_for_service(gate.service);
    if args.len() != descriptor.parameters.len() {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "typed service call argument count differs from its catalog signature",
        ));
    }
    let pin = state.pin_invocation(gate.provider)?;
    let dispatched = match gate.service.family() {
        crate::Win32HostImportFamily::Runtime => {
            system::runtime_service(state, gate.service, args)
        }
        crate::Win32HostImportFamily::Loader => {
            loader::dispatch(state, gate, cpu, memory, host, modules, args)
        }
        crate::Win32HostImportFamily::File => files::dispatch(state, gate, memory, host, args),
        crate::Win32HostImportFamily::Path => paths::dispatch(state, gate, memory, host, args),
        crate::Win32HostImportFamily::Volume | crate::Win32HostImportFamily::Environment => {
            queries::dispatch(state, gate, memory, host, args)
        }
        crate::Win32HostImportFamily::System => {
            system::dispatch(state, gate, cpu, memory, host, args)
        }
    };
    let primary = match (memory.storage_failure(), dispatched) {
        (Some(storage), Err(service)) => Err(crate::runtime_error(storage).with_cleanup(
            "guest RAM storage failed during typed PE32 service",
            service,
        )),
        (Some(storage), Ok(_)) => Err(crate::runtime_error(storage)),
        (None, result) => result,
    };
    let cleanup = release_invocation_provider_pin(state, pin, host);
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(primary.with_cleanup(
            "typed PE32 service and invocation-pin cleanup both failed",
            cleanup,
        )),
    }
}

fn stack_arguments(
    cpu: &Cpu,
    memory: &mut Memory,
    count: usize,
    start: u32,
    end: u32,
) -> Result<Vec<u32>, RuntimeError> {
    if cpu.regs.cs != CODE_SELECTOR || cpu.regs.ss != STACK_SELECTOR {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "PE32 host service arrived with an unexpected flat CS:SS",
        ));
    }
    let byte_count = count
        .checked_mul(4)
        .ok_or_else(|| exhausted("PE32 service arguments"))?;
    let total = byte_count
        .checked_add(4)
        .ok_or_else(|| exhausted("PE32 service stack"))?;
    let stack_end = cpu
        .regs
        .esp
        .checked_add(u32::try_from(total).map_err(|_| exhausted("PE32 service stack"))?)
        .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "PE32 service stack wraps"))?;
    if cpu.regs.esp < start || stack_end > end {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "PE32 service return address or arguments escape the owned guest stack",
        ));
    }
    let mut args = Vec::new();
    args.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve PE32 Win32 arguments",
            error,
        )
    })?;
    for index in 0..count {
        let offset = u32::try_from(
            index
                .checked_add(1)
                .and_then(|v| v.checked_mul(4))
                .ok_or_else(|| exhausted("PE32 service argument offset"))?,
        )
        .map_err(|_| exhausted("PE32 service argument offset"))?;
        let address =
            cpu.regs.esp.checked_add(offset).ok_or_else(|| {
                RuntimeError::new(Kind::GuestFault, "PE32 argument address wraps")
            })?;
        args.push(memory::read_u32(memory, address)?);
    }
    Ok(args)
}

pub(super) fn invoke(
    state: &mut Win32ImportState,
    gate: Win32ServiceGate,
    host: &mut impl RuntimeHost,
    operation: Win32HostServiceOperation,
) -> Result<Win32HostImportValue, RuntimeError> {
    invoke_result(state, gate, host, operation).map(|result| result.value)
}

pub(super) fn invoke_result(
    state: &mut Win32ImportState,
    gate: Win32ServiceGate,
    host: &mut impl RuntimeHost,
    operation: Win32HostServiceOperation,
) -> Result<Win32HostImportResult, RuntimeError> {
    if state.service_gate(gate.address) != Some(gate) {
        return Err(invariant(
            "PE32 service gate changed before native dispatch",
        ));
    }
    let descriptor = win32_import_catalog::descriptor_for_service(gate.service);
    let service = Win32HostServiceIdentity::from_catalog(
        gate.service as u16,
        gate.service.family(),
        descriptor.export,
    );
    let result = host.win32_import(Win32HostImportCall::InvokeService {
        export: gate.export,
        service,
        operation,
    })?;
    if let Some(error) = result.last_error {
        state.set_last_error(error);
    }
    Ok(result)
}

pub(super) fn expect_bool(value: Win32HostImportValue) -> Result<bool, RuntimeError> {
    match value {
        Win32HostImportValue::Bool(value) => Ok(value),
        _ => Err(invariant(
            "PE32 Win32 BOOL service returned an incompatible host value",
        )),
    }
}

pub(super) fn expect_dword(value: Win32HostImportValue) -> Result<u32, RuntimeError> {
    match value {
        Win32HostImportValue::Dword(value) => Ok(value),
        _ => Err(invariant(
            "PE32 Win32 DWORD service returned an incompatible host value",
        )),
    }
}

pub(super) fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

pub(super) fn guest_fault(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::GuestFault, message)
}

pub(super) fn exhausted(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, message)
}

fn release_invocation_provider_pin(
    state: &mut Win32ImportState,
    pin: Win32ProviderInvocationPin,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let provider = pin.provider();
    let owner = state.host_owner(provider)?;
    let Some(module) = state.release_invocation_pin(pin)? else {
        return Ok(());
    };
    match host.win32_import(Win32HostImportCall::FreeSystemModule { module, owner }) {
        Ok(response) => match response.value {
            Win32HostImportValue::Bool(true) => state.finish_release_module(provider, true),
            Win32HostImportValue::Bool(false) => {
                let primary = owner.release_failure(RuntimeError::with_source(
                    Kind::HostFailure,
                    "FreeLibrary failed after a typed PE32 provider invocation",
                    ProviderPinReleaseFailure {
                        provider_id: provider.id(),
                        provider_generation: provider.generation(),
                        last_error: response.last_error,
                    },
                ));
                Err(restore_invocation_provider(state, provider, primary))
            }
            _ => {
                let primary = owner.release_failure(RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "provider invocation release returned a non-BOOL result",
                    ProviderPinReleaseFailure {
                        provider_id: provider.id(),
                        provider_generation: provider.generation(),
                        last_error: response.last_error,
                    },
                ));
                Err(restore_invocation_provider(state, provider, primary))
            }
        },
        Err(primary) => Err(restore_invocation_provider(
            state,
            provider,
            owner.release_failure(primary.with_context(
                "FreeLibrary for a typed PE32 provider invocation failed")),
        )),
    }
}

fn restore_invocation_provider(
    state: &mut Win32ImportState,
    provider: Win32SystemModuleIdentity,
    primary: RuntimeError,
) -> RuntimeError {
    match state.finish_release_module(provider, false) {
        Ok(()) => primary,
        Err(cleanup) => primary.with_cleanup(
            "provider release failed and its live owner could not be restored",
            cleanup,
        ),
    }
}

#[derive(Debug)]
struct ProviderPinReleaseFailure {
    provider_id: u64,
    provider_generation: u64,
    last_error: Option<u32>,
}

impl std::fmt::Display for ProviderPinReleaseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "provider {} generation {} release failed", self.provider_id,
            self.provider_generation)?;
        match self.last_error {
            Some(code) => write!(formatter, " with Windows error code {code}"),
            None => formatter.write_str("; Windows last-error unavailable"),
        }
    }
}

impl std::error::Error for ProviderPinReleaseFailure {}
