//! Direct export aliases and generic-call target validation.

use guest_core::memory::Memory;
use win16_abi::SelectorTable;
use win16_abi::generic_thunk::{
    Win16GenericThunkDisposition, Win16GenericThunkFrame,
    resolve_get_vdm_pointer32w,
};
use x86_cpu::Cpu;

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    pe32::{Pe32CallCompletion, Pe32ExportKey, Pe32ModuleStage, Pe32SymbolResult},
    pe32_call::{Pe32CallConvention, Pe32GenericThunkTarget, validate_generic_thunk_target},
    win32_import_catalog::{self, Win32ImportReturn},
    win32_import_state::{Win32ImportState, Win32ServiceGate},
};

use super::{Pe32ThunkDispatcher, ProcedureHandle, aggregate_errors};

impl Pe32ThunkDispatcher {
    pub(super) fn get_proc_address(
        &mut self,
        imports: &mut Win32ImportState,
        module_handle: u32,
        name: &[u8],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(module_index) = self.handle_index(module_handle) else {
            return self.get_system_proc_address(imports, module_handle, name, memory, host);
        };
        if name.is_empty() || name.contains(&0) {
            return Ok(0);
        }
        let module = &self.modules[module_index].transaction;
        let identity = module.module();
        let token = identity.token();
        if self.registry.identity(token) != Some(identity) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "GetProcAddress32W module handle lost its exact registry generation",
            ));
        }
        let mut owned_name = Vec::new();
        if let Err(error) = owned_name.try_reserve_exact(name.len()) {
            host.report_diagnostic(
                &Diagnostic::warning(
                    Kind::ResourceExhausted,
                    "GetProcAddress32W could not copy its guest procedure name",
                )
                .with_cause(error),
            );
            return Ok(0);
        }
        owned_name.extend_from_slice(name);
        let symbol = self
            .registry
            .lookup_export(token, &Pe32ExportKey::Name(owned_name))?;
        match symbol {
            None => Ok(0),
            Some(Pe32SymbolResult::Procedure(procedure)) => {
                if let Some(existing) = self
                    .procedures
                    .iter()
                    .find(|entry| entry.module == identity && entry.token == procedure)
                {
                    return Ok(existing.value);
                }
                if let Err(error) = self.procedures.try_reserve(1) {
                    host.report_diagnostic(
                        &Diagnostic::warning(
                            Kind::ResourceExhausted,
                            "GetProcAddress32W could not retain a procedure alias",
                        )
                        .with_cause(error),
                    );
                    return Ok(0);
                }
                let value = match self.allocate_procedure_handle() {
                    Ok(value) => value,
                    Err(error) if error.kind() == Kind::ResourceExhausted => {
                        host.report_diagnostic(
                            &Diagnostic::warning(
                                Kind::ResourceExhausted,
                                "GetProcAddress32W exhausted guest procedure aliases",
                            )
                            .with_cause(error),
                        );
                        return Ok(0);
                    }
                    Err(error) => return Err(error),
                };
                self.procedures.push(ProcedureHandle {
                    value,
                    module: identity,
                    token: procedure,
                });
                Ok(value)
            }
            Some(Pe32SymbolResult::Data { module, address }) if module == identity => {
                if memory
                    .validate_ram_range(guest_core::PhysAddr(address.0), 1, false)
                    .is_ok()
                {
                    Ok(address.0)
                } else if let Some(error) = memory.storage_failure() {
                    Err(crate::runtime_error(error))
                } else {
                    Ok(0)
                }
            }
            Some(Pe32SymbolResult::Data { .. }) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 data export changed module identity",
            )),
            Some(Pe32SymbolResult::Forwarder { .. }) => {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "PE32 forwarded GetProcAddress32W export is not resolved",
                ));
                Ok(0)
            }
        }
    }

    fn get_system_proc_address(
        &mut self,
        imports: &mut Win32ImportState,
        module_handle: u32,
        name: &[u8],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(provider) = imports.system_module_for_handle(module_handle) else {
            imports.set_last_error(6);
            return Ok(0);
        };
        if name.is_empty() || name.contains(&0) {
            imports.set_last_error(crate::win32_import_bridge::ERROR_PROC_NOT_FOUND);
            return Ok(0);
        }
        if win32_import_catalog::lookup(name).is_none() {
            imports.set_last_error(crate::win32_import_bridge::ERROR_PROC_NOT_FOUND);
            return Ok(0);
        }
        let mut owned_name = Vec::new();
        if let Err(error) = owned_name.try_reserve_exact(name.len()) {
            imports.set_last_error(8);
            host.report_diagnostic(
                &Diagnostic::warning(
                    Kind::ResourceExhausted,
                    "GetProcAddress32W could not own the system export name",
                )
                .with_cause(error),
            );
            return Ok(0);
        }
        owned_name.extend_from_slice(name);
        let symbol = crate::Win32ImportSymbol::Name(owned_name);
        let resolution = crate::win32_import_bridge::resolve_service_gate(
            imports,
            provider,
            symbol,
            memory,
            |call| host.win32_import(call),
        );
        let (resolved, last_error) = match resolution {
            Ok(value) => value,
            Err(error) if error.kind() == Kind::ResourceExhausted => {
                imports.set_last_error(8);
                host.report_diagnostic(
                    &Diagnostic::warning(
                        Kind::ResourceExhausted,
                        "GetProcAddress32W could not reserve a typed service gate",
                    )
                    .with_cause(error),
                );
                return Ok(0);
            }
            Err(error) => return Err(error),
        };
        match resolved {
            Some((descriptor, gate))
                if gate.provider == provider
                    && gate.service == descriptor.service
                    && gate.address != 0
                    && imports.service_gate(gate.address) == Some(gate) =>
            {
                Ok(gate.address)
            }
            Some(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "GetProcAddress32W received a mismatched provider export gate",
            )),
            None => match last_error {
                Some(error) => {
                    imports.set_last_error(if error == 0 {
                        crate::win32_import_bridge::ERROR_PROC_NOT_FOUND
                    } else {
                        error
                    });
                    Ok(0)
                }
                None => {
                    imports.set_last_error(crate::win32_import_bridge::ERROR_PROC_NOT_FOUND);
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "GetProcAddress32W could not publish the catalogued system export",
                    ));
                    Ok(0)
                }
            },
        }
    }

    pub(super) fn call_procedure(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
        selectors: &SelectorTable,
        frame: Win16GenericThunkFrame,
        step_limit: u64,
    ) -> Result<u32, RuntimeError> {
        if frame.disposition == Win16GenericThunkDisposition::ReturnZero {
            if frame.stack_cleanup.callee_pop_bytes.is_none() {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "generic-thunk documented zero path has unknown Win16 stack cleanup",
                ));
            }
            return Ok(0);
        }
        let parameter_count = usize::try_from(frame.parameter_count).map_err(|_| {
            RuntimeError::new(Kind::InternalInvariant, "PE32 parameter count overflowed")
        })?;
        if parameter_count != frame.parameters.len() || parameter_count > 32 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "decoded PE32 parameter count is inconsistent",
            ));
        }
        // Validate supported flags/count/mask before resolving any FAR
        // argument. Rejected contracts must not cause speculative guest reads.
        if let Err(error) = validate_generic_thunk_target(&frame, &frame.parameters) {
            if error.kind() != Kind::CompatibilityGap { return Err(error); }
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                format!("generic-thunk contract unavailable: target=0x{:08X}, nParams=0x{:08X}, mask=0x{:08X}",
                    frame.target_procedure, frame.encoded_parameter_count, frame.pointer_mask))
                .with_cause(error));
            return Ok(0);
        }
        let mut arguments = Vec::new();
        arguments
            .try_reserve_exact(parameter_count)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve PE32 call arguments",
                    error,
                )
            })?;
        for (index, value) in frame.parameters.iter().copied().enumerate() {
            if frame.parameter_pointer_bit(index).is_some_and(|bit| frame.pointer_mask & bit != 0)
            {
                if value == 0 {
                    arguments.push(0);
                    continue;
                }
                let resolved =
                    resolve_get_vdm_pointer32w(value, 1, selectors).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::GuestFault,
                            "generic-thunk far parameter cannot be resolved",
                            error,
                        )
                    })?;
                if let Some(error) = memory.storage_failure() {
                    return Err(crate::runtime_error(error));
                }
                if memory
                    .validate_ram_range(resolved.address, 1, false)
                    .is_err()
                {
                    if let Some(error) = memory.storage_failure() {
                        return Err(crate::runtime_error(error));
                    }
                    return Err(RuntimeError::new(
                        Kind::GuestFault,
                        "generic-thunk far parameter is outside guest RAM",
                    ));
                }
                arguments.push(resolved.address.0);
            } else {
                arguments.push(value);
            }
        }
        let validated = match validate_generic_thunk_target(&frame, &arguments) {
            Ok(value) => value,
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                host.report_diagnostic(
                    &Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "CallProc32 thunk flags or target convention are not verified",
                    )
                    .with_cause(error),
                );
                return Ok(0);
            }
            Err(error) => return Err(error),
        };
        let (procedure_alias, convention, arguments) = match validated {
            Pe32GenericThunkTarget::ReturnZero => return Ok(0),
            Pe32GenericThunkTarget::Invoke {
                procedure,
                convention,
                arguments,
            } => (procedure, convention, arguments),
        };
        if let Some(gate) = imports.service_gate(procedure_alias) {
            return self.call_typed_service(
                cpu, memory, imports, host, gate, convention, arguments, step_limit,
            );
        }
        if imports
            .service_gate_guard_addresses()
            .any(|address| address == procedure_alias)
        {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "CallProc target is a retired PE32 typed-service gate",
            ));
            return Ok(0);
        }
        let Some(alias) = self
            .procedures
            .iter()
            .find(|entry| entry.value == procedure_alias)
            .copied()
        else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "CallProc target is neither a live typed gate nor a PE32 procedure alias",
            ));
            return Ok(0);
        };
        if self.registry.identity(alias.module.token()) != Some(alias.module)
            || self.registry.stage(alias.module.token()) != Some(Pe32ModuleStage::Published)
        {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "CallProc target PE32 procedure alias has retired",
            ));
            return Ok(0);
        }
        let Some(lease) = self
            .registry
            .prepare_call(alias.token, arguments, convention)?
        else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "CallProc PE32 procedure is no longer published",
            ));
            return Ok(0);
        };
        let dispatch_start = self.budget_position();
        let result = match self.execute_lease(cpu, memory, imports, host, lease, step_limit) {
            Ok(Pe32CallCompletion::Returned(value)) => Ok(value),
            Ok(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 export call returned a lifecycle completion",
            )),
            Err(error) => Err(error),
        };
        let cleanup = self.drain_retiring(cpu, memory, imports, host, step_limit, dispatch_start);
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(primary), Err(cleanup)) => Err(aggregate_errors(
                "PE32 call and deferred unload both failed",
                primary,
                cleanup,
            )),
        }
    }

    fn call_typed_service(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut Win32ImportState,
        host: &mut impl RuntimeHost,
        gate: Win32ServiceGate,
        convention: Pe32CallConvention,
        arguments: &[u32],
        step_limit: u64,
    ) -> Result<u32, RuntimeError> {
        if imports.service_gate(gate.address) != Some(gate) {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "CallProc target provider or gate generation has retired",
            ));
        }
        let descriptor = win32_import_catalog::descriptor_for_service(gate.service);
        if arguments.len() != descriptor.parameters.len() {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "CallProc argument count does not match the typed system export",
            ));
            return Ok(0);
        }
        if convention != Pe32CallConvention::Stdcall {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "CallProc cdecl target does not match the Win32 system export contract",
            ));
            return Ok(0);
        }
        if descriptor.result == Win32ImportReturn::QwordEaxEdx {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "CallProc cannot return the typed system export's EDX:EAX result through KERNEL",
            ));
            return Ok(0);
        }

        let budget_owner = self.begin_budget(step_limit)?;
        let result = self.call_typed_service_inner(
            cpu,
            memory,
            imports,
            host,
            gate,
            descriptor.result,
            arguments,
        );
        self.finish_budget(budget_owner);
        result
    }

    fn call_typed_service_inner(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut Win32ImportState,
        host: &mut impl RuntimeHost,
        gate: Win32ServiceGate,
        result_kind: Win32ImportReturn,
        arguments: &[u32],
    ) -> Result<u32, RuntimeError> {
        self.charge_service_boundary()?;
        let value = crate::win32_import_guest::execute_typed_service_call(
            imports, gate, cpu, memory, host, self, arguments,
        )?;
        match result_kind {
            Win32ImportReturn::Void if value.eax.is_none() && value.edx.is_none() => {
                Ok(cpu.regs.eax)
            }
            Win32ImportReturn::Boolean
            | Win32ImportReturn::Dword
            | Win32ImportReturn::Handle
            | Win32ImportReturn::Pointer
                if value.edx.is_none() =>
            {
                value.eax.ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "typed CallProc scalar result lacks EAX",
                    )
                })
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed CallProc result shape differs from its catalog signature",
            )),
        }
    }
}
