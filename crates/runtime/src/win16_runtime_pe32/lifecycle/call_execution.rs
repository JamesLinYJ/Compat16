//! Instruction and service-gate execution for an entered PE32 call.

use guest_core::memory::Memory;
use x86_cpu::Cpu;

use crate::pe32_call::Pe32ExecutingCall;
use crate::pe32_execute::{Pe32CallBoundary, step_pe32_call};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

use super::super::lifecycle_errors::finish_fault;
use super::super::{
    ActiveCall, Pe32ThunkDispatcher, aggregate_errors, environment,
};
use crate::pe32::Pe32CallCompletion;

impl Pe32ThunkDispatcher {
    pub(super) fn execute_frame(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
        frame: Pe32ExecutingCall,
        stack_top: u32,
        module_owner: Option<crate::pe32::Pe32ModuleIdentity>,
    ) -> Result<Pe32CallCompletion, RuntimeError> {
        let nonce = frame.nonce();
        let stack_start = self.support.base();
        self.active.push(ActiveCall {
            nonce,
            module: module_owner,
            paused_at_service: false,
            stack_start,
            stack_top,
            stack_selector: 0x0010,
        });
        let mut frame = frame;
        let result = loop {
            let boundary = match step_pe32_call(
                cpu,
                memory,
                &frame,
                nonce,
                |cs, eip| cs == 0x0008 && imports.service_gate(eip).is_some(),
                || self.ensure_budget(),
            ) {
                Ok(boundary) => boundary,
                Err(primary) => {
                    break finish_fault(&mut self.registry, cpu, &mut frame, nonce, primary);
                }
            };
            match boundary {
                Pe32CallBoundary::Returned => {
                    break frame.finish_return(&mut self.registry, cpu, nonce);
                }
                Pe32CallBoundary::CpuStep => {
                    if let Err(primary) = self.record_steps(1) {
                        break finish_fault(&mut self.registry, cpu, &mut frame, nonce, primary);
                    }
                }
                Pe32CallBoundary::Fault(primary) => {
                    if let Err(error) = self.record_steps(1) {
                        break finish_fault(
                            &mut self.registry,
                            cpu,
                            &mut frame,
                            nonce,
                            aggregate_errors(
                                "PE32 instruction fault and step accounting failed",
                                primary,
                                error,
                            ),
                        );
                    }
                    break finish_fault(&mut self.registry, cpu, &mut frame, nonce, primary);
                }
                Pe32CallBoundary::ServiceGate(eip) => {
                    if let Err(primary) = self.charge_service_boundary() {
                        break finish_fault(&mut self.registry, cpu, &mut frame, nonce, primary);
                    }
                    if let Some(active) = self.active.last_mut() {
                        active.paused_at_service = true;
                    }
                    let request = crate::win32_import_guest::capture_service_request(
                        imports,
                        cpu,
                        memory,
                        eip,
                        nonce,
                        stack_start,
                        stack_top,
                    );
                    let dispatched = match request {
                        Ok(request) => crate::win32_import_guest::execute_service_request(
                            imports, request, cpu, memory, host, self,
                        ),
                        Err(error) => Err(error),
                    };
                    let failure = match (memory.storage_failure(), dispatched) {
                        (Some(storage), Err(service)) => Some(crate::runtime_error(storage).with_cleanup(
                            "PE32 guest storage failed during nested service dispatch",
                            service,
                        )),
                        (Some(storage), Ok(())) => Some(crate::runtime_error(storage)),
                        (None, Err(error)) => Some(error),
                        (None, Ok(())) => None,
                    };
                    if let Some(primary) = failure {
                        break finish_fault(
                            &mut self.registry,
                            cpu,
                            &mut frame,
                            nonce,
                            primary.with_context(format!("PE32 service gate at {eip:08X}")),
                        );
                    }
                    let refreshed = match environment::executable_ranges(self, imports, None) {
                        Ok(ranges) => frame.refresh_executable_ranges(nonce, ranges),
                        Err(error) => Err(error),
                    };
                    if let Err(primary) = refreshed {
                        break finish_fault(
                            &mut self.registry,
                            cpu,
                            &mut frame,
                            nonce,
                            primary
                                .with_context("refresh PE32 executable module map after service"),
                        );
                    }
                    if let Some(active) = self.active.last_mut() {
                        active.paused_at_service = false;
                    }
                }
            }
        };
        let unfinished = !frame.is_finished();
        let result = if unfinished && result.is_ok() {
            Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 call returned without finalizing its saved CPU context",
            ))
        } else {
            result
        };
        if unfinished {
            // The context restore failed before registry completion. Preserve
            // the owned continuation and leave its active nonce on the stack.
            self.retained_frames.push(frame);
        }
        let active_matches = self
            .active
            .last()
            .is_some_and(|active| active.nonce == nonce);
        let cleanup = if unfinished && active_matches {
            None
        } else if !unfinished && active_matches {
            self.active.pop();
            None
        } else {
            Some(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 nested call stack lost its exact active nonce",
            ))
        };
        match (result, cleanup) {
            (Ok(value), None) => Ok(value),
            (Err(error), None) => Err(error),
            (Ok(_), Some(cleanup)) => Err(cleanup),
            (Err(primary), Some(cleanup)) => Err(aggregate_errors(
                "PE32 guest call failed while its active nonce stack was inconsistent",
                primary,
                cleanup,
            )),
        }
    }
}
