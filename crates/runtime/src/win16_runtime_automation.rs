//! Task ownership for guest-local Automation allocations.

use guest_core::memory::Memory;
use win16_abi::{Win16Ole2DispCall, Win16Ole2DispConvertCall};

use super::Win16State;
use crate::win16_automation::Win16AutomationGuestResult;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16AutomationConversionServices, Win16Ole2DispConversionOperation,
    Win16Ole2DispConversionResult,
};

struct ConversionServices<'a, H>(&'a mut H);

impl<H: RuntimeHost> Win16AutomationConversionServices for ConversionServices<'_, H> {
    fn report_diagnostic(&mut self, diagnostic: Diagnostic) {
        self.0.report_diagnostic(&diagnostic);
    }

    fn convert(
        &mut self,
        operation: Win16Ole2DispConversionOperation,
    ) -> Result<Win16Ole2DispConversionResult, RuntimeError> {
        self.0.win16_ole2disp_conversion(operation)
    }
}

impl Win16State {
    pub(super) fn ole2disp_convert_api(
        &mut self,
        request: Win16Ole2DispConvertCall,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let owner = self.tasks.current().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 Automation conversion has no current task",
            )
        })?;
        let result = self.automation.execute_guest_ole2disp_convert_call(
            &request,
            &mut self.heap,
            &mut self.selectors,
            memory,
            owner,
            &mut ConversionServices(host),
        )?;
        Ok(match result {
            Win16AutomationGuestResult::Void => 0,
            Win16AutomationGuestResult::Word(value) => u32::from(value),
            Win16AutomationGuestResult::Dword(value)
            | Win16AutomationGuestResult::FarPointer(value)
            | Win16AutomationGuestResult::HResult(value) => value,
        })
    }

    pub(super) fn ole2disp_api(
        &mut self,
        request: Win16Ole2DispCall,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let owner = self.tasks.current().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 Automation call has no current task",
            )
        })?;
        let result = self.automation.execute_guest_ole2disp_call(
            &request,
            &mut self.heap,
            &mut self.selectors,
            memory,
            owner,
            &mut |diagnostic| host.report_diagnostic(&diagnostic),
        )?;
        Ok(match result {
            Win16AutomationGuestResult::Void => 0,
            Win16AutomationGuestResult::Word(value) => u32::from(value),
            Win16AutomationGuestResult::Dword(value)
            | Win16AutomationGuestResult::FarPointer(value)
            | Win16AutomationGuestResult::HResult(value) => value,
        })
    }

    pub(super) fn close_automation(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut first_error = None;
        let mut owners = Vec::new();
        owners.try_reserve_exact(self.task_handles.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 Automation task-owner teardown snapshot", error))?;
        owners.extend(self.task_handles.keys().copied());
        for owner in owners {
            if let Err(error) = self.automation.release_owner_contents(
                &mut self.heap,
                &mut self.selectors,
                memory,
                owner,
                &mut |diagnostic| host.report_diagnostic(&diagnostic),
            ) {
                remember_automation_error(&mut first_error, error);
            }
            let allocations = match self.automation.owner_allocations(owner) {
                Ok(allocations) => allocations,
                Err(error) => {
                    remember_automation_error(&mut first_error, error);
                    continue;
                }
            };
            for (far, allocation) in allocations {
                match self.free_runtime_global_on_teardown(allocation) {
                    Ok(super::global_memory::GlobalTeardownResult::Freed) => {
                        if let Err(error) = self.automation.retire_allocation(far, allocation) {
                            remember_automation_error(&mut first_error, error);
                        }
                    }
                    Ok(retained @ super::global_memory::GlobalTeardownResult::Retained { .. }) => {
                        let error = retained.retained_error("Automation allocation").unwrap_or_else(||
                            RuntimeError::new(Kind::InternalInvariant,
                                "Retained Automation teardown result lost its cause"));
                        let error = self.automation.remember_retirement_failure(far, allocation, error);
                        remember_automation_error(&mut first_error, error);
                    }
                    Err(error) => {
                        let error = self.automation.remember_retirement_failure(far, allocation, error);
                        remember_automation_error(&mut first_error, error);
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn remember_automation_error(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    *slot = Some(match slot.take() {
        None => error,
        Some(primary) => primary.with_cleanup("multiple Win16 Automation cleanup failures", error),
    });
}
