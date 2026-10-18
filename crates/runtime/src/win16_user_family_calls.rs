//! Submission of owned USER family requests to the native UI worker.

use guest_core::{memory::Memory, Registers};
use win16_abi::{Win16ReturnKind, Win16UserFamilyRequest};

use super::{user_services_controls::Win16UserFamilyPreparation, windows::WindowReturn,
    Win16State};
use crate::{RuntimeError, RuntimeHost, Win16WindowOperation};

impl Win16State {
    pub(super) fn begin_user_family_request(
        &mut self,
        request: Win16UserFamilyRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        match self.prepare_user_family(request, memory, host, return_kind)? {
            Win16UserFamilyPreparation::TerminateTask { status } => {
                // USER.2 follows INT 21h/4C00h: use the shared guest task-exit
                // continuation, including ToolHelp callbacks and source drain.
                if let Some(status) = self.finish_task(memory, host, status)? {
                    return Ok(Some(status));
                }
                self.complete_return(registers, return_to.0, return_to.1,
                    return_to.2, u32::from(status), return_kind)
            }
            Win16UserFamilyPreparation::Immediate {
                value,
                return_kind,
                window_creation_observation,
            } => {
                let result = self.complete_return(registers, return_to.0, return_to.1,
                    return_to.2, value, return_kind)?;
                if let Some(observation) = window_creation_observation {
                    if host.win16_service_trace_enabled() {
                        host.observe_win16_io(&crate::Win16IoEvent::WindowCreation {
                            api: observation.api,
                            phase: crate::Win16WindowCreationPhase::GuestApiCompleted,
                            native_return: observation.native_api_return,
                            preflight_rejection: observation.preflight_rejection,
                            class_instance: observation.class_instance,
                            window_class: observation.window_class.as_ref(),
                            live_window: observation.live_window,
                            guest_window: observation.guest_window,
                            dialog_ncdestroy_observed: observation.dialog_ncdestroy_observed,
                            dialog_template: observation.dialog_template.as_ref(),
                        });
                    }
                }
                Ok(result)
            }
            Win16UserFamilyPreparation::WindowService { operation, continuation } => {
                self.begin_window_operation(registers, memory, host,
                    Win16WindowOperation::UserService(operation),
                    WindowReturn::UserFamily(continuation), return_to)
            }
        }
    }
}
