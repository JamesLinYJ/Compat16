//! KERNEL generic-thunk release path for PE32 and system module identities.

use guest_core::memory::Memory;
use x86_cpu::Cpu;

use crate::win32_import_guest::release_system_provider;
use crate::win32_import_state::Win32ImportState;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win32HostImportValue};

use super::super::Pe32ThunkDispatcher;

impl Pe32ThunkDispatcher {
    pub(in crate::win16_runtime::pe32_dispatch) fn free_library(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut Win32ImportState,
        host: &mut impl RuntimeHost,
        guest_handle: u32,
        step_limit: u64,
    ) -> Result<bool, RuntimeError> {
        if let Some(provider) = imports.system_module_for_handle(guest_handle) {
            if imports.guest_reference_count(provider)? == 0 {
                imports.set_last_error(6);
                return Ok(false);
            }
            let response = release_system_provider(imports, provider, host)?;
            let Win32HostImportValue::Bool(released) = response.value else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "FreeLibrary32W system provider returned a non-BOOL result",
                ));
            };
            if !released {
                if let Some(error) = response.last_error {
                    imports.set_last_error(error);
                }
            }
            return Ok(released);
        }

        let group = self.active_load_group_for_current_call();
        let Some(index) = self
            .handle_index(guest_handle)
            .or_else(|| group.and_then(|group| self.group_handle_index(group, guest_handle)))
        else {
            imports.set_last_error(6);
            return Ok(false);
        };
        if self.modules[index].image_released {
            imports.set_last_error(6);
            return Ok(false);
        }
        let identity = self.modules[index].transaction.module();
        let token = identity.token();
        if self.registry.identity(token) != Some(identity) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 module handle lost its exact registry generation",
            ));
        }
        if self.registry.stage(token) != Some(crate::pe32::Pe32ModuleStage::Published) {
            let Some(member) = self.modules[index].group_member.as_mut() else {
                return Ok(false);
            };
            if group != Some(member.group) || member.guest_references == 0 {
                return Ok(false);
            }
            member.guest_references -= 1;
            return Ok(true);
        }
        if !self.registry.release(token)? {
            return Ok(false);
        }
        let start = self.budget_position();
        self.drain_retiring(cpu, memory, imports, host, step_limit, start)?;
        Ok(true)
    }
}
