//! SHELL compatibility calls whose data source is the guest DOS environment.
//!
//! These APIs never consult the host process environment. The environment
//! selector is a checked alias of the current task's DOS block, and every
//! caller buffer is copied and validated before it is changed.

use guest_core::Registers;
use guest_core::memory::Memory;
use win16_abi::{Win16ReturnKind, Win16ShellRequest};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    pub(super) fn shell_compat_api(
        &mut self,
        request: Win16ShellRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let value = match request {
            Win16ShellRequest::FindEnvironmentString { query } => {
                self.compat.find_environment_string(&self.selectors, memory, &query)?
            }
            Win16ShellRequest::DoEnvironmentSubst { buffer, capacity } => {
                let pointer = self.selectors.pointer_from_far(buffer)
                    .map_err(crate::runtime_error)?;
                let capacity = usize::from(capacity);
                if capacity == 0 {
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, return_kind);
                }

                // Validate both read and write ranges before inspecting the
                // source. The API leaves the original buffer untouched when
                // an expansion does not fit.
                let original = self.read_text_bytes(memory, pointer, capacity)?;
                self.preflight_text_write(memory, pointer, capacity)?;
                let environment = self.compat.environment_list_bytes(&self.selectors, memory)?;
                let result = compat_services::win16_shell::do_environment_subst(
                    &original,
                    u16::try_from(capacity).map_err(|error| RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "Win16 DoEnvironmentSubst capacity exceeds its decoded word",
                        error,
                    ))?,
                    &environment,
                ).map_err(|error| RuntimeError::with_source(
                    Kind::GuestFault,
                    "Win16 DoEnvironmentSubst could not scan the guest environment",
                    error,
                ))?;
                if let Some(output) = result.output {
                    self.write_text_bytes(memory, pointer, &output)?;
                }
                result.result
            }
        };

        self.complete_return(registers, return_to.0, return_to.1,
            return_to.2, value, return_kind)
    }
}
