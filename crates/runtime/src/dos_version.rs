//! Reported DOS identity is a live per-process PSP word, not the true version.
use crate::{DiagnosticKind, Runtime, RuntimeError, runtime_error};
use guest_core::{GuestMemory, real_address};

impl Runtime {
    /// Select AH=30h's initial-process compatibility version before execution.
    /// Child PSPs start with their normal default, and AH=33h/AL=06h keeps
    /// reporting the underlying DOS identity. Guest writes to PSP:40h remain
    /// effective after startup; there is no application-name override table.
    pub fn set_dos_reported_version(&mut self, version: u16) -> Result<(), RuntimeError> {
        if self.instructions != 0 {
            return Err(RuntimeError::new(
                DiagnosticKind::InvalidInput,
                "reported DOS version must be selected before guest execution",
            ));
        }
        self.memory
            .write(
                real_address(self.dos.psp_segment(), 0x40),
                &version.to_le_bytes(),
            )
            .map_err(runtime_error)
    }
}

#[cfg(test)]
#[path = "dos_version_tests.rs"]
mod tests;
