//! Copy the native process command line without applying argv parsing.

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::System::Environment::GetCommandLineW;

pub fn current_command_line() -> Result<Vec<u16>, RuntimeError> {
    // SAFETY: Windows owns the returned UTF-16, NUL-terminated process string
    // for the process lifetime. We only read and copy it, never modify/free it.
    let raw = unsafe { GetCommandLineW() };
    if raw.is_null() {
        return Err(RuntimeError::new(Kind::HostFailure, "native command line is unavailable"));
    }
    let mut command = Vec::new();
    // CreateProcessW's limit includes the terminating NUL. Keep the scan
    // bounded even if native process state does not satisfy that contract.
    for index in 0..32_767 {
        // SAFETY: The system string is readable through its terminating NUL;
        // each unit is copied before the next unit is inspected.
        let unit = unsafe { *raw.add(index) };
        if unit == 0 {
            return Ok(command);
        }
        command.push(unit);
    }
    Err(RuntimeError::new(Kind::InvalidInput, "native command line exceeds the process limit"))
}
