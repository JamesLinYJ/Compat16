//! SHELL drive classification through the shared Win16 storage service.

use super::Win16State;
use crate::{RuntimeError, RuntimeHost};

impl Win16State {
    pub(crate) fn shell_drive_type(
        &self,
        drive: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Ok(drive) = u16::try_from(drive) else {
            // SHELL.262 has a LONG stack slot, while this guest storage
            // service accepts the Win16 drive index as WORD. Never alias a
            // larger LONG to an unrelated low-word drive.
            return Ok(0);
        };
        Ok(u32::from(self.drive_type(drive, host)?))
    }
}
