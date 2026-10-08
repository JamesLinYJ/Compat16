//! Typed SHELL drive-classification request.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16ShellDriveRequest {
    pub drive: u32,
}

/// Preserve the complete LONG until runtime checks its representable range.
pub fn decode_shell_drive_type(
    arguments: &[Win16Argument],
) -> Result<Win16ShellDriveRequest, Win16Error> {
    match arguments.first() {
        Some(Win16Argument::Dword(value)) => Ok(Win16ShellDriveRequest {
            drive: *value,
        }),
        _ => Err(Win16Error::InvalidRange),
    }
}
