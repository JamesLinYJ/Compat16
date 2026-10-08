//! Core-module failure evidence saved separately from guest console handles.

use std::io::Write;
use std::path::Path;
use runtime::{Diagnostic, RuntimeError};

pub(crate) fn save(path: &Path, trace: &Diagnostic, error: &RuntimeError) -> std::io::Result<()> {
    // Never overwrite an existing user file to create diagnostic evidence.
    let mut file = std::fs::File::create_new(path)?;
    writeln!(file, "{trace}\n{error}")?;
    file.flush()
}

pub(crate) fn save_guest_memory(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Guest dumps can be large; create_new still prevents overwriting a file
    // selected by the caller.
    let mut file = std::fs::File::create_new(path)?;
    file.write_all(bytes)?;
    file.flush()
}

/// A guest can return a nonzero status without raising a runtime exception.
/// Preserve the requested history without classifying that status as a fault.
pub(crate) fn save_guest_exit(path: &Path, status: u8, trace: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::create_new(path)?;
    writeln!(file, "guest exit status: {status}\ninstruction history (oldest first):\n{trace}")?;
    file.flush()
}
