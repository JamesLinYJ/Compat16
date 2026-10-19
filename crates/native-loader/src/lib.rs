//! Windows module loading boundary used by the thin process launchers.
#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::io;

#[cfg(windows)]
mod windows;

#[derive(Debug)]
pub enum EngineLoadError {
    UnsupportedHost,
    ExecutablePath(io::Error),
    MissingParent,
    Load { path: std::path::PathBuf, source: io::Error },
    MissingExport { name: &'static str, source: io::Error },
    IncompatibleVersion(u32),
    ProcessLifetime(io::Error),
}

impl fmt::Display for EngineLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => write!(f, "this launcher requires Windows"),
            Self::ExecutablePath(error) => write!(f, "resolve launcher path: {error}"),
            Self::MissingParent => write!(f, "the launcher path has no parent directory"),
            Self::Load { path, source } => write!(f, "load execution module {}: {source}", path.display()),
            Self::MissingExport { name, source } => write!(f, "resolve execution-module export {name}: {source}"),
            Self::IncompatibleVersion(version) => write!(f, "execution-module ABI version {version} is unsupported; expected version 1"),
            Self::ProcessLifetime(error) => write!(f, "retain execution module through process termination: {error}"),
        }
    }
}

impl std::error::Error for EngineLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ExecutablePath(source) | Self::Load { source, .. }
            | Self::MissingExport { source, .. } => Some(source),
            Self::ProcessLifetime(source) => Some(source),
            _ => None,
        }
    }
}

pub fn run_engine() -> Result<i32, EngineLoadError> {
    #[cfg(windows)]
    { windows::run_engine() }
    #[cfg(not(windows))]
    { Err(EngineLoadError::UnsupportedHost) }
}

/// Original Windows command text, before argv parsing removes guest quotes.
#[cfg(windows)]
pub fn command_line() -> io::Result<Vec<u16>> { windows::command_line() }
