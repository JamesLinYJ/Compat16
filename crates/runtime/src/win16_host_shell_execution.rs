//! Owned SHELL requests and opaque native activation identities.

use std::{error::Error, fmt, sync::Arc};

use crate::{RuntimeError, Win16HostIcon, Win16WindowTarget};

/// Opaque host process lease identity. The native HANDLE stays in the USER
/// worker and is never interpreted as a guest module or pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Win16HostProcess(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWinExecFailure {
    pub code: u16,
    pub native_error: Option<u32>,
}

#[derive(Clone, Debug)]
pub enum Win16HostShellExecutionOperation {
    WinExec { command_line: Vec<u8>, directory: String, show: u16 },
    DragAcceptFiles { owner: Win16WindowTarget, accept: bool },
    Execute {
        owner: Win16WindowTarget,
        operation: Option<Vec<u8>>,
        file: Vec<u8>,
        parameters: Option<Vec<u8>>,
        directory: Option<Vec<u8>>,
        show: i16,
    },
    FindExecutable {
        file: Vec<u8>,
        directory: Option<Vec<u8>>,
    },
    About {
        owner: Win16WindowTarget,
        app: Vec<u8>,
        other_stuff: Option<Vec<u8>>,
        icon: Option<Win16HostIcon>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostShellActivation {
    /// ShellExecuteEx supplied a process handle retained by the USER worker.
    ProcessStarted { process: Win16HostProcess },
    /// Windows confirmed activation but supplied no process handle (for
    /// example, a DDE or already-running application activation).
    NativeActivationReceipt,
}

/// Native failures that SHELL maps to its documented HINSTANCE error range.
/// COM initialization retains the original HRESULT for a host diagnostic.
#[derive(Clone, Debug)]
pub enum Win16HostShellFailure {
    Api(u16),
    Preparation(Arc<RuntimeError>),
    ComInitialization { hresult: i32 },
    HostContractViolation,
    ExecutableInputNotRepresentable(Win16HostShellInputEncodingFailure),
    ExecutablePathNotRepresentable(Win16HostShellPathEncodingFailure),
}

#[derive(Clone, Debug)]
pub struct Win16HostShellInputEncodingFailure {
    pub input: Vec<u8>,
    pub cause: Win16HostShellPathEncodingCause,
}

/// Preserves the exact host path and both path-encoding attempts when an
/// executable path cannot be returned through the Win16 ANSI output buffer.
#[derive(Clone, Debug)]
pub struct Win16HostShellPathEncodingFailure {
    pub path: Vec<u16>,
    pub full_path_cause: Win16HostShellPathEncodingCause,
    pub short_path_cause: Win16HostShellPathEncodingCause,
}

#[derive(Clone, Debug)]
pub enum Win16HostShellPathEncodingCause {
    ConversionFailed { last_error: u32 },
    DefaultCharacterUsed,
    RoundTripMismatch,
    ShortAliasUnavailable { last_error: u32 },
    ShortAliasTooLong { required: usize },
}

impl fmt::Display for Win16HostShellPathEncodingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "resolved executable path is not losslessly representable in the host ANSI code page (full-path cause: {}, short-path cause: ",
            self.full_path_cause
        )?;
        write!(formatter, "{})", self.short_path_cause)
    }
}

impl fmt::Display for Win16HostShellInputEncodingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Win16 SHELL input path cannot be represented losslessly in the host code page: {}",
            self.cause
        )
    }
}

impl Error for Win16HostShellPathEncodingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.full_path_cause)
    }
}

impl Error for Win16HostShellInputEncodingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

impl fmt::Display for Win16HostShellPathEncodingCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversionFailed { last_error } => write!(
                formatter,
                "Windows ANSI conversion failed (error {last_error})"
            ),
            Self::DefaultCharacterUsed => formatter
                .write_str("Windows ANSI conversion required a default replacement character"),
            Self::RoundTripMismatch => formatter.write_str(
                "Windows ANSI conversion did not round-trip to the original UTF-16 path",
            ),
            Self::ShortAliasUnavailable { last_error } => write!(
                formatter,
                "Windows could not obtain an 8.3 path alias (error {last_error})"
            ),
            Self::ShortAliasTooLong { required } => write!(
                formatter,
                "the Windows short-path alias requires {required} UTF-16 units"
            ),
        }
    }
}

impl Error for Win16HostShellPathEncodingCause {}

impl fmt::Display for Win16HostShellFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(code) => write!(formatter, "native Shell API returned error {code}"),
            Self::Preparation(error) => write!(formatter, "host preparation failed: {error}"),
            Self::ComInitialization { hresult } => write!(
                formatter,
                "native USER worker COM STA initialization failed (HRESULT 0x{:08X})",
                *hresult as u32,
            ),
            Self::HostContractViolation => formatter.write_str(
                "native FindExecutable reported success without a complete nonempty path",
            ),
            Self::ExecutableInputNotRepresentable(error) => fmt::Display::fmt(error, formatter),
            Self::ExecutablePathNotRepresentable(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for Win16HostShellFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Preparation(error) => Some(error.as_ref()),
            Self::ExecutableInputNotRepresentable(error) => Some(error),
            Self::ExecutablePathNotRepresentable(error) => Some(error),
            Self::Api(_) | Self::ComInitialization { .. } | Self::HostContractViolation => None,
        }
    }
}

#[derive(Debug)]
pub enum Win16HostShellExecutionResult {
    WinExec(Result<Win16HostShellActivation, Win16HostWinExecFailure>),
    /// Native DragAcceptFiles is void; false reports that the owner did not
    /// identify a live native HWND, not a successful registration.
    DragAcceptFiles(bool),
    Execute(Result<Win16HostShellActivation, Win16HostShellFailure>),
    /// On success, `path` is the exact NUL-free path written by FindExecutable.
    FindExecutable(Result<Vec<u8>, Win16HostShellFailure>),
    /// Native ShellAboutA success/failure, mapped to Win16 DialogBoxParam by runtime.
    About(bool),
}
