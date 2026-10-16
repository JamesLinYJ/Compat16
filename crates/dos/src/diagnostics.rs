//! DOS-facing error codes and readable host-side diagnostics.

use guest_core::MemoryError;

/// DOS error values returned by host filesystem and console operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DosErrorCode {
    InvalidFunction = 1,
    FileNotFound = 2,
    PathNotFound = 3,
    TooManyOpenFiles = 4,
    AccessDenied = 5,
    InvalidHandle = 6,
    McbDestroyed = 7,
    InsufficientMemory = 8,
    InvalidMemoryBlock = 9,
    InvalidEnvironment = 10,
    InvalidFormat = 11,
    InvalidAccess = 12,
    InvalidData = 13,
    UnknownUnit = 15,
    CannotRemoveCurrentDirectory = 16,
    NotSameDevice = 17,
    NoMoreFiles = 18,
    WriteProtected = 19,
    DriveNotReady = 21,
    SharingViolation = 32,
    LockViolation = 33,
    DiskFull = 39,
    GeneralFailure = 31,
    FileExists = 80,
}

impl std::fmt::Display for DosErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            Self::InvalidFunction => "invalid function",
            Self::FileNotFound => "file not found",
            Self::PathNotFound => "path not found",
            Self::TooManyOpenFiles => "too many open files",
            Self::AccessDenied => "access denied",
            Self::InvalidHandle => "invalid handle",
            Self::McbDestroyed => "memory control block destroyed",
            Self::InsufficientMemory => "insufficient memory",
            Self::InvalidMemoryBlock => "invalid memory block",
            Self::InvalidEnvironment => "invalid environment",
            Self::InvalidFormat => "invalid format",
            Self::InvalidAccess => "invalid access mode",
            Self::InvalidData => "invalid data",
            Self::UnknownUnit => "unknown device unit",
            Self::CannotRemoveCurrentDirectory => "cannot remove the current directory",
            Self::NotSameDevice => "operation crosses devices",
            Self::NoMoreFiles => "no more files",
            Self::WriteProtected => "write protected",
            Self::DriveNotReady => "drive not ready",
            Self::SharingViolation => "sharing violation",
            Self::LockViolation => "lock violation",
            Self::DiskFull => "disk full",
            Self::GeneralFailure => "general failure",
            Self::FileExists => "file already exists",
        };
        f.write_str(description)
    }
}

/// A host operation failed. Only `code` is returned through the guest ABI;
/// an optional typed cause stays on the Rust side for host diagnostics.
#[derive(Debug)]
pub struct DosHostError {
    pub code: DosErrorCode,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl DosHostError {
    pub const fn new(code: DosErrorCode) -> Self {
        Self { code, source: None }
    }

    pub fn with_source(
        code: DosErrorCode,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            code,
            source: Some(Box::new(source)),
        }
    }
}

impl std::fmt::Display for DosHostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DOS host operation failed: {} (DOS error 0x{:04X})",
            self.code, self.code as u16
        )?;
        if let Some(source) = &self.source {
            write!(f, "; host cause: {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DosHostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Runtime classification for failures at the DOS caller-pointer boundary.
/// The typed source remains attached separately for diagnostics and recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DosCallerAddressSpaceFailureKind {
    InvalidPointer,
    Unsupported,
    ResourceExhausted,
    HostFailure,
    InternalInvariant,
}

impl std::fmt::Display for DosCallerAddressSpaceFailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::InvalidPointer => "invalid caller pointer",
            Self::Unsupported => "unsupported caller address operation",
            Self::ResourceExhausted => "caller address resources exhausted",
            Self::HostFailure => "caller address host failure",
            Self::InternalInvariant => "caller address internal invariant failed",
        };
        f.write_str(label)
    }
}

#[derive(Debug)]
pub enum DosError {
    Memory(MemoryError),
    HostOperation(DosHostError),
    MalformedGuestInput(&'static str),
    /// A guest-visible MCB header was reached at the position implied by the
    /// preceding chain entries, but its signature is not `M` or `Z`.
    InvalidMcbSignature {
        segment: u16,
        chain_head: u16,
        psp_segment: u16,
        previous: Option<(u16, u16)>,
        header: [u8; 16],
    },
    HostContractViolation(&'static str),
    HostMemoryContractViolation {
        detail: &'static str,
        source: MemoryError,
    },
    CallerAddressSpace {
        operation: &'static str,
        kind: DosCallerAddressSpaceFailureKind,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    RollbackFailure {
        operation: &'static str,
        cause: Box<DosError>,
        rollback: Box<DosError>,
    },
    /// Closing a duplicated inherited host file failed during child setup.
    /// The DOS kernel has already retained that file identity in its orphan
    /// handle ledger, so this pair is a retryable host cleanup failure rather
    /// than evidence that guest-visible MCB state was damaged.
    HostHandleRollbackFailure {
        operation: &'static str,
        cause: Box<DosError>,
        rollback: Box<DosError>,
    },
}

impl From<MemoryError> for DosError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

impl DosError {
    /// Preserve selector-table or persistent-pointer causes at the DOS/runtime
    /// boundary instead of disguising them as a real-mode MemoryError.
    pub fn caller_address_space(
        kind: DosCallerAddressSpaceFailureKind,
        operation: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::CallerAddressSpace {
            operation,
            kind,
            source: Box::new(source),
        }
    }
}

impl std::fmt::Display for DosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(error) => {
                f.write_str("DOS guest-memory access failed: ")?;
                write!(f, "{error}")
            }
            Self::HostOperation(error) => write!(f, "{error}"),
            Self::MalformedGuestInput(detail) => write!(f, "malformed DOS guest input: {detail}"),
            Self::InvalidMcbSignature {
                segment,
                chain_head,
                psp_segment,
                previous,
                header,
            } => {
                let owner = u16::from_le_bytes([header[1], header[2]]);
                let size = u16::from_le_bytes([header[3], header[4]]);
                write!(
                    f,
                    "DOS MCB chain corruption at segment 0x{segment:04X}: signature 0x{:02X}; chain head 0x{chain_head:04X}, PSP 0x{psp_segment:04X}, owner 0x{owner:04X}, size 0x{size:04X}",
                    header[0]
                )?;
                if let Some((previous_segment, previous_size)) = previous {
                    write!(
                        f,
                        "; previous MCB 0x{previous_segment:04X} size 0x{previous_size:04X} implies this header position"
                    )?;
                } else {
                    f.write_str("; this is the chain head")?;
                }
                f.write_str("; header bytes=")?;
                for byte in header {
                    write!(f, "{byte:02X}")?;
                }
                Ok(())
            }
            Self::HostContractViolation(detail) => {
                write!(f, "DOS host contract violation: {detail}")
            }
            Self::HostMemoryContractViolation { detail, source } => {
                write!(f, "DOS host-memory contract violation while {detail}: ")?;
                write!(f, "{source}")
            }
            Self::CallerAddressSpace {
                operation,
                kind,
                source,
            } => {
                write!(
                    f,
                    "DOS caller address access failed while {operation} ({kind}): {source}"
                )
            }
            Self::RollbackFailure {
                operation,
                cause,
                rollback,
            } => {
                write!(
                    f,
                    "DOS {operation} failed: {cause}; rollback also failed: {rollback}"
                )
            }
            Self::HostHandleRollbackFailure {
                operation,
                cause,
                rollback,
            } => {
                write!(
                    f,
                    "DOS {operation} failed: {cause}; closing a duplicated host file handle during rollback also failed: {rollback}"
                )
            }
        }
    }
}

impl std::error::Error for DosError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) | Self::HostMemoryContractViolation { source: error, .. } => {
                Some(error)
            }
            Self::HostOperation(error) => Some(error),
            Self::CallerAddressSpace { source, .. } => Some(source.as_ref()),
            Self::RollbackFailure { cause, .. }
            | Self::HostHandleRollbackFailure { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
