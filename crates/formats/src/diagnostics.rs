//! Structured executable-format failures and user-readable descriptions.

use guest_core::{MemoryError, PhysAddr};
use crate::NeImportTarget;

/// Why a required NE data import could not be connected to owned runtime state.
/// The export identity stays alongside this reason in [`FormatError`], so a
/// load failure names the importing module and the declaration it requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeDataImportIssue {
    /// A runtime selector equate has no supported live guest-memory alias.
    SelectorAliasUnavailable {
        equate: &'static str,
        detail: &'static str,
    },
    /// The declared variable's runtime initialization/update rules are not
    /// represented by this runtime.
    RuntimeVariableStateUnspecified,
    /// A data import resolved to a declaration kind that is not data-backed.
    UnsupportedDeclarationKind,
}

/// A failed attempt to restore one guest-memory range after a staged image
/// write failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestMemoryRollbackFailure {
    pub address: PhysAddr,
    pub error: MemoryError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FormatError {
    Truncated { context: &'static str, offset: usize, needed: usize },
    InvalidSignature { expected: &'static str },
    InvalidCom(&'static str),
    InvalidMzHeader(&'static str),
    InvalidNe(&'static str),
    ArithmeticOverflow,
    AddressOutOfRange { address: u32, length: usize, memory_len: u32 },
    UnsupportedExecutable(&'static str),
    UnsupportedNeLoading,
    UnsupportedNeFeature(&'static str),
    /// A required Win16 data export could not be resolved from runtime-owned
    /// state. This differs from a callable export lookup and retains both the
    /// source declaration and the original NE import target.
    NeDataImportFailure {
        module: Vec<u8>,
        declared_name: &'static str,
        ordinal: u16,
        target: NeImportTarget,
        issue: NeDataImportIssue,
    },
    InvalidNeLoad(&'static str),
    UnsupportedNeFixup(&'static str),
    UnresolvedNeImport { module: Vec<u8>, target: NeImportTarget },
    AllocationFailed,
    GuestMemory(MemoryError),
    /// The primary guest-memory write failed and one or more rollback writes
    /// also failed. The affected memory may remain partially modified.
    GuestMemoryRollback {
        failed_address: PhysAddr,
        primary_error: MemoryError,
        rollback_failures: Vec<GuestMemoryRollbackFailure>,
    },
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use FormatError as E;

        match self {
            E::Truncated { context, offset, needed } => {
                let end = (*offset as u128) + (*needed as u128);
                write!(f, "truncated {context}: file range 0x{offset:X}..0x{end:X} requires {needed} bytes")
            }
            E::InvalidSignature { expected } => {
                write!(f, "invalid executable signature; expected {expected}")
            }
            E::InvalidCom(detail) => write!(f, "invalid COM image: {detail}"),
            E::InvalidMzHeader(detail) => write!(f, "invalid MZ header: {detail}"),
            E::InvalidNe(detail) => write!(f, "invalid NE image: {detail}"),
            E::ArithmeticOverflow => write!(f, "executable image size or address calculation overflowed"),
            E::AddressOutOfRange { address, length, memory_len } => {
                let end = u128::from(*address) + (*length as u128);
                write!(
                    f,
                    "guest memory range 0x{address:08X}..0x{end:X} ({length} bytes) exceeds available memory size 0x{memory_len:08X}"
                )
            }
            E::UnsupportedExecutable(format) => write!(f, "unsupported executable format: {format}"),
            E::UnsupportedNeLoading => {
                write!(f, "NE executable is recognized, but this DOS image loader does not execute it")
            }
            E::UnsupportedNeFeature(feature) => write!(f, "unsupported NE feature: {feature}"),
            E::NeDataImportFailure { module, declared_name, ordinal, target, issue } => {
                write!(f, "Win16 data import {}!{} (ordinal #{ordinal}, requested ",
                    String::from_utf8_lossy(module), declared_name)?;
                match target {
                    NeImportTarget::Ordinal(requested) => write!(f, "#{requested}"),
                    NeImportTarget::Name(name) => write!(f, "{}", String::from_utf8_lossy(name)),
                }?;
                f.write_str("): ")?;
                match issue {
                    NeDataImportIssue::SelectorAliasUnavailable { equate, detail } =>
                        write!(f, "selector equate {equate} is unavailable: {detail}"),
                    NeDataImportIssue::RuntimeVariableStateUnspecified =>
                        f.write_str("runtime variable initialization and updates are unspecified"),
                    NeDataImportIssue::UnsupportedDeclarationKind =>
                        f.write_str("the declaration has no supported data binding"),
                }
            }
            E::InvalidNeLoad(detail) => write!(f, "invalid NE load request: {detail}"),
            E::UnsupportedNeFixup(detail) => write!(f, "unsupported NE fixup: {detail}"),
            E::UnresolvedNeImport { module, target } => {
                write!(f, "Win16 import {}!", String::from_utf8_lossy(module))?;
                match target {
                    NeImportTarget::Ordinal(ordinal) => write!(f, "#{ordinal}"),
                    NeImportTarget::Name(name) => write!(f, "{}", String::from_utf8_lossy(name)),
                }
            }
            E::AllocationFailed => write!(f, "unable to allocate storage for executable loading"),
            E::GuestMemory(error) => {
                f.write_str("guest-memory access failed: ")?;
                write!(f, "{error}")
            }
            E::GuestMemoryRollback { failed_address, primary_error, rollback_failures } => {
                write!(f, "guest-memory write at physical address 0x{:08X} failed: ", failed_address.0)?;
                write!(f, "{primary_error}")?;
                write!(f, "; {} rollback write(s) also failed", rollback_failures.len())?;
                for failure in rollback_failures {
                    write!(f, "; rollback at physical address 0x{:08X} failed: ", failure.address.0)?;
                    write!(f, "{}", failure.error)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::GuestMemory(error) => Some(error),
            Self::GuestMemoryRollback { primary_error, .. } => Some(primary_error),
            _ => None,
        }
    }
}

impl From<MemoryError> for FormatError {
    fn from(value: MemoryError) -> Self { Self::GuestMemory(value) }
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
