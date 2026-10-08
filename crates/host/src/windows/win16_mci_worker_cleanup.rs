//! Typed failure summaries for native MCI device cleanup.

use std::error::Error;
use std::fmt;

use super::super::combine_failure_kind;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostMciDevice};

pub(super) enum MciCloseFailure {
    Device(Win16HostMciDevice, u32),
    Alias(Vec<u8>, u32),
    NativeId(u32, u32),
    Error(RuntimeError),
}

struct MciCloseFailures(Vec<MciCloseFailure>);

impl fmt::Debug for MciCloseFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MciCloseFailures")
            .field("failure_count", &self.0.len())
            .finish()
    }
}

impl fmt::Display for MciCloseFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} native MCI close(s) failed", self.0.len())?;
        for failure in &self.0 {
            match failure {
                MciCloseFailure::Device(device, result) => write!(
                    formatter,
                    "; token {} generation {} returned 0x{result:08X}",
                    device.token, device.generation
                )?,
                MciCloseFailure::Alias(alias, result) => {
                    formatter.write_str("; retained alias '")?;
                    for byte in alias {
                        write!(formatter, "{}", byte.escape_ascii())?;
                    }
                    write!(formatter, "' returned 0x{result:08X}")?;
                }
                MciCloseFailure::NativeId(native_id, result) => write!(
                    formatter,
                    "; unregistered native id {native_id} returned 0x{result:08X}"
                )?,
                MciCloseFailure::Error(error) => {
                    write!(formatter, "; cleanup call failed: {error}")?
                }
            }
        }
        Ok(())
    }
}

impl Error for MciCloseFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0
            .iter()
            .filter_map(|failure| match failure {
                MciCloseFailure::Error(error) => Some(error),
                _ => None,
            })
            .find(|error| error.kind() == Kind::InternalInvariant)
            .map(|error| error as &(dyn Error + 'static))
            .or_else(|| {
                self.0.iter().find_map(|failure| match failure {
                    MciCloseFailure::Error(error) => Some(error as &(dyn Error + 'static)),
                    _ => None,
                })
            })
    }
}

pub(super) fn close_failure_result(
    operation: &'static str,
    failures: Vec<MciCloseFailure>,
) -> Result<(), RuntimeError> {
    if failures.is_empty() {
        return Ok(());
    }
    let kind = failures
        .iter()
        .fold(None, |kind, failure| {
            let next = match failure {
                MciCloseFailure::Error(error) => error.kind(),
                MciCloseFailure::Device(..)
                | MciCloseFailure::Alias(..)
                | MciCloseFailure::NativeId(..) => Kind::HostFailure,
            };
            Some(kind.map_or(next, |primary| combine_failure_kind(primary, next)))
        })
        .unwrap_or(Kind::HostFailure);
    Err(RuntimeError::with_source(
        kind,
        operation,
        MciCloseFailures(failures),
    ))
}
