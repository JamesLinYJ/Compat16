//! Typed aggregation for MCI worker receipt and wake failures.

use std::error::Error;
use std::fmt;

use super::super::combine_failure_kind;
use runtime::{DiagnosticKind as Kind, RuntimeError};

#[derive(Debug)]
struct MciWorkerFailurePair {
    primary_label: &'static str,
    primary: RuntimeError,
    secondary_label: &'static str,
    secondary: RuntimeError,
}

impl fmt::Display for MciWorkerFailurePair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}; {}: {}",
            self.primary_label, self.primary, self.secondary_label, self.secondary
        )
    }
}

impl Error for MciWorkerFailurePair {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if self.primary.kind() == Kind::InternalInvariant {
            Some(&self.primary)
        } else if self.secondary.kind() == Kind::InternalInvariant {
            Some(&self.secondary)
        } else {
            Some(&self.primary)
        }
    }
}

pub(super) fn combine_worker_failures(
    message: &'static str,
    primary_label: &'static str,
    primary: RuntimeError,
    secondary_label: &'static str,
    secondary: RuntimeError,
) -> RuntimeError {
    let kind = combine_failure_kind(primary.kind(), secondary.kind());
    RuntimeError::with_source(
        kind,
        message,
        MciWorkerFailurePair {
            primary_label,
            primary,
            secondary_label,
            secondary,
        },
    )
}
