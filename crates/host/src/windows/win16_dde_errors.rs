//! Preserve all typed causes when multiple DDE cleanup steps fail.

use std::error::Error;
use std::fmt;

use runtime::RuntimeError;

#[derive(Debug)]
struct CleanupErrorPair {
    primary: RuntimeError,
    additional: RuntimeError,
}

impl fmt::Display for CleanupErrorPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; additional cleanup failure: {}",
            self.primary, self.additional
        )
    }
}

impl Error for CleanupErrorPair {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}

pub(super) fn combine_cleanup_errors(
    primary: RuntimeError,
    additional: RuntimeError,
    operation: &'static str,
) -> RuntimeError {
    let kind = primary.kind().with_cleanup(additional.kind());
    RuntimeError::with_source(
        kind,
        operation,
        CleanupErrorPair {
            primary,
            additional,
        },
    )
}
