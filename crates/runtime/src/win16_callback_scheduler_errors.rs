//! Typed failures shared by asynchronous callback scheduling paths.

use std::sync::Arc;

use crate::{DiagnosticKind as Kind, RuntimeError};

pub(super) fn combine_callback_failure(
    primary: Arc<RuntimeError>,
    additional: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    let kind = match (primary.kind(), additional.kind()) {
        (Kind::InternalInvariant, _) | (_, Kind::InternalInvariant) => Kind::InternalInvariant,
        (Kind::ExecutionLimit, additional) => additional,
        (primary, _) => primary,
    };
    RuntimeError::with_source(kind, context, CallbackFailurePair { primary, additional })
}

pub(super) fn callback_binding_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

#[derive(Debug)]
struct CallbackFailurePair {
    primary: Arc<RuntimeError>,
    additional: RuntimeError,
}

impl std::fmt::Display for CallbackFailurePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; callback cleanup failure: {}", self.primary, self.additional)
    }
}

impl std::error::Error for CallbackFailurePair {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.primary.as_ref())
    }
}
