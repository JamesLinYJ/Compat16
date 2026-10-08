//! Shared callback failure wrappers used while exact callback owners remain live.

use std::{error::Error, fmt, sync::Arc};

use crate::RuntimeError;

pub(super) fn shared_runtime_error(error: Arc<RuntimeError>) -> RuntimeError {
    RuntimeError::with_source(
        error.kind(),
        "Win16 callback owner retains its original failure",
        SharedRuntimeError(error),
    )
}

#[derive(Debug)]
struct SharedRuntimeError(Arc<RuntimeError>);

impl fmt::Display for SharedRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl Error for SharedRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
