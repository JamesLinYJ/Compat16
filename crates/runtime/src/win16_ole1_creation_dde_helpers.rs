use super::Win16Ole1Status;
use crate::{DiagnosticKind as Kind, RuntimeError};

pub(super) fn copy_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, context, error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

pub(super) fn dde_status_error(status: Win16Ole1Status, context: &'static str) -> RuntimeError {
    RuntimeError::new(
        Kind::ResourceExhausted,
        format!("{context} failed with OLE1 status {status}"),
    )
}

pub(super) fn dde_error(kind: Kind, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(kind, message)
}
