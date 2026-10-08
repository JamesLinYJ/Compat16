//! Validation helpers shared by typed OLE1 creation setup and its safe-point driver.

use super::super::OLE1_ERROR_MEMORY;
use crate::{DiagnosticKind as Kind, RuntimeError, Win16ComHostInterface};

pub(super) fn status_runtime(status: u16) -> RuntimeError {
    let kind = if status == OLE1_ERROR_MEMORY {
        Kind::ResourceExhausted
    } else {
        Kind::HostFailure
    };
    RuntimeError::new(kind, format!("OLE1 creation could not reserve state (status {status})"))
}

pub(super) fn hresult_failure(operation: &'static str, status: u32) -> RuntimeError {
    RuntimeError::new(
        Kind::HostFailure,
        format!("{operation} returned failing HRESULT 0x{status:08X}"),
    )
}

pub(super) fn protocol_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

pub(super) fn owned_interface(
    interface: Win16ComHostInterface,
    owner: crate::Win16ComHostOwnerIdentity,
    iid: compat_services::com::Guid,
) -> bool {
    interface.object.0 != 0
        && interface.owner == owner
        && interface.iid == iid
        && interface.disposition == compat_services::com::ReferenceDisposition::Owned
}

pub(super) fn iid_ole_object() -> compat_services::com::Guid {
    compat_services::com::Guid::new(0x0000_0112, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46])
}

pub(super) fn iid_iadvise_sink() -> compat_services::com::Guid {
    compat_services::com::Guid::new(0x0000_010f, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46])
}
