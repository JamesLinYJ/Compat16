//! OLE1 server class registration validation against the Win16 ClassesRoot
//! bridge and atom namespace.

use crate::{
    Win16HostRegistryOperation, Win16HostRegistryResult, Win16RegistryKeyRef, Win16RegistryRoot,
};

use super::win16_ole1_server_state::{OLE_ERROR_REGISTRATION, Ole1Status};
use crate::{RuntimeError, RuntimeHost};

/// XP `ValidateSrvrClass` queries the default value at
/// `HKCR\\<class>\\protocol\\StdFileEditing\\server` into `MAX_STR` bytes,
/// rejects an empty string, and derives the executable atom from the portion
/// after the last backslash or colon. The returned bytes remain guest-codepage
/// bytes; callers must not interpret the registered value as a host pointer.
pub(super) fn validate_server_registration(
    host: &mut impl RuntimeHost,
    class_name: &[u8],
) -> Result<Result<ServerClassRegistration, Ole1Status>, RuntimeError> {
    let mut subkey = Vec::new();
    subkey.try_reserve(class_name.len() + 39).map_err(|error| {
        RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve OLE1 server registration key",
            error,
        )
    })?;
    subkey.extend_from_slice(class_name);
    subkey.extend_from_slice(b"\\protocol\\StdFileEditing\\server");
    let result = host.win16_registry(Win16HostRegistryOperation::QueryValue {
        key: Win16RegistryKeyRef::Predefined(Win16RegistryRoot::ClassesRoot),
        subkey,
        output: crate::Win16RegistryQueryOutput::Bounded(124),
        // OLE1 consumes the Win3.1 string view, just like SHELL. Retain
        // environment references instead of rejecting REG_EXPAND_SZ.
        view: crate::Win16RegistryQueryView::Win31Strings,
    })?;
    let Win16HostRegistryResult::QueryValue {
        status,
        value_type: _,
        required_bytes: _,
        bytes,
    } = result
    else {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 server registration query returned the wrong registry result",
        ));
    };
    if status != 0 || bytes.first().copied().unwrap_or(0) == 0 {
        return Ok(Err(OLE_ERROR_REGISTRATION));
    }
    let Some(nul) = bytes.iter().position(|byte| *byte == 0) else {
        return Ok(Err(OLE_ERROR_REGISTRATION));
    };
    let value = bytes[..nul].to_vec();
    let basename_start = value
        .iter()
        .rposition(|byte| matches!(*byte, b'\\' | b':'))
        .map_or(0, |index| index + 1);
    let executable_name = value[basename_start..].to_vec();
    if executable_name.is_empty() {
        return Ok(Err(OLE_ERROR_REGISTRATION));
    }
    Ok(Ok(ServerClassRegistration {
        registry_value: value,
        executable_name,
    }))
}

/// XP `UtilQueryProtocol` tests whether the exact protocol child key exists;
/// it does not read or interpret the protocol's value. The returned boolean
/// therefore distinguishes `StdExecute` registration from server launch
/// registration, which is queried separately above.
pub(super) fn server_has_protocol(
    host: &mut impl RuntimeHost,
    class_name: &[u8],
    protocol: &[u8],
) -> Result<bool, RuntimeError> {
    if class_name.is_empty()
        || protocol.is_empty()
        || class_name.contains(&0)
        || protocol.contains(&0)
    {
        return Ok(false);
    }
    let mut subkey = Vec::new();
    let reserve = class_name
        .len()
        .checked_add(protocol.len())
        .and_then(|length| length.checked_add(20))
        .ok_or_else(|| {
            RuntimeError::new(
                crate::DiagnosticKind::ResourceExhausted,
                "OLE1 protocol registry path length overflow",
            )
        })?;
    subkey.try_reserve_exact(reserve).map_err(|error| {
        RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve OLE1 protocol registration key",
            error,
        )
    })?;
    subkey.extend_from_slice(class_name);
    subkey.extend_from_slice(b"\\protocol\\");
    subkey.extend_from_slice(protocol);
    subkey.extend_from_slice(b"\\server");
    let opened = host.win16_registry(Win16HostRegistryOperation::OpenKey {
        root: Win16RegistryKeyRef::Predefined(Win16RegistryRoot::ClassesRoot),
        subkey,
    })?;
    let Win16HostRegistryResult::OpenKey { status, key } = opened else {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 protocol registration query returned the wrong registry result",
        ));
    };
    if status != 0 {
        return Ok(false);
    }
    let Some(key) = key else {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "successful OLE1 protocol registry open returned no key identity",
        ));
    };
    let closed = host.win16_registry(Win16HostRegistryOperation::CloseKey {
        key: Win16RegistryKeyRef::Opened(key),
    })?;
    let Win16HostRegistryResult::CloseKey { status } = closed else {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 protocol registry close returned the wrong result",
        ));
    };
    if status != 0 {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::HostFailure,
            "OLE1 protocol registry handle could not be closed",
        ));
    }
    Ok(true)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ServerClassRegistration {
    pub(super) registry_value: Vec<u8>,
    pub(super) executable_name: Vec<u8>,
}
