//! OLE1 class and DDE application lookup through the guest ClassesRoot view.
//!
//! This uses the shared Win16 registry service, which performs the guest
//! encoding to Windows registry UTF-16 conversion. Registry values are read
//! using the service's required-size contract; their size is independent of
//! the fixed OLE1 scratch buffers used to build registry key names.

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostRegistryOperation,
    Win16HostRegistryResult, Win16RegistryKeyRef, Win16RegistryRoot,
};

const ERROR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const MAX_CLASS_REGISTRY_KEY_BYTES: usize = 256;
const REGISTRY_QUERY_ATTEMPTS: usize = 4;

/// Class identity and its OLE1 DDE application name from the registered
/// `StdFileEditing` server value. Neither field is an object or COM pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Win16Ole1ResolvedClass {
    pub(super) class_name: Vec<u8>,
    pub(super) application_name: Vec<u8>,
}

/// Mirrors OLE1 `QueryApp`: look up
/// `HKCR\\<class>\\protocol\\<protocol>\\server` in the existing guest
/// ClassesRoot view. The 256-byte bound applies to XP's local key buffer,
/// not the returned registry value.
pub(super) fn resolve_class_application(
    host: &mut impl RuntimeHost,
    class_name: &[u8],
    protocol: &[u8],
) -> Result<Option<Win16Ole1ResolvedClass>, RuntimeError> {
    if class_name.is_empty()
        || class_name.contains(&0)
        || protocol.is_empty()
        || protocol.contains(&0)
    {
        return Ok(None);
    }

    let suffix_len = b"\\protocol\\"
        .len()
        .checked_add(protocol.len())
        .and_then(|length| length.checked_add(b"\\server".len()));
    let Some(key_len) = suffix_len.and_then(|length| length.checked_add(class_name.len())) else {
        return Ok(None);
    };
    // XP's QueryApp constructs this key in `char key[MAX_STR]`, including its
    // trailing NUL. Returned value length is deliberately not part of this
    // constraint and is sized separately below.
    if key_len >= MAX_CLASS_REGISTRY_KEY_BYTES {
        return Ok(None);
    }
    let mut key = Vec::new();
    key.try_reserve_exact(key_len).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve OLE1 class registry key",
            error,
        )
    })?;
    key.extend_from_slice(class_name);
    key.extend_from_slice(b"\\protocol\\");
    key.extend_from_slice(protocol);
    key.extend_from_slice(b"\\server");

    let Some(application_name) = query_default_string(host, &key)? else {
        return Ok(None);
    };
    let mut retained_class = Vec::new();
    retained_class
        .try_reserve_exact(class_name.len())
        .map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "retain OLE1 class name", error)
        })?;
    retained_class.extend_from_slice(class_name);
    Ok(Some(Win16Ole1ResolvedClass {
        class_name: retained_class,
        application_name,
    }))
}

/// Read a default value from the ClassesRoot registry service. A zero-capacity
/// query supplies the exact guest-byte requirement, including a REG_SZ NUL;
/// the second query uses that requirement. If the value changes between those
/// calls, repeat with the new requirement instead of treating `MORE_DATA` as
/// a missing class. The service owns the UTF-16 boundary and reports guest
/// encoding byte counts here.
fn query_default_string(
    host: &mut impl RuntimeHost,
    subkey: &[u8],
) -> Result<Option<Vec<u8>>, RuntimeError> {
    let mut capacity = 0_u32;
    let mut owned = Vec::new();

    for _ in 0..REGISTRY_QUERY_ATTEMPTS {
        let mut request_subkey = Vec::new();
        request_subkey
            .try_reserve_exact(subkey.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "copy OLE1 registry subkey",
                    error,
                )
            })?;
        request_subkey.extend_from_slice(subkey);
        let result = host.win16_registry(Win16HostRegistryOperation::QueryValue {
            key: Win16RegistryKeyRef::Predefined(Win16RegistryRoot::ClassesRoot),
            subkey: request_subkey,
            output: crate::Win16RegistryQueryOutput::Bounded(capacity),
        })?;
        let Win16HostRegistryResult::QueryValue {
            status,
            required_bytes,
            bytes,
            ..
        } = result
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host returned the wrong result for OLE1 class registry lookup",
            ));
        };

        if status == ERROR_MORE_DATA {
            // The host service can return zero here if its own bounded native
            // retry exhausted while the registration changed concurrently.
            // Retry the query; do not infer absence or a malformed record.
            if required_bytes == 0 {
                continue;
            }
            if required_bytes <= capacity || !bytes.is_empty() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "host registry MORE_DATA result violates the Win16 capacity contract",
                ));
            }
            owned.clear();
            owned
                .try_reserve_exact(usize::try_from(required_bytes).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve OLE1 registry value bytes",
                        error,
                    )
                })?)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve OLE1 registry value bytes",
                        error,
                    )
                })?;
            capacity = required_bytes;
            continue;
        }
        if status != ERROR_SUCCESS {
            // NTVDM QueryApp/MapExtToClass report a failed RegQueryValue as
            // an absent class/server. This is an ordinary OLE lookup result.
            return Ok(None);
        }

        let required = usize::try_from(required_bytes).map_err(|error| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "host OLE1 registry requirement does not fit runtime memory",
                error,
            )
        })?;
        if bytes.len() != required || required_bytes > capacity {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host OLE1 registry result disagrees with its guest-byte capacity",
            ));
        }
        owned.clear();
        owned.try_reserve_exact(bytes.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain OLE1 registry value bytes",
                error,
            )
        })?;
        owned.extend_from_slice(&bytes);

        let Some(0) = owned.last().copied() else {
            return Ok(None);
        };
        let value = &owned[..owned.len() - 1];
        if value.is_empty() || value.contains(&0) {
            return Ok(None);
        }
        let mut result = Vec::new();
        result.try_reserve_exact(value.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain OLE1 registry string",
                error,
            )
        })?;
        result.extend_from_slice(value);
        return Ok(Some(result));
    }

    Err(RuntimeError::new(
        Kind::HostFailure,
        "OLE1 registry value changed during every size-query retry",
    ))
}
