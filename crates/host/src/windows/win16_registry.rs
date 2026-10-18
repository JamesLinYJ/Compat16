//! Native registry-key ownership for the Win16 SHELL registry service.

use std::collections::BTreeMap;
use std::ptr::{null, null_mut};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostRegistryKey,
    Win16HostRegistryOperation, Win16HostRegistryResult, Win16RegistryKeyRef,
    Win16RegistryRoot, Win16RegistryQueryOutput};
use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, ERROR_NOT_ENOUGH_MEMORY,
    ERROR_INVALID_DATA, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
    ERROR_NO_UNICODE_TRANSLATION, ERROR_SUCCESS, FILETIME};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyW, RegDeleteKeyW, RegEnumKeyExW, RegOpenKeyW,
    RegQueryValueW, RegSetValueW, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG,
    HKEY_CURRENT_USER, HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA,
    HKEY_USERS, REG_SZ,
};

use super::guest_text::GuestTextCodec;

const MAX_REGISTRY_KEY_NAME_WCHARS: usize = 256;

/// Owns only keys returned by successful OpenKey/CreateKey calls. Predefined
/// roots are borrowed Windows constants and never enter this table.
pub(super) struct RegistryHandles {
    keys: BTreeMap<u64, HKEY>,
    next_identity: u64,
}

impl RegistryHandles {
    pub(super) fn new() -> Self {
        Self { keys: BTreeMap::new(), next_identity: 1 }
    }

    pub(super) fn execute(
        &mut self,
        codec: GuestTextCodec,
        operation: Win16HostRegistryOperation,
    ) -> Result<Win16HostRegistryResult, RuntimeError> {
        match operation {
            Win16HostRegistryOperation::OpenKey { root, subkey } => {
                let Ok(root) = self.native_key(root) else {
                    return Ok(Win16HostRegistryResult::OpenKey {
                        status: ERROR_INVALID_HANDLE, key: None,
                    });
                };
                let subkey = match wide_z(codec, &subkey) {
                    Ok(subkey) => subkey,
                    Err(error) => return Ok(Win16HostRegistryResult::OpenKey {
                        status: conversion_status(error)?, key: None,
                    }),
                };
                let mut native = null_mut();
                // SAFETY: `root` is a validated predefined or live owned HKEY;
                // `subkey` is an owned NUL-terminated UTF-16 string and `native`
                // points to one writable HKEY slot.
                let status = unsafe { RegOpenKeyW(root, subkey.as_ptr(), &mut native) };
                if status != ERROR_SUCCESS {
                    return Ok(Win16HostRegistryResult::OpenKey { status, key: None });
                }
                let Some(key) = self.store(native) else {
                    // SAFETY: `native` was just returned successfully and has
                    // not yet entered the ownership table.
                    let _ = unsafe { RegCloseKey(native) };
                    return Ok(Win16HostRegistryResult::OpenKey {
                        status: ERROR_NOT_ENOUGH_MEMORY, key: None,
                    });
                };
                Ok(Win16HostRegistryResult::OpenKey { status, key: Some(key) })
            }
            Win16HostRegistryOperation::CreateKey { root, subkey } => {
                let Ok(root) = self.native_key(root) else {
                    return Ok(Win16HostRegistryResult::CreateKey {
                        status: ERROR_INVALID_HANDLE, key: None,
                    });
                };
                let subkey = match wide_z(codec, &subkey) {
                    Ok(subkey) => subkey,
                    Err(error) => return Ok(Win16HostRegistryResult::CreateKey {
                        status: conversion_status(error)?, key: None,
                    }),
                };
                let mut native = null_mut();
                // SAFETY: `root`, `subkey`, and the output slot meet the native
                // RegCreateKeyW contract described above.
                let status = unsafe { RegCreateKeyW(root, subkey.as_ptr(), &mut native) };
                if status != ERROR_SUCCESS {
                    return Ok(Win16HostRegistryResult::CreateKey { status, key: None });
                }
                let Some(key) = self.store(native) else {
                    // SAFETY: `native` is the newly acquired owned HKEY.
                    let _ = unsafe { RegCloseKey(native) };
                    return Ok(Win16HostRegistryResult::CreateKey {
                        status: ERROR_NOT_ENOUGH_MEMORY, key: None,
                    });
                };
                Ok(Win16HostRegistryResult::CreateKey { status, key: Some(key) })
            }
            Win16HostRegistryOperation::CloseKey { key } => {
                let Ok((native, identity)) = self.resolve(key) else {
                    return Ok(Win16HostRegistryResult::CloseKey { status: ERROR_INVALID_HANDLE });
                };
                // SAFETY: `native` is a validated predefined HKEY or a live
                // handle retained by this owner table.
                let status = unsafe { RegCloseKey(native) };
                if status == ERROR_SUCCESS {
                    if let Some(identity) = identity { self.keys.remove(&identity); }
                }
                Ok(Win16HostRegistryResult::CloseKey { status })
            }
            Win16HostRegistryOperation::DeleteKey { root, subkey } => {
                let Ok(root) = self.native_key(root) else {
                    return Ok(Win16HostRegistryResult::DeleteKey { status: ERROR_INVALID_HANDLE });
                };
                let subkey = match wide_z(codec, &subkey) {
                    Ok(subkey) => subkey,
                    Err(error) => return Ok(Win16HostRegistryResult::DeleteKey {
                        status: conversion_status(error)?,
                    }),
                };
                // SAFETY: `root` is live and `subkey` is a bounded owned UTF-16
                // string terminated for the native API.
                let status = unsafe { RegDeleteKeyW(root, subkey.as_ptr()) };
                Ok(Win16HostRegistryResult::DeleteKey { status })
            }
            Win16HostRegistryOperation::SetValue { key, subkey, value_type, value } => {
                if value_type != REG_SZ {
                    return Ok(Win16HostRegistryResult::SetValue { status: ERROR_INVALID_PARAMETER });
                }
                let Ok((native, _)) = self.resolve(key) else {
                    return Ok(Win16HostRegistryResult::SetValue { status: ERROR_INVALID_HANDLE });
                };
                let subkey = match wide_z(codec, &subkey) {
                    Ok(subkey) => subkey,
                    Err(error) => return Ok(Win16HostRegistryResult::SetValue {
                        status: conversion_status(error)?,
                    }),
                };
                let value = match wide_z(codec, &value) {
                    Ok(value) => value,
                    Err(error) => return Ok(Win16HostRegistryResult::SetValue {
                        status: conversion_status(error)?,
                    }),
                };
                // RegSetValueW ignores cbData. Always supply an owned,
                // terminated UTF-16 string, even for an empty guest string.
                // https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regsetvaluew
                // SAFETY: `native` is live and both strings remain owned for
                // the call. Guest FAR values never cross this boundary.
                let status = unsafe {
                    RegSetValueW(native, subkey.as_ptr(), REG_SZ, value.as_ptr(), 0)
                };
                Ok(Win16HostRegistryResult::SetValue { status })
            }
            Win16HostRegistryOperation::QueryValue { key, subkey, output } => {
                let Ok((native, _)) = self.resolve(key) else {
                    return Ok(Win16HostRegistryResult::QueryValue {
                        status: ERROR_INVALID_HANDLE, value_type: 0, required_bytes: 0,
                        bytes: Vec::new(),
                    });
                };
                let subkey = match wide_z(codec, &subkey) {
                    Ok(subkey) => subkey,
                    Err(error) => return Ok(Win16HostRegistryResult::QueryValue {
                        status: conversion_status(error)?, value_type: 0,
                        required_bytes: 0, bytes: Vec::new(),
                    }),
                };
                query_value(codec, native, &subkey, output)
            }
            Win16HostRegistryOperation::EnumKey { key, index, capacity } => {
                let Ok((native, _)) = self.resolve(key) else {
                    return Ok(Win16HostRegistryResult::EnumKey {
                        status: ERROR_INVALID_HANDLE, required_bytes: 0, name: Vec::new(),
                    });
                };
                let capacity = match usize::try_from(capacity) {
                    Ok(capacity) => capacity,
                    Err(_) => return Ok(Win16HostRegistryResult::EnumKey {
                        status: windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER,
                        required_bytes: 0, name: Vec::new(),
                    }),
                };
                let mut wide_name = Vec::new();
                wide_name.try_reserve_exact(MAX_REGISTRY_KEY_NAME_WCHARS).map_err(|error|
                    RuntimeError::with_source(Kind::ResourceExhausted,
                        "allocate Win16 registry enumeration buffer", error))?;
                wide_name.resize(MAX_REGISTRY_KEY_NAME_WCHARS, 0);
                let mut name_length = u32::try_from(wide_name.len()).map_err(|error|
                    RuntimeError::with_source(Kind::InternalInvariant,
                        "registry enumeration capacity exceeds DWORD", error))?;
                let mut last_write = FILETIME::default();
                // SAFETY: `native` is live; the UTF-16 name buffer and its
                // length pointer are owned. Optional class and reserved outputs are null.
                let status = unsafe { RegEnumKeyExW(native, index, wide_name.as_mut_ptr(), &mut name_length,
                    null(), null_mut(), null_mut(), &mut last_write) };
                if status == ERROR_SUCCESS {
                    let actual = usize::try_from(name_length).map_err(|error|
                        RuntimeError::with_source(Kind::InternalInvariant,
                            "RegEnumKey returned an invalid name length", error))?;
                    if actual >= wide_name.len() {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "RegEnumKey returned a name without room for its terminator"));
                    }
                    let encoded = match codec.from_wide(&wide_name[..actual]) {
                        Ok(encoded) => encoded.bytes,
                        Err(error) if guest_output_conversion_failure(&error) => {
                            return Ok(Win16HostRegistryResult::EnumKey {
                                status: ERROR_NO_UNICODE_TRANSLATION,
                                required_bytes: 0,
                                name: Vec::new(),
                            });
                        }
                        Err(error) => return Err(error),
                    };
                    let required_bytes = u32::try_from(encoded.len().checked_add(1).ok_or_else(||
                        RuntimeError::new(Kind::ResourceExhausted,
                            "size Win16 registry key name"))?).map_err(|error|
                        RuntimeError::with_source(Kind::InvalidInput,
                            "Win16 registry key name exceeds DWORD", error))?;
                    if usize::try_from(required_bytes).ok().is_some_and(|required| required > capacity) {
                        return Ok(Win16HostRegistryResult::EnumKey {
                            status: ERROR_MORE_DATA,
                            required_bytes,
                            name: Vec::new(),
                        });
                    }
                    return Ok(Win16HostRegistryResult::EnumKey {
                        status: ERROR_SUCCESS,
                        required_bytes,
                        name: encoded,
                    });
                } else {
                    // The guest caller receives the native registry status;
                    // required size is meaningful only for a converted name.
                    return Ok(Win16HostRegistryResult::EnumKey {
                        status,
                        required_bytes: 0,
                        name: Vec::new(),
                    });
                }
            }
        }
    }

    fn resolve(&self, key: Win16RegistryKeyRef) -> Result<(HKEY, Option<u64>), u32> {
        match key {
            Win16RegistryKeyRef::Predefined(root) => Ok((predefined_root(root), None)),
            Win16RegistryKeyRef::Opened(key) => self.keys.get(&key.0).copied()
                .map(|native| (native, Some(key.0)))
                .ok_or(ERROR_INVALID_HANDLE),
        }
    }

    fn native_key(&self, key: Win16RegistryKeyRef) -> Result<HKEY, u32> {
        self.resolve(key).map(|(native, _)| native)
    }

    fn store(&mut self, native: HKEY) -> Option<Win16HostRegistryKey> {
        let identity = self.next_identity;
        if identity == 0 { return None; }
        self.next_identity = identity.checked_add(1).unwrap_or(0);
        self.keys.insert(identity, native);
        Some(Win16HostRegistryKey(identity))
    }
}

impl Drop for RegistryHandles {
    fn drop(&mut self) {
        for native in std::mem::take(&mut self.keys).into_values() {
            // SAFETY: every stored entry was returned by a successful native
            // open/create and remained owned until close or this Drop.
            let _ = unsafe { RegCloseKey(native) };
        }
    }
}

fn predefined_root(root: Win16RegistryRoot) -> HKEY {
    match root {
        Win16RegistryRoot::ClassesRoot => HKEY_CLASSES_ROOT,
        Win16RegistryRoot::CurrentUser => HKEY_CURRENT_USER,
        Win16RegistryRoot::LocalMachine => HKEY_LOCAL_MACHINE,
        Win16RegistryRoot::Users => HKEY_USERS,
        Win16RegistryRoot::PerformanceData => HKEY_PERFORMANCE_DATA,
        Win16RegistryRoot::CurrentConfig => HKEY_CURRENT_CONFIG,
        Win16RegistryRoot::DynamicData => HKEY_DYN_DATA,
    }
}

enum TextConversionError {
    GuestStatus(u32),
    Runtime(RuntimeError),
}

fn wide_z(codec: GuestTextCodec, bytes: &[u8]) -> Result<Vec<u16>, TextConversionError> {
    if bytes.contains(&0) {
        return Err(TextConversionError::GuestStatus(ERROR_INVALID_PARAMETER));
    }
    wide_z_data(codec, bytes)
}

fn wide_z_data(codec: GuestTextCodec, bytes: &[u8]) -> Result<Vec<u16>, TextConversionError> {
    codec.to_wide_z(bytes).map_err(|error| match error.kind() {
        Kind::ResourceExhausted => TextConversionError::GuestStatus(ERROR_NOT_ENOUGH_MEMORY),
        Kind::HostFailure | Kind::InvalidInput => {
            TextConversionError::GuestStatus(ERROR_NO_UNICODE_TRANSLATION)
        }
        _ => TextConversionError::Runtime(error),
    })
}

fn conversion_status(error: TextConversionError) -> Result<u32, RuntimeError> {
    match error {
        TextConversionError::GuestStatus(status) => Ok(status),
        TextConversionError::Runtime(error) => Err(error),
    }
}

fn query_value(
    codec: GuestTextCodec,
    key: HKEY,
    subkey: &[u16],
    output: Win16RegistryQueryOutput,
) -> Result<Win16HostRegistryResult, RuntimeError> {
    if let Win16RegistryQueryOutput::WithoutLength { data_present } = output {
        // Preserve native ordering: a missing subkey is reported before a
        // non-NULL data buffer with no length is rejected. Native data never
        // points into guest memory. The one-unit buffer also accommodates the
        // legacy empty-default case; a nonempty transfer requires lpcbData.
        let mut unused = 0_u16;
        let data = if data_present { &mut unused as *mut u16 } else { null_mut() };
        // SAFETY: key/subkey remain live. With NULL lpcbData the native API
        // rejects nonempty data transfer; the owned unit covers an empty NUL.
        let status = unsafe { RegQueryValueW(key, subkey.as_ptr(), data, null_mut()) };
        return Ok(query_result(status, 0, Vec::new()));
    }
    let mut native_size = 0_i32;
    // RegQueryValueW's null-output query reports the native UTF-16 data size in
    // bytes. A complete value is needed to compute the guest code-page byte
    // count; the legacy Win16 capacity remains in guest bytes below.
    // SAFETY: the key and UTF-16 subkey are live, and `native_size` is writable.
    let sizing_status = unsafe {
        RegQueryValueW(key, subkey.as_ptr(), null_mut(), &mut native_size)
    };
    if sizing_status != ERROR_SUCCESS {
        return Ok(query_result(sizing_status, 0, Vec::new()));
    }
    if native_size < 0 || native_size % 2 != 0 {
        return Ok(query_result(ERROR_INVALID_DATA, 0, Vec::new()));
    }

    let mut required_native = usize::try_from(native_size).map_err(|error| {
        RuntimeError::with_source(Kind::InternalInvariant,
            "RegQueryValue returned an invalid UTF-16 byte count", error)
    })?;
    for attempt in 0..3 {
        if required_native % 2 != 0 {
            return Ok(query_result(ERROR_INVALID_DATA, 0, Vec::new()));
        }
        let wide_units = required_native / 2;
        let mut wide = Vec::new();
        wide.try_reserve_exact(wide_units).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "allocate Win16 registry query buffer", error)
        })?;
        wide.resize(wide_units, 0);
        let mut returned_native = i32::try_from(required_native).map_err(|error| {
            RuntimeError::with_source(Kind::InvalidInput,
                "registry value exceeds the native byte-count range", error)
        })?;
        let native_output = if wide.is_empty() { null_mut() } else { wide.as_mut_ptr() };
        // SAFETY: the optional output is writable for exactly the byte count
        // passed through `returned_native`, and all pointers remain live.
        let status = unsafe {
            RegQueryValueW(key, subkey.as_ptr(), native_output, &mut returned_native)
        };
        if status == ERROR_MORE_DATA && attempt < 2
            && returned_native >= 0
            && usize::try_from(returned_native).is_ok_and(|length| length > required_native)
        {
            required_native = returned_native as usize;
            continue;
        }
        if status != ERROR_SUCCESS {
            return Ok(query_result(status, 0, Vec::new()));
        }
        if returned_native < 0
            || returned_native % 2 != 0
            || usize::try_from(returned_native).ok().is_none_or(|length| length > required_native)
        {
            return Ok(query_result(ERROR_INVALID_DATA, 0, Vec::new()));
        }
        wide.truncate(returned_native as usize / 2);
        let mut bytes = match codec.from_wide(&wide) {
            Ok(encoded) => encoded.bytes,
            Err(error) if guest_output_conversion_failure(&error) => {
                return Ok(query_result(ERROR_NO_UNICODE_TRANSLATION, 0, Vec::new()));
            }
            Err(error) => return Err(error),
        };
        let required_bytes = u32::try_from(bytes.len()).map_err(|error| {
            RuntimeError::with_source(Kind::InvalidInput,
                "Win16 registry value exceeds DWORD byte count", error)
        })?;
        if matches!(output, Win16RegistryQueryOutput::Bounded(capacity) if bytes.len() > capacity as usize) {
            return Ok(query_result(ERROR_MORE_DATA, required_bytes, Vec::new()));
        }
        // The size-only query still converts the complete native value so a
        // DBCS byte count cannot be mistaken for its UTF-16 storage size.
        if output == Win16RegistryQueryOutput::SizeOnly {
            bytes.clear();
        }
        return Ok(query_result(ERROR_SUCCESS, required_bytes, bytes));
    }
    Ok(query_result(ERROR_MORE_DATA, 0, Vec::new()))
}

fn query_result(status: u32, required_bytes: u32, bytes: Vec<u8>) -> Win16HostRegistryResult {
    Win16HostRegistryResult::QueryValue {
        status,
        value_type: REG_SZ,
        required_bytes,
        bytes,
    }
}

fn guest_output_conversion_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::HostFailure | Kind::InvalidInput)
}
