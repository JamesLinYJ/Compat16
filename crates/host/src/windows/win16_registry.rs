//! Native registry-key ownership for the Win16 SHELL registry service.

use std::collections::BTreeMap;
use std::ptr::{null, null_mut};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostRegistryKey,
    Win16HostRegistryOperation, Win16HostRegistryResult, Win16RegistryKeyRef,
    Win16RegistryRoot};
use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, ERROR_NOT_ENOUGH_MEMORY,
    ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
    ERROR_NO_UNICODE_TRANSLATION, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyW, RegDeleteKeyW, RegEnumKeyExW, RegOpenKeyW,
    RegSetValueW, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG,
    HKEY_CURRENT_USER, HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA,
    HKEY_USERS, REG_SZ,
};

use super::guest_text::GuestTextCodec;

mod names;
mod query;
use query::query_value;

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
                let subkey = match names::native_path(codec, root, &subkey) {
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
                let subkey = match names::native_path(codec, root, &subkey) {
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
                let subkey = match names::native_path(codec, root, &subkey) {
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
                let subkey = match names::native_path(codec, native, &subkey) {
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
            Win16HostRegistryOperation::QueryValue { key, subkey, output, view } => {
                let Ok((native, _)) = self.resolve(key) else {
                    return Ok(Win16HostRegistryResult::QueryValue {
                        status: ERROR_INVALID_HANDLE, value_type: 0, required_bytes: 0,
                        bytes: Vec::new(),
                    });
                };
                let subkey = match names::native_path(codec, native, &subkey) {
                    Ok(subkey) => subkey,
                    Err(error) => return Ok(Win16HostRegistryResult::QueryValue {
                        status: conversion_status(error)?, value_type: 0,
                        required_bytes: 0, bytes: Vec::new(),
                    }),
                };
                query_value(codec, native, &subkey, output, view)
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
                let wide_name = match enum_native_name(native, index) {
                    Ok(name) => name,
                    Err(error) => return Ok(Win16HostRegistryResult::EnumKey {
                        status: conversion_status(error)?, required_bytes: 0, name: Vec::new(),
                    }),
                };
                let encoded = match names::guest_name(codec, native, &wide_name) {
                    Ok(encoded) => encoded,
                    Err(error) => return Ok(Win16HostRegistryResult::EnumKey {
                        status: conversion_status(error)?, required_bytes: 0, name: Vec::new(),
                    }),
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
                Ok(Win16HostRegistryResult::EnumKey {
                    status: ERROR_SUCCESS,
                    required_bytes,
                    name: encoded,
                })

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

fn enum_native_name(key: HKEY, index: u32) -> Result<Vec<u16>, TextConversionError> {
    let mut name = vec![0_u16; MAX_REGISTRY_KEY_NAME_WCHARS];
    let mut length = name.len() as u32;
    // SAFETY: the validated native key, owned UTF-16 output and writable count
    // remain live. All unused outputs are NULL. Key components are at most 255
    // UTF-16 units, with separate room for the native terminator.
    // https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regenumkeyexw
    let status = unsafe {
        RegEnumKeyExW(key, index, name.as_mut_ptr(), &mut length,
            null(), null_mut(), null_mut(), null_mut())
    };
    if status != ERROR_SUCCESS {
        return Err(TextConversionError::GuestStatus(status));
    }
    let length = length as usize;
    if length >= name.len() {
        return Err(TextConversionError::Runtime(RuntimeError::new(Kind::InternalInvariant,
            "RegEnumKey returned a name without room for its terminator")));
    }
    name.truncate(length);
    Ok(name)
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

fn guest_output_conversion_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::HostFailure | Kind::InvalidInput)
}
