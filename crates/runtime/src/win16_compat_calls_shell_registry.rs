//! SHELL registry APIs with per-task guest HKEY aliases and native host keys.

use guest_core::memory::Memory;
use win16_abi::{Access, Win16ShellRegistryRequest};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostRegistryKey, Win16HostRegistryOperation, Win16HostRegistryResult,
    Win16RegistryKeyRef};

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_HANDLE: u32 = 6;

impl Win16State {
    pub(crate) fn shell_registry_api(
        &mut self,
        request: Win16ShellRegistryRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16ShellRegistryRequest::OpenKey { root, subkey, output } => self
                .shell_registry_open(root, subkey, output, false, memory, host),
            Win16ShellRegistryRequest::CreateKey { root, subkey, output } => self
                .shell_registry_open(root, subkey, output, true, memory, host),
            Win16ShellRegistryRequest::CloseKey { key } => {
                let Ok(key_ref) = self.compat.registry_key(key) else {
                    return Ok(ERROR_INVALID_HANDLE);
                };
                let result = host.win16_registry(Win16HostRegistryOperation::CloseKey { key: key_ref })?;
                let Win16HostRegistryResult::CloseKey { status } = result else {
                    return Err(wrong_registry_result("RegCloseKey"));
                };
                if status == ERROR_SUCCESS && matches!(key_ref, Win16RegistryKeyRef::Opened(_)) {
                    self.compat.remove_registry_key(key);
                }
                Ok(status)
            }
            Win16ShellRegistryRequest::DeleteKey { root, subkey } => {
                let Ok(root) = self.compat.registry_key(root) else {
                    return Ok(ERROR_INVALID_HANDLE);
                };
                let result = host.win16_registry(
                    Win16HostRegistryOperation::DeleteKey { root, subkey })?;
                let Win16HostRegistryResult::DeleteKey { status } = result else {
                    return Err(wrong_registry_result("RegDeleteKey"));
                };
                Ok(status)
            }
            Win16ShellRegistryRequest::SetValue {
                key, subkey, value_type, value, declared_byte_count,
            } => {
                let Ok(key) = self.compat.registry_key(key) else {
                    return Ok(ERROR_INVALID_HANDLE);
                };
                if usize::try_from(declared_byte_count).ok() != Some(value.len()) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 RegSetValue buffer length differs from its declared byte count"));
                }
                let result = host.win16_registry(Win16HostRegistryOperation::SetValue {
                    key,
                    subkey,
                    value_type,
                    value,
                    declared_byte_count,
                })?;
                let Win16HostRegistryResult::SetValue { status } = result else {
                    return Err(wrong_registry_result("RegSetValue"));
                };
                Ok(status)
            }
            Win16ShellRegistryRequest::QueryValue {
                key, subkey, output, byte_count, byte_count_output,
            } => self.shell_registry_query_value(
                key, subkey, output, byte_count, byte_count_output, memory, host),
            Win16ShellRegistryRequest::EnumKey { key, index, output, capacity } => {
                let Ok(key) = self.compat.registry_key(key) else {
                    return Ok(ERROR_INVALID_HANDLE);
                };
                let capacity = usize::try_from(capacity).map_err(|error|
                    RuntimeError::with_source(Kind::GuestFault,
                        "Win16 RegEnumKey buffer capacity exceeds the host range", error))?;
                if capacity != 0 { self.preflight_registry_output(memory, output, capacity)?; }
                let result = host.win16_registry(Win16HostRegistryOperation::EnumKey {
                    key,
                    index,
                    capacity: u32::try_from(capacity).map_err(|error| RuntimeError::with_source(
                        Kind::InternalInvariant, "Win16 RegEnumKey capacity lost its DWORD width", error))?,
                })?;
                let Win16HostRegistryResult::EnumKey { status, required_bytes, name } = result else {
                    return Err(wrong_registry_result("RegEnumKey"));
                };
                if status == ERROR_SUCCESS {
                    let required = name.len().checked_add(1).ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant, "Win16 RegEnumKey result length overflow"))?;
                    if required > capacity || required_bytes as usize > capacity {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "host RegEnumKey result exceeds its caller buffer"));
                    }
                    let mut bytes = name;
                    bytes.try_reserve(1).map_err(|error| RuntimeError::with_source(
                        Kind::ResourceExhausted, "reserve Win16 RegEnumKey terminator", error))?;
                    bytes.push(0);
                    self.write_registry_output(memory, output, &bytes)?;
                }
                Ok(status)
            }
        }
    }

    fn shell_registry_open(
        &mut self,
        guest_root: u32,
        subkey: Vec<u8>,
        output: u32,
        create: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.preflight_registry_output(memory, output, 4)?;
        let Ok(root) = self.compat.registry_key(guest_root) else {
            return Ok(ERROR_INVALID_HANDLE);
        };
        let operation = if create {
            Win16HostRegistryOperation::CreateKey { root, subkey }
        } else {
            Win16HostRegistryOperation::OpenKey { root, subkey }
        };
        let result = host.win16_registry(operation)?;
        let (status, key) = match (create, result) {
            (false, Win16HostRegistryResult::OpenKey { status, key }) => (status, key),
            (true, Win16HostRegistryResult::CreateKey { status, key }) => (status, key),
            _ => return Err(wrong_registry_result(if create { "RegCreateKey" } else { "RegOpenKey" })),
        };
        if status != ERROR_SUCCESS {
            if let Some(key) = key { self.close_unclaimed_registry_key(host, key)?; }
            return Ok(status);
        }
        let Some(key) = key else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host registry open succeeded without returning a native key"));
        };
        let guest_key = match self.compat.add_registry_key(key) {
            Ok(handle) => handle,
            Err(error) => {
                self.close_unclaimed_registry_key(host, key)?;
                return Err(error);
            }
        };
        if let Err(error) = self.write_registry_output(memory, output, &guest_key.to_le_bytes()) {
            self.compat.remove_registry_key(guest_key);
            self.close_unclaimed_registry_key(host, key)?;
            return Err(error);
        }
        Ok(status)
    }

    fn shell_registry_query_value(
        &mut self,
        guest_key: u32,
        subkey: Vec<u8>,
        output: u32,
        capacity: u32,
        capacity_output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Ok(key) = self.compat.registry_key(guest_key) else {
            return Ok(ERROR_INVALID_HANDLE);
        };
        let capacity_output_pointer = self.preflight_registry_output(memory, capacity_output, 4)?;
        let capacity = usize::try_from(capacity).map_err(|error| RuntimeError::with_source(
            Kind::GuestFault, "Win16 RegQueryValue capacity exceeds the host range", error))?;
        if capacity != 0 { self.preflight_registry_output(memory, output, capacity)?; }
        let capacity_dword = u32::try_from(capacity).map_err(|error| RuntimeError::with_source(
            Kind::InternalInvariant, "Win16 RegQueryValue capacity lost its DWORD width", error))?;
        let result = host.win16_registry(Win16HostRegistryOperation::QueryValue {
            key,
            subkey,
            capacity: capacity_dword,
        })?;
        let Win16HostRegistryResult::QueryValue {
            status, value_type: _, required_bytes, bytes,
        } = result else {
            return Err(wrong_registry_result("RegQueryValue"));
        };
        if status == ERROR_SUCCESS {
            if bytes.len() > capacity || required_bytes as usize > capacity {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "host RegQueryValue result exceeds its caller buffer"));
            }
            if !bytes.is_empty() { self.write_registry_output(memory, output, &bytes)?; }
        }
        self.selectors.write(memory, capacity_output_pointer, &required_bytes.to_le_bytes())
            .map_err(crate::runtime_error)?;
        Ok(status)
    }

    fn close_unclaimed_registry_key(
        &mut self,
        host: &mut impl RuntimeHost,
        key: Win16HostRegistryKey,
    ) -> Result<(), RuntimeError> {
        let result = host.win16_registry(Win16HostRegistryOperation::CloseKey {
            key: Win16RegistryKeyRef::Opened(key),
        })?;
        let Win16HostRegistryResult::CloseKey { .. } = result else {
            return Err(wrong_registry_result("unclaimed RegCloseKey"));
        };
        Ok(())
    }

    fn preflight_registry_output(
        &self,
        memory: &Memory,
        address: u32,
        count: usize,
    ) -> Result<win16_abi::SegmentedPointer, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(address).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Write, count, memory)
            .map_err(crate::runtime_error)?;
        Ok(pointer)
    }

    fn write_registry_output(
        &self,
        memory: &mut Memory,
        address: u32,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        let pointer = self.preflight_registry_output(memory, address, bytes.len())?;
        self.selectors.write(memory, pointer, bytes).map_err(crate::runtime_error)
    }
}

fn wrong_registry_result(operation: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant,
        format!("host returned the wrong result for Win16 {operation}"))
}
