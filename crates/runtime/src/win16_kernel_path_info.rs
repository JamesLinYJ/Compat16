//! Synchronous KERNEL directory and temporary-file queries.

use guest_core::memory::Memory;
use win16_abi::{Access, Win16KernelPathInfoRequest};

use super::{guest_ranges::{GuestOutputRange, commit_guest_writes}, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostPathInfoOperation as Operation, Win16HostPathInfoResult as ResultValue};

const TEMP_FILE_NAME_BUFFER_BYTES: usize = 144;

impl Win16State {
    pub(in crate::win16_runtime) fn execute_kernel_path_info(
        &self,
        request: Win16KernelPathInfoRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16KernelPathInfoRequest::GetTempDrive { drive } => {
                let letter = super::temp_drive::select(
                    drive,
                    || self.kernel_file_system.current_drive(self.current_task_owner()?),
                    |drive| self.drive_type(u16::from(drive), host).map(|kind| kind == 3),
                )?;
                // WINDOWS.H declares BYTE (AL). The original Windows 3.1
                // implementation additionally leaves ':' in AH. Deliberately
                // use the Word return path; DX is not part of this API result.
                Ok(u32::from(u16::from_le_bytes([letter, b':'])))
            }
            Win16KernelPathInfoRequest::GetWindowsDirectory { output, capacity } =>
                self.directory_query(Operation::WindowsDirectory, output, capacity, memory, host),
            Win16KernelPathInfoRequest::GetSystemDirectory { output, capacity } =>
                self.directory_query(Operation::SystemDirectory, output, capacity, memory, host),
            Win16KernelPathInfoRequest::GetTempFileName { drive, prefix, unique, output } =>
                self.temp_file_name(drive, prefix, unique, output, memory, host),
            Win16KernelPathInfoRequest::GetShortPathName { long_path, output, capacity } =>
                self.short_path_name(long_path, output, capacity, memory, host),
        }
    }

    fn directory_query(
        &self,
        operation: Operation,
        output: u32,
        capacity: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let path = match host.win16_path_info(operation)? {
            ResultValue::Directory(Some(path)) => path,
            ResultValue::Directory(None) => return Ok(0),
            _ => return Err(invariant("host path-info result does not match directory request")),
        };
        if path.is_empty() || path.contains(&0) {
            return Err(invariant("host directory result is not a plain path"));
        }
        let required = path.len().checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 directory result length overflow"))?;
        let Ok(required_word) = u16::try_from(required) else { return Ok(0); };
        if usize::from(capacity) < required {
            // Windows 3.1 returns the required buffer size, including NUL,
            // without touching the caller's buffer when it is too small.
            return Ok(u32::from(required_word));
        }

        let range = match self.capture_output(output, required, memory) {
            Ok(range) => range,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        let bytes = nul_terminated(&path)?;
        match commit_guest_writes(self, memory, vec![(range, bytes)]) {
            Ok(()) => Ok(path.len() as u32),
            Err(error) if guest_api_failure(&error) => Ok(0),
            Err(error) => Err(error),
        }
    }

    fn temp_file_name(
        &self,
        drive: u8,
        prefix: Option<Vec<u8>>,
        unique: u16,
        output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        // The Windows 3.1 SDK specifies a 144-byte minimum buffer for this
        // API. Preflight that guest range before unique==0 can create a file.
        let range = match self.capture_output(output, TEMP_FILE_NAME_BUFFER_BYTES, memory) {
            Ok(range) => range,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(TEMP_FILE_NAME_BUFFER_BYTES).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 temporary-file output", error))?;
        let mut writes = Vec::new();
        writes.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 temporary-file transaction", error,
        ))?;
        let result = match host.win16_path_info(Operation::TempFileName { drive, prefix, unique })? {
            ResultValue::TempFileName(Some(result)) => result,
            ResultValue::TempFileName(None) => return Ok(0),
            _ => return Err(invariant("host path-info result does not match temporary-file request")),
        };
        if result.path.is_empty() || result.path.contains(&0) || result.unique == 0 {
            return Err(invariant("host temporary-file result is malformed"));
        }
        if (unique == 0) != result.created
            || (unique != 0 && unique != result.unique)
        {
            return Err(invariant("host temporary-file creation result disagrees with request"));
        }
        if result.path.len() >= TEMP_FILE_NAME_BUFFER_BYTES {
            return if result.created {
                Err(invariant("host created a temporary file whose path exceeds the Win16 output buffer"))
            } else {
                Ok(0)
            };
        }

        bytes.extend_from_slice(&result.path);
        bytes.push(0);
        writes.push((range, bytes));
        // unique==0 has already created the host file. Propagate commit
        // failures and leave ownership with the guest; never delete it here.
        commit_guest_writes(self, memory, writes)?;
        Ok(u32::from(result.unique))
    }

    fn capture_output(
        &self,
        output: u32,
        length: usize,
        memory: &Memory,
    ) -> Result<GuestOutputRange, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
        // These KERNEL parameters are ordinary FAR buffers. Reject a range
        // that crosses its selector even though the shared capture helper can
        // also represent huge ranges for APIs that explicitly use them.
        self.selectors.translate(pointer, Access::Write, length, memory)
            .map_err(crate::runtime_error)?;
        GuestOutputRange::capture(self, memory, pointer, length)
    }
}

fn nul_terminated(path: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let length = path.len().checked_add(1).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 path output length overflow"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate Win16 path output", error,
    ))?;
    bytes.extend_from_slice(path);
    bytes.push(0);
    Ok(bytes)
}

fn guest_api_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

#[cfg(test)]
#[path = "win16_get_temp_drive_tests.rs"]
mod get_temp_drive_tests;

#[cfg(test)]
#[path = "win16_short_path_profile_struct_tests.rs"]
mod short_path_profile_struct_tests;
