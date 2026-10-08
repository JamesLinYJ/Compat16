//! Exact task/provider ownership for native System32 module references.

use std::ptr;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win32HostImportResult,
    Win32HostImportValue, Win32HostModule, Win32HostModuleOwner, Win32ImportString};
use windows_sys::Win32::{
    Foundation::{FreeLibrary, GetLastError},
    System::LibraryLoader::{LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32},
};

use super::{OwnedModule, OwnedModuleReference, Win32ImportSystem, copy_wide_path,
    exhausted, invariant, module_path, native_failure, path_in_directory, result, text,
    system_directory, NativeRollbackFailure};

impl Win32ImportSystem {
    pub(super) fn compensate_unpublished_reference(&mut self, id: u64,
        raw: windows_sys::Win32::Foundation::HMODULE, path: Vec<u16>,
        owner: Win32HostModuleOwner, fresh: Vec<OwnedModuleReference>,
        primary: RuntimeError, operation: &'static str) -> RuntimeError {
        if unsafe { FreeLibrary(raw) } != 0 { return primary; }
        let code = unsafe { GetLastError() };
        self.retain_failed_module_owner(id, raw, path, owner, code, fresh);
        native_rollback_failure(
            "native module reference could not be rolled back",
            primary,
            native_failure(operation, code),
        )
    }

    pub(super) fn free_system_module(&mut self, token: Win32HostModule,
        owner: Win32HostModuleOwner) -> Result<Win32HostImportResult, RuntimeError> {
        let index = self.modules.iter().position(|entry| entry.id == token.host_id())
            .ok_or_else(|| invariant("stale PE32 native module token"))?;
        let owner_index = self.modules[index].owners.iter().position(|entry| entry.owner == owner)
            .ok_or_else(|| invariant("native module release does not match its provider owner"))?;
        // A failed prior release remains attached to this exact owner; a retry
        // never consumes another task's reference.
        let raw = self.modules[index].raw;
        // SAFETY: this releases only the native reference recorded for the
        // exact task/provider generation above.
        if unsafe { FreeLibrary(raw) } != 0 {
            self.modules[index].owners.swap_remove(owner_index);
        } else {
            let error = unsafe { GetLastError() };
            self.modules[index].owners[owner_index].last_release_error = Some(error);
            return Ok(result(Win32HostImportValue::Bool(false), Some(error)));
        }
        if self.modules[index].owners.is_empty() {
            self.modules.swap_remove(index);
            self.exports.retain(|export| export.module_id != token.host_id());
        }
        Ok(result(Win32HostImportValue::Bool(true), None))
    }

    pub(super) fn module_owner_exists(&self, owner: Win32HostModuleOwner) -> bool {
        self.modules.iter().any(|module| module.owners.iter()
            .any(|reference| reference.owner == owner))
    }

    pub(super) fn reserve_module_owner_slots(&mut self) -> Result<(), RuntimeError> {
        for module in &mut self.modules {
            module.owners.try_reserve(1).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve native module provider reference", error))?;
        }
        Ok(())
    }

    pub(super) fn retain_failed_module_owner(&mut self, id: u64,
        raw: windows_sys::Win32::Foundation::HMODULE, path: Vec<u16>,
        owner: Win32HostModuleOwner, error: u32, mut fresh: Vec<OwnedModuleReference>) {
        let reference = OwnedModuleReference { owner, last_release_error: Some(error) };
        if let Some(index) = self.modules.iter().position(|module| module.raw == raw) {
            if self.modules[index].path.is_empty() && !path.is_empty() {
                self.modules[index].path = path;
            }
            self.modules[index].owners.push(reference);
        } else {
            fresh.push(reference);
            self.modules.push(OwnedModule { id, raw, path, owners: fresh });
        }
    }

    pub(super) fn retain_system_module_path(&mut self, path: Win32ImportString,
        owner: Win32HostModuleOwner) -> Result<Win32HostImportResult, RuntimeError> {
        let valid = match &path {
            Win32ImportString::Ansi(value) => !value.is_empty() && !value.contains(&0)
                && value.iter().any(|unit| matches!(*unit, b'/' | b'\\' | b':')),
            Win32ImportString::Wide(value) => !value.is_empty() && !value.contains(&0)
                && value.iter().any(|unit| matches!(*unit, 0x2f | 0x5c | 0x3a)),
        };
        if !valid {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "provider retention requires a resolved module path"));
        }
        if self.module_owner_exists(owner) {
            return Err(invariant("duplicate native provider reference owner"));
        }
        self.reserve_module_owner_slots()?;
        self.modules.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve retained System32 module", error))?;
        let mut fresh_owners = Vec::new();
        fresh_owners.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve retained module owner record", error))?;
        let system_directory = system_directory()?;
        let id = self.next_module.ok_or_else(|| exhausted("native module identities"))?;
        self.next_module = id.checked_add(1);
        let path = text::to_wide_z(self.codec, path,
            "resolved native module path contains embedded NUL")?;
        // SAFETY: this path was resolved and classified as a System32 host
        // provider; its UTF-16 storage and exact owner remain host-owned.
        let raw = unsafe { LoadLibraryExW(path.as_ptr(), ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if raw.is_null() {
            let error = unsafe { GetLastError() };
            return Ok(result(Win32HostImportValue::Module { module: None, path: Vec::new() }, Some(error)));
        }
        let resolved = match module_path(raw) {
            Ok(actual) if path_in_directory(&actual, &system_directory) => actual,
            Ok(actual) => {
                if unsafe { FreeLibrary(raw) } != 0 {
                    return Ok(result(Win32HostImportValue::Module { module: None, path: Vec::new() }, None));
                }
                let cleanup_code = unsafe { GetLastError() };
                self.retain_failed_module_owner(id, raw, actual, owner, cleanup_code, fresh_owners);
                return Err(RuntimeError::with_source(Kind::HostFailure,
                    "resolved module was outside System32 and could not be released",
                    native_failure("FreeLibrary after provider-path validation", cleanup_code)));
            }
            Err(primary) => {
                if unsafe { FreeLibrary(raw) } != 0 { return Err(primary); }
                let cleanup_code = unsafe { GetLastError() };
                self.retain_failed_module_owner(id, raw, Vec::new(), owner, cleanup_code, fresh_owners);
                return Err(native_rollback_failure(
                    "retained module path query failed and native owner remains held",
                    primary,
                    native_failure("FreeLibrary after retained module-path failure", cleanup_code),
                ));
            }
        };
        if let Some(index) = self.modules.iter().position(|entry| entry.raw == raw) {
            let path_for_response = if self.modules[index].path.is_empty() {
                &resolved
            } else {
                &self.modules[index].path
            };
            let stored = match copy_wide_path(path_for_response) {
                Ok(path) => path,
                Err(primary) => return Err(self.compensate_unpublished_reference(
                    id, raw, resolved, owner, fresh_owners, primary,
                    "FreeLibrary after retained-path response allocation failure")),
            };
            self.modules[index].owners.push(OwnedModuleReference { owner, last_release_error: None });
            if self.modules[index].path.is_empty() { self.modules[index].path = resolved; }
            let module_id = self.modules[index].id;
            Ok(result(Win32HostImportValue::Module {
                module: Some(Win32HostModule::from_host_id(module_id)), path: stored,
            }, None))
        } else {
            let stored = match copy_wide_path(&resolved) {
                Ok(path) => path,
                Err(primary) => return Err(self.compensate_unpublished_reference(
                    id, raw, resolved, owner, fresh_owners, primary,
                    "FreeLibrary after retained-path response allocation failure")),
            };
            fresh_owners.push(OwnedModuleReference { owner, last_release_error: None });
            self.modules.push(OwnedModule { id, raw, path: resolved, owners: fresh_owners });
            Ok(result(Win32HostImportValue::Module {
                module: Some(Win32HostModule::from_host_id(id)), path: stored,
            }, None))
        }
    }
}

fn native_rollback_failure(
    context: &'static str,
    primary: RuntimeError,
    cleanup: RuntimeError,
) -> RuntimeError {
    let kind = match (primary.kind(), cleanup.kind()) {
        (Kind::InternalInvariant, _) | (_, Kind::InternalInvariant) => Kind::InternalInvariant,
        (Kind::ExecutionLimit, additional) => additional,
        (primary, _) => primary,
    };
    RuntimeError::with_source(kind, context, NativeRollbackFailure { primary, cleanup })
}
