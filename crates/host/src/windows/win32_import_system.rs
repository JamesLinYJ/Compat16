//! Native Windows owner for typed PE32 Win32 imports.
//!
//! HMODULE, HANDLE and FARPROC stay in this adapter. Runtime-visible values are
//! monotonic opaque ids; GetProcAddress is never returned as a callable pointer.

use std::{error::Error, fmt, ptr};

use super::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win32HostHandle, Win32HostImportCall,
    Win32HostImportFamily, Win32HostImportResult, Win32HostImportValue, Win32HostModule,
    Win32HostModuleOwner, Win32HostResolvedExport, Win32HostSearchHandle, Win32HostServiceIdentity,
    Win32HostServiceOperation, Win32ImportSymbol,
};
use windows_sys::Win32::{
    Foundation::{FreeLibrary, HANDLE},
    System::LibraryLoader::{
        GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    },
    System::SystemInformation::GetSystemDirectoryW,
};

#[path = "win32_import_system_files.rs"]
mod files;
#[path = "win32_import_system_loader.rs"]
mod loader;
#[path = "win32_import_system_owners.rs"]
mod owners;
#[path = "win32_import_system_paths.rs"]
mod paths;
#[path = "win32_import_system_queries.rs"]
mod queries;
#[path = "win32_import_system_text.rs"]
mod text;

#[derive(Clone, Copy)]
struct OwnedHandle {
    id: u64,
    raw: HANDLE,
}

#[derive(Clone, Copy)]
struct OwnedSearchHandle {
    id: u64,
    raw: HANDLE,
}

#[derive(Clone)]
struct OwnedModuleReference {
    owner: Win32HostModuleOwner,
    last_release_error: Option<u32>,
}

#[derive(Clone)]
struct OwnedModule {
    id: u64,
    raw: windows_sys::Win32::Foundation::HMODULE,
    path: Vec<u16>,
    // One entry per successful native LoadLibraryEx, keyed by the exact
    // task/provider generation that must release that reference.
    owners: Vec<OwnedModuleReference>,
}

#[derive(Clone)]
struct OwnedExport {
    id: u64,
    module_id: u64,
    service: Win32HostServiceIdentity,
    symbol: Vec<u8>,
    native_address: usize,
}

/// Per-host table of native resources created through the PE32 import bridge.
pub(super) struct Win32ImportSystem {
    pub(super) codec: GuestTextCodec,
    handles: Vec<OwnedHandle>,
    searches: Vec<OwnedSearchHandle>,
    modules: Vec<OwnedModule>,
    exports: Vec<OwnedExport>,
    next_handle: Option<u64>,
    next_search: Option<u64>,
    next_module: Option<u64>,
    next_export: Option<u64>,
}

impl Win32ImportSystem {
    pub(super) fn new(codec: GuestTextCodec) -> Self {
        Self {
            codec,
            handles: Vec::new(),
            searches: Vec::new(),
            modules: Vec::new(),
            exports: Vec::new(),
            next_handle: Some(1),
            next_search: Some(1),
            next_module: Some(1),
            next_export: Some(1),
        }
    }

    pub(super) fn execute(
        &mut self,
        call: Win32HostImportCall,
    ) -> Result<Win32HostImportResult, RuntimeError> {
        match call {
            Win32HostImportCall::LoadSystemModule { basename, owner } => {
                self.load_system_module(basename, owner)
            }
            Win32HostImportCall::IsSystemDirectoryPath { path } => {
                loader::is_system_directory_path(path, self.codec)
            }
            Win32HostImportCall::FindLoadedSystemModule { name } => {
                self.find_loaded_system_module(name)
            }
            Win32HostImportCall::RetainSystemModulePath { path, owner } => {
                self.retain_system_module_path(path, owner)
            }
            Win32HostImportCall::FreeSystemModule { module, owner } => {
                self.free_system_module(module, owner)
            }
            Win32HostImportCall::ResolveSystemExport {
                module,
                symbol,
                service,
            } => self.resolve_system_export(module, symbol, service),
            Win32HostImportCall::CloseOwnedHandle { handle } => files::close(self, handle),
            Win32HostImportCall::CloseOwnedSearchHandle { handle } => {
                files::close_search(self, handle)
            }
            Win32HostImportCall::InvokeService {
                export,
                service,
                operation,
            } => self.invoke_service(export, service, operation),
            Win32HostImportCall::Shutdown => {
                self.shutdown()?;
                Ok(result(Win32HostImportValue::Void, None))
            }
        }
    }

    pub(super) fn shutdown(&mut self) -> Result<(), RuntimeError> {
        let owner_count = self
            .modules
            .iter()
            .try_fold(0usize, |count, module| {
                count.checked_add(module.owners.len())
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "PE32 native module-owner count overflowed",
                )
            })?;
        let count = self
            .handles
            .len()
            .checked_add(self.searches.len())
            .and_then(|count| count.checked_add(owner_count))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "PE32 native resource count overflowed",
                )
            })?;
        let mut failures = Vec::new();
        failures.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 native cleanup results",
                error,
            )
        })?;
        let mut index = 0;
        while index < self.searches.len() {
            let resource = self.searches[index];
            if files::close_search_raw(resource.raw) {
                self.searches.swap_remove(index);
            } else {
                let code = crate::windows::win32_safe::last_error();
                failures.push(RuntimeError::with_source(
                    Kind::HostFailure,
                    "FindClose during PE32 shutdown failed",
                    NativeSearchCloseFailure { error: code },
                ));
                index += 1;
            }
        }
        index = 0;
        while index < self.handles.len() {
            let resource = self.handles[index];
            // SAFETY: `raw` is retained from a successful CreateFile call and
            // remains owned by this table until CloseHandle succeeds.
            if (crate::windows::win32_safe::close_handle(resource.raw)) != 0 {
                self.handles.swap_remove(index);
            } else {
                let code = crate::windows::win32_safe::last_error();
                failures.push(native_failure("CloseHandle during PE32 shutdown", code));
                index += 1;
            }
        }
        index = 0;
        while index < self.modules.len() {
            let module = &mut self.modules[index];
            let mut released = true;
            while !module.owners.is_empty() {
                let owner = module.owners[0].owner;
                let previous_error = module.owners[0].last_release_error;
                // SAFETY: each successful LoadLibraryEx reference has an
                // exact provider owner and is released at most once.
                if unsafe { FreeLibrary(module.raw) } != 0 {
                    module.owners.remove(0);
                } else {
                    let code = crate::windows::win32_safe::last_error();
                    module.owners[0].last_release_error = Some(code);
                    failures.push(RuntimeError::with_source(
                        Kind::HostFailure,
                        "FreeLibrary during PE32 shutdown failed",
                        NativeModuleReleaseFailure {
                            owner,
                            previous_error,
                            error: code,
                        },
                    ));
                    released = false;
                    break;
                }
            }
            if released {
                let module = self.modules.swap_remove(index);
                self.exports.retain(|export| export.module_id != module.id);
            } else {
                index += 1;
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::with_source(
                Kind::HostFailure,
                "one or more PE32 native resources could not be released",
                NativeCleanupFailures(failures),
            ))
        }
    }

    pub(super) fn native_handle(&self, token: Win32HostHandle) -> Result<HANDLE, RuntimeError> {
        self.handles
            .iter()
            .find(|entry| entry.id == token.host_id())
            .map(|entry| entry.raw)
            .ok_or_else(|| invariant("stale PE32 native HANDLE token"))
    }

    pub(super) fn native_search_handle(
        &self,
        token: Win32HostSearchHandle,
    ) -> Result<HANDLE, RuntimeError> {
        self.searches
            .iter()
            .find(|entry| entry.id == token.host_id())
            .map(|entry| entry.raw)
            .ok_or_else(|| invariant("stale PE32 native search HANDLE token"))
    }

    fn load_system_module(
        &mut self,
        basename: runtime::Win32ImportString,
        owner: Win32HostModuleOwner,
    ) -> Result<Win32HostImportResult, RuntimeError> {
        let valid = match &basename {
            runtime::Win32ImportString::Ansi(value) => {
                !value.is_empty()
                    && !value.contains(&0)
                    && !value
                        .iter()
                        .any(|unit| matches!(*unit, b'/' | b'\\' | b':'))
            }
            runtime::Win32ImportString::Wide(value) => {
                !value.is_empty()
                    && !value.contains(&0)
                    && !value.iter().any(|unit| matches!(*unit, 0x2f | 0x5c | 0x3a))
            }
        };
        if !valid {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "system-provider resolution requires a DLL basename",
            ));
        }
        if self.module_owner_exists(owner) {
            return Err(invariant("duplicate native provider reference owner"));
        }
        self.reserve_module_owner_slots()?;
        self.modules.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve system-module ownership",
                error,
            )
        })?;
        let mut fresh_owners = Vec::new();
        fresh_owners.try_reserve_exact(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native system-module reference owner",
                error,
            )
        })?;
        let system_directory = system_directory()?;
        let id = self
            .next_module
            .ok_or_else(|| exhausted("native module identities"))?;
        self.next_module = id.checked_add(1);
        let basename = text::to_wide_z(
            self.codec,
            basename,
            "system-module basename contains embedded NUL",
        )?;
        // SAFETY: the owned UTF-16 basename is terminated and the explicit
        // search flag asks Windows to select the native System32 provider.
        let raw = unsafe {
            LoadLibraryExW(
                basename.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if raw.is_null() {
            let error = crate::windows::win32_safe::last_error();
            return Ok(result(
                Win32HostImportValue::Module {
                    module: None,
                    path: Vec::new(),
                },
                Some(error),
            ));
        }
        match module_path(raw) {
            Ok(path) => {
                if !path_in_directory(&path, &system_directory) {
                    // LoadLibraryEx can return a same-named module that was
                    // loaded earlier from another directory. It is not a
                    // system provider; balance this temporary reference before
                    // asking the guest PE loader to search its own paths.
                    // SAFETY: FreeLibrary balances one loader reference this module owns.
                    if unsafe { FreeLibrary(raw) } != 0 {
                        return Ok(result(
                            Win32HostImportValue::Module {
                                module: None,
                                path: Vec::new(),
                            },
                            None,
                        ));
                    }
                    let cleanup_code = crate::windows::win32_safe::last_error();
                    self.retain_failed_module_owner(
                        id,
                        raw,
                        Vec::new(),
                        owner,
                        cleanup_code,
                        fresh_owners,
                    );
                    return Err(RuntimeError::with_source(
                        Kind::HostFailure,
                        "non-system module reference could not be released",
                        native_failure(
                            "FreeLibrary after non-system provider resolution",
                            cleanup_code,
                        ),
                    ));
                }
                if let Some(index) = self.modules.iter().position(|entry| entry.raw == raw) {
                    let path_for_response = if self.modules[index].path.is_empty() {
                        &path
                    } else {
                        &self.modules[index].path
                    };
                    let response_path = match copy_wide_path(path_for_response) {
                        Ok(path) => path,
                        Err(primary) => {
                            return Err(self.compensate_unpublished_reference(
                                id,
                                raw,
                                path,
                                owner,
                                fresh_owners,
                                primary,
                                "FreeLibrary after system-module response allocation failure",
                            ));
                        }
                    };
                    self.modules[index].owners.push(OwnedModuleReference {
                        owner,
                        last_release_error: None,
                    });
                    if self.modules[index].path.is_empty() {
                        self.modules[index].path = path;
                    }
                    let module_id = self.modules[index].id;
                    Ok(result(
                        Win32HostImportValue::Module {
                            module: Some(Win32HostModule::from_host_id(module_id)),
                            path: response_path,
                        },
                        None,
                    ))
                } else {
                    let response_path = match copy_wide_path(&path) {
                        Ok(path) => path,
                        Err(primary) => {
                            return Err(self.compensate_unpublished_reference(
                                id,
                                raw,
                                path,
                                owner,
                                fresh_owners,
                                primary,
                                "FreeLibrary after system-module response allocation failure",
                            ));
                        }
                    };
                    fresh_owners.push(OwnedModuleReference {
                        owner,
                        last_release_error: None,
                    });
                    self.modules.push(OwnedModule {
                        id,
                        raw,
                        path,
                        owners: fresh_owners,
                    });
                    Ok(result(
                        Win32HostImportValue::Module {
                            module: Some(Win32HostModule::from_host_id(id)),
                            path: response_path,
                        },
                        None,
                    ))
                }
            }
            Err(primary) => {
                // Preserve ownership if compensation fails: the outer host
                // table retains the exact HMODULE through explicit shutdown.
                // Its path is unknown, so it can never become a service provider.
                // SAFETY: this balances the LoadLibraryExW reference above.
                Err(self.compensate_unpublished_reference(
                    id,
                    raw,
                    Vec::new(),
                    owner,
                    fresh_owners,
                    primary,
                    "FreeLibrary after module-path failure",
                ))
            }
        }
    }

    fn find_loaded_system_module(
        &self,
        name: runtime::Win32ImportString,
    ) -> Result<Win32HostImportResult, RuntimeError> {
        let empty_name = match &name {
            runtime::Win32ImportString::Ansi(value) => value.is_empty(),
            runtime::Win32ImportString::Wide(value) => value.is_empty(),
        };
        if empty_name {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "loaded System32 module name is empty",
            ));
        }
        let name = text::to_wide_z(
            self.codec,
            name,
            "loaded System32 module name contains embedded NUL",
        )?;
        // SAFETY: the expected module identity remains host-owned; this
        // terminated UTF-16 lookup acquires no additional native reference.
        crate::windows::win32_safe::set_last_error(0);
        let raw = unsafe { GetModuleHandleW(name.as_ptr()) };
        if raw.is_null() {
            return Ok(result(
                Win32HostImportValue::Module {
                    module: None,
                    path: Vec::new(),
                },
                None,
            ));
        }
        let system_directory = system_directory()?;
        let resolved = module_path(raw)?;
        if !path_in_directory(&resolved, &system_directory) {
            return Ok(result(
                Win32HostImportValue::Module {
                    module: None,
                    path: Vec::new(),
                },
                None,
            ));
        }
        let path = copy_wide_path(&resolved)?;
        let owner = self
            .modules
            .iter()
            .find(|entry| entry.raw == raw && !entry.path.is_empty());
        Ok(result(
            Win32HostImportValue::Module {
                module: owner.map(|entry| Win32HostModule::from_host_id(entry.id)),
                path,
            },
            None,
        ))
    }

    fn resolve_system_export(
        &mut self,
        token: Win32HostModule,
        symbol: Win32ImportSymbol,
        service: Win32HostServiceIdentity,
    ) -> Result<Win32HostImportResult, RuntimeError> {
        let module = self
            .modules
            .iter()
            .find(|entry| entry.id == token.host_id())
            .ok_or_else(|| invariant("stale PE32 native module token"))?;
        if module.path.is_empty() {
            return Err(invariant(
                "system module with unknown path cannot provide imports",
            ));
        }
        let Win32ImportSymbol::Name(name) = symbol else {
            return Ok(result(Win32HostImportValue::ResolvedExport(None), None));
        };
        if service.export() != name.as_slice() {
            return Err(invariant("service id and requested export name differ"));
        }
        if name.is_empty() || name.contains(&0) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "GetProcAddress name is empty or contains NUL",
            ));
        }
        if let Some(export) = self.exports.iter().find(|entry| {
            entry.module_id == token.host_id() && entry.service == service && entry.symbol == name
        }) {
            return Ok(result(
                Win32HostImportValue::ResolvedExport(Some(Win32HostResolvedExport::from_host_id(
                    export.id,
                ))),
                None,
            ));
        }
        let id = self
            .next_export
            .ok_or_else(|| exhausted("resolved export identities"))?;
        let mut terminated = Vec::new();
        terminated
            .try_reserve_exact(name.len().saturating_add(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "terminate imported procedure name",
                    error,
                )
            })?;
        terminated.extend_from_slice(&name);
        terminated.push(0);
        let mut retained_name = Vec::new();
        retained_name
            .try_reserve_exact(name.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain resolved export identity",
                    error,
                )
            })?;
        retained_name.extend_from_slice(&name);
        self.exports.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve resolved export identity",
                error,
            )
        })?;
        crate::windows::win32_safe::set_last_error(0);
        // SAFETY: this HMODULE is an exact owned module reference and the
        // terminated export name is host-owned. Windows resolves forwarders.
        let target = unsafe { GetProcAddress(module.raw, terminated.as_ptr()) };
        let Some(target) = target else {
            let error = crate::windows::win32_safe::last_error();
            return Ok(result(
                Win32HostImportValue::ResolvedExport(None),
                Some(error),
            ));
        };
        let Some(canonical) = kernel32_export(&terminated)? else {
            let error = crate::windows::win32_safe::last_error();
            return Ok(result(
                Win32HostImportValue::ResolvedExport(None),
                Some(error),
            ));
        };
        let address = target as usize;
        if address != canonical as usize {
            return Ok(result(Win32HostImportValue::ResolvedExport(None), None));
        }
        self.next_export = id.checked_add(1);
        self.exports.push(OwnedExport {
            id,
            module_id: token.host_id(),
            service,
            symbol: retained_name,
            native_address: address,
        });
        Ok(result(
            Win32HostImportValue::ResolvedExport(Some(Win32HostResolvedExport::from_host_id(id))),
            None,
        ))
    }

    fn invoke_service(
        &mut self,
        token: Win32HostResolvedExport,
        service: Win32HostServiceIdentity,
        operation: Win32HostServiceOperation,
    ) -> Result<Win32HostImportResult, RuntimeError> {
        let Some(entry) = self.exports.iter().find(|entry| {
            entry.id == token.host_id() && entry.service == service && entry.native_address != 0
        }) else {
            return Err(invariant(
                "typed service invocation does not match resolved export",
            ));
        };
        if entry.symbol.as_slice() != service.export()
            || !operation_matches_export(&entry.symbol, &operation)
        {
            return Err(invariant(
                "typed service operation differs from its resolved export",
            ));
        }
        match (service.family(), operation) {
            (Win32HostImportFamily::Loader, Win32HostServiceOperation::Loader(call)) => {
                loader::execute(self, call)
            }
            (Win32HostImportFamily::File, Win32HostServiceOperation::File(call)) => {
                files::execute(self, call)
            }
            (Win32HostImportFamily::Path, Win32HostServiceOperation::Path(call)) => {
                paths::execute(call, self.codec)
            }
            (Win32HostImportFamily::Volume, Win32HostServiceOperation::Volume(call)) => {
                queries::volume(call, self.codec)
            }
            (Win32HostImportFamily::Environment, Win32HostServiceOperation::Environment(call)) => {
                queries::environment(call, self.codec)
            }
            (Win32HostImportFamily::System, Win32HostServiceOperation::System(call)) => {
                queries::system(call, self.codec)
            }
            _ => Err(invariant(
                "native service family does not match its typed operation",
            )),
        }
    }

    pub(super) fn reserve_file_handle(&mut self) -> Result<u64, RuntimeError> {
        self.handles.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native file-handle ownership",
                error,
            )
        })?;
        let id = self
            .next_handle
            .ok_or_else(|| exhausted("native file handles"))?;
        self.next_handle = id.checked_add(1);
        Ok(id)
    }

    pub(super) fn publish_file_handle(&mut self, id: u64, raw: HANDLE) {
        self.handles.push(OwnedHandle { id, raw });
    }

    pub(super) fn remove_file_handle(
        &mut self,
        token: Win32HostHandle,
    ) -> Result<HANDLE, RuntimeError> {
        let index = self
            .handles
            .iter()
            .position(|entry| entry.id == token.host_id())
            .ok_or_else(|| invariant("stale PE32 native HANDLE token"))?;
        Ok(self.handles.swap_remove(index).raw)
    }

    pub(super) fn file_handle(&self, token: Win32HostHandle) -> Result<HANDLE, RuntimeError> {
        self.native_handle(token)
    }

    pub(super) fn reserve_search_handle(&mut self) -> Result<u64, RuntimeError> {
        self.searches.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native search-handle ownership",
                error,
            )
        })?;
        let id = self
            .next_search
            .ok_or_else(|| exhausted("native search handles"))?;
        self.next_search = id.checked_add(1);
        Ok(id)
    }

    pub(super) fn publish_search_handle(&mut self, id: u64, raw: HANDLE) {
        self.searches.push(OwnedSearchHandle { id, raw });
    }

    pub(super) fn remove_search_handle(
        &mut self,
        token: Win32HostSearchHandle,
    ) -> Result<HANDLE, RuntimeError> {
        let index = self
            .searches
            .iter()
            .position(|entry| entry.id == token.host_id())
            .ok_or_else(|| invariant("stale PE32 native search HANDLE token"))?;
        Ok(self.searches.swap_remove(index).raw)
    }
}

impl Drop for Win32ImportSystem {
    fn drop(&mut self) {
        // Explicit shutdown reports failures and retains failed entries for
        // retry. Drop is only a best-effort last native cleanup attempt.
        while let Some(handle) = self.handles.pop() {
            // SAFETY: entry is still owned by this adapter; process teardown is
            // the terminal fallback if the OS refuses CloseHandle.
            let _ = crate::windows::win32_safe::close_handle(handle.raw);
        }
        while let Some(search) = self.searches.pop() {
            // SAFETY: this table entry is a live result of FindFirstFile[A/W]
            // and remains owned here until FindClose succeeds or Drop ends.
            let _ = files::close_search_raw(search.raw);
        }
        while let Some(module) = self.modules.pop() {
            // SAFETY: each retained owner is one successful native load
            // reference; Drop is the last best-effort attempt after explicit
            // shutdown has reported any release failures.
            for _owner in module.owners {
                let _ = unsafe { FreeLibrary(module.raw) };
            }
        }
    }
}

pub(super) fn result(
    value: Win32HostImportValue,
    last_error: Option<u32>,
) -> Win32HostImportResult {
    Win32HostImportResult { value, last_error }
}

pub(super) fn api_error() -> u32 {
    crate::windows::win32_safe::last_error()
}

pub(super) fn set_api_error(value: u32) {
    crate::windows::win32_safe::set_last_error(value)
}

fn operation_matches_export(name: &[u8], operation: &Win32HostServiceOperation) -> bool {
    use runtime::{
        Win32HostEnvironmentCall as E, Win32HostFileCall as F, Win32HostLoaderCall as L,
        Win32HostPathCall as P, Win32HostServiceOperation as O, Win32HostSystemCall as S,
        Win32HostVolumeCall as V, Win32ImportString as I, Win32ImportTextEncoding as X,
        Win32PathQuery as Q, Win32PathTransform as T,
    };
    let encoded = |ansi: &[u8], wide: &[u8], encoding: X| {
        name == if encoding == X::Wide { wide } else { ansi }
    };
    let text_encoding = |text: &I| text.encoding();
    match operation {
        O::Loader(call) => match call {
            L::LoadSystemModule { basename, .. } => match text_encoding(basename) {
                X::Ansi => name == b"LoadLibraryA" || name == b"LoadLibraryExA",
                X::Wide => name == b"LoadLibraryW" || name == b"LoadLibraryExW",
            },
            L::FreeSystemModule { .. } => name == b"FreeLibrary",
            L::GetModuleHandle {
                name: module_name, ..
            } => encoded(
                b"GetModuleHandleA",
                b"GetModuleHandleW",
                text_encoding(module_name),
            ),
            L::GetModuleFileName { encoding, .. } => {
                encoded(b"GetModuleFileNameA", b"GetModuleFileNameW", *encoding)
            }
        },
        O::File(call) => match call {
            F::Create { path, .. } => encoded(b"CreateFileA", b"CreateFileW", text_encoding(path)),
            F::Read { .. } => name == b"ReadFile",
            F::Write { .. } => name == b"WriteFile",
            F::Close { .. } => name == b"CloseHandle",
            F::Delete { path } => encoded(b"DeleteFileA", b"DeleteFileW", text_encoding(path)),
            F::Move { from, to } => {
                text_encoding(from) == text_encoding(to)
                    && encoded(b"MoveFileA", b"MoveFileW", text_encoding(from))
            }
            F::Copy { from, to, .. } => {
                text_encoding(from) == text_encoding(to)
                    && encoded(b"CopyFileA", b"CopyFileW", text_encoding(from))
            }
            F::CreateDirectory { path } => encoded(
                b"CreateDirectoryA",
                b"CreateDirectoryW",
                text_encoding(path),
            ),
            F::RemoveDirectory { path } => encoded(
                b"RemoveDirectoryA",
                b"RemoveDirectoryW",
                text_encoding(path),
            ),
            F::GetAttributes { path } => encoded(
                b"GetFileAttributesA",
                b"GetFileAttributesW",
                text_encoding(path),
            ),
            F::SetAttributes { path, .. } => encoded(
                b"SetFileAttributesA",
                b"SetFileAttributesW",
                text_encoding(path),
            ),
            F::GetType { .. } => name == b"GetFileType",
            F::GetSize { .. } => name == b"GetFileSize",
            F::GetSizeEx { .. } => name == b"GetFileSizeEx",
            F::SetPointer { .. } => name == b"SetFilePointer",
            F::SetEndOfFile { .. } => name == b"SetEndOfFile",
            F::Flush { .. } => name == b"FlushFileBuffers",
            F::FindFirst { path } => {
                encoded(b"FindFirstFileA", b"FindFirstFileW", text_encoding(path))
            }
            F::FindFirstEx { path, .. } => encoded(
                b"FindFirstFileExA",
                b"FindFirstFileExW",
                text_encoding(path),
            ),
            F::FindNext { encoding, .. } => encoded(b"FindNextFileA", b"FindNextFileW", *encoding),
            F::FindClose { .. } => name == b"FindClose",
        },
        O::Path(call) => match call {
            P::Query { kind, encoding, .. } => {
                let (a, w) = match kind {
                    Q::CurrentDirectory => (
                        b"GetCurrentDirectoryA".as_slice(),
                        b"GetCurrentDirectoryW".as_slice(),
                    ),
                    Q::SystemDirectory => (
                        b"GetSystemDirectoryA".as_slice(),
                        b"GetSystemDirectoryW".as_slice(),
                    ),
                    Q::WindowsDirectory => (
                        b"GetWindowsDirectoryA".as_slice(),
                        b"GetWindowsDirectoryW".as_slice(),
                    ),
                    Q::TempPath => (b"GetTempPathA".as_slice(), b"GetTempPathW".as_slice()),
                };
                name == if *encoding == X::Wide { w } else { a }
            }
            P::SetCurrentDirectory { path } => encoded(
                b"SetCurrentDirectoryA",
                b"SetCurrentDirectoryW",
                text_encoding(path),
            ),
            P::Transform { kind, path, .. } => {
                let (a, w) = match kind {
                    T::Full => (
                        b"GetFullPathNameA".as_slice(),
                        b"GetFullPathNameW".as_slice(),
                    ),
                    T::Long => (
                        b"GetLongPathNameA".as_slice(),
                        b"GetLongPathNameW".as_slice(),
                    ),
                    T::Short => (
                        b"GetShortPathNameA".as_slice(),
                        b"GetShortPathNameW".as_slice(),
                    ),
                };
                encoded(a, w, text_encoding(path))
            }
        },
        O::Volume(call) => match call {
            V::LogicalDrives => name == b"GetLogicalDrives",
            V::DriveType { wide, .. } => {
                encoded(b"GetDriveTypeA", b"GetDriveTypeW", bool_encoding(*wide))
            }
            V::DiskFreeSpace { wide, .. } => encoded(
                b"GetDiskFreeSpaceA",
                b"GetDiskFreeSpaceW",
                bool_encoding(*wide),
            ),
            V::DiskFreeSpaceEx { wide, .. } => encoded(
                b"GetDiskFreeSpaceExA",
                b"GetDiskFreeSpaceExW",
                bool_encoding(*wide),
            ),
            V::VolumeInformation { wide, .. } => encoded(
                b"GetVolumeInformationA",
                b"GetVolumeInformationW",
                bool_encoding(*wide),
            ),
        },
        O::Environment(call) => match call {
            E::Get { name: variable, .. } => encoded(
                b"GetEnvironmentVariableA",
                b"GetEnvironmentVariableW",
                text_encoding(variable),
            ),
            E::Set {
                name: variable,
                value,
                ..
            } => {
                value
                    .as_ref()
                    .is_none_or(|value| text_encoding(value) == text_encoding(variable))
                    && encoded(
                        b"SetEnvironmentVariableA",
                        b"SetEnvironmentVariableW",
                        text_encoding(variable),
                    )
            }
            E::Expand { source, .. } => encoded(
                b"ExpandEnvironmentStringsA",
                b"ExpandEnvironmentStringsW",
                text_encoding(source),
            ),
        },
        O::System(call) => match call {
            S::Version => name == b"GetVersion",
            S::VersionInfo { encoding, .. } => {
                encoded(b"GetVersionExA", b"GetVersionExW", *encoding)
            }
            S::TickCount => name == b"GetTickCount",
            S::ProcessId => name == b"GetCurrentProcessId",
            S::ThreadId => name == b"GetCurrentThreadId",
            S::SystemTime { local: false } => name == b"GetSystemTime",
            S::SystemTime { local: true } => name == b"GetLocalTime",
            S::SystemTimeAsFileTime => name == b"GetSystemTimeAsFileTime",
            S::QueryPerformance { frequency: false } => name == b"QueryPerformanceCounter",
            S::QueryPerformance { frequency: true } => name == b"QueryPerformanceFrequency",
            S::SystemInfo { native: false } => name == b"GetSystemInfo",
            S::SystemInfo { native: true } => name == b"GetNativeSystemInfo",
        },
    }
}

fn bool_encoding(wide: bool) -> runtime::Win32ImportTextEncoding {
    if wide {
        runtime::Win32ImportTextEncoding::Wide
    } else {
        runtime::Win32ImportTextEncoding::Ansi
    }
}

fn kernel32_export(
    name: &[u8],
) -> Result<Option<unsafe extern "system" fn() -> isize>, RuntimeError> {
    const KERNEL32: [u16; 13] = [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108, 0];
    // SAFETY: the static module name is NUL-terminated. Kernel32 is process
    // infrastructure loaded before Rust host adapters execute.
    let module = unsafe { GetModuleHandleW(KERNEL32.as_ptr()) };
    if module.is_null() {
        return Err(native_failure("GetModuleHandleW(kernel32)", api_error()));
    }
    // SAFETY: the caller supplies a host-owned NUL-terminated exact export name.
    Ok(unsafe { GetProcAddress(module, name.as_ptr()) })
}

fn system_directory() -> Result<Vec<u16>, RuntimeError> {
    let mut capacity = 260_usize;
    loop {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(capacity).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Windows system-directory buffer",
                error,
            )
        })?;
        buffer.resize(capacity, 0u16);
        let size = u32::try_from(capacity).map_err(|_| exhausted("system-directory buffer"))?;
        // SAFETY: buffer is writable for the size passed to the Windows API.
        let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), size) } as usize;
        if written == 0 {
            return Err(native_failure("GetSystemDirectoryW", api_error()));
        }
        if written < capacity {
            buffer.truncate(written);
            return Ok(buffer);
        }
        if capacity >= 32_768 {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Windows system directory exceeds the documented path limit",
            ));
        }
        capacity = capacity.saturating_mul(2).min(32_768);
    }
}

fn path_in_directory(path: &[u16], directory: &[u16]) -> bool {
    path.get(..directory.len())
        .is_some_and(|prefix| wide_path_eq(prefix, directory))
        && path
            .get(directory.len())
            .is_some_and(|unit| matches!(*unit, 0x2f | 0x5c))
}

fn wide_path_eq(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| lower(*left) == lower(*right))
}

fn lower(value: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&value) {
        value + 0x20
    } else {
        value
    }
}

pub(super) fn native_failure(operation: &'static str, code: u32) -> RuntimeError {
    RuntimeError::new(
        Kind::HostFailure,
        format!("{operation} failed with Windows error {code}"),
    )
}

#[derive(Debug)]
struct NativeSearchCloseFailure {
    error: u32,
}

impl fmt::Display for NativeSearchCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Windows FindClose returned FALSE with error {}",
            self.error
        )
    }
}

impl Error for NativeSearchCloseFailure {}

pub(super) fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}

fn module_path(raw: windows_sys::Win32::Foundation::HMODULE) -> Result<Vec<u16>, RuntimeError> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    let mut capacity = 260_usize;
    loop {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(capacity).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve native module path", error)
        })?;
        buffer.resize(capacity, 0);
        let count = u32::try_from(capacity).map_err(|_| exhausted("module path buffer"))?;
        // SAFETY: the output buffer is writable for `count` UTF-16 code units.
        let written = unsafe { GetModuleFileNameW(raw, buffer.as_mut_ptr(), count) } as usize;
        if written == 0 {
            return Err(native_failure("GetModuleFileNameW", api_error()));
        }
        if written < capacity {
            buffer.truncate(written);
            return Ok(buffer);
        }
        if capacity >= 32_768 {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "system module path exceeds the Windows path buffer limit",
            ));
        }
        capacity = capacity.checked_mul(2).unwrap_or(32_768).min(32_768);
    }
}

fn copy_wide_path(path: &[u16]) -> Result<Vec<u16>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(path.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy resolved native module path",
            error,
        )
    })?;
    copy.extend_from_slice(path);
    Ok(copy)
}

#[derive(Debug)]
struct NativeRollbackFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl fmt::Display for NativeRollbackFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; rollback failed: {}", self.primary, self.cleanup)
    }
}

impl Error for NativeRollbackFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}

#[derive(Debug)]
struct NativeCleanupFailures(Vec<RuntimeError>);

#[derive(Debug)]
struct NativeModuleReleaseFailure {
    owner: Win32HostModuleOwner,
    previous_error: Option<u32>,
    error: u32,
}

impl fmt::Display for NativeModuleReleaseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native module owner task {} provider {} generation {} failed with Windows error {}",
            self.owner.task(),
            self.owner.provider(),
            self.owner.generation(),
            self.error
        )?;
        if let Some(previous) = self.previous_error {
            write!(
                f,
                "; prior release attempt failed with Windows error {previous}"
            )
        } else {
            write!(f, "; no earlier release failure was recorded")
        }
    }
}

impl Error for NativeModuleReleaseFailure {}

impl fmt::Display for NativeCleanupFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} native release operations failed", self.0.len())
    }
}

impl Error for NativeCleanupFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.first().map(|error| error as &(dyn Error + 'static))
    }
}
