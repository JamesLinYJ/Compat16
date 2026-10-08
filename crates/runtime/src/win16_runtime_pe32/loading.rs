//! PE32 library search and iterative load-group dispatch.

use std::error::Error;

use guest_core::memory::Memory;
use x86_cpu::Cpu;

use crate::win32_import_state::Win32ImportState;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ModuleImage,
    pe32::Pe32ImportTarget,
};

use super::{
    Pe32ThunkDispatcher, published_basename_key, query_basename_key,
    query_default_extension_needed,
};

#[path = "loading/group/mod.rs"]
mod group;

#[derive(Clone, Debug)]
pub(super) struct HostImportBinding {
    pub(super) module: Vec<u8>,
    pub(super) symbol: formats::Pe32ImportTarget,
    pub(super) target: Pe32ImportTarget,
}

impl Pe32ThunkDispatcher {
    pub(super) fn retry_load_group_provider_releases(
        &mut self,
        imports: &mut Win32ImportState,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.active_load_group.is_none() {
            return Ok(());
        }
        group::release_group_temporary_providers(self, imports, host)
    }

    pub(super) fn load_library(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut Win32ImportState,
        host: &mut impl RuntimeHost,
        name: &[u8],
        reserved_file: u32,
        flags: u32,
        application_path: &[u8],
        step_limit: u64,
    ) -> Result<u32, RuntimeError> {
        let path_bearing = name.iter().any(|byte| matches!(*byte, b'/' | b'\\' | b':'));
        let requested = match query_basename_key(name) {
            Ok(name) => name,
            Err(error) => return guest_load_failure(imports, host, error),
        };
        if reserved_file != 0 || flags != 0 {
            return guest_load_failure(
                imports,
                host,
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "LoadLibraryEx32W nonzero reserved file or unverified flags are unsupported",
                ),
            );
        }
        let explicit_path = if path_bearing {
            match explicit_path_with_default_extension(name) {
                Ok(path) => path,
                Err(error) => return guest_load_failure(imports, host, error),
            }
        } else {
            None
        };
        let search_name = explicit_path.as_deref().unwrap_or(name);
        if !path_bearing {
            if let Some(index) = self.find_basename(&requested) {
                return self.retain_loaded(index);
            }
        }

        let file = match host.win16_read_module(search_name, application_path) {
            Err(error) => return guest_load_failure(imports, host, error),
            Ok(Ok(file)) => file,
            Ok(Err(error @ (2 | 3))) => {
                if path_bearing {
                    return guest_load_failure(
                        imports,
                        host,
                        RuntimeError::with_source(
                            Kind::CompatibilityGap,
                            "LoadLibraryEx32W explicit path search failed",
                            ModuleSearchFailure(error),
                        ),
                    );
                }
                return match group::load_system_provider(imports, host, name) {
                    Ok((handle, error)) => Ok(finish_system_load(imports, handle, error)),
                    Err(error) => guest_load_failure(imports, host, error),
                };
            }
            Ok(Err(error)) => {
                return guest_load_failure(
                    imports,
                    host,
                    RuntimeError::with_source(
                        Kind::CompatibilityGap,
                        "LoadLibraryEx32W guest search failed",
                        ModuleSearchFailure(error),
                    ),
                );
            }
        };
        match group::is_system_path_for_load(host, &file.path) {
            Ok(true) => {
                let provider = group::load_system_provider_path(imports, host, &file.path);
                return match provider {
                    Ok((handle, error)) => Ok(finish_system_load(imports, handle, error)),
                    Err(error) => guest_load_failure(imports, host, error),
                };
            }
            Ok(false) => {}
            Err(error) => return guest_load_failure(imports, host, error),
        }
        let actual_name = match published_basename_key(&file.path) {
            Ok(name) => name,
            Err(error) => return guest_load_failure(imports, host, error),
        };
        let existing = if path_bearing {
            self.find_resolved_path(&file.path)
        } else {
            self.find_basename(&actual_name)
        };
        if let Some(index) = existing {
            return self.retain_loaded(index);
        }
        match self.load_parsed_file(cpu, memory, imports, host, file, actual_name, step_limit) {
            Ok(handle) => Ok(handle),
            Err(error) => guest_load_failure(imports, host, error),
        }
    }

    pub(super) fn load_parsed_file(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut Win32ImportState,
        host: &mut impl RuntimeHost,
        file: Win16ModuleImage,
        basename: Vec<u8>,
        step_limit: u64,
    ) -> Result<u32, RuntimeError> {
        group::load_parsed_file(self, cpu, memory, imports, host, file, basename, step_limit)
    }

    pub(super) fn find_basename(&self, basename: &[u8]) -> Option<usize> {
        self.modules
            .iter()
            .position(|module| module.basename.eq_ignore_ascii_case(basename))
    }

    pub(super) fn find_resolved_path(&self, path: &[u8]) -> Option<usize> {
        self.modules.iter().position(|module| {
            !module.image_released && resolved_path_eq(&module.path, path)
        })
    }

    pub(super) fn retain_loaded(&mut self, index: usize) -> Result<u32, RuntimeError> {
        let module = self
            .modules
            .get(index)
            .ok_or_else(|| invariant("PE32 module index changed before retaining its owner"))?;
        if module.image_released {
            return Ok(0);
        }
        let identity = module.transaction.module();
        if self.registry.identity(identity.token()) != Some(identity) {
            return Err(invariant(
                "PE32 module owner lost its exact registry generation",
            ));
        }
        if self.registry.stage(identity.token()) != Some(crate::pe32::Pe32ModuleStage::Published) {
            let active_group = self.active_load_group_for_current_call();
            let Some(member) = self
                .modules
                .get_mut(index)
                .and_then(|module| module.group_member.as_mut())
            else {
                return Ok(0);
            };
            if active_group != Some(member.group) {
                return Ok(0);
            }
            member.guest_references = member.guest_references.checked_add(1).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "PE32 staged LoadLibrary reference count is exhausted",
                )
            })?;
            return Ok(member.load_handle);
        }
        let handle = self.modules[index]
            .handle
            .ok_or_else(|| invariant("published PE32 module has no guest handle"))?;
        if !self.registry.retain(identity.token())? {
            return Ok(0);
        }
        Ok(handle)
    }
}

fn resolved_path_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| {
        let normalize = |byte: u8| {
            if byte == b'/' { b'\\' } else { byte.to_ascii_lowercase() }
        };
        normalize(*left) == normalize(*right)
    })
}

// Win32 LoadLibrary adds .DLL to a path leaf without an extension, while a
// trailing period suppresses that addition. The host's path-bearing file
// lookup opens the supplied spelling literally, so preserve the full guest
// path and apply that loader rule before handing it to the copied-file reader.
fn explicit_path_with_default_extension(name: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
    let leaf_start = name
        .iter()
        .rposition(|byte| matches!(*byte, b'/' | b'\\' | b':'))
        .map_or(0, |index| index + 1);
    if !query_default_extension_needed(&name[leaf_start..]) {
        return Ok(None);
    }
    let length = name.len().checked_add(4).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "explicit PE32 module path length overflow")
    })?;
    let mut resolved = Vec::new();
    resolved.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "append default DLL extension to explicit PE32 path",
            error,
        )
    })?;
    resolved.extend_from_slice(name);
    resolved.extend_from_slice(b".DLL");
    Ok(Some(resolved))
}

pub(super) fn guest_load_failure(
    imports: &mut Win32ImportState,
    host: &mut impl RuntimeHost,
    error: RuntimeError,
) -> Result<u32, RuntimeError> {
    match error.kind() {
        Kind::InvalidInput | Kind::CompatibilityGap | Kind::ResourceExhausted => {
            let kind = error.kind();
            let last_error = win32_load_error(&error);
            host.report_diagnostic(
                &Diagnostic::warning(kind, "PE32 LoadLibraryEx32W returned NULL").with_cause(error),
            );
            imports.set_last_error(last_error);
            Ok(0)
        }
        Kind::HostFailure | Kind::ExecutionLimit | Kind::InternalInvariant | Kind::GuestFault => {
            Err(error)
        }
    }
}

fn win32_load_error(error: &RuntimeError) -> u32 {
    let mut cause = error.source();
    while let Some(current) = cause {
        if let Some(code) = current.downcast_ref::<Win32LoadErrorCode>() {
            return code.0;
        }
        if let Some(failure) = current.downcast_ref::<ModuleSearchFailure>() {
            return map_search_error(failure.0);
        }
        cause = current.source();
    }
    match error.kind() {
        Kind::InvalidInput => 193,
        Kind::ResourceExhausted => 8,
        Kind::CompatibilityGap => 126,
        _ => 31,
    }
}

fn finish_system_load(
    imports: &mut Win32ImportState,
    handle: Option<u32>,
    last_error: Option<u32>,
) -> u32 {
    if let Some(handle) = handle {
        return handle;
    }
    imports.set_last_error(last_error.unwrap_or(126));
    0
}

#[derive(Debug)]
pub(super) struct Win32LoadErrorCode(pub(super) u32);

impl std::fmt::Display for Win32LoadErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Win32 LoadLibrary failure code {}", self.0)
    }
}

impl Error for Win32LoadErrorCode {}

#[derive(Debug)]
pub(super) struct ModuleSearchFailure(pub(super) u16);

impl std::fmt::Display for ModuleSearchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "guest module search returned DOS error {}",
            self.0
        )
    }
}

impl Error for ModuleSearchFailure {}

pub(super) fn map_search_error(error: u16) -> u32 {
    match error {
        11 => 193,
        8 => 8,
        value => u32::from(value),
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
