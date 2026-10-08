//! Shared-identity adapter for KERNEL32 module and export queries.

use guest_core::memory::Memory;
use x86_cpu::Cpu;

use crate::pe32::{Pe32ExportKey, Pe32ModuleStage, Pe32SymbolResult};
use crate::win32_import_guest::{
    GuestModuleLoadProbe, GuestProcedureLookup, Win32GuestModuleResolver,
};
use crate::win32_import_state::Win32ImportState;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ModuleImage,
    Win32HostImportCall, Win32HostImportValue, Win32ImportString, Win32ImportSymbol,
};

use super::{
    Pe32ThunkDispatcher, published_basename_key, query_basename_key,
    query_default_extension_needed, query_full_path_key,
};

impl Win32GuestModuleResolver for Pe32ThunkDispatcher {
    fn guest_module_handle(
        &mut self,
        name: &Win32ImportString,
    ) -> Result<Option<u32>, RuntimeError> {
        let visible_group = self.active_load_group_for_current_call();
        if let Some(path) = full_path_bytes(name)? {
            for (index, module) in self.modules.iter().enumerate() {
                if windows_path_eq(&module.path, &path) {
                    if let Some(handle) = self.visible_guest_handle(index, visible_group)? {
                        return Ok(Some(handle));
                    }
                }
            }
            return Ok(None);
        }
        let Some(key) = module_key(name)? else {
            return Ok(None);
        };
        for (index, module) in self.modules.iter().enumerate() {
            if module.basename.eq_ignore_ascii_case(&key) {
                if let Some(handle) = self.visible_guest_handle(index, visible_group)? {
                    return Ok(Some(handle));
                }
            }
        }
        Ok(None)
    }

    fn retain_guest_module(
        &mut self,
        name: &Win32ImportString,
    ) -> Result<Option<u32>, RuntimeError> {
        let Some(handle) = self.guest_module_handle(name)? else {
            return Ok(None);
        };
        let index = self
            .handle_index(handle)
            .or_else(|| {
                self.active_load_group_for_current_call()
                    .and_then(|group| self.group_handle_index(group, handle))
            })
            .ok_or_else(|| invariant("PE32 guest module handle disappeared during LoadLibrary"))?;
        Ok((self.retain_loaded(index)? != 0).then_some(handle))
    }

    fn probe_guest_module(
        &mut self,
        name: &Win32ImportString,
        host: &mut impl RuntimeHost,
    ) -> Result<GuestModuleLoadProbe, RuntimeError> {
        let search_name = ansi_search_name(name)?;
        let file = match host.win16_read_module(&search_name, &self.application_path)? {
            Ok(file) => file,
            Err(error @ (2 | 3)) => return Ok(GuestModuleLoadProbe::NotFound(u32::from(error))),
            Err(error) => {
                return Ok(GuestModuleLoadProbe::Failure(
                    super::loading::map_search_error(error),
                ));
            }
        };
        let response = host.win32_import(Win32HostImportCall::IsSystemDirectoryPath {
            path: Win32ImportString::Ansi(copy_bytes(&file.path)?),
        })?;
        if response.last_error.is_some() {
            return Err(invariant(
                "system-path classifier returned an unexpected last error",
            ));
        }
        let Win32HostImportValue::Bool(system_path) = response.value else {
            return Err(invariant("system-path classifier returned a non-BOOL DTO"));
        };
        if system_path {
            return Ok(GuestModuleLoadProbe::SystemDirectory { resolved_path: file.path });
        }
        match formats::parse_pe32(&file.image) {
            Ok(image) if image.is_dll() => {
                let basename = published_basename_key(&file.path)?;
                Ok(GuestModuleLoadProbe::GuestPe32 { file, basename })
            }
            Ok(_) | Err(formats::Pe32Error::InvalidImage(_)) => {
                Ok(GuestModuleLoadProbe::Failure(193))
            }
            Err(formats::Pe32Error::OutOfMemory(_) | formats::Pe32Error::ImageTooLarge { .. }) => {
                Ok(GuestModuleLoadProbe::Failure(8))
            }
            Err(error) => {
                let cause = RuntimeError::with_source(
                    Kind::CompatibilityGap,
                    "selected non-System32 DLL needs an unsupported PE32 loader feature",
                    error,
                );
                host.report_diagnostic(
                    &Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "LoadLibrary rejected an unsupported guest PE32 module",
                    )
                    .with_cause(cause),
                );
                Ok(GuestModuleLoadProbe::Failure(193))
            }
        }
    }

    fn load_guest_module(
        &mut self,
        state: &mut Win32ImportState,
        file: Win16ModuleImage,
        basename: Vec<u8>,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if let Some(index) = self.find_resolved_path(&file.path) {
            return self.retain_loaded(index);
        }
        let remaining = self.remaining_active_steps();
        match self.load_parsed_file(cpu, memory, state, host, file, basename, remaining) {
            Ok(handle) => Ok(handle),
            Err(error) => super::loading::guest_load_failure(state, host, error),
        }
    }

    fn active_service_nonce(&self) -> Option<crate::pe32_call::Pe32CallNonce> {
        self.active
            .last()
            .filter(|active| active.paused_at_service)
            .map(|active| active.nonce)
    }

    fn release_guest_module(
        &mut self,
        imports: &mut Win32ImportState,
        handle: u32,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<bool>, RuntimeError> {
        let Some(index) = self.handle_index(handle).or_else(|| {
            self.active_load_group_for_current_call()
                .and_then(|group| self.group_handle_index(group, handle))
        }) else {
            return Ok(None);
        };
        if self.modules[index].image_released {
            return Ok(Some(false));
        }
        let identity = self.modules[index].transaction.module();
        if self.registry.identity(identity.token()) != Some(identity) {
            return Err(invariant(
                "PE32 module handle lost its exact registry generation",
            ));
        }
        if self.registry.stage(identity.token()) != Some(Pe32ModuleStage::Published) {
            let group = self.active_load_group_for_current_call();
            let Some(member) = self.modules[index].group_member.as_mut() else {
                return Ok(Some(false));
            };
            if group != Some(member.group) {
                return Ok(Some(false));
            }
            if member.guest_references == 0 {
                return Ok(Some(false));
            }
            member.guest_references -= 1;
            return Ok(Some(true));
        }
        let released = self.registry.release(identity.token())?;
        if released {
            let dispatch_start = self.budget_position();
            let remaining = self.remaining_active_steps();
            self.drain_retiring(cpu, memory, imports, host, remaining, dispatch_start)?;
        }
        Ok(Some(released))
    }

    fn resolve_guest_procedure(
        &mut self,
        handle: u32,
        symbol: &Win32ImportSymbol,
    ) -> Result<GuestProcedureLookup, RuntimeError> {
        let visible_group = self.active_load_group_for_current_call();
        let Some(index) = self
            .handle_index(handle)
            .or_else(|| visible_group.and_then(|group| self.group_handle_index(group, handle)))
        else {
            return Ok(GuestProcedureLookup::NotGuestModule);
        };
        let identity = self.modules[index].transaction.module();
        if self.modules[index].image_released {
            return Ok(GuestProcedureLookup::NotGuestModule);
        }
        if self.registry.identity(identity.token()) != Some(identity) {
            return Err(invariant(
                "PE32 procedure handle lost its exact module generation",
            ));
        }
        let group = visible_group.filter(|group| {
            self.modules[index]
                .group_member
                .as_ref()
                .is_some_and(|member| member.group == *group)
        });
        if self.registry.stage(identity.token()) != Some(Pe32ModuleStage::Published)
            && group.is_none()
        {
            return Ok(GuestProcedureLookup::Missing);
        }
        let key = match symbol {
            Win32ImportSymbol::Name(name) => Pe32ExportKey::Name(copy_bytes(name)?),
            Win32ImportSymbol::Ordinal(value) => Pe32ExportKey::Ordinal(u32::from(*value)),
        };
        let symbol = match group {
            Some(group) => self
                .registry
                .lookup_export_in_group(identity.token(), &key, group)?,
            None => self.registry.lookup_export(identity.token(), &key)?,
        };
        match symbol {
            None => Ok(GuestProcedureLookup::Missing),
            Some(Pe32SymbolResult::Procedure(procedure)) => {
                let address = match group {
                    Some(group) => self
                        .registry
                        .procedure_guest_address_in_group(procedure, group)?,
                    None => self.registry.procedure_guest_address(procedure)?,
                }
                .ok_or_else(|| invariant("visible PE32 procedure has no guest-code target"))?;
                Ok(GuestProcedureLookup::Found(address.0))
            }
            Some(Pe32SymbolResult::Data { module, address }) if module == identity => {
                Ok(GuestProcedureLookup::Found(address.0))
            }
            Some(Pe32SymbolResult::Data { .. }) => {
                Err(invariant("PE32 data export changed module identity"))
            }
            Some(Pe32SymbolResult::Forwarder { .. }) => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "GetProcAddress cannot resolve a forwarded guest PE export yet",
            )),
        }
    }

    fn guest_module_path(
        &mut self,
        handle: u32,
        wide: bool,
    ) -> Result<Option<Win32ImportString>, RuntimeError> {
        let Some(index) = self.handle_index(handle).or_else(|| {
            self.active_load_group_for_current_call()
                .and_then(|group| self.group_handle_index(group, handle))
        }) else {
            return Ok(None);
        };
        if self.visible_guest_handle(index, self.active_load_group_for_current_call())?
            != Some(handle)
        {
            return Ok(None);
        }
        let path = &self.modules[index].path;
        if wide {
            if path.iter().any(|byte| !byte.is_ascii()) {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "GetModuleFileNameW needs host ACP conversion for this guest path",
                ));
            }
            let mut words = Vec::new();
            words.try_reserve_exact(path.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "copy PE32 module path as UTF-16",
                    error,
                )
            })?;
            words.extend(path.iter().map(|byte| u16::from(*byte)));
            Ok(Some(Win32ImportString::Wide(words)))
        } else {
            Ok(Some(Win32ImportString::Ansi(copy_bytes(path)?)))
        }
    }
}

impl Pe32ThunkDispatcher {
    fn visible_guest_handle(
        &self,
        index: usize,
        visible_group: Option<crate::pe32::Pe32LoadGroupId>,
    ) -> Result<Option<u32>, RuntimeError> {
        let Some(module) = self.modules.get(index) else {
            return Ok(None);
        };
        let identity = module.transaction.module();
        if self.registry.identity(identity.token()) != Some(identity) || module.image_released {
            return Ok(None);
        }
        if self.registry.stage(identity.token()) == Some(Pe32ModuleStage::Published) {
            return Ok(module.handle);
        }
        let Some(group) = visible_group else {
            return Ok(None);
        };
        let Some(member) = module.group_member.as_ref() else {
            return Ok(None);
        };
        if member.group != group || self.registry.load_group(identity)? != Some(group) {
            return Ok(None);
        }
        Ok(Some(member.load_handle))
    }
}

fn ansi_search_name(name: &Win32ImportString) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = match name {
        Win32ImportString::Ansi(bytes) => copy_bytes(bytes)?,
        Win32ImportString::Wide(words) => {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(words.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "convert PE32 module name for guest search",
                    error,
                )
            })?;
            for word in words {
                if *word > 0x7f {
                    return Err(RuntimeError::new(
                        Kind::CompatibilityGap,
                        "wide LoadLibrary path needs host-code-page conversion for guest search",
                    ));
                }
                bytes.push(*word as u8);
            }
            bytes
        }
    };
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "PE32 module search name is empty or contains NUL",
        ));
    }
    append_default_dll_extension(&mut bytes, "append guest DLL extension")?;
    Ok(bytes)
}

fn append_default_dll_extension(
    bytes: &mut Vec<u8>,
    context: &'static str,
) -> Result<(), RuntimeError> {
    let leaf_start = bytes
        .iter()
        .rposition(|byte| matches!(*byte, b'/' | b'\\' | b':'))
        .map_or(0, |index| index + 1);
    if query_default_extension_needed(&bytes[leaf_start..]) {
        bytes.try_reserve(4).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, context, error)
        })?;
        bytes.extend_from_slice(b".DLL");
    }
    Ok(())
}

fn module_key(name: &Win32ImportString) -> Result<Option<Vec<u8>>, RuntimeError> {
    let bytes = match name {
        Win32ImportString::Ansi(bytes) => bytes,
        Win32ImportString::Wide(words) => {
            if words.iter().any(|word| *word > 0x7f) {
                return Ok(None);
            }
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(words.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "copy PE32 wide module basename",
                    error,
                )
            })?;
            bytes.extend(words.iter().map(|word| *word as u8));
            return module_key(&Win32ImportString::Ansi(bytes));
        }
    };
    if bytes
        .iter()
        .any(|byte| matches!(*byte, b'/' | b'\\' | b':'))
    {
        return Ok(None);
    }
    match query_basename_key(bytes) {
        Ok(key) => Ok(Some(key)),
        Err(error) if error.kind() == Kind::InvalidInput => Ok(None),
        Err(error) => Err(error),
    }
}

fn full_path_bytes(name: &Win32ImportString) -> Result<Option<Vec<u8>>, RuntimeError> {
    let bytes = match name {
        Win32ImportString::Ansi(bytes) => bytes,
        Win32ImportString::Wide(words) => {
            if words.iter().any(|word| *word > 0x7f) {
                return Ok(None);
            }
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(words.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "copy PE32 module path for identity lookup",
                    error,
                )
            })?;
            bytes.extend(words.iter().map(|word| *word as u8));
            return full_path_bytes(&Win32ImportString::Ansi(bytes));
        }
    };
    if !bytes
        .iter()
        .any(|byte| matches!(*byte, b'/' | b'\\' | b':'))
    {
        return Ok(None);
    }
    match query_full_path_key(bytes) {
        Ok(path) => Ok(Some(path)),
        Err(error) if error.kind() == Kind::InvalidInput => Ok(None),
        Err(error) => Err(error),
    }
}

fn windows_path_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            let normalize = |byte: u8| {
                if byte == b'/' {
                    b'\\'
                } else {
                    byte.to_ascii_lowercase()
                }
            };
            normalize(*left) == normalize(*right)
        })
}

fn copy_bytes(source: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(source.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy PE32 loader name", error)
    })?;
    bytes.extend_from_slice(source);
    Ok(bytes)
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
