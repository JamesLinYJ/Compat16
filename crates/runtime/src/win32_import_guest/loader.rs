//! PE32 loader APIs backed by guest identities and checked system-provider gates.

use guest_core::memory::Memory;

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win32HostImportCall as HC,
    Win32HostImportValue as HV, Win32HostLoaderCall as LC, Win32HostServiceOperation as SO,
    Win32ImportString as S, Win32ImportSymbol as Symbol, Win32ImportTextEncoding as E};
use crate::win32_import_catalog::{self, Win32ImportService as A};
use crate::win32_import_state::{Win32ImportState, Win32ServiceGate, Win32SystemModuleIdentity};

use super::{GuestProcedureLookup, Win32GuestModuleResolver, Win32GuestReturn,
    GuestModuleLoadProbe, expect_bool, guest_fault, invariant, invoke, invoke_result};
use super::memory::{self, GuestOutput};
use super::provider_names::{ResolvedSystemProviderPath, SystemProviderQueryName};

pub(super) fn dispatch(state: &mut Win32ImportState, gate: Win32ServiceGate,
    cpu: &mut x86_cpu::Cpu, memory: &mut Memory, host: &mut impl RuntimeHost,
    modules: &mut impl Win32GuestModuleResolver, a: &[u32])
    -> Result<Win32GuestReturn, RuntimeError> {
    match gate.service {
        A::LoadLibraryA | A::LoadLibraryW => load(state, gate, cpu, memory, host, modules, a[0],
            gate.service == A::LoadLibraryW),
        A::LoadLibraryExA | A::LoadLibraryExW => {
            if a[1] != 0 || a[2] != 0 {
                return Err(gap("LoadLibraryEx file handles and flags require loader-search semantics"));
            }
            load(state, gate, cpu, memory, host, modules, a[0], gate.service == A::LoadLibraryExW)
        }
        A::FreeLibrary => free(state, gate, cpu, memory, host, modules, a[0]),
        A::GetModuleHandleA | A::GetModuleHandleW => get_module(state, gate, memory,
            host, modules, a[0], gate.service == A::GetModuleHandleW),
        A::GetProcAddress => get_proc(state, gate, memory, host, modules, a[0], a[1]),
        A::GetModuleFileNameA | A::GetModuleFileNameW => module_file_name(
            state, gate, memory, host, modules, a[0], a[1], a[2],
            gate.service == A::GetModuleFileNameW),
        _ => Err(invariant("loader dispatcher received a non-loader service")),
    }
}

/// Adds one guest-visible system-provider reference, using Windows' actual
/// system-directory loader and retaining only an opaque native module token.
pub(crate) fn acquire_system_provider(state: &mut Win32ImportState,
    requested: &S, host: &mut impl RuntimeHost)
    -> Result<(Option<Win32SystemModuleIdentity>, Option<u32>), RuntimeError> {
    let requested = SystemProviderQueryName::from_name(requested)?;
    let existing = match &requested.identity {
        S::Ansi(value) => state.find_module(value),
        S::Wide(value) => state.find_module_by_wide(value),
    };
    if let Some(identity) = existing {
        state.retain_module(identity)?;
        return Ok((Some(identity), None));
    }
    // Query first so a task that already owns this exact loaded HMODULE can
    // reuse its provider generation without acquiring a second native ref.
    // A trailing period must reach LoadLibraryEx as query syntax. Loading it
    // directly also avoids turning its resolved extensionless path back into
    // a default-extension query during path retention.
    let loaded_path = if requested.trailing_period_query {
        None
    } else {
        let loaded = host.win32_import(HC::FindLoadedSystemModule {
            name: copy_name(&requested.native_query)?,
        })?;
        match loaded.value {
            HV::Module { module: Some(native), path } => {
                if path.is_empty() {
                    return Err(invariant("loaded System32 provider has no resolved path"));
                }
                if let Some(existing) = state.find_module_by_host(native)? {
                    state.retain_module(existing)?;
                    return Ok((Some(existing), loaded.last_error));
                }
                Some(path)
            }
            HV::Module { module: None, path } if !path.is_empty() => Some(path),
            HV::Module { module: None, .. } => None,
            _ => return Err(invariant("loaded-module lookup returned an incompatible DTO")),
        }
    };
    let reservation = state.reserve_system_module(&requested.identity)?;
    let owner = state.reservation_owner(&reservation);
    let response = if let Some(path) = loaded_path {
        host.win32_import(HC::RetainSystemModulePath {
            path: S::Wide(path), owner,
        })?
    } else {
        host.win32_import(HC::LoadSystemModule {
            basename: copy_name(&requested.native_query)?, owner,
        })?
    };
    let error = response.last_error;
    let (native, path) = match response.value {
        HV::Module { module: Some(native), path } => (native, path),
        HV::Module { module: None, .. } => return Ok((None, error)),
        _ => return Err(invariant("system loader returned an incompatible module DTO")),
    };
    let identity = register_acquired_provider(state, reservation, native, path,
        owner, ProviderReference::GuestLoad, host)?;
    Ok((Some(identity), error))
}

/// Acquires a provider from a path already resolved and classified as System32.
/// Path-bearing KERNEL requests must keep this identity route instead of falling
/// back to a basename lookup.
pub(crate) fn acquire_system_provider_path(
    state: &mut Win32ImportState,
    path: &[u8],
    host: &mut impl RuntimeHost,
) -> Result<(Option<Win32SystemModuleIdentity>, Option<u32>), RuntimeError> {
    let resolved = ResolvedSystemProviderPath::from_path(path)?;
    let requested = S::Ansi(resolved.identity_basename);
    let reservation = state.reserve_system_module(&requested)?;
    let owner = state.reservation_owner(&reservation);
    let response = host.win32_import(HC::RetainSystemModulePath {
        path: S::Ansi(resolved.native_path),
        owner,
    })?;
    let error = response.last_error;
    let (native, resolved_path) = match response.value {
        HV::Module { module: Some(native), path } => (native, path),
        HV::Module { module: None, .. } => return Ok((None, error)),
        _ => return Err(invariant("resolved System32 provider returned an incompatible DTO")),
    };
    let identity = register_acquired_provider(state, reservation, native, resolved_path,
        owner, ProviderReference::GuestLoad, host)?;
    Ok((Some(identity), error))
}

pub(crate) fn release_system_provider(state: &mut Win32ImportState,
    identity: Win32SystemModuleIdentity, host: &mut impl RuntimeHost)
    -> Result<crate::Win32HostImportResult, RuntimeError> {
    let owner = state.host_owner(identity)?;
    let Some(module) = state.begin_release_module(identity)? else {
        return Ok(crate::Win32HostImportResult {
            value: HV::Bool(true), last_error: None,
        });
    };
    let result = host.win32_import(HC::FreeSystemModule { module, owner });
    match result {
        Ok(response) => {
            let last_error = response.last_error;
            match response.value {
                HV::Bool(released) => {
                    if let Err(cleanup) = state.finish_release_module(identity, released) {
                        if released { return Err(cleanup); }
                        let primary = owner.release_failure(native_cleanup_failure(
                            "FreeLibrary for staged PE32 provider",
                            HV::Bool(false),
                            last_error,
                        ));
                        return Err(combine(primary, cleanup));
                    }
                    Ok(crate::Win32HostImportResult { value: HV::Bool(released), last_error })
                }
                value => {
                    let primary = owner.release_failure(native_cleanup_failure(
                        "FreeLibrary for staged PE32 provider", value, last_error));
                    Err(finish_release_preserving(state, identity, false, primary))
                }
            }
        }
        Err(primary) => Err(finish_release_preserving(state, identity, false,
            owner.release_failure(primary))),
    }
}

fn load(state: &mut Win32ImportState, gate: Win32ServiceGate, cpu: &mut x86_cpu::Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost, modules: &mut impl Win32GuestModuleResolver,
    pointer: u32, wide: bool)
    -> Result<Win32GuestReturn, RuntimeError> {
    let name = memory::read_string(memory, pointer, wide)?;
    if name.is_empty() { state.set_last_error(126); return Ok(ret(0)); }
    if let Some(handle) = modules.retain_guest_module(&name)? { return Ok(ret(handle)); }
    let explicit_path = has_directory_component(&name);
    let basename = if explicit_path { leaf_name(&name)? } else { normalize_basename(&name)? };
    if basename_empty(&basename) { state.set_last_error(126); return Ok(ret(0)); }
    let existing = match &basename {
        S::Ansi(value) => state.find_module(value),
        S::Wide(value) => state.find_module_by_wide(value),
    };
    if !explicit_path && existing.is_some() {
        let identity = existing.ok_or_else(|| invariant("loaded module identity disappeared"))?;
        state.retain_module(identity)?;
        return Ok(ret(state.guest_module_handle(identity)?));
    }
    match modules.probe_guest_module(&name, host)? {
        GuestModuleLoadProbe::GuestPe32 { file, basename } => {
            let handle = modules.load_guest_module(state, file, basename, cpu, memory, host)?;
            Ok(ret(handle))
        }
        GuestModuleLoadProbe::Failure(error) => {
            state.set_last_error(error);
            Ok(ret(0))
        }
        GuestModuleLoadProbe::NotFound(error) if explicit_path => {
            state.set_last_error(error);
            Ok(ret(0))
        }
        GuestModuleLoadProbe::SystemDirectory { resolved_path } => {
            let resolved = ResolvedSystemProviderPath::from_path(&resolved_path)?;
            let lookup = host.win32_import(HC::FindLoadedSystemModule {
                name: S::Ansi(copy_bytes(&resolved.native_path)?),
            })?;
            match lookup.value {
                HV::Module { module: Some(native), path } => {
                    if path.is_empty() {
                        return Err(invariant("loaded System32 provider has no resolved path"));
                    }
                    if let Some(existing) = state.find_module_by_host(native)? {
                        state.retain_module(existing)?;
                        return Ok(ret(state.guest_module_handle(existing)?));
                    }
                }
                HV::Module { module: None, .. } => {}
                _ => return Err(invariant("loaded-module lookup returned an incompatible DTO")),
            }
            let requested = S::Ansi(copy_bytes(&resolved.identity_basename)?);
            let reservation = state.reserve_system_module(&requested)?;
            let owner = state.reservation_owner(&reservation);
            let response = host.win32_import(HC::RetainSystemModulePath {
                path: S::Ansi(resolved.native_path), owner,
            })?;
            if let Some(error) = response.last_error { state.set_last_error(error); }
            match response.value {
                HV::Module { module: Some(native), path } => {
                    let identity = register_acquired_provider(state, reservation, native, path,
                        owner, ProviderReference::GuestLoad, host)?;
                    Ok(ret(state.guest_module_handle(identity)?))
                }
                HV::Module { module: None, .. } if response.last_error.is_some() => Ok(ret(0)),
                HV::Module { module: None, .. } => Err(gap(
                    "resolved System32 path failed native provider revalidation")),
                _ => Err(invariant("resolved-path load returned an incompatible module DTO")),
            }
        }
        GuestModuleLoadProbe::NotFound(_) => {
            let reservation = state.reserve_system_module(&basename)?;
            let owner = state.reservation_owner(&reservation);
            let response = invoke_result(state, gate, host, SO::Loader(LC::LoadSystemModule {
                basename: reservation.copy_requested_basename()?, owner,
            }))?;
            match response.value {
                HV::Module { module: Some(native), path } => {
                    let identity = register_acquired_provider(state, reservation, native, path,
                        owner, ProviderReference::GuestLoad, host)?;
                    Ok(ret(state.guest_module_handle(identity)?))
                }
                HV::Module { module: None, .. } if response.last_error.is_some() => Ok(ret(0)),
                HV::Module { module: None, .. } => Err(gap(
                    "Windows resolved a non-System32 module that this typed provider cannot expose")),
                _ => Err(invariant("LoadLibrary returned an incompatible module DTO")),
            }
        }
    }
}

fn has_directory_component(name: &S) -> bool {
    match name {
        S::Ansi(bytes) => bytes.iter().any(|byte| matches!(*byte, b'/' | b'\\' | b':')),
        S::Wide(words) => words.iter().any(|word| matches!(*word, 0x2f | 0x5c | 0x3a)),
    }
}

fn basename_empty(name: &S) -> bool {
    match name { S::Ansi(bytes) => bytes.is_empty(), S::Wide(words) => words.is_empty() }
}

fn free(state: &mut Win32ImportState, gate: Win32ServiceGate,
    cpu: &mut x86_cpu::Cpu, memory: &mut Memory, host: &mut impl RuntimeHost,
    modules: &mut impl Win32GuestModuleResolver,
    handle: u32) -> Result<Win32GuestReturn, RuntimeError> {
    let Some(identity) = state.system_module_for_handle(handle) else {
        return match modules.release_guest_module(state, handle, cpu, memory, host)? {
            Some(released) => {
                if !released { state.set_last_error(6); }
                Ok(ret(u32::from(released)))
            }
            None => { state.set_last_error(6); Ok(ret(0)) }
        };
    };
    if state.guest_reference_count(identity)? == 0 {
        state.set_last_error(6);
        return Ok(ret(0));
    }
    let owner = state.host_owner(identity)?;
    let Some(module) = state.begin_release_module(identity)? else { return Ok(ret(1)); };
    let result = invoke(state, gate, host, SO::Loader(LC::FreeSystemModule { module, owner }));
    let result = match result {
        Ok(value) => value,
        Err(primary) => return Err(finish_release_preserving(state, identity, false, primary)),
    };
    let released = match expect_bool(result) {
        Ok(released) => released,
        Err(primary) => return Err(finish_release_preserving(state, identity, false, primary)),
    };
    state.finish_release_module(identity, released)?;
    Ok(ret(u32::from(released)))
}

fn get_module(state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, modules: &mut impl Win32GuestModuleResolver,
    pointer: u32, wide: bool)
    -> Result<Win32GuestReturn, RuntimeError> {
    if pointer == 0 {
        return Err(gap("GetModuleHandle(NULL) needs the PE32 process-image identity"));
    }
    let name = memory::read_string(memory, pointer, wide)?;
    if name.is_empty() { state.set_last_error(126); return Ok(ret(0)); }
    if let Some(handle) = modules.guest_module_handle(&name)? { return Ok(ret(handle)); }
    let basename = leaf_name(&name)?;
    let response = host.win32_import(HC::FindLoadedSystemModule { name: name.clone() })?;
    let loaded_path = match response.value {
        HV::Module { module: Some(native), path } => {
            if path.is_empty() {
                return Err(invariant("loaded System32 provider has no resolved native path"));
            }
            if let Some(existing) = state.find_module_by_host(native)? {
                state.retain_lookup_lease(existing)?;
                return Ok(ret(state.guest_module_handle(existing)?));
            }
            Some(path)
        }
        HV::Module { module: None, path } => (!path.is_empty()).then_some(path),
        _ => return Err(invariant("loaded-module lookup returned an incompatible DTO")),
    };
    if let Some(path) = loaded_path {
        let reservation = state.reserve_system_module(&basename)?;
        let owner = state.reservation_owner(&reservation);
        let retained = host.win32_import(HC::RetainSystemModulePath {
            path: S::Wide(path), owner,
        })?;
        if let Some(error) = retained.last_error { state.set_last_error(error); }
        let identity = match retained.value {
            HV::Module { module: Some(module), path } => register_acquired_provider(
                state, reservation, module, path, owner, ProviderReference::BorrowedLookup, host)?,
            HV::Module { module: None, .. } => {
                if retained.last_error.is_none() { state.set_last_error(126); }
                return Ok(ret(0));
            }
            _ => return Err(invariant("provider retention returned an incompatible DTO")),
        };
        return Ok(ret(state.guest_module_handle(identity)?));
    }
    let identity = match &basename {
        S::Ansi(value) => state.find_module(value),
        S::Wide(value) => state.find_module_by_wide(value),
    };
    let Some(identity) = identity else { state.set_last_error(126); return Ok(ret(0)); };
    let (module, _) = state.module(identity)?;
    let result = invoke(state, gate, host, SO::Loader(LC::GetModuleHandle {
        expected: module, name,
    }))?;
    if expect_bool(result)? {
        state.retain_lookup_lease(identity)?;
        Ok(ret(state.guest_module_handle(identity)?))
    } else {
        Ok(ret(0))
    }
}

fn get_proc(state: &mut Win32ImportState, _gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, modules: &mut impl Win32GuestModuleResolver,
    module_handle: u32, name_or_ordinal: u32)
    -> Result<Win32GuestReturn, RuntimeError> {
    let symbol = if name_or_ordinal <= u32::from(u16::MAX) {
        Symbol::Ordinal(name_or_ordinal as u16)
    } else {
        let name = memory::read_string(memory, name_or_ordinal, false)?;
        let S::Ansi(name) = name else { return Err(invariant("ANSI export name changed encoding")); };
        if name.is_empty() {
            state.set_last_error(crate::win32_import_bridge::ERROR_PROC_NOT_FOUND);
            return Ok(ret(0));
        }
        Symbol::Name(name)
    };
    match modules.resolve_guest_procedure(module_handle, &symbol)? {
        GuestProcedureLookup::Found(address) => return Ok(ret(address)),
        GuestProcedureLookup::Missing => {
            state.set_last_error(crate::win32_import_bridge::ERROR_PROC_NOT_FOUND);
            return Ok(ret(0));
        }
        GuestProcedureLookup::NotGuestModule => {}
    }
    let Some(identity) = state.system_module_for_handle(module_handle) else {
        state.set_last_error(6);
        return Ok(ret(0));
    };
    if match &symbol {
        Symbol::Name(name) => win32_import_catalog::lookup(name).is_none(),
        Symbol::Ordinal(ordinal) => win32_import_catalog::lookup_ordinal(*ordinal).is_none(),
    } {
        state.set_last_error(crate::win32_import_bridge::ERROR_PROC_NOT_FOUND);
        return Ok(ret(0));
    }
    let (resolved, last_error) = crate::win32_import_bridge::resolve_service_gate(
        state, identity, symbol, memory, |call| host.win32_import(call))?;
    match resolved {
        Some((_, service_gate)) if service_gate.address != 0 => Ok(ret(service_gate.address)),
        Some(_) => Err(invariant("GetProcAddress published a zero service-gate address")),
        None => match last_error {
            Some(error) if error != 0 => { state.set_last_error(error); Ok(ret(0)) }
            Some(_) | None => {
                state.set_last_error(crate::win32_import_bridge::ERROR_PROC_NOT_FOUND);
                Ok(ret(0))
            }
        },
    }
}

fn module_file_name(state: &mut Win32ImportState, gate: Win32ServiceGate,
    memory: &mut Memory, host: &mut impl RuntimeHost,
    modules: &mut impl Win32GuestModuleResolver, handle: u32,
    pointer: u32, capacity: u32, wide: bool)
    -> Result<Win32GuestReturn, RuntimeError> {
    let identity = state.system_module_for_handle(handle);
    let size = usize::try_from(capacity).ok().and_then(|value|
        value.checked_mul(if wide { 2 } else { 1 }))
        .ok_or_else(|| super::exhausted("GetModuleFileName output capacity"))?;
    let mut output = match (pointer, capacity) {
        (0, 0) => None,
        (0, _) => return Err(guest_fault("GetModuleFileName output is NULL with nonzero capacity")),
        (_, _) => Some(GuestOutput::new(memory, pointer, size)?),
    };
    if let Some(text) = modules.guest_module_path(handle, wide)? {
        return guest_module_file_name(state, memory, capacity, wide, text, output.as_mut());
    }
    if handle == 0 {
        return Err(gap("GetModuleFileName(NULL) needs the PE32 process-image identity"));
    }
    let Some(identity) = identity else {
        state.set_last_error(126);
        return Ok(ret(0));
    };
    let (module, _) = state.module(identity)?;
    let value = invoke(state, gate, host, SO::Loader(LC::GetModuleFileName {
        module, encoding: if wide { E::Wide } else { E::Ansi }, capacity,
    }))?;
    let HV::ModuleFileName { result, output_valid, output: text, terminated } = value else {
        return Err(invariant("GetModuleFileName returned an incompatible native-span DTO"));
    };
    if output_valid {
        let output = output.as_mut().ok_or_else(|| invariant(
            "GetModuleFileName host output lacks its preflighted guest buffer"))?;
        match (text, wide) {
            (S::Ansi(bytes), false) => {
                if terminated != (bytes.last() == Some(&0)) {
                    return Err(invariant("GetModuleFileName ANSI span termination metadata differs"));
                }
                output.set(&bytes)?;
            }
            (S::Wide(units), true) => {
                if terminated != (units.last() == Some(&0)) {
                    return Err(invariant("GetModuleFileName UTF-16 span termination metadata differs"));
                }
                output.set_wide_units(&units)?;
            }
            _ => return Err(invariant("GetModuleFileName text encoding changed")),
        }
        memory::commit(memory, std::slice::from_mut(output))?;
    }
    Ok(ret(result))
}

fn guest_module_file_name(state: &mut Win32ImportState, memory: &mut Memory,
    capacity: u32, wide: bool, text: S, output: Option<&mut GuestOutput>)
    -> Result<Win32GuestReturn, RuntimeError> {
    let length = match (&text, wide) {
        (S::Ansi(bytes), false) => bytes.len(),
        (S::Wide(words), true) => words.len(),
        _ => return Err(invariant("guest module path encoding changed")),
    };
    if capacity == 0 { return Ok(ret(0)); }
    let units = usize::try_from(capacity).map_err(|_| super::exhausted("module path capacity"))?;
    let copied = length.min(units.saturating_sub(1));
    let output = output.ok_or_else(|| invariant("guest module path lacks preflighted output"))?;
    match text {
        S::Ansi(bytes) => output.set_ansi(&bytes[..copied], true)?,
        S::Wide(words) => output.set_wide(&words[..copied], true)?,
    }
    memory::commit(memory, std::slice::from_mut(output))?;
    if length >= units { state.set_last_error(122); Ok(ret(capacity)) }
    else { Ok(ret(u32::try_from(length).map_err(|_| super::exhausted("module path length"))?)) }
}

fn normalize_basename(name: &S) -> Result<S, RuntimeError> {
    let (wide, has_extension, invalid_path) = match name {
        S::Ansi(value) => (false, value.iter().rposition(|byte| *byte == b'.').is_some(),
            value.iter().any(|byte| matches!(*byte, b'/' | b'\\' | b':'))),
        S::Wide(value) => (true, value.iter().rposition(|unit| *unit == u16::from(b'.')).is_some(),
            value.iter().any(|unit| matches!(*unit, 0x2f | 0x5c | 0x3a))),
    };
    if invalid_path { return Err(gap("LoadLibrary path search is not a system-provider basename")); }
    if name.is_empty() { return Err(guest_fault("LoadLibrary name is empty")); }
    if has_extension { return copy_name(name); }
    match (name, wide) {
        (S::Ansi(value), false) => {
            let mut output = Vec::new();
            output.try_reserve_exact(value.len().saturating_add(4)).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted, "append DLL extension", error))?;
            output.extend_from_slice(value); output.extend_from_slice(b".dll");
            Ok(S::Ansi(output))
        }
        (S::Wide(value), true) => {
            let mut output = Vec::new();
            output.try_reserve_exact(value.len().saturating_add(4)).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted, "append DLL extension", error))?;
            output.extend_from_slice(value); output.extend_from_slice(&[b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16]);
            Ok(S::Wide(output))
        }
        _ => Err(invariant("module-name encoding branch changed")),
    }
}

fn leaf_name(name: &S) -> Result<S, RuntimeError> {
    match name {
        S::Ansi(value) => {
            let start = value.iter().rposition(|byte| matches!(*byte, b'/' | b'\\' | b':'))
                .map_or(0, |index| index + 1);
            normalize_basename(&S::Ansi(copy_bytes(&value[start..])?))
        }
        S::Wide(value) => {
            let start = value.iter().rposition(|unit| matches!(*unit, 0x2f | 0x5c | 0x3a))
                .map_or(0, |index| index + 1);
            normalize_basename(&S::Wide(copy_words(&value[start..])?))
        }
    }
}

fn copy_bytes(input: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(input.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy module basename", error))?;
    output.extend_from_slice(input);
    Ok(output)
}

fn copy_words(input: &[u16]) -> Result<Vec<u16>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(input.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy module basename", error))?;
    output.extend_from_slice(input);
    Ok(output)
}

fn copy_name(name: &S) -> Result<S, RuntimeError> {
    match name {
        S::Ansi(value) => { let mut output = Vec::new(); output.try_reserve_exact(value.len())
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "copy system module name", error))?; output.extend_from_slice(value); Ok(S::Ansi(output)) }
        S::Wide(value) => { let mut output = Vec::new(); output.try_reserve_exact(value.len())
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "copy system module name", error))?; output.extend_from_slice(value); Ok(S::Wide(output)) }
    }
}

#[derive(Clone, Copy)]
enum ProviderReference { GuestLoad, BorrowedLookup }

fn register_acquired_provider(state: &mut Win32ImportState,
    reservation: crate::win32_import_state::Win32SystemModuleReservation,
    native: crate::Win32HostModule, path: Vec<u16>, owner: crate::Win32HostModuleOwner,
    reference: ProviderReference, host: &mut impl RuntimeHost)
    -> Result<Win32SystemModuleIdentity, RuntimeError> {
    if path.is_empty() {
        let primary = invariant("native provider acquisition returned no canonical path");
        return Err(compensate_module(host, native, owner, primary));
    }
    let existing = match state.find_module_by_host(native) {
        Ok(existing) => existing,
        Err(primary) => return Err(compensate_module(host, native, owner, primary)),
    };
    if let Some(existing) = existing {
        release_acquired_owner(host, native, owner,
            "FreeLibrary after exact provider identity reuse")?;
        match reference {
            ProviderReference::GuestLoad => state.retain_module(existing)?,
            ProviderReference::BorrowedLookup => state.retain_lookup_lease(existing)?,
        }
        return Ok(existing);
    }
    let (guest_references, lookup_lease) = match reference {
        ProviderReference::GuestLoad => (1, false),
        ProviderReference::BorrowedLookup => (0, true),
    };
    match state.register_system_module(
        reservation, native, path, guest_references, lookup_lease,
    ) {
        Ok(identity) => Ok(identity),
        Err(primary) => Err(compensate_module(host, native, owner, primary)),
    }
}

fn release_acquired_owner(host: &mut impl RuntimeHost, module: crate::Win32HostModule,
    owner: crate::Win32HostModuleOwner, operation: &'static str) -> Result<(), RuntimeError> {
    match host.win32_import(HC::FreeSystemModule { module, owner }) {
        Ok(response) => match response.value {
            HV::Bool(true) => Ok(()),
            value => Err(owner.release_failure(
                native_cleanup_failure(operation, value, response.last_error))),
        },
        Err(error) => Err(owner.release_failure(error)),
    }
}

fn compensate_module(host: &mut impl RuntimeHost,
    module: crate::Win32HostModule, owner: crate::Win32HostModuleOwner,
    primary: RuntimeError) -> RuntimeError {
    match release_acquired_owner(host, module, owner,
        "FreeLibrary after PE32 system-module registration failure") {
        Ok(()) => primary,
        Err(cleanup) => combine(primary, cleanup),
    }
}

fn finish_release_preserving(state: &mut Win32ImportState, identity: Win32SystemModuleIdentity,
    released: bool, primary: RuntimeError) -> RuntimeError {
    match state.finish_release_module(identity, released) {
        Ok(()) => primary,
        Err(cleanup) => combine(primary, cleanup),
    }
}

fn combine(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    primary.with_cleanup("PE32 system-module cleanup failed", cleanup)
}

fn native_cleanup_failure(
    operation: &'static str,
    value: HV,
    last_error: Option<u32>,
) -> RuntimeError {
    let kind = if matches!(&value, HV::Bool(false)) { Kind::HostFailure }
        else { Kind::InternalInvariant };
    RuntimeError::with_source(kind, operation, NativeCleanupOutcome { value, last_error })
}

#[derive(Debug)]
struct NativeCleanupOutcome { value: HV, last_error: Option<u32> }

impl std::fmt::Display for NativeCleanupOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.value {
            HV::Bool(false) => formatter.write_str("Windows returned FALSE")?,
            _ => formatter.write_str("native cleanup returned an unexpected result shape")?,
        }
        match self.last_error {
            Some(code) => write!(formatter, " with Windows error {code}")?,
            None => formatter.write_str("; Windows last-error unavailable")?,
        }
        Ok(())
    }
}

impl std::error::Error for NativeCleanupOutcome {}

fn ret(eax: u32) -> Win32GuestReturn { Win32GuestReturn { eax: Some(eax), edx: None } }
fn gap(message: &'static str) -> RuntimeError { RuntimeError::new(Kind::CompatibilityGap, message) }
