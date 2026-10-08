use super::super::ModuleSearchFailure;
use super::helpers::{
    copy_bytes, copy_format_target, invariant, reserve, resource_error, win32_symbol,
};
use super::*;
use crate::win16_runtime::pe32_dispatch::{published_basename_key, query_basename_key};

pub(super) fn discover_root(
    dispatcher: &mut Pe32ThunkDispatcher,
    file: Win16ModuleImage,
    basename: Vec<u8>,
) -> Result<DiscoveredModule, RuntimeError> {
    let image = parse_and_preflight(&file.path, &file.image)?;
    let handle = dispatcher.allocate_module_handle()?;
    discovered(file.path, basename, image, handle)
}

pub(super) fn discover_dependencies(
    dispatcher: &mut Pe32ThunkDispatcher,
    imports: &Win32ImportState,
    host: &mut impl RuntimeHost,
    group: Pe32LoadGroupId,
    nodes: &mut Vec<DiscoveredModule>,
) -> Result<(), RuntimeError> {
    let mut cursor = 0_usize;
    while cursor < nodes.len() {
        let pending = clone_import_modules_owned(&nodes[cursor].imports)?;
        for imported in pending {
            if guest_provider_known(dispatcher, group, nodes, &imported.name)?
                || imports.find_module(&imported.name).is_some()
            {
                continue;
            }
            let requested = query_basename_key(&imported.name)?;
            if nodes
                .iter()
                .any(|node| node.basename.eq_ignore_ascii_case(&requested))
            {
                continue;
            }
            match host.win16_read_module(&imported.name, &dispatcher.application_path)? {
                Ok(candidate) => {
                    if is_system_path(host, &candidate.path)? {
                        continue;
                    }
                    let basename = published_basename_key(&candidate.path)?;
                    if guest_provider_key_known(dispatcher, group, nodes, &basename)? {
                        continue;
                    }
                    if nodes.len() >= MAX_PE32_LOAD_GROUP_MEMBERS {
                        return Err(resource_error(
                            "PE32 dependency graph exceeds its bounded module-work budget",
                        ));
                    }
                    let image = parse_and_preflight(&candidate.path, &candidate.image)?;
                    let handle = dispatcher.allocate_module_handle()?;
                    let node = discovered(candidate.path, basename, image, handle)?;
                    nodes.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "extend iterative PE32 dependency queue",
                            error,
                        )
                    })?;
                    nodes.push(node);
                }
                Err(2 | 3) => {}
                Err(code) => {
                    return Err(RuntimeError::with_source(
                        Kind::CompatibilityGap,
                        "PE32 dependency search failed before system-provider resolution",
                        ModuleSearchFailure(code),
                    ));
                }
            }
        }
        cursor += 1;
    }
    Ok(())
}

fn discovered(
    path: Vec<u8>,
    basename: Vec<u8>,
    image: formats::Pe32Image,
    handle: u32,
) -> Result<DiscoveredModule, RuntimeError> {
    let imports = clone_import_modules(image.imports())?;
    let code_count = image
        .sections()
        .iter()
        .filter(|section| section.is_executable() && section.virtual_size() != 0)
        .count();
    let mut relative_code = Vec::new();
    reserve(
        &mut relative_code,
        code_count,
        "reserve PE32 group executable sections",
    )?;
    relative_code.extend(image.sections().iter().filter_map(|section| {
        (section.is_executable() && section.virtual_size() != 0)
            .then_some((section.rva(), section.virtual_size()))
    }));
    Ok(DiscoveredModule {
        path,
        basename,
        image: Some(image),
        imports,
        relative_code,
        executable_ranges: Vec::new(),
        handle,
        identity: None,
        host_bindings: Vec::new(),
        host_dependencies: Vec::new(),
    })
}

fn clone_import_modules(
    modules: &[formats::Pe32ImportModule],
) -> Result<Vec<ImportModule>, RuntimeError> {
    let mut result = Vec::new();
    reserve(&mut result, modules.len(), "copy PE32 import work list")?;
    for module in modules {
        let name = copy_bytes(module.name(), "copy PE32 import module name")?;
        if name.is_empty() || name.contains(&0) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "PE32 import module identity is empty or contains NUL",
            ));
        }
        let mut symbols = Vec::new();
        reserve(
            &mut symbols,
            module.symbols().len(),
            "copy PE32 imported symbols",
        )?;
        for symbol in module.symbols() {
            symbols.push(copy_format_target(symbol.target())?);
        }
        result.push(ImportModule { name, symbols });
    }
    Ok(result)
}

fn guest_provider_known(
    dispatcher: &Pe32ThunkDispatcher,
    group: Pe32LoadGroupId,
    nodes: &[DiscoveredModule],
    module_name: &[u8],
) -> Result<bool, RuntimeError> {
    let wanted = query_basename_key(module_name)?;
    guest_provider_key_known(dispatcher, group, nodes, &wanted)
}

fn guest_provider_key_known(
    dispatcher: &Pe32ThunkDispatcher,
    group: Pe32LoadGroupId,
    nodes: &[DiscoveredModule],
    wanted: &[u8],
) -> Result<bool, RuntimeError> {
    if nodes
        .iter()
        .any(|node| node.basename.eq_ignore_ascii_case(wanted))
    {
        return Ok(true);
    }
    for module in &dispatcher.modules {
        if !module.basename.eq_ignore_ascii_case(wanted) || module.image_released {
            continue;
        }
        let identity = module.transaction.module();
        if dispatcher.registry.identity(identity.token()) != Some(identity) {
            continue;
        }
        let stage = dispatcher.registry.stage(identity.token());
        let visible = stage == Some(Pe32ModuleStage::Published)
            || (dispatcher.registry.load_group(identity)? == Some(group)
                && matches!(
                    stage,
                    Some(
                        Pe32ModuleStage::Mapped
                            | Pe32ModuleStage::Linked
                            | Pe32ModuleStage::Initializing
                            | Pe32ModuleStage::Initialized
                    )
                ));
        if visible {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn resolve_host_imports(
    dispatcher: &mut Pe32ThunkDispatcher,
    imports: &mut Win32ImportState,
    host: &mut impl RuntimeHost,
    memory: &mut Memory,
    group: Pe32LoadGroupId,
    nodes: &mut [DiscoveredModule],
) -> Result<(), RuntimeError> {
    for index in 0..nodes.len() {
        let imports_for_node = clone_import_modules_owned(&nodes[index].imports)?;
        for imported in imports_for_node {
            if guest_provider_known(dispatcher, group, nodes, &imported.name)? {
                continue;
            }
            let provider = if let Some(existing) = imports.find_module(&imported.name) {
                existing
            } else {
                let requested = Win32ImportString::Ansi(copy_bytes(
                    &imported.name,
                    "copy PE32 system provider name",
                )?);
                let (provider, last_error) = acquire_system_provider(imports, &requested, host)?;
                let Some(provider) = provider else {
                    let code = last_error.unwrap_or(126);
                    return Err(RuntimeError::with_source(
                        Kind::CompatibilityGap,
                        "Windows system loader did not resolve a PE32 import provider",
                        super::super::Win32LoadErrorCode(code),
                    ));
                };
                dispatcher
                    .active_load_group
                    .as_mut()
                    .ok_or_else(|| {
                        invariant("PE32 system provider has no active load-group owner")
                    })?
                    .temporary_providers
                    .push(provider);
                provider
            };
            if !nodes[index].host_dependencies.contains(&provider) {
                nodes[index]
                    .host_dependencies
                    .try_reserve(1)
                    .map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve PE32 host-provider pins",
                            error,
                        )
                    })?;
                nodes[index].host_dependencies.push(provider);
            }
            for target in &imported.symbols {
                let symbol = win32_symbol(target)?;
                let (resolved, _) =
                    resolve_service_gate(imports, provider, symbol, memory, |call| {
                        host.win32_import(call)
                    })?;
                let Some((descriptor, gate)) = resolved else {
                    return Err(RuntimeError::new(
                        Kind::CompatibilityGap,
                        "PE32 system import lacks a verified export or typed service gate",
                    ));
                };
                nodes[index].host_bindings.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve PE32 typed host import bindings",
                        error,
                    )
                })?;
                nodes[index].host_bindings.push(HostImportBinding {
                    module: copy_bytes(&imported.name, "copy PE32 host import module")?,
                    symbol: copy_format_target(target)?,
                    target: Pe32ImportTarget::TypedHostService {
                        service_id: descriptor.service.id(),
                        address: Pe32GuestAddress(gate.address),
                    },
                });
            }
        }
    }
    Ok(())
}

fn clone_import_modules_owned(modules: &[ImportModule]) -> Result<Vec<ImportModule>, RuntimeError> {
    let mut cloned = Vec::new();
    reserve(
        &mut cloned,
        modules.len(),
        "copy PE32 pending import modules",
    )?;
    for module in modules {
        let name = copy_bytes(&module.name, "copy PE32 pending import name")?;
        let mut symbols = Vec::new();
        reserve(
            &mut symbols,
            module.symbols.len(),
            "copy PE32 pending import symbols",
        )?;
        for symbol in &module.symbols {
            symbols.push(copy_format_target(symbol)?);
        }
        cloned.push(ImportModule { name, symbols });
    }
    Ok(cloned)
}

fn parse_and_preflight(name: &[u8], bytes: &[u8]) -> Result<formats::Pe32Image, RuntimeError> {
    let image = formats::parse_pe32(bytes).map_err(|error| {
        let kind = match &error {
            formats::Pe32Error::Unsupported(_)
            | formats::Pe32Error::UnsupportedMachine(_)
            | formats::Pe32Error::UnsupportedRelocation { .. }
            | formats::Pe32Error::RelocationsUnavailable => Kind::CompatibilityGap,
            formats::Pe32Error::OutOfMemory(_) | formats::Pe32Error::ImageTooLarge { .. } => {
                Kind::ResourceExhausted
            }
            _ => Kind::InvalidInput,
        };
        RuntimeError::with_source(kind, "parse PE32 load-group image", error)
    })?;
    preflight_unlinked_group_image(name, &image)?;
    Ok(image)
}

fn is_system_path(host: &mut impl RuntimeHost, path: &[u8]) -> Result<bool, RuntimeError> {
    let response = host.win32_import(Win32HostImportCall::IsSystemDirectoryPath {
        path: Win32ImportString::Ansi(copy_bytes(path, "copy PE32 path provenance")?),
    })?;
    if response.last_error.is_some() {
        return Err(invariant(
            "PE32 search provenance returned an unexpected last error",
        ));
    }
    match response.value {
        Win32HostImportValue::Bool(value) => Ok(value),
        _ => Err(invariant("PE32 search provenance returned a non-BOOL DTO")),
    }
}

pub(in crate::win16_runtime::pe32_dispatch::loading) fn is_system_path_for_load(
    host: &mut impl RuntimeHost,
    path: &[u8],
) -> Result<bool, RuntimeError> {
    is_system_path(host, path)
}

pub(in crate::win16_runtime::pe32_dispatch::loading) fn load_system_provider(
    imports: &mut Win32ImportState,
    host: &mut impl RuntimeHost,
    requested_name: &[u8],
) -> Result<(Option<u32>, Option<u32>), RuntimeError> {
    // Preserve the guest spelling for Windows loader search. The provider
    // acquisition boundary separately derives its task-state query key.
    let requested = Win32ImportString::Ansi(copy_bytes(
        requested_name,
        "copy PE32 system-provider query spelling",
    )?);
    let (provider, last_error) = acquire_system_provider(imports, &requested, host)?;
    let Some(provider) = provider else {
        return Ok((None, last_error));
    };
    imports
        .guest_module_handle(provider)
        .map(|handle| (Some(handle), last_error))
}

pub(in crate::win16_runtime::pe32_dispatch::loading) fn load_system_provider_path(
    imports: &mut Win32ImportState,
    host: &mut impl RuntimeHost,
    path: &[u8],
) -> Result<(Option<u32>, Option<u32>), RuntimeError> {
    let (provider, last_error) = acquire_system_provider_path(imports, path, host)?;
    let Some(provider) = provider else {
        return Ok((None, last_error));
    };
    imports
        .guest_module_handle(provider)
        .map(|handle| (Some(handle), last_error))
}
