//! Iterative PE32 dependency discovery and load-group transactions.

use guest_core::{PhysAddr, memory::Memory};
use x86_cpu::Cpu;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ModuleImage, Win32HostImportCall,
    Win32HostImportValue, Win32ImportString, Win32ImportSymbol,
    pe32::{
        Pe32CallCompletion, Pe32GuestAddress, Pe32ImportBinding, Pe32ImportTarget, Pe32LinkPlan,
        Pe32LoadGroupId, Pe32ModuleIdentity, Pe32ModuleStage,
    },
    pe32_call::Pe32GuestCodeRange,
    win32_import_bridge::resolve_service_gate,
    win32_import_guest::{
        acquire_system_provider, acquire_system_provider_path, release_system_provider,
    },
    win32_import_state::{Win32ImportState, Win32SystemModuleIdentity},
};

use super::HostImportBinding;
use crate::pe32::{preflight_unlinked_group_image, prepare_unlinked_group_module};
use crate::win16_runtime::pe32_dispatch::{
    ActiveLoadGroup, LoadGroupMember, LoadGroupPhase, LoadedModule, MAX_PE32_LOAD_GROUP_MEMBERS,
    Pe32ThunkDispatcher,
};

#[path = "attach.rs"]
mod attach;
#[path = "discovery.rs"]
mod discovery;
#[path = "helpers.rs"]
mod helpers;
#[path = "link.rs"]
mod link;

pub(super) use attach::release_group_temporary_providers;
pub(super) use discovery::{
    is_system_path_for_load, load_system_provider, load_system_provider_path,
};

#[derive(Clone)]
struct ImportModule {
    name: Vec<u8>,
    symbols: Vec<formats::Pe32ImportTarget>,
}

struct DiscoveredModule {
    path: Vec<u8>,
    basename: Vec<u8>,
    image: Option<formats::Pe32Image>,
    imports: Vec<ImportModule>,
    relative_code: Vec<(u32, u32)>,
    executable_ranges: Vec<Pe32GuestCodeRange>,
    handle: u32,
    identity: Option<Pe32ModuleIdentity>,
    host_bindings: Vec<HostImportBinding>,
    host_dependencies: Vec<Win32SystemModuleIdentity>,
}

struct LinkEdges {
    module: Pe32ModuleIdentity,
    dependencies: Vec<Pe32ModuleIdentity>,
}

pub(super) fn load_parsed_file(
    dispatcher: &mut Pe32ThunkDispatcher,
    cpu: &mut Cpu,
    memory: &mut Memory,
    imports: &mut Win32ImportState,
    host: &mut impl RuntimeHost,
    file: Win16ModuleImage,
    basename: Vec<u8>,
    step_limit: u64,
) -> Result<u32, RuntimeError> {
    if let Some(index) = dispatcher.find_resolved_path(&file.path) {
        return dispatcher.retain_loaded(index);
    }
    let budget_owner = dispatcher.begin_budget(step_limit)?;
    let (group, owns_group, member_checkpoint) = match begin_or_extend(dispatcher) {
        Ok(state) => state,
        Err(error) => {
            dispatcher.finish_budget(budget_owner);
            return Err(error);
        }
    };
    let operation = (|| {
        let mut nodes = Vec::new();
        helpers::reserve(&mut nodes, 1, "reserve PE32 load-group discovery")?;
        nodes.push(discovery::discover_root(dispatcher, file, basename)?);
        discovery::discover_dependencies(dispatcher, imports, host, group, &mut nodes)?;
        let (_import_count, provider_count) = nodes
            .iter()
            .try_fold((0_usize, 0_usize), |(symbols, providers), node| {
                let symbols = node.imports.iter().try_fold(symbols, |count, module| {
                    count.checked_add(module.symbols.len())
                })?;
                Some((symbols, providers.checked_add(node.imports.len())?))
            })
            .ok_or_else(|| helpers::resource_error("PE32 group import count overflowed"))?;
        for node in &mut nodes {
            helpers::reserve(
                &mut node.executable_ranges,
                node.relative_code.len(),
                "reserve PE32 absolute executable ranges",
            )?;
        }
        reserve_group_owners(dispatcher, nodes.len(), provider_count, member_checkpoint)?;
        discovery::resolve_host_imports(dispatcher, imports, host, memory, group, &mut nodes)?;
        let identities = link::map_group(dispatcher, memory, group, &mut nodes)?;
        dispatcher
            .active_load_group
            .as_mut()
            .ok_or_else(|| helpers::invariant("PE32 active group disappeared before linking"))?
            .phase = LoadGroupPhase::Linking;
        let (links, edges) = link::link_group(dispatcher, memory, group, &identities, &nodes)?;
        dispatcher.registry.commit_group_links(group, links)?;
        link::pin_host_dependencies(dispatcher, imports, &mut nodes)?;
        attach::release_group_temporary_providers(dispatcher, imports, host)?;
        let order = attach::attach_order(&identities, &edges)?;
        dispatcher
            .active_load_group
            .as_mut()
            .ok_or_else(|| helpers::invariant("PE32 active group disappeared before attach"))?
            .phase = LoadGroupPhase::Attaching;
        attach::attach_members(
            dispatcher, cpu, memory, imports, host, group, &order, step_limit,
        )?;
        let root_handle = nodes[0].handle;
        if owns_group {
            attach::publish_group(dispatcher, group)?;
            dispatcher.active_load_group = None;
        } else if let Some(active) = dispatcher.active_load_group.as_mut() {
            active.phase = LoadGroupPhase::Attaching;
        }
        Ok(root_handle)
    })();

    let result = match operation {
        Ok(handle) => Ok(handle),
        Err(primary) => {
            let cleanup = attach::rollback_group_operation(
                dispatcher,
                cpu,
                memory,
                imports,
                host,
                group,
                owns_group,
                member_checkpoint,
                step_limit,
            );
            if !owns_group && let Some(active) = dispatcher.active_load_group.as_mut() {
                active.phase = if cleanup.is_some() {
                    LoadGroupPhase::RollingBack
                } else {
                    LoadGroupPhase::Attaching
                };
            }
            Err(helpers::combine(primary, cleanup))
        }
    };
    dispatcher.finish_budget(budget_owner);
    result
}

fn begin_or_extend(
    dispatcher: &mut Pe32ThunkDispatcher,
) -> Result<(Pe32LoadGroupId, bool, usize), RuntimeError> {
    if let Some(active) = dispatcher.active_load_group.as_ref() {
        if active.phase != LoadGroupPhase::Attaching
            || dispatcher.active_load_group_for_current_call() != Some(active.id)
        {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "nested PE32 LoadLibrary requires its exact paused DllMain service frame",
            ));
        }
        if !active.temporary_providers.is_empty() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "PE32 load group retains a failed system-provider release",
            ));
        }
        let id = active.id;
        let checkpoint = active.members.len();
        dispatcher
            .active_load_group
            .as_mut()
            .ok_or_else(|| {
                helpers::invariant("PE32 active group disappeared while beginning nested load")
            })?
            .phase = LoadGroupPhase::Discovering;
        return Ok((id, false, checkpoint));
    }
    // Reserve all group identity slots before native work or guest callbacks.
    // Reentrant DllMain loads may consume these slots, so per-call reservations
    // would not prove that outer attach completion can be recorded without OOM.
    dispatcher
        .modules
        .try_reserve(MAX_PE32_LOAD_GROUP_MEMBERS)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve bounded PE32 load-group image owners",
                error,
            )
        })?;
    dispatcher
        .recoveries
        .try_reserve(MAX_PE32_LOAD_GROUP_MEMBERS)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve bounded PE32 load-group recovery owners",
                error,
            )
        })?;
    let mut members = Vec::new();
    helpers::reserve(
        &mut members,
        MAX_PE32_LOAD_GROUP_MEMBERS,
        "reserve bounded PE32 load-group member identities",
    )?;
    let mut attach_order = Vec::new();
    helpers::reserve(
        &mut attach_order,
        MAX_PE32_LOAD_GROUP_MEMBERS,
        "reserve bounded PE32 load-group attach identities",
    )?;
    let id = dispatcher.registry.begin_load_group()?;
    dispatcher.active_load_group = Some(ActiveLoadGroup {
        id,
        root: None,
        members,
        attach_order,
        temporary_providers: Vec::new(),
        next_attach_sequence: 0,
        phase: LoadGroupPhase::Discovering,
    });
    Ok((id, true, 0))
}

fn reserve_group_owners(
    dispatcher: &mut Pe32ThunkDispatcher,
    module_count: usize,
    provider_count: usize,
    checkpoint: usize,
) -> Result<(), RuntimeError> {
    if module_count > MAX_PE32_LOAD_GROUP_MEMBERS
        || checkpoint
            .checked_add(module_count)
            .is_none_or(|count| count > MAX_PE32_LOAD_GROUP_MEMBERS)
    {
        return Err(helpers::resource_error(
            "PE32 load group exceeds its bounded module-work budget",
        ));
    }
    dispatcher
        .modules
        .try_reserve(module_count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact PE32 image owners before mapping",
                error,
            )
        })?;
    dispatcher
        .recoveries
        .try_reserve(module_count.saturating_add(1))
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact PE32 load-group recovery owners",
                error,
            )
        })?;
    let group = dispatcher.active_load_group.as_mut().ok_or_else(|| {
        helpers::invariant("PE32 active group disappeared while reserving its owners")
    })?;
    group.members.try_reserve(module_count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve PE32 load-group identities",
            error,
        )
    })?;
    group
        .attach_order
        .try_reserve(module_count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 load-group attach order",
                error,
            )
        })?;
    group
        .temporary_providers
        .try_reserve(provider_count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 temporary provider identities",
                error,
            )
        })?;
    Ok(())
}
