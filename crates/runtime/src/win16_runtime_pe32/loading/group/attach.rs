use super::helpers::{invariant, merge_error, provider_release_failure, reserve, resource_error};
use super::*;

pub(in crate::win16_runtime::pe32_dispatch::loading) fn release_group_temporary_providers(
    dispatcher: &mut Pe32ThunkDispatcher,
    imports: &mut Win32ImportState,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let mut first = None;
    let mut index = 0;
    loop {
        let identity = dispatcher
            .active_load_group
            .as_ref()
            .ok_or_else(|| invariant("PE32 provider release lost its active load group"))?
            .temporary_providers
            .get(index)
            .copied();
        let Some(identity) = identity else {
            break;
        };
        match release_system_provider(imports, identity, host) {
            Ok(response) if matches!(response.value, Win32HostImportValue::Bool(true)) => {
                let Some(active) = dispatcher.active_load_group.as_mut() else {
                    return Err(invariant(
                        "PE32 load group disappeared after provider release",
                    ));
                };
                let Some(position) = active
                    .temporary_providers
                    .iter()
                    .position(|provider| *provider == identity)
                else {
                    return Err(invariant(
                        "PE32 released provider lost its exact temporary owner",
                    ));
                };
                active.temporary_providers.remove(position);
            }
            Ok(response) => {
                merge_error(
                    &mut first,
                    provider_release_failure(response.value, response.last_error),
                );
                index += 1;
            }
            Err(error) => {
                merge_error(&mut first, error);
                index += 1;
            }
        }
    }
    match first {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub(super) fn attach_order(
    identities: &[Pe32ModuleIdentity],
    edges: &[LinkEdges],
) -> Result<Vec<Pe32ModuleIdentity>, RuntimeError> {
    // An explicit DFS stack bounds host call-stack use. Postorder places each
    // discovered dependency before its importer; cycles use a stable edge
    // order without claiming a platform-specific Windows callback ordering.
    let mut colors = Vec::new();
    reserve(
        &mut colors,
        identities.len(),
        "reserve PE32 attach traversal state",
    )?;
    colors.extend(identities.iter().copied().map(|identity| (identity, 0_u8)));
    let mut stack = Vec::new();
    reserve(
        &mut stack,
        identities.len(),
        "reserve PE32 attach work stack",
    )?;
    let mut order = Vec::new();
    reserve(&mut order, identities.len(), "reserve PE32 attach order")?;
    for root in identities.iter().copied() {
        if color(&colors, root) == Some(2) {
            continue;
        }
        set_color(&mut colors, root, 1)?;
        stack.push((root, 0_usize));
        while let Some((module, next_dependency)) = stack.last_mut() {
            let dependencies = edges
                .iter()
                .find(|edge| edge.module == *module)
                .map_or(&[][..], |edge| edge.dependencies.as_slice());
            if *next_dependency < dependencies.len() {
                let dependency = dependencies[*next_dependency];
                *next_dependency += 1;
                if !identities.contains(&dependency) || color(&colors, dependency) != Some(0) {
                    continue;
                }
                set_color(&mut colors, dependency, 1)?;
                stack.push((dependency, 0));
                continue;
            }
            let (finished, _) = stack
                .pop()
                .ok_or_else(|| invariant("PE32 attach work stack lost its current module"))?;
            set_color(&mut colors, finished, 2)?;
            order.push(finished);
        }
    }
    Ok(order)
}

fn color(colors: &[(Pe32ModuleIdentity, u8)], identity: Pe32ModuleIdentity) -> Option<u8> {
    colors
        .iter()
        .find_map(|(candidate, color)| (*candidate == identity).then_some(*color))
}

fn set_color(
    colors: &mut [(Pe32ModuleIdentity, u8)],
    identity: Pe32ModuleIdentity,
    color: u8,
) -> Result<(), RuntimeError> {
    let slot = colors
        .iter_mut()
        .find(|(candidate, _)| *candidate == identity)
        .ok_or_else(|| invariant("PE32 attach traversal lost an exact module identity"))?;
    slot.1 = color;
    Ok(())
}

pub(super) fn attach_members(
    dispatcher: &mut Pe32ThunkDispatcher,
    cpu: &mut Cpu,
    memory: &mut Memory,
    imports: &mut Win32ImportState,
    host: &mut impl RuntimeHost,
    group: Pe32LoadGroupId,
    order: &[Pe32ModuleIdentity],
    step_limit: u64,
) -> Result<(), RuntimeError> {
    for identity in order.iter().copied() {
        let index = dispatcher
            .module_index(identity)
            .ok_or_else(|| invariant("PE32 attach identity no longer has an image owner"))?;
        let entry = dispatcher.modules[index].transaction.entry_rva();
        if entry.is_none() {
            dispatcher
                .registry
                .complete_initialization_without_entrypoint(identity)?;
            continue;
        }
        let lease = dispatcher
            .registry
            .prepare_process_attach(identity)?
            .ok_or_else(|| invariant("PE32 DLL entrypoint attach lease was not prepared"))?;
        let sequence = {
            let active = dispatcher
                .active_load_group
                .as_mut()
                .ok_or_else(|| invariant("PE32 active group disappeared before DllMain"))?;
            if active.id != group {
                return Err(invariant(
                    "PE32 DllMain entered under a different load group",
                ));
            }
            let sequence = active.next_attach_sequence;
            active.next_attach_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| resource_error("PE32 attach sequence exhausted"))?;
            sequence
        };
        let remaining = dispatcher.remaining_active_steps().min(step_limit);
        let completion = dispatcher.execute_lease(cpu, memory, imports, host, lease, remaining);
        match completion {
            Ok(Pe32CallCompletion::AttachAccepted) => {
                record_attach(dispatcher, group, identity, sequence, true)?;
            }
            Ok(Pe32CallCompletion::AttachRejected) => {
                // A real FALSE return remains in the detach order by contract.
                record_attach(dispatcher, group, identity, sequence, false)?;
                return Err(RuntimeError::with_source(
                    Kind::CompatibilityGap,
                    "PE32 DLL rejected DLL_PROCESS_ATTACH",
                    super::super::Win32LoadErrorCode(1114),
                ));
            }
            Ok(_) => return Err(invariant("PE32 attach lease returned wrong completion")),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn record_attach(
    dispatcher: &mut Pe32ThunkDispatcher,
    group: Pe32LoadGroupId,
    identity: Pe32ModuleIdentity,
    sequence: u64,
    attached: bool,
) -> Result<(), RuntimeError> {
    let index = dispatcher
        .module_index(identity)
        .ok_or_else(|| invariant("PE32 DllMain owner moved without its exact identity"))?;
    let member = dispatcher.modules[index]
        .group_member
        .as_mut()
        .ok_or_else(|| invariant("PE32 DllMain owner lost its group record"))?;
    if member.group != group || member.attach_sequence.is_some() {
        return Err(invariant(
            "PE32 DllMain completion changed its group identity",
        ));
    }
    member.attached = attached;
    member.attach_sequence = Some(sequence);
    let active = dispatcher
        .active_load_group
        .as_mut()
        .ok_or_else(|| invariant("PE32 active group disappeared after DllMain"))?;
    if active.id != group || active.attach_order.contains(&identity) {
        return Err(invariant(
            "PE32 attach order contains a duplicate or foreign module",
        ));
    }
    active.attach_order.push(identity);
    Ok(())
}

pub(super) fn publish_group(
    dispatcher: &mut Pe32ThunkDispatcher,
    group: Pe32LoadGroupId,
) -> Result<(), RuntimeError> {
    let members = copy_group_members(dispatcher, 0)?;
    dispatcher.registry.load_group_members(group, &members)?;
    let mut references = Vec::new();
    reserve(
        &mut references,
        members.len(),
        "reserve PE32 group initial references",
    )?;
    for identity in &members {
        let index = dispatcher
            .module_index(*identity)
            .ok_or_else(|| invariant("PE32 group member disappeared before publication"))?;
        let member = dispatcher.modules[index]
            .group_member
            .as_ref()
            .ok_or_else(|| invariant("PE32 group member lost its external-reference owner"))?;
        references.push(member.guest_references);
    }
    dispatcher
        .registry
        .publish_load_group(group, &members, &references)?;
    for identity in &members {
        let index = dispatcher
            .module_index(*identity)
            .ok_or_else(|| invariant("published PE32 identity lost its module owner"))?;
        dispatcher.modules[index]
            .transaction
            .confirm_group_published(&dispatcher.registry, group)?;
    }
    for identity in members {
        let index = dispatcher
            .module_index(identity)
            .ok_or_else(|| invariant("published PE32 identity lost its module handle"))?;
        let member = dispatcher.modules[index]
            .group_member
            .as_ref()
            .ok_or_else(|| invariant("published PE32 member lost its guest handle"))?;
        dispatcher.modules[index].handle = Some(member.load_handle);
    }
    Ok(())
}

pub(super) fn rollback_group_operation(
    dispatcher: &mut Pe32ThunkDispatcher,
    cpu: &mut Cpu,
    memory: &mut Memory,
    imports: &mut Win32ImportState,
    host: &mut impl RuntimeHost,
    group: Pe32LoadGroupId,
    owns_group: bool,
    checkpoint: usize,
    step_limit: u64,
) -> Option<RuntimeError> {
    let mut first = None;
    if let Some(active) = dispatcher.active_load_group.as_mut() {
        active.phase = LoadGroupPhase::RollingBack;
    } else {
        merge_error(
            &mut first,
            invariant("PE32 rollback lost its active load group"),
        );
    }
    let members = match copy_group_members(dispatcher, checkpoint) {
        Ok(members) => members,
        Err(error) => return Some(error),
    };
    let attach_order = match copy_attach_order(dispatcher) {
        Ok(order) => order,
        Err(error) => {
            merge_error(&mut first, error);
            Vec::new()
        }
    };
    if !members.is_empty() {
        let abort = if checkpoint == 0 && owns_group {
            dispatcher.registry.abort_load_group(group, &members)
        } else {
            dispatcher
                .registry
                .abort_load_group_members(group, &members)
        };
        if let Err(error) = abort {
            merge_error(&mut first, error);
        }
        for identity in attach_order.into_iter().rev() {
            if !members.contains(&identity) {
                continue;
            }
            let lease = match dispatcher
                .registry
                .prepare_group_member_process_detach(group, &members, identity)
            {
                Ok(Some(lease)) => lease,
                Ok(None) => continue,
                Err(error) => {
                    merge_error(&mut first, error);
                    continue;
                }
            };
            let lease_id = lease.id();
            match dispatcher.execute_lease(
                cpu,
                memory,
                imports,
                host,
                lease,
                dispatcher.remaining_active_steps().min(step_limit),
            ) {
                Ok(Pe32CallCompletion::ProcessDetached) => {}
                Ok(_) => merge_error(
                    &mut first,
                    invariant("PE32 rollback detach returned wrong completion"),
                ),
                Err(error) => {
                    if dispatcher.registry.lease_state(lease_id)
                        != Some(crate::pe32::Pe32CallLeaseState::Retired)
                        && let Some(index) = dispatcher.module_index(identity)
                    {
                        dispatcher.modules[index].quarantined = true;
                    }
                    merge_error(&mut first, error);
                }
            }
        }
        let cleared = if owns_group && checkpoint == 0 {
            dispatcher
                .registry
                .clear_retired_group_edges(group, &members)
        } else {
            dispatcher
                .registry
                .clear_retired_group_member_edges(group, &members)
        };
        match cleared {
            Ok(Some(_)) => {
                let start = dispatcher.budget_position();
                let remaining = dispatcher.remaining_active_steps().min(step_limit);
                if let Err(error) =
                    dispatcher.drain_retiring(cpu, memory, imports, host, remaining, start)
                {
                    merge_error(&mut first, error);
                }
            }
            Ok(None) => merge_error(
                &mut first,
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "PE32 load-group rollback still has an attached or referenced owner",
                ),
            ),
            Err(error) => merge_error(&mut first, error),
        }
    }
    if let Err(error) = release_group_temporary_providers(dispatcher, imports, host) {
        merge_error(&mut first, error);
    }
    let no_members = dispatcher
        .active_load_group
        .as_ref()
        .is_some_and(|active| active.members.is_empty());
    let no_providers = dispatcher
        .active_load_group
        .as_ref()
        .is_some_and(|active| active.temporary_providers.is_empty());
    if owns_group && no_members && no_providers {
        dispatcher.active_load_group = None;
    }
    first
}

fn copy_group_members(
    dispatcher: &Pe32ThunkDispatcher,
    start: usize,
) -> Result<Vec<Pe32ModuleIdentity>, RuntimeError> {
    let active = dispatcher
        .active_load_group
        .as_ref()
        .ok_or_else(|| invariant("PE32 load-group rollback lost its identity owner"))?;
    let members = active
        .members
        .get(start..)
        .ok_or_else(|| invariant("PE32 load-group checkpoint exceeds its member count"))?;
    let mut result = Vec::new();
    reserve(
        &mut result,
        members.len(),
        "snapshot PE32 rollback identities",
    )?;
    result.extend_from_slice(members);
    Ok(result)
}

fn copy_attach_order(
    dispatcher: &Pe32ThunkDispatcher,
) -> Result<Vec<Pe32ModuleIdentity>, RuntimeError> {
    let active = dispatcher
        .active_load_group
        .as_ref()
        .ok_or_else(|| invariant("PE32 rollback lost its attach-order owner"))?;
    let mut result = Vec::new();
    reserve(
        &mut result,
        active.attach_order.len(),
        "snapshot PE32 attach order",
    )?;
    result.extend_from_slice(&active.attach_order);
    Ok(result)
}
