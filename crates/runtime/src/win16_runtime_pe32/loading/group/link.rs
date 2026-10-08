use super::helpers::{combine_load_failure, invariant, merge_error, reserve, resource_error};
use super::*;
use crate::win16_runtime::pe32_dispatch::aggregate_errors;

pub(super) fn map_group(
    dispatcher: &mut Pe32ThunkDispatcher,
    memory: &mut Memory,
    group: Pe32LoadGroupId,
    nodes: &mut [DiscoveredModule],
) -> Result<Vec<Pe32ModuleIdentity>, RuntimeError> {
    for (node_index, node) in nodes.iter_mut().enumerate() {
        let image = node
            .image
            .take()
            .ok_or_else(|| invariant("PE32 discovery image was consumed more than once"))?;
        let transaction = match prepare_unlinked_group_module(
            &mut dispatcher.registry,
            &mut dispatcher.arena,
            memory,
            &node.path,
            image,
            group,
        ) {
            Ok(transaction) => transaction,
            Err(failure) => {
                let (primary, mut cleanup, recovery) = failure.into_parts();
                if let Some(recovery) = recovery {
                    match recovery {
                        crate::pe32::Pe32LoadRecovery::Module(transaction) => {
                            let identity = transaction.module();
                            dispatcher
                                .push_recovery(crate::pe32::Pe32LoadRecovery::Module(transaction));
                            let owner_is_grouped =
                                match dispatcher.registry.identity(identity.token()) {
                                    Some(current) if current == identity => {
                                        matches!(dispatcher.registry.load_group(identity),
                                        Ok(Some(current)) if current == group)
                                    }
                                    _ => false,
                                };
                            if owner_is_grouped {
                                if let Some(active) = dispatcher.active_load_group.as_mut() {
                                    if !active.members.contains(&identity) {
                                        active.members.push(identity);
                                    }
                                    if active.root.is_none() {
                                        active.root = Some(identity);
                                    }
                                } else {
                                    merge_error(
                                        &mut cleanup,
                                        invariant(
                                            "PE32 group disappeared while retaining map recovery",
                                        ),
                                    );
                                }
                            } else {
                                merge_error(
                                    &mut cleanup,
                                    invariant("PE32 map recovery lost its exact group identity"),
                                );
                            }
                        }
                        recovery @ crate::pe32::Pe32LoadRecovery::Unbound(_) => {
                            dispatcher.push_recovery(recovery);
                        }
                    }
                }
                return Err(combine_load_failure(primary, cleanup));
            }
        };
        let identity = transaction.module();
        let base = transaction.image_lease().base();
        for (rva, size) in &node.relative_code {
            node.executable_ranges
                .push(Pe32GuestCodeRange::from_rva(base, *rva, *size));
        }
        let guest_references = u32::from(node_index == 0);
        dispatcher.modules.push(LoadedModule {
            transaction,
            handle: None,
            basename: std::mem::take(&mut node.basename),
            path: std::mem::take(&mut node.path),
            executable_ranges: std::mem::take(&mut node.executable_ranges),
            pending_retirement: None,
            quarantined: false,
            image_released: false,
            system_dependencies: Vec::new(),
            group_member: Some(LoadGroupMember {
                group,
                load_handle: node.handle,
                guest_references,
                pending_host_bindings: std::mem::take(&mut node.host_bindings),
                attached: false,
                attach_sequence: None,
            }),
        });
        node.identity = Some(identity);
        let active = dispatcher
            .active_load_group
            .as_mut()
            .ok_or_else(|| invariant("PE32 group disappeared while registering its image owner"))?;
        active.members.push(identity);
        if active.root.is_none() {
            active.root = Some(identity);
        }
    }
    let mut identities = Vec::new();
    reserve(
        &mut identities,
        nodes.len(),
        "retain new PE32 group identities",
    )?;
    identities.extend(nodes.iter().filter_map(|node| node.identity));
    if identities.len() != nodes.len() {
        return Err(invariant(
            "PE32 group image did not retain every exact module identity",
        ));
    }
    Ok(identities)
}

pub(super) fn link_group(
    dispatcher: &mut Pe32ThunkDispatcher,
    memory: &mut Memory,
    group: Pe32LoadGroupId,
    identities: &[Pe32ModuleIdentity],
    nodes: &[DiscoveredModule],
) -> Result<(Vec<Pe32LinkPlan>, Vec<LinkEdges>), RuntimeError> {
    let mut links = Vec::new();
    reserve(
        &mut links,
        identities.len(),
        "reserve PE32 group link plans",
    )?;
    let mut edges = Vec::new();
    reserve(
        &mut edges,
        identities.len(),
        "reserve PE32 group dependency edges",
    )?;
    for (node, identity) in nodes.iter().zip(identities.iter().copied()) {
        let mut targets = Vec::new();
        let target_count = node
            .imports
            .iter()
            .try_fold(0_usize, |count, imported| {
                count.checked_add(imported.symbols.len())
            })
            .ok_or_else(|| resource_error("PE32 import target count overflowed"))?;
        reserve(
            &mut targets,
            target_count,
            "reserve PE32 resolved import targets",
        )?;
        for imported in &node.imports {
            for symbol in &imported.symbols {
                let target = match dispatcher.registry.resolve_group_guest_import(
                    group,
                    &imported.name,
                    symbol,
                )? {
                    Some(target) => target,
                    None => {
                        let module = dispatcher.module_index(identity).ok_or_else(|| {
                            invariant("PE32 group import owner disappeared before link")
                        })?;
                        let binding = dispatcher.modules[module].group_member.as_ref()
                            .and_then(|member| member.pending_host_bindings.iter().find(|binding| {
                                binding.module.eq_ignore_ascii_case(&imported.name)
                                    && binding.symbol == *symbol
                            }))
                            .ok_or_else(|| RuntimeError::new(Kind::CompatibilityGap,
                                "PE32 import has no guest provider or verified typed host binding"))?;
                        binding.target
                    }
                };
                targets.push(target);
            }
        }
        let sites = dispatcher.registry.import_sites(identity)?;
        if sites.len() != targets.len() {
            return Err(invariant(
                "PE32 group import-site count changed before link",
            ));
        }
        let mut bindings = Vec::new();
        reserve(
            &mut bindings,
            sites.len(),
            "reserve PE32 group site bindings",
        )?;
        bindings.extend(
            sites
                .iter()
                .zip(targets)
                .map(|(site, target)| Pe32ImportBinding::new(site, target)),
        );
        let link = dispatcher
            .registry
            .prepare_group_link(group, identity, &bindings)?;
        let mut dependencies = Vec::new();
        reserve(
            &mut dependencies,
            link.dependencies().len(),
            "retain PE32 group link order",
        )?;
        dependencies.extend_from_slice(link.dependencies());
        edges.push(LinkEdges {
            module: identity,
            dependencies,
        });
        links.push(link);
    }

    // Prepare every write in owned copies before the first guest-memory write.
    // If a later checked write fails, quarantine the whole group because an
    // earlier image may already contain committed IAT bytes.
    let mut staged_images = Vec::new();
    reserve(
        &mut staged_images,
        links.len(),
        "reserve PE32 staged IAT images",
    )?;
    for link in &links {
        let index = dispatcher
            .module_index(link.module())
            .ok_or_else(|| invariant("PE32 group image owner disappeared while writing its IAT"))?;
        let transaction = &dispatcher.modules[index].transaction;
        let length = usize::try_from(transaction.image_lease().size()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "PE32 group image size does not fit host indexing",
                error,
            )
        })?;
        let address = PhysAddr(transaction.image_lease().base());
        if let Err(error) = memory.validate_ram_range(address, length, true) {
            return Err(quarantine_group(
                dispatcher,
                identities,
                crate::runtime_error(error),
            ));
        }
        let mut image = Vec::new();
        image.try_reserve_exact(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "stage PE32 group IAT writeback",
                error,
            )
        })?;
        image.resize(length, 0);
        if let Err(error) = memory.read_physical(address, &mut image) {
            let primary = crate::runtime_error(error);
            return Err(quarantine_group(dispatcher, identities, primary));
        }
        if let Err(primary) = crate::pe32::apply_group_iat_writes(&mut image, link.writes()) {
            return Err(quarantine_group(dispatcher, identities, primary));
        }
        staged_images.push((link.module(), address, image));
    }
    for (_identity, address, image) in staged_images {
        if let Err(error) = memory.write_physical(address, &image) {
            let primary = crate::runtime_error(error);
            return Err(quarantine_group(dispatcher, identities, primary));
        }
    }
    Ok((links, edges))
}

fn quarantine_group(
    dispatcher: &mut Pe32ThunkDispatcher,
    identities: &[Pe32ModuleIdentity],
    primary: RuntimeError,
) -> RuntimeError {
    let mut error = None;
    for identity in identities {
        if let Some(index) = dispatcher.module_index(*identity) {
            let lease = dispatcher.modules[index].transaction.image_lease();
            if let Err(cleanup) = dispatcher.arena.quarantine(lease, Some(*identity)) {
                merge_error(&mut error, cleanup);
            }
        }
    }
    match error {
        Some(cleanup) => aggregate_errors(
            "PE32 group storage failed and image quarantine was incomplete",
            primary,
            cleanup,
        ),
        None => primary,
    }
}

pub(super) fn pin_host_dependencies(
    dispatcher: &mut Pe32ThunkDispatcher,
    imports: &mut Win32ImportState,
    nodes: &mut [DiscoveredModule],
) -> Result<(), RuntimeError> {
    for node in nodes {
        let identity = node
            .identity
            .ok_or_else(|| invariant("PE32 host dependency pin has no mapped module identity"))?;
        imports.pin_dependencies(&node.host_dependencies, identity)?;
        let index = dispatcher
            .module_index(identity)
            .ok_or_else(|| invariant("PE32 host dependency owner disappeared after pin"))?;
        dispatcher.modules[index].system_dependencies = std::mem::take(&mut node.host_dependencies);
    }
    Ok(())
}
