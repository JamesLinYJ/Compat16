//! Atomic visibility and internal dependency handling for PE32 load groups.

use super::*;

impl Pe32ModuleRegistry {
    pub(crate) fn entrypoint_needs_detach(
        &self,
        module: Pe32ModuleIdentity,
    ) -> Result<bool, RuntimeError> {
        Ok(self.record(module)?.entrypoint == Pe32EntryPointLifecycle::DetachPending)
    }

    pub(crate) fn retiring_group_members(
        &self,
        group: Pe32LoadGroupId,
    ) -> Result<Vec<Pe32ModuleIdentity>, RuntimeError> {
        let count = self
            .modules
            .values()
            .filter(|record| {
                record.load_group == Some(group) && record.stage == Pe32ModuleStage::Retiring
            })
            .count();
        let mut members = Vec::new();
        members.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot retiring PE32 load-group identities",
                error,
            )
        })?;
        members.extend(self.modules.values().filter_map(|record| {
            (record.load_group == Some(group) && record.stage == Pe32ModuleStage::Retiring)
                .then_some(record.identity)
        }));
        Ok(members)
    }

    pub(crate) fn stage_module_in_group(
        &mut self,
        spec: Pe32ModuleSpec,
        group: Pe32LoadGroupId,
    ) -> Result<Pe32ModuleIdentity, RuntimeError> {
        self.stage_module_with_group(spec, Some(group))
    }

    pub(super) fn stage_module_with_group(
        &mut self,
        spec: Pe32ModuleSpec,
        load_group: Option<Pe32LoadGroupId>,
    ) -> Result<Pe32ModuleIdentity, RuntimeError> {
        if self.tearing_down {
            return Err(invariant("PE32 registry is tearing down"));
        }
        validate_module_spec(&spec)?;
        let token = Pe32ModuleToken::new(self.next_module_mut()?.take()?);
        let generation = self.next_module_generation_mut()?.take()?;
        let identity = Pe32ModuleIdentity::new(token, generation);
        let entrypoint = if spec.entry_rva.is_some() {
            Pe32EntryPointLifecycle::AttachPending
        } else {
            Pe32EntryPointLifecycle::NotRequired
        };
        self.modules.insert(
            token,
            ModuleRecord {
                identity,
                load_group,
                spec,
                stage: Pe32ModuleStage::Prepared,
                entrypoint,
                mapped: false,
                external_references: 0,
                dependencies: BTreeSet::new(),
                active_calls: 0,
            },
        );
        Ok(identity)
    }

    pub(crate) fn lookup_export_in_group(
        &mut self,
        token: Pe32ModuleToken,
        key: &Pe32ExportKey,
        group: Pe32LoadGroupId,
    ) -> Result<Option<Pe32SymbolResult>, RuntimeError> {
        self.lookup_export_for_group(token, key, Some(group))
    }

    pub(super) fn lookup_export_for_group(
        &mut self,
        token: Pe32ModuleToken,
        key: &Pe32ExportKey,
        group: Option<Pe32LoadGroupId>,
    ) -> Result<Option<Pe32SymbolResult>, RuntimeError> {
        let (identity, image, executable_ranges, export) = {
            let Some(record) = self.modules.get(&token) else {
                return Ok(None);
            };
            let visible_group_member = group.is_some_and(|group| {
                record.load_group == Some(group)
                    && matches!(
                        record.stage,
                        Pe32ModuleStage::Mapped
                            | Pe32ModuleStage::Linked
                            | Pe32ModuleStage::Initializing
                            | Pe32ModuleStage::Initialized
                    )
            });
            if record.stage != Pe32ModuleStage::Published && !visible_group_member {
                return Ok(None);
            }
            let Some(export) = record
                .spec
                .exports
                .iter()
                .find(|export| export_matches_key(export, key))
                .cloned()
            else {
                return Ok(None);
            };
            (
                record.identity,
                record.spec.image,
                record.spec.executable_ranges.clone(),
                export,
            )
        };
        match export.target {
            Pe32ExportTarget::Forwarder { module, symbol } => {
                Ok(Some(Pe32SymbolResult::Forwarder { module, symbol }))
            }
            Pe32ExportTarget::Rva(rva) => {
                if !rva_in_image(image.size, rva) {
                    return Err(invariant("PE32 export RVA is outside its loaded image"));
                }
                if executable_ranges
                    .iter()
                    .any(|range| range_contains(*range, rva))
                {
                    let procedure = if let Some(token) =
                        self.procedures_by_export.get(&(identity, export.ordinal))
                    {
                        *token
                    } else {
                        let token = Pe32ProcedureToken::new(self.next_procedure_mut()?.take()?);
                        let procedure_identity = Pe32ProcedureIdentity::new(
                            token,
                            self.next_procedure_generation_mut()?.take()?,
                        );
                        let target = Pe32CallableTarget::GuestCode {
                            address: guest_address(image, rva)?,
                        };
                        self.procedures.insert(
                            token,
                            ProcedureRecord {
                                identity: procedure_identity,
                                module: Some(identity),
                                export_ordinal: Some(export.ordinal),
                                target,
                            },
                        );
                        self.procedures_by_export
                            .insert((identity, export.ordinal), token);
                        token
                    };
                    Ok(Some(Pe32SymbolResult::Procedure(procedure)))
                } else {
                    Ok(Some(Pe32SymbolResult::Data {
                        module: identity,
                        address: guest_address(image, rva)?,
                    }))
                }
            }
        }
    }

    pub(crate) fn procedure_guest_address_in_group(
        &self,
        token: Pe32ProcedureToken,
        group: Pe32LoadGroupId,
    ) -> Result<Option<Pe32GuestAddress>, RuntimeError> {
        self.procedure_guest_address_for_group(token, Some(group))
    }

    pub(super) fn procedure_guest_address_for_group(
        &self,
        token: Pe32ProcedureToken,
        group: Option<Pe32LoadGroupId>,
    ) -> Result<Option<Pe32GuestAddress>, RuntimeError> {
        let Some(procedure) = self.procedures.get(&token) else {
            return Ok(None);
        };
        let Some(module) = procedure.module else {
            return Ok(None);
        };
        let Some(owner) = self.modules.get(&module.token()) else {
            return Ok(None);
        };
        let visible_group_member = group.is_some_and(|group| {
            owner.load_group == Some(group)
                && matches!(
                    owner.stage,
                    Pe32ModuleStage::Mapped
                        | Pe32ModuleStage::Linked
                        | Pe32ModuleStage::Initializing
                        | Pe32ModuleStage::Initialized
                )
        });
        if owner.identity != module
            || (owner.stage != Pe32ModuleStage::Published && !visible_group_member)
        {
            return Ok(None);
        }
        match procedure.target {
            Pe32CallableTarget::GuestCode { address } => Ok(Some(address)),
        }
    }

    pub(crate) fn begin_load_group(&mut self) -> Result<Pe32LoadGroupId, RuntimeError> {
        if self.tearing_down {
            return Err(invariant("PE32 registry is tearing down"));
        }
        Ok(Pe32LoadGroupId(self.next_load_group_mut()?.take()?))
    }

    pub(crate) fn load_group(
        &self,
        module: Pe32ModuleIdentity,
    ) -> Result<Option<Pe32LoadGroupId>, RuntimeError> {
        Ok(self.record(module)?.load_group)
    }

    pub(crate) fn load_group_members(
        &self,
        group: Pe32LoadGroupId,
        members: &[Pe32ModuleIdentity],
    ) -> Result<(), RuntimeError> {
        validate_members(self, group, members)
    }

    /// Publish all linked members in one registry transition. Their initial
    /// guest references are separate from dependency edges in the import graph.
    pub(crate) fn publish_load_group(
        &mut self,
        group: Pe32LoadGroupId,
        members: &[Pe32ModuleIdentity],
        initial_references: &[u32],
    ) -> Result<(), RuntimeError> {
        if self.tearing_down || members.is_empty() || members.len() != initial_references.len() {
            return Err(invariant("PE32 load-group publication shape is invalid"));
        }
        validate_members(self, group, members)?;
        for module in members {
            let record = self.record(*module)?;
            if record.stage != Pe32ModuleStage::Initialized {
                return Err(invariant(
                    "PE32 load group published before every attach completed",
                ));
            }
            check_loader_requirements(&record.spec)?;
        }
        for (module, references) in members.iter().zip(initial_references) {
            let record = self.record_mut(*module)?;
            record.external_references = *references;
            record.stage = Pe32ModuleStage::Published;
        }
        Ok(())
    }

    /// Move the entire unpublished group to retirement while retaining its
    /// internal edges until every required detach callback has returned.
    pub(crate) fn abort_load_group(
        &mut self,
        group: Pe32LoadGroupId,
        members: &[Pe32ModuleIdentity],
    ) -> Result<(), RuntimeError> {
        validate_members(self, group, members)?;
        for module in members {
            let record = self.record(*module)?;
            if record.stage == Pe32ModuleStage::Published {
                return Err(invariant("published PE32 group cannot use load rollback"));
            }
        }
        for module in members {
            let record = self.record_mut(*module)?;
            record.external_references = 0;
            record.stage = Pe32ModuleStage::Retiring;
            if record.entrypoint == Pe32EntryPointLifecycle::AttachPending {
                record.entrypoint = Pe32EntryPointLifecycle::AttachAborted;
            }
        }
        Ok(())
    }

    /// Abort only the members added by a reentrant LoadLibrary call. The
    /// surrounding DllMain group remains attached and keeps its identities.
    pub(crate) fn abort_load_group_members(
        &mut self,
        group: Pe32LoadGroupId,
        members: &[Pe32ModuleIdentity],
    ) -> Result<(), RuntimeError> {
        validate_subset(self, group, members)?;
        for module in members {
            if self.record(*module)?.stage == Pe32ModuleStage::Published {
                return Err(invariant(
                    "published PE32 member cannot use extension rollback",
                ));
            }
        }
        for module in members {
            let record = self.record_mut(*module)?;
            record.external_references = 0;
            record.stage = Pe32ModuleStage::Retiring;
            if record.entrypoint == Pe32EntryPointLifecycle::AttachPending {
                record.entrypoint = Pe32EntryPointLifecycle::AttachAborted;
            }
        }
        Ok(())
    }

    /// Remove dependency edges inside a ready retiring subset. This breaks
    /// import cycles while keeping external providers pinned until release.
    pub(crate) fn clear_retired_group_edges(
        &mut self,
        group: Pe32LoadGroupId,
        members: &[Pe32ModuleIdentity],
    ) -> Result<Option<bool>, RuntimeError> {
        // A published group may retire only part of its load set at a time;
        // validate these exact retiring identities without requiring retained
        // siblings to be retired too.
        validate_subset(self, group, members)?;
        for module in members {
            let record = self.record(*module)?;
            if record.stage != Pe32ModuleStage::Retiring
                || record.active_calls != 0
                || !entrypoint_can_retire(record.entrypoint)
            {
                return Ok(None);
            }
        }
        let had_internal_edges = members.iter().try_fold(false, |found, module| {
            Ok::<_, RuntimeError>(
                found
                    || self
                        .record(*module)?
                        .dependencies
                        .iter()
                        .any(|dependency| members.contains(dependency)),
            )
        })?;
        for module in members {
            let record = self.record_mut(*module)?;
            record
                .dependencies
                .retain(|dependency| !members.contains(dependency));
        }
        // Readiness and graph progress are separate: a ready acyclic module
        // still needs its retirement receipt collected by the caller.
        Ok(Some(had_internal_edges))
    }

    /// Break a failed reentrant extension after its callbacks have unwound.
    /// Edges from surviving group members must not keep the extension alive.
    pub(crate) fn clear_retired_group_member_edges(
        &mut self,
        group: Pe32LoadGroupId,
        members: &[Pe32ModuleIdentity],
    ) -> Result<Option<bool>, RuntimeError> {
        validate_subset(self, group, members)?;
        for module in members {
            let record = self.record(*module)?;
            if record.stage != Pe32ModuleStage::Retiring
                || record.active_calls != 0
                || !entrypoint_can_retire(record.entrypoint)
            {
                return Ok(None);
            }
        }
        if self.modules.values().any(|source| {
            !members.contains(&source.identity)
                && source
                    .dependencies
                    .iter()
                    .any(|dependency| members.contains(dependency))
        }) {
            return Ok(None);
        }
        let changed = members.iter().try_fold(false, |found, module| {
            Ok::<_, RuntimeError>(found || !self.record(*module)?.dependencies.is_empty())
        })?;
        for module in members {
            self.record_mut(*module)?.dependencies.clear();
        }
        Ok(Some(changed))
    }

    /// Prepare a member's detach even when a cyclic import edge exists inside
    /// the same retiring group. The runtime supplies reverse attach order.
    pub(crate) fn prepare_group_process_detach(
        &mut self,
        group: Pe32LoadGroupId,
        module: Pe32ModuleIdentity,
    ) -> Result<Option<Pe32CallLease>, RuntimeError> {
        let (image, entry_rva) = {
            let record = self.record(module)?;
            if record.load_group != Some(group)
                || record.stage != Pe32ModuleStage::Retiring
                || record.entrypoint != Pe32EntryPointLifecycle::DetachPending
                || record.active_calls != 0
                || self.modules.values().any(|source| {
                    source.identity != module
                        && source.load_group != Some(group)
                        && source.dependencies.contains(&module)
                })
            {
                return Ok(None);
            }
            (record.spec.image, record.spec.entry_rva)
        };
        let entry_rva =
            entry_rva.ok_or_else(|| invariant("PE32 group detach lacks an entrypoint"))?;
        let target = Pe32CallableTarget::GuestCode {
            address: guest_address(image, entry_rva)?,
        };
        let args = crate::pe32_call::process_detach_arguments(image.base.0);
        let lease = self.create_lease(
            Some(module),
            None,
            target,
            Pe32CallReason::ProcessDetach,
            Pe32CallConvention::Stdcall,
            &args,
        )?;
        self.record_mut(module)?.entrypoint = Pe32EntryPointLifecycle::DetachPrepared;
        Ok(Some(lease))
    }

    pub(crate) fn prepare_group_member_process_detach(
        &mut self,
        group: Pe32LoadGroupId,
        members: &[Pe32ModuleIdentity],
        module: Pe32ModuleIdentity,
    ) -> Result<Option<Pe32CallLease>, RuntimeError> {
        validate_subset(self, group, members)?;
        if !members.contains(&module) {
            return Err(invariant(
                "PE32 detach target is outside its rollback subset",
            ));
        }
        let (image, entry_rva) = {
            let record = self.record(module)?;
            if record.stage != Pe32ModuleStage::Retiring
                || record.entrypoint != Pe32EntryPointLifecycle::DetachPending
                || record.active_calls != 0
                || self.modules.values().any(|source| {
                    source.identity != module
                        && !members.contains(&source.identity)
                        && source.dependencies.contains(&module)
                })
            {
                return Ok(None);
            }
            (record.spec.image, record.spec.entry_rva)
        };
        let entry_rva = entry_rva
            .ok_or_else(|| invariant("PE32 rollback-subset detach lacks an entrypoint"))?;
        let target = Pe32CallableTarget::GuestCode {
            address: guest_address(image, entry_rva)?,
        };
        let args = crate::pe32_call::process_detach_arguments(image.base.0);
        let lease = self.create_lease(
            Some(module),
            None,
            target,
            Pe32CallReason::ProcessDetach,
            Pe32CallConvention::Stdcall,
            &args,
        )?;
        self.record_mut(module)?.entrypoint = Pe32EntryPointLifecycle::DetachPrepared;
        Ok(Some(lease))
    }
}

fn validate_subset(
    registry: &Pe32ModuleRegistry,
    group: Pe32LoadGroupId,
    members: &[Pe32ModuleIdentity],
) -> Result<(), RuntimeError> {
    if members.is_empty() {
        return Err(invariant("PE32 load-group subset is empty"));
    }
    for (index, identity) in members.iter().copied().enumerate() {
        if registry.record(identity)?.load_group != Some(group)
            || members[..index].contains(&identity)
        {
            return Err(invariant(
                "PE32 load-group subset has a foreign or duplicate identity",
            ));
        }
    }
    Ok(())
}

fn validate_members(
    registry: &Pe32ModuleRegistry,
    group: Pe32LoadGroupId,
    members: &[Pe32ModuleIdentity],
) -> Result<(), RuntimeError> {
    if members.is_empty() {
        return Err(invariant("PE32 load group has no retained members"));
    }
    for (index, identity) in members.iter().copied().enumerate() {
        let record = registry.record(identity)?;
        if record.load_group != Some(group) || members[..index].contains(&identity) {
            return Err(invariant(
                "PE32 load group contains a duplicate or foreign identity",
            ));
        }
    }
    if registry
        .modules
        .values()
        .any(|record| record.load_group == Some(group) && !members.contains(&record.identity))
    {
        return Err(invariant("PE32 load group omitted a registered member"));
    }
    Ok(())
}
