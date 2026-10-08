//! Import validation and dependency commit for PE32 module linking.

use super::*;

impl Pe32ModuleRegistry {
    pub(crate) fn resolve_group_guest_import(
        &mut self,
        group: Pe32LoadGroupId,
        imported_module: &[u8],
        symbol: &formats::Pe32ImportTarget,
    ) -> Result<Option<Pe32ImportTarget>, RuntimeError> {
        self.resolve_guest_import_inner(Some(group), imported_module, symbol)
    }

    fn resolve_guest_import_inner(
        &mut self,
        group: Option<Pe32LoadGroupId>,
        imported_module: &[u8],
        symbol: &formats::Pe32ImportTarget,
    ) -> Result<Option<Pe32ImportTarget>, RuntimeError> {
        if imported_module.is_empty() || imported_module.contains(&0) {
            return Err(loader_failure("PE32 import module name is invalid"));
        }
        let requested = Pe32ImportModuleQueryKey::from_import_name(imported_module)?;
        let mut providers = self.modules.values().filter(|record| {
            (record.stage == Pe32ModuleStage::Published
                || group.is_some_and(|group| {
                    record.load_group == Some(group)
                        && matches!(
                            record.stage,
                            Pe32ModuleStage::Mapped
                                | Pe32ModuleStage::Linked
                                | Pe32ModuleStage::Initializing
                                | Pe32ModuleStage::Initialized
                        )
                }))
                && provider_matches(record, &requested)
        });
        let Some(provider) = providers.next() else {
            return Ok(None);
        };
        if providers.next().is_some() {
            return Err(loader_failure(
                "PE32 import module basename matches multiple published guest modules",
            ));
        }
        let token = provider.identity.token;
        let key = match symbol {
            formats::Pe32ImportTarget::Name { name, .. } => {
                let mut copy = Vec::new();
                copy.try_reserve_exact(name.len()).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "copy PE32 import lookup name",
                        error,
                    )
                })?;
                copy.extend_from_slice(name);
                Pe32ExportKey::Name(copy)
            }
            formats::Pe32ImportTarget::Ordinal(ordinal) => {
                Pe32ExportKey::Ordinal(u32::from(*ordinal))
            }
        };
        let result = match group {
            Some(group) => self.lookup_export_in_group(token, &key, group)?,
            None => self.lookup_export(token, &key)?,
        };
        match result {
            Some(Pe32SymbolResult::Procedure(procedure)) => {
                Ok(Some(Pe32ImportTarget::Procedure(procedure)))
            }
            Some(Pe32SymbolResult::Data { module, address }) => {
                Ok(Some(Pe32ImportTarget::Data { module, address }))
            }
            Some(Pe32SymbolResult::Forwarder { .. }) => Err(loader_failure(
                "PE32 forwarded imports need a separately resolved guest provider",
            )),
            None => Ok(None),
        }
    }

    pub(crate) fn import_sites(
        &self,
        module: Pe32ModuleIdentity,
    ) -> Result<&[Pe32ImportSite], RuntimeError> {
        Ok(&self.record(module)?.spec.imports)
    }

    pub(crate) fn prepare_group_link(
        &self,
        group: Pe32LoadGroupId,
        module: Pe32ModuleIdentity,
        bindings: &[Pe32ImportBinding<'_>],
    ) -> Result<Pe32LinkPlan, RuntimeError> {
        self.prepare_link_inner(module, Some(group), bindings)
    }

    fn prepare_link_inner(
        &self,
        module: Pe32ModuleIdentity,
        group: Option<Pe32LoadGroupId>,
        bindings: &[Pe32ImportBinding<'_>],
    ) -> Result<Pe32LinkPlan, RuntimeError> {
        let record = self.record(module)?;
        let expected_stage = if group.is_some() {
            matches!(
                record.stage,
                Pe32ModuleStage::Mapped | Pe32ModuleStage::Linked
            )
        } else {
            record.stage == Pe32ModuleStage::Mapped
        };
        if self.tearing_down || !expected_stage || record.load_group != group {
            return Err(invariant("PE32 imports were linked before image mapping"));
        }
        if bindings.len() != record.spec.imports.len() {
            return Err(loader_failure(
                "PE32 image has unresolved or duplicate imports",
            ));
        }

        let mut sites = BTreeSet::new();
        for site in &record.spec.imports {
            if !sites.insert(site.iat_rva) {
                return Err(invariant("PE32 plan contains duplicate IAT locations"));
            }
        }
        let mut writes = Vec::new();
        writes.try_reserve_exact(bindings.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve PE32 import writes", error)
        })?;
        let mut dependencies = BTreeSet::new();
        for binding in bindings {
            if !sites.remove(&binding.site.iat_rva) {
                return Err(loader_failure(
                    "PE32 import resolution does not match the load plan",
                ));
            }
            let site = record
                .spec
                .imports
                .iter()
                .find(|site| site.iat_rva == binding.site.iat_rva)
                .ok_or_else(|| invariant("validated PE32 IAT site disappeared"))?;
            if site != binding.site {
                return Err(loader_failure(
                    "PE32 import resolution changed the planned module or symbol",
                ));
            }
            if site.delayed {
                return Err(loader_failure(
                    "PE32 delay-import activation is not implemented",
                ));
            }
            let value = match binding.target {
                Pe32ImportTarget::Procedure(token) => {
                    let requested =
                        Pe32ImportModuleQueryKey::from_import_name(&binding.site.module)?;
                    let procedure = self.procedures.get(&token).ok_or_else(|| {
                        loader_failure("PE32 import procedure identity is stale or unresolved")
                    })?;
                    let Some(owner) = procedure.module else {
                        return Err(loader_failure("typed host import has no guest IAT thunk"));
                    };
                    let provider = self.record(owner)?;
                    let group_provider = group.is_some_and(|group| {
                        provider.load_group == Some(group)
                            && matches!(
                                provider.stage,
                                Pe32ModuleStage::Mapped
                                    | Pe32ModuleStage::Linked
                                    | Pe32ModuleStage::Initializing
                                    | Pe32ModuleStage::Initialized
                            )
                    });
                    if (provider.stage != Pe32ModuleStage::Published && !group_provider)
                        || !provider_matches(provider, &requested)
                        || !direct_export_matches(
                            provider,
                            procedure.export_ordinal,
                            &binding.site.symbol,
                        )
                    {
                        return Err(loader_failure(
                            "PE32 import procedure does not match a published direct export",
                        ));
                    }
                    let Pe32CallableTarget::GuestCode { address } = procedure.target;
                    let export = direct_export(provider, &binding.site.symbol)
                        .ok_or_else(|| invariant("validated PE32 export disappeared"))?;
                    let Pe32ExportTarget::Rva(export_rva) = &export.target else {
                        return Err(invariant("validated PE32 direct export became a forwarder"));
                    };
                    let expected = guest_address(provider.spec.image, *export_rva)?;
                    if !address_in_image(provider.spec.image, address) || address != expected {
                        return Err(invariant(
                            "PE32 procedure target differs from its exact owner export",
                        ));
                    }
                    dependencies.insert(owner);
                    address.0
                }
                Pe32ImportTarget::Data {
                    module: owner,
                    address,
                } => {
                    let requested =
                        Pe32ImportModuleQueryKey::from_import_name(&binding.site.module)?;
                    let dependency = self.record(owner)?;
                    let Some(export) = direct_export(dependency, &binding.site.symbol) else {
                        return Err(loader_failure(
                            "PE32 data import does not match a direct export",
                        ));
                    };
                    let Pe32ExportTarget::Rva(export_rva) = &export.target else {
                        return Err(loader_failure("forwarded data imports are not implemented"));
                    };
                    let group_provider = group.is_some_and(|group| {
                        dependency.load_group == Some(group)
                            && matches!(
                                dependency.stage,
                                Pe32ModuleStage::Mapped
                                    | Pe32ModuleStage::Linked
                                    | Pe32ModuleStage::Initializing
                                    | Pe32ModuleStage::Initialized
                            )
                    });
                    if !provider_matches(dependency, &requested)
                        || (dependency.stage != Pe32ModuleStage::Published && !group_provider)
                        || !address_in_image(dependency.spec.image, address)
                        || guest_address(dependency.spec.image, *export_rva)? != address
                        || dependency
                            .spec
                            .executable_ranges
                            .iter()
                            .any(|range| range_contains(*range, *export_rva))
                    {
                        return Err(loader_failure(
                            "PE32 imported data does not match the published export",
                        ));
                    }
                    dependencies.insert(owner);
                    address.0
                }
                Pe32ImportTarget::TypedHostService {
                    service_id,
                    address,
                } => {
                    if address.0 == 0 || service_id.raw() == 0 {
                        return Err(loader_failure("PE32 host-service IAT target is invalid"));
                    }
                    address.0
                }
            };
            writes.push(Pe32IatWrite {
                rva: binding.site.iat_rva,
                value,
            });
        }
        if !sites.is_empty() {
            return Err(loader_failure("PE32 image has unresolved imports"));
        }
        Ok(Pe32LinkPlan {
            module,
            dependencies: dependencies.into_iter().collect(),
            writes,
        })
    }

    pub(crate) fn commit_group_links(
        &mut self,
        group: Pe32LoadGroupId,
        links: Vec<Pe32LinkPlan>,
    ) -> Result<(), RuntimeError> {
        if self.tearing_down || links.is_empty() {
            return Err(invariant(
                "PE32 group link transaction is empty or shutting down",
            ));
        }
        for (index, link) in links.iter().enumerate() {
            let record = self.record(link.module)?;
            if record.load_group != Some(group)
                || record.stage != Pe32ModuleStage::Mapped
                || links[..index]
                    .iter()
                    .any(|prior| prior.module == link.module)
            {
                return Err(invariant(
                    "PE32 group link contains a duplicate or foreign module",
                ));
            }
            for dependency in &link.dependencies {
                let provider = self.record(*dependency)?;
                let eligible_group_member = provider.load_group == Some(group)
                    && matches!(
                        provider.stage,
                        Pe32ModuleStage::Mapped
                            | Pe32ModuleStage::Linked
                            | Pe32ModuleStage::Initializing
                            | Pe32ModuleStage::Initialized
                    );
                if provider.stage != Pe32ModuleStage::Published && !eligible_group_member {
                    return Err(loader_failure("PE32 group dependency is not linkable"));
                }
            }
        }
        for link in links {
            let record = self.record_mut(link.module)?;
            record.dependencies = link.dependencies.into_iter().collect();
            record.stage = Pe32ModuleStage::Linked;
        }
        Ok(())
    }
}
