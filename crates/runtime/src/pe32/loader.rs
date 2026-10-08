//! Rollback-safe PE32 guest image placement and direct guest import linking.

use guest_core::{PhysAddr, memory::Memory};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::{
    Pe32LoadGroupId, Pe32ModuleIdentity, Pe32ModuleRegistry, Pe32ModuleStage,
    Pe32RetirementInfo,
    image_arena::{Pe32ImageArena, Pe32ImageLease},
    load::{loader_directories_from_formats, module_spec_from_plan},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionState {
    Staged,
    Published,
    AbortRequested,
    ReleasePrepared,
    RegistryRetired,
    Released,
}

/// Owns the exact arena lease alongside its registry generation until both
/// registry retirement and allocator release have completed.
#[must_use = "a PE32 module lease must be retained through publish or retirement"]
#[derive(Debug)]
pub(crate) struct Pe32LoadTransaction {
    module: Pe32ModuleIdentity,
    image: Pe32ImageLease,
    entry_rva: Option<u32>,
    load_group: Option<Pe32LoadGroupId>,
    arena_bound: bool,
    state: TransactionState,
}

impl Pe32LoadTransaction {
    pub(crate) const fn module(&self) -> Pe32ModuleIdentity {
        self.module
    }
    pub(crate) const fn entry_rva(&self) -> Option<u32> {
        self.entry_rva
    }
    pub(crate) const fn load_group(&self) -> Option<Pe32LoadGroupId> {
        self.load_group
    }
    pub(crate) const fn image_lease(&self) -> &Pe32ImageLease {
        &self.image
    }
    pub(crate) fn confirm_group_published(
        &mut self,
        registry: &Pe32ModuleRegistry,
        group: Pe32LoadGroupId,
    ) -> Result<(), RuntimeError> {
        if self.state != TransactionState::Staged
            || self.load_group != Some(group)
            || registry.identity(self.module.token()) != Some(self.module)
            || registry.stage(self.module.token()) != Some(Pe32ModuleStage::Published)
        {
            return Err(invariant(
                "PE32 transaction does not match published load group",
            ));
        }
        self.state = TransactionState::Published;
        Ok(())
    }

    /// Abort an unpublished load. Attach rejection/attached modules stay owned
    /// until the registry's required DllMain detach callback has completed.
    pub(crate) fn abort_unpublished(
        &mut self,
        registry: &mut Pe32ModuleRegistry,
        arena: &mut Pe32ImageArena,
    ) -> Result<(), RuntimeError> {
        if self.state == TransactionState::Staged {
            match registry.stage(self.module.token()) {
                Some(Pe32ModuleStage::Retiring) => {}
                Some(Pe32ModuleStage::Published) | None => {
                    return Err(invariant("PE32 load abort lost its unpublished module"));
                }
                Some(_) => registry.abort_load(self.module)?,
            }
            self.state = TransactionState::AbortRequested;
        }
        if self.state == TransactionState::Published || self.state == TransactionState::Released {
            return Err(invariant(
                "PE32 abort targeted a published or released image",
            ));
        }
        if self.state == TransactionState::RegistryRetired {
            arena.finish_release(&self.image)?;
            self.state = TransactionState::Released;
            return Ok(());
        }
        let retirement = registry.retirement_if_ready(self.module)?.ok_or_else(|| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "PE32 module remains retained for DllMain detach or a live dependency",
            )
        })?;
        self.complete_registry_retirement(registry, arena, retirement)
    }

    /// Finish an already-authorized unload receipt after dependency and detach
    /// handling. The registry record is removed before the allocator reuses RAM.
    pub(crate) fn complete_unload(
        &mut self,
        registry: &mut Pe32ModuleRegistry,
        arena: &mut Pe32ImageArena,
        retirement: Pe32RetirementInfo,
    ) -> Result<(), RuntimeError> {
        if self.state != TransactionState::Published
            && self.state != TransactionState::ReleasePrepared
            && self.state != TransactionState::RegistryRetired
        {
            return Err(invariant(
                "PE32 unload does not match a published module lease",
            ));
        }
        self.complete_registry_retirement(registry, arena, retirement)
    }

    fn complete_registry_retirement(
        &mut self,
        registry: &mut Pe32ModuleRegistry,
        arena: &mut Pe32ImageArena,
        retirement: Pe32RetirementInfo,
    ) -> Result<(), RuntimeError> {
        let expected = arena.guest_image(&self.image)?;
        if retirement.module() != self.module || retirement.image() != expected {
            return Err(invariant(
                "PE32 retirement receipt does not match arena lease",
            ));
        }
        if self.state == TransactionState::RegistryRetired {
            arena.finish_release(&self.image)?;
            self.state = TransactionState::Released;
            return Ok(());
        }
        let arena_owner = self.arena_bound.then_some(self.module);
        arena.begin_release(&self.image, arena_owner)?;
        self.state = TransactionState::ReleasePrepared;
        registry.complete_retirement(retirement)?;
        self.state = TransactionState::RegistryRetired;
        arena.finish_release(&self.image)?;
        self.state = TransactionState::Released;
        Ok(())
    }
}

/// A failure keeps the primary cause and, when rollback cannot finish, the
/// still-owning token needed for retry. It never frees a range by dropping it.
#[derive(Debug)]
#[must_use = "a PE32 load failure may own an allocation or pending detach retry token"]
pub(crate) struct Pe32LoadFailure {
    primary: RuntimeError,
    cleanup: Option<RuntimeError>,
    recovery: Option<Pe32LoadRecovery>,
}

#[derive(Debug)]
#[must_use = "retain the recovery token until its exact allocation or module is retired"]
pub(crate) enum Pe32LoadRecovery {
    Unbound(Pe32ImageLease),
    Module(Pe32LoadTransaction),
}

impl Pe32LoadFailure {
    pub(crate) fn into_parts(
        self,
    ) -> (RuntimeError, Option<RuntimeError>, Option<Pe32LoadRecovery>) {
        (self.primary, self.cleanup, self.recovery)
    }

}

impl std::fmt::Display for Pe32LoadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PE32 load failed: {}", self.primary)?;
        if let Some(cleanup) = &self.cleanup {
            write!(f, "; rollback also failed: {cleanup}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Pe32LoadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn module_failure(
    primary: RuntimeError,
    registry: &mut Pe32ModuleRegistry,
    arena: &mut Pe32ImageArena,
    mut transaction: Pe32LoadTransaction,
) -> Pe32LoadFailure {
    match transaction.abort_unpublished(registry, arena) {
        Ok(()) => primary_failure(primary),
        Err(cleanup) => Pe32LoadFailure {
            primary,
            cleanup: Some(cleanup),
            recovery: Some(Pe32LoadRecovery::Module(transaction)),
        },
    }
}

/// Map a checked image into its group without resolving or exposing any IAT
/// entry. Group callers discover every provider first, then link all members
/// before running any DllMain callback.
pub(crate) fn prepare_unlinked_group_module(
    registry: &mut Pe32ModuleRegistry,
    arena: &mut Pe32ImageArena,
    memory: &mut Memory,
    name: &[u8],
    image: formats::Pe32Image,
    group: Pe32LoadGroupId,
) -> Result<Pe32LoadTransaction, Pe32LoadFailure> {
    if let Err(error) = preflight_unlinked_group_image(name, &image) {
        return Err(primary_failure(error));
    }

    let image_size = image.image_size();
    let section_alignment = image.section_alignment();
    let preferred_base = image.preferred_base();
    let lease = match arena.reserve(image_size, section_alignment, preferred_base) {
        Ok(lease) => lease,
        Err(error) => return Err(primary_failure(error)),
    };
    let plan = match formats::plan_pe32_load(
        image,
        formats::Pe32LoadOptions {
            load_base: lease.base(),
            max_image_size: arena.region().length(),
        },
    ) {
        Ok(plan) => plan,
        Err(error) => return Err(unbound_failure(pe32_error(error), arena, lease)),
    };
    let guest_image = match arena.guest_image(&lease) {
        Ok(image) => image,
        Err(error) => return Err(unbound_failure(error, arena, lease)),
    };
    let spec = match module_spec_from_plan(name, guest_image, &plan) {
        Ok(spec) => spec,
        Err(error) => return Err(unbound_failure(error, arena, lease)),
    };
    let mut mapped = Vec::new();
    if let Err(error) = mapped.try_reserve_exact(plan.mapped_image().len()) {
        return Err(unbound_failure(
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "stage PE32 load-group image",
                error,
            ),
            arena,
            lease,
        ));
    }
    mapped.extend_from_slice(plan.mapped_image());
    let expected_length = match usize::try_from(guest_image.size) {
        Ok(length) => length,
        Err(error) => {
            return Err(unbound_failure(
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "PE32 group image extent does not fit host indexing",
                    error,
                ),
                arena,
                lease,
            ));
        }
    };
    if mapped.len() != expected_length {
        return Err(unbound_failure(
            invariant("PE32 group image length differs from its reserved extent"),
            arena,
            lease,
        ));
    }
    if let Err(error) = memory.validate_ram_range(PhysAddr(guest_image.base.0), mapped.len(), true)
    {
        return Err(unbound_failure(crate::runtime_error(error), arena, lease));
    }

    let module = match registry.stage_module_in_group(spec, group) {
        Ok(module) => module,
        Err(error) => return Err(unbound_failure(error, arena, lease)),
    };
    let mut transaction = Pe32LoadTransaction {
        module,
        image: lease,
        entry_rva: plan.entry_rva(),
        load_group: Some(group),
        arena_bound: false,
        state: TransactionState::Staged,
    };
    if let Err(primary) = arena.bind_module(&transaction.image, module) {
        return Err(module_failure(primary, registry, arena, transaction));
    }
    transaction.arena_bound = true;
    if let Err(error) = memory.write_physical(PhysAddr(guest_image.base.0), &mapped) {
        let primary = crate::runtime_error(error);
        if let Err(cleanup) = arena.quarantine(&transaction.image, Some(module)) {
            return Err(quarantine_failure(primary, cleanup, transaction));
        }
        return Err(module_failure(primary, registry, arena, transaction));
    }
    if let Err(error) = registry.mark_mapped(module, guest_image) {
        return Err(module_failure(error, registry, arena, transaction));
    }
    Ok(transaction)
}

/// Reject unsupported image requirements before the group reserves memory,
/// registers a provider, or exposes any guest-visible image state.
pub(crate) fn preflight_unlinked_group_image(
    name: &[u8],
    image: &formats::Pe32Image,
) -> Result<(), RuntimeError> {
    if name.is_empty() || name.contains(&0) || !image.is_dll() {
        return Err(loader_failure("PE32 group input is not a named DLL"));
    }
    let directories = loader_directories_from_formats(image.data_directories())?;
    super::registry::preflight_loader_directories(&directories)?;
    import_count(image)?;
    if image
        .imports()
        .iter()
        .any(|module| matches!(module.kind(), formats::Pe32ImportKind::Delay(_)))
    {
        return Err(loader_failure(
            "PE32 delay-import activation is not implemented",
        ));
    }
    Ok(())
}

pub(crate) fn apply_group_iat_writes(
    image: &mut [u8],
    writes: &[super::Pe32IatWrite],
) -> Result<(), RuntimeError> {
    apply_iat_writes(image, writes)
}

fn quarantine_failure(
    primary: RuntimeError,
    cleanup: RuntimeError,
    transaction: Pe32LoadTransaction,
) -> Pe32LoadFailure {
    Pe32LoadFailure {
        primary,
        cleanup: Some(cleanup),
        recovery: Some(Pe32LoadRecovery::Module(transaction)),
    }
}

fn unbound_failure(
    primary: RuntimeError,
    arena: &mut Pe32ImageArena,
    lease: Pe32ImageLease,
) -> Pe32LoadFailure {
    match arena.release_unbound(&lease) {
        Ok(()) => primary_failure(primary),
        Err(cleanup) => Pe32LoadFailure {
            primary,
            cleanup: Some(cleanup),
            recovery: Some(Pe32LoadRecovery::Unbound(lease)),
        },
    }
}

fn primary_failure(primary: RuntimeError) -> Pe32LoadFailure {
    Pe32LoadFailure {
        primary,
        cleanup: None,
        recovery: None,
    }
}

fn import_count(image: &formats::Pe32Image) -> Result<usize, RuntimeError> {
    image
        .imports()
        .iter()
        .try_fold(0_usize, |count, module| {
            count.checked_add(module.symbols().len())
        })
        .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted, "PE32 import count overflowed"))
}

fn apply_iat_writes(bytes: &mut [u8], writes: &[super::Pe32IatWrite]) -> Result<(), RuntimeError> {
    for write in writes {
        let start = usize::try_from(write.rva()).map_err(|error| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "PE32 IAT RVA does not fit host memory",
                error,
            )
        })?;
        let end = start
            .checked_add(4)
            .ok_or_else(|| invariant("PE32 IAT range overflowed"))?;
        let slot = bytes
            .get_mut(start..end)
            .ok_or_else(|| invariant("PE32 IAT escaped mapped image"))?;
        slot.copy_from_slice(&write.value().to_le_bytes());
    }
    Ok(())
}

fn pe32_error(error: formats::Pe32Error) -> RuntimeError {
    let kind = match &error {
        formats::Pe32Error::OutOfMemory(_) | formats::Pe32Error::ImageTooLarge { .. } => {
            Kind::ResourceExhausted
        }
        formats::Pe32Error::Unsupported(_)
        | formats::Pe32Error::UnsupportedMachine(_)
        | formats::Pe32Error::RelocationsUnavailable
        | formats::Pe32Error::UnsupportedRelocation { .. }
        | formats::Pe32Error::InvalidLoadBase(_) => Kind::CompatibilityGap,
        formats::Pe32Error::InvalidImage(_) => Kind::InvalidInput,
    };
    RuntimeError::with_source(kind, "plan PE32 guest image", error)
}

fn loader_failure(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::CompatibilityGap, message)
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
