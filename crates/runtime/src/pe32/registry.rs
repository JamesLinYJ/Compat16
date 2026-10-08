//! PE32 module ownership, checked load stages, and cancellable call leases.

#[path = "registry/calls.rs"]
mod calls;
#[path = "registry/group.rs"]
mod group;
#[path = "registry/link.rs"]
mod link;
#[path = "registry/validation.rs"]
mod validation;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::pe32_call::Pe32CallConvention;
use crate::{DiagnosticKind as Kind, RuntimeError};

use super::identity::{
    MonotonicU32, MonotonicU64, Pe32CallLease, Pe32CallLeaseId, Pe32EntryPointLifecycle,
    Pe32ModuleIdentity, Pe32ModuleToken, Pe32ProcedureIdentity, Pe32ProcedureToken,
};

use super::types::*;
use validation::*;

pub(super) fn preflight_loader_directories(
    directories: &[Pe32LoaderDirectory],
) -> Result<(), RuntimeError> {
    validation::check_loader_directories(directories)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseStatus {
    Prepared,
    Executing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LeaseRecord {
    module: Option<Pe32ModuleIdentity>,
    procedure: Option<Pe32ProcedureIdentity>,
    reason: Pe32CallReason,
    target: Pe32CallableTarget,
    convention: Pe32CallConvention,
    status: LeaseStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcedureRecord {
    identity: Pe32ProcedureIdentity,
    module: Option<Pe32ModuleIdentity>,
    export_ordinal: Option<u32>,
    target: Pe32CallableTarget,
}

const MAX_PE32_CALL_ARGUMENTS: usize = 32;

struct ModuleRecord {
    identity: Pe32ModuleIdentity,
    load_group: Option<Pe32LoadGroupId>,
    spec: Pe32ModuleSpec,
    stage: Pe32ModuleStage,
    entrypoint: Pe32EntryPointLifecycle,
    mapped: bool,
    external_references: u32,
    dependencies: BTreeSet<Pe32ModuleIdentity>,
    active_calls: u32,
}

impl ModuleRecord {
    fn retirement_info(&self) -> Pe32RetirementInfo {
        Pe32RetirementInfo {
            module: self.identity,
            image: self.spec.image,
            mapped: self.mapped,
        }
    }
}

pub(crate) struct Pe32ModuleRegistry {
    next_module: Option<MonotonicU32>,
    next_procedure: Option<MonotonicU32>,
    next_module_generation: Option<MonotonicU64>,
    next_procedure_generation: Option<MonotonicU64>,
    next_lease: Option<MonotonicU64>,
    next_load_group: Option<MonotonicU64>,
    modules: BTreeMap<Pe32ModuleToken, ModuleRecord>,
    procedures: BTreeMap<Pe32ProcedureToken, ProcedureRecord>,
    procedures_by_export: BTreeMap<(Pe32ModuleIdentity, u32), Pe32ProcedureToken>,
    leases: BTreeMap<Pe32CallLeaseId, LeaseRecord>,
    tearing_down: bool,
}

impl Pe32ModuleRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn mark_mapped(
        &mut self,
        module: Pe32ModuleIdentity,
        image: Pe32GuestImage,
    ) -> Result<(), RuntimeError> {
        if self.tearing_down {
            return Err(invariant("PE32 registry is tearing down"));
        }
        let record = self.record_mut(module)?;
        if record.stage != Pe32ModuleStage::Prepared || record.spec.image != image {
            return Err(invariant(
                "PE32 image mapping did not match its prepared owner identity",
            ));
        }
        record.mapped = true;
        record.stage = Pe32ModuleStage::Mapped;
        Ok(())
    }

    /// Abort any not-yet-published transaction. The caller releases its guest
    /// allocation and then passes the resulting retirement receipt to the
    /// normal completion path so a failed rollback remains diagnosable.
    pub(crate) fn abort_load(&mut self, module: Pe32ModuleIdentity) -> Result<(), RuntimeError> {
        let record = self.record_mut(module)?;
        if matches!(
            record.stage,
            Pe32ModuleStage::Published | Pe32ModuleStage::Retiring
        ) || record.active_calls != 0
        {
            return Err(invariant(
                "PE32 load abort did not target an unpublished idle module",
            ));
        }
        record.external_references = 0;
        if record.entrypoint == Pe32EntryPointLifecycle::AttachPending {
            // This transaction is abandoned before guest DllMain was entered.
            // Keep that distinct from a guest FALSE return and from an attach
            // fault; all three have different loader cleanup obligations.
            record.entrypoint = Pe32EntryPointLifecycle::AttachAborted;
        }
        record.stage = Pe32ModuleStage::Retiring;
        Ok(())
    }

    pub(crate) fn complete_initialization_without_entrypoint(
        &mut self,
        module: Pe32ModuleIdentity,
    ) -> Result<(), RuntimeError> {
        if self.tearing_down {
            return Err(invariant("PE32 registry is tearing down"));
        }
        let record = self.record_mut(module)?;
        if record.stage != Pe32ModuleStage::Linked || record.spec.entry_rva.is_some() {
            return Err(invariant(
                "PE32 no-entrypoint initialization does not match the image",
            ));
        }
        check_loader_requirements(&record.spec)?;
        record.stage = Pe32ModuleStage::Initialized;
        Ok(())
    }

    pub(crate) fn lookup_export(
        &mut self,
        token: Pe32ModuleToken,
        key: &Pe32ExportKey,
    ) -> Result<Option<Pe32SymbolResult>, RuntimeError> {
        self.lookup_export_for_group(token, key, None)
    }

    /// Resolve a published guest export to its checked guest-linear code
    /// address for Win32 GetProcAddress. Procedure tokens themselves are
    /// runtime identities and must never escape as guest pointers.
    pub(crate) fn procedure_guest_address(
        &self,
        token: Pe32ProcedureToken,
    ) -> Result<Option<Pe32GuestAddress>, RuntimeError> {
        self.procedure_guest_address_for_group(token, None)
    }

    pub(crate) fn retain(&mut self, token: Pe32ModuleToken) -> Result<bool, RuntimeError> {
        if self.tearing_down {
            return Ok(false);
        }
        let Some(record) = self.modules.get_mut(&token) else {
            return Ok(false);
        };
        if record.stage != Pe32ModuleStage::Published {
            return Ok(false);
        }
        let next = record.external_references.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "PE32 module reference count is exhausted",
            )
        })?;
        record.external_references = next;
        Ok(true)
    }

    pub(crate) fn release(&mut self, token: Pe32ModuleToken) -> Result<bool, RuntimeError> {
        let Some(record) = self.modules.get_mut(&token) else {
            return Ok(false);
        };
        if record.stage != Pe32ModuleStage::Published || record.external_references == 0 {
            return Ok(false);
        }
        record.external_references -= 1;
        Ok(true)
    }

    /// Mark modules unreachable from external references, staging, or
    /// in-flight calls as Retiring. Dependency cycles are collected as a
    /// group by graph reachability instead of leaking through refcount cycles.
    pub(crate) fn begin_teardown(&mut self) -> Result<Vec<Pe32RetirementInfo>, RuntimeError> {
        self.tearing_down = true;
        for record in self.modules.values_mut() {
            record.external_references = 0;
            record.stage = Pe32ModuleStage::Retiring;
            if record.entrypoint == Pe32EntryPointLifecycle::AttachPending {
                // Teardown can retire a staged image that never entered
                // DllMain; this is distinct from a guest FALSE or guest fault.
                record.entrypoint = Pe32EntryPointLifecycle::AttachAborted;
            }
        }
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(self.leases.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve prepared PE32 lease teardown",
                    error,
                )
            })?;
        prepared.extend(
            self.leases
                .iter()
                .filter_map(|(id, record)| (record.status == LeaseStatus::Prepared).then_some(*id)),
        );
        for id in prepared {
            let record = self
                .leases
                .get(&id)
                .cloned()
                .ok_or_else(|| invariant("prepared PE32 lease disappeared during teardown"))?;
            if let Some(module_identity) = record.module {
                let module = self.record_mut(module_identity)?;
                module.active_calls = module.active_calls.checked_sub(1).ok_or_else(|| {
                    invariant("PE32 module in-flight count underflowed during teardown")
                })?;
                match record.reason {
                    Pe32CallReason::ProcessAttach => {
                        // A Prepared attach cancelled by teardown never entered
                        // guest code and therefore needs no PROCESS_DETACH.
                        module.entrypoint = Pe32EntryPointLifecycle::AttachAborted;
                    }
                    Pe32CallReason::ProcessDetach => {
                        module.entrypoint = Pe32EntryPointLifecycle::DetachPending;
                    }
                    Pe32CallReason::Export => {}
                }
            }
            self.leases
                .remove(&id)
                .ok_or_else(|| invariant("prepared PE32 lease disappeared during teardown"))?;
        }
        Ok(self.collect_retiring())
    }

    pub(crate) fn collect_retiring(&mut self) -> Vec<Pe32RetirementInfo> {
        let mut reachable = BTreeSet::new();
        let mut pending = VecDeque::new();
        for record in self.modules.values() {
            if record.external_references != 0
                || record.active_calls != 0
                || matches!(
                    record.stage,
                    Pe32ModuleStage::Prepared
                        | Pe32ModuleStage::Mapped
                        | Pe32ModuleStage::Linked
                        | Pe32ModuleStage::Initializing
                        | Pe32ModuleStage::Initialized
                )
            {
                pending.push_back(record.identity);
            }
        }
        while let Some(identity) = pending.pop_front() {
            if !reachable.insert(identity) {
                continue;
            }
            if let Some(record) = self.modules.get(&identity.token) {
                if record.identity == identity {
                    pending.extend(record.dependencies.iter().copied());
                }
            }
        }
        for record in self.modules.values_mut() {
            if record.stage == Pe32ModuleStage::Published && !reachable.contains(&record.identity) {
                record.stage = Pe32ModuleStage::Retiring;
            }
        }
        self.modules
            .values()
            .filter(|record| {
                record.stage == Pe32ModuleStage::Retiring
                    && record.active_calls == 0
                    && entrypoint_can_retire(record.entrypoint)
                    && !self.has_incoming_dependency(record.identity)
                    && !reachable.contains(&record.identity)
            })
            .map(ModuleRecord::retirement_info)
            .collect()
    }

    /// Return a retirement receipt for this exact module without collecting
    /// unrelated unreachable modules as a side effect of load rollback.
    pub(crate) fn retirement_if_ready(
        &self,
        module: Pe32ModuleIdentity,
    ) -> Result<Option<Pe32RetirementInfo>, RuntimeError> {
        let record = self.record(module)?;
        Ok((record.stage == Pe32ModuleStage::Retiring
            && record.active_calls == 0
            && entrypoint_can_retire(record.entrypoint)
            && !self.has_incoming_dependency(module))
        .then(|| record.retirement_info()))
    }

    /// Complete retirement only after the caller successfully released the
    /// exact guest image reservation. Failure leaves the record and tokens
    /// present for an explicit retry.
    pub(crate) fn complete_retirement(
        &mut self,
        retirement: Pe32RetirementInfo,
    ) -> Result<(), RuntimeError> {
        let record = self.record(retirement.module)?;
        if record.stage != Pe32ModuleStage::Retiring
            || record.active_calls != 0
            || !entrypoint_can_retire(record.entrypoint)
            || self.has_incoming_dependency(retirement.module)
            || record.retirement_info() != retirement
        {
            return Err(invariant(
                "PE32 retirement did not match an idle retained image",
            ));
        }
        self.modules.remove(&retirement.module.token);
        self.procedures
            .retain(|_, procedure| procedure.module != Some(retirement.module));
        self.procedures_by_export
            .retain(|(module, _), _| *module != retirement.module);
        Ok(())
    }

    pub(crate) fn stage(&self, token: Pe32ModuleToken) -> Option<Pe32ModuleStage> {
        self.modules.get(&token).map(|record| record.stage)
    }

    pub(crate) fn identity(&self, token: Pe32ModuleToken) -> Option<Pe32ModuleIdentity> {
        self.modules.get(&token).map(|record| record.identity)
    }

    fn create_lease(
        &mut self,
        module: Option<Pe32ModuleIdentity>,
        procedure: Option<Pe32ProcedureIdentity>,
        target: Pe32CallableTarget,
        reason: Pe32CallReason,
        convention: Pe32CallConvention,
        arguments: &[u32],
    ) -> Result<Pe32CallLease, RuntimeError> {
        if self.tearing_down && reason != Pe32CallReason::ProcessDetach {
            return Err(loader_failure("PE32 registry is tearing down"));
        }
        if arguments.len() > MAX_PE32_CALL_ARGUMENTS {
            return Err(loader_failure(
                "PE32 calls support at most 32 explicit DWORD arguments",
            ));
        }
        let mut owned_arguments = Vec::new();
        owned_arguments
            .try_reserve_exact(arguments.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve PE32 call arguments",
                    error,
                )
            })?;
        owned_arguments.extend_from_slice(arguments);
        let id = Pe32CallLeaseId::new(self.next_lease_mut()?.take()?);
        if let Some(module) = module {
            let record = self.record_mut(module)?;
            record.active_calls = record.active_calls.checked_add(1).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "PE32 in-flight call count is exhausted",
                )
            })?;
        }
        let lease_record = LeaseRecord {
            module,
            procedure,
            reason,
            target,
            convention,
            status: LeaseStatus::Prepared,
        };
        self.leases.insert(id, lease_record);
        Ok(Pe32CallLease {
            id,
            module,
            procedure,
            target,
            convention,
            reason,
            arguments: owned_arguments,
        })
    }

    fn release_call_lease(
        &mut self,
        lease: &Pe32CallLease,
        executing: bool,
    ) -> Result<(), RuntimeError> {
        let record = self.lease_record(lease)?.clone();
        let expected = if executing {
            LeaseStatus::Executing
        } else {
            LeaseStatus::Prepared
        };
        if record.status != expected {
            return Err(invariant("PE32 call lease lifecycle state is inconsistent"));
        }
        if let Some(module_identity) = record.module {
            let module = self.record_mut(module_identity)?;
            module.active_calls = module
                .active_calls
                .checked_sub(1)
                .ok_or_else(|| invariant("PE32 module in-flight count underflowed"))?;
        }
        if !executing {
            if let Some(identity) = record.module {
                let tearing_down = self.tearing_down;
                let module = self.record_mut(identity)?;
                match record.reason {
                    Pe32CallReason::ProcessAttach => {
                        if tearing_down {
                            // A Prepared lease has not entered DllMain. Keep
                            // that fact separate from rejection and fault.
                            module.entrypoint = Pe32EntryPointLifecycle::AttachAborted;
                        } else {
                            module.entrypoint = Pe32EntryPointLifecycle::AttachPending;
                            module.stage = Pe32ModuleStage::Linked;
                        }
                    }
                    Pe32CallReason::ProcessDetach => {
                        module.entrypoint = Pe32EntryPointLifecycle::DetachPending;
                    }
                    Pe32CallReason::Export => {}
                }
            }
        }
        self.leases
            .remove(&lease.id)
            .ok_or_else(|| invariant("PE32 call lease disappeared during release"))?;
        Ok(())
    }

    fn lease_record(&self, lease: &Pe32CallLease) -> Result<&LeaseRecord, RuntimeError> {
        let record = self
            .leases
            .get(&lease.id)
            .ok_or_else(|| invariant("PE32 call lease identity is missing"))?;
        if record.module != lease.module
            || record.procedure != lease.procedure
            || record.reason != lease.reason
            || record.target != lease.target
            || record.convention != lease.convention
        {
            return Err(invariant(
                "PE32 call lease contents do not match retained identity",
            ));
        }
        Ok(record)
    }

    fn record(&self, identity: Pe32ModuleIdentity) -> Result<&ModuleRecord, RuntimeError> {
        let record = self
            .modules
            .get(&identity.token)
            .ok_or_else(|| invariant("PE32 module identity is missing"))?;
        if record.identity != identity {
            return Err(invariant(
                "PE32 module generation does not match retained identity",
            ));
        }
        Ok(record)
    }

    fn record_mut(
        &mut self,
        identity: Pe32ModuleIdentity,
    ) -> Result<&mut ModuleRecord, RuntimeError> {
        let record = self
            .modules
            .get_mut(&identity.token)
            .ok_or_else(|| invariant("PE32 module identity is missing"))?;
        if record.identity != identity {
            return Err(invariant(
                "PE32 module generation does not match retained identity",
            ));
        }
        Ok(record)
    }

    fn has_incoming_dependency(&self, provider: Pe32ModuleIdentity) -> bool {
        self.modules
            .values()
            .any(|record| record.identity != provider && record.dependencies.contains(&provider))
    }

    fn next_module_mut(&mut self) -> Result<&mut MonotonicU32, RuntimeError> {
        self.next_module
            .as_mut()
            .ok_or_else(|| invariant("PE32 module token generator is absent"))
    }

    fn next_procedure_mut(&mut self) -> Result<&mut MonotonicU32, RuntimeError> {
        self.next_procedure
            .as_mut()
            .ok_or_else(|| invariant("PE32 procedure token generator is absent"))
    }

    fn next_module_generation_mut(&mut self) -> Result<&mut MonotonicU64, RuntimeError> {
        self.next_module_generation
            .as_mut()
            .ok_or_else(|| invariant("PE32 module generation source is absent"))
    }

    fn next_procedure_generation_mut(&mut self) -> Result<&mut MonotonicU64, RuntimeError> {
        self.next_procedure_generation
            .as_mut()
            .ok_or_else(|| invariant("PE32 procedure generation source is absent"))
    }

    fn next_lease_mut(&mut self) -> Result<&mut MonotonicU64, RuntimeError> {
        self.next_lease
            .as_mut()
            .ok_or_else(|| invariant("PE32 call lease generator is absent"))
    }

    fn next_load_group_mut(&mut self) -> Result<&mut MonotonicU64, RuntimeError> {
        self.next_load_group
            .as_mut()
            .ok_or_else(|| invariant("PE32 load-group identity source is absent"))
    }
}

impl Default for Pe32ModuleRegistry {
    fn default() -> Self {
        Self {
            next_module: Some(MonotonicU32::new("PE32 module")),
            next_procedure: Some(MonotonicU32::new("PE32 procedure")),
            next_module_generation: Some(MonotonicU64::new("PE32 module")),
            next_procedure_generation: Some(MonotonicU64::new("PE32 procedure")),
            next_lease: Some(MonotonicU64::new("PE32 call lease")),
            next_load_group: Some(MonotonicU64::new("PE32 load group")),
            modules: BTreeMap::new(),
            procedures: BTreeMap::new(),
            procedures_by_export: BTreeMap::new(),
            leases: BTreeMap::new(),
            tearing_down: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32CallCompletion {
    Returned(u32),
    AttachAccepted,
    AttachRejected,
    ProcessDetached,
}
