//! Transactional NE dependency discovery and relocation in shared guest RAM.

use std::{collections::BTreeSet, error::Error, fmt};
use formats::{parse_ne, plan_ne_segments, ne_segment_allocation_size};
use win16_abi::{exports::export_descriptors, Win16ProcReference};
use super::*;
use super::module_memory::{ModuleAllocation, ModuleAllocationRelease};
use super::module_registry::{ModuleRecord, ModuleState, builtin_name};

// NE module flags: library image, one shared automatic data segment.
const NE_LIBRARY: u16 = 0x8000;
const NE_SINGLE_DATA: u16 = 0x0001;
const NE_MULTIPLE_DATA: u16 = 0x0002;
// Resource policy bounds recursive dependency discovery, not the ABI.
const MAX_MODULE_DEPTH: usize = 256;
const MODULE_HEADER_BYTES: u32 = 64;

/// Physical removal may wait for the guest's matching UnlockSegment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ModuleRemoval {
    Removed,
    DeferredByGuestLock,
}

impl Win16State {
    pub(super) fn initialize_modules(&mut self, image: &[u8], definition: &NeModule,
        memory: &mut Memory) -> Result<(), RuntimeError> {
        let header = ModuleAllocation::allocate(&mut self.heap, &mut self.selectors,
            memory, MODULE_HEADER_BYTES, false)?;
        let handle = header.selector.raw().0;
        let bytes = &image[definition.ne_header_offset..definition.ne_header_offset + 64];
        self.selectors.write(memory, SegmentedPointer::new(header.selector, 0), bytes)
            .map_err(crate::runtime_error)?;
        let name = definition.resident_names.iter().find(|entry| entry.ordinal == 0)
            .map_or_else(|| builtin_name(&self.module_path), |entry| entry.name.clone());
        let main = ModuleRecord {
            handle, instance: self.instance_handle, path: self.module_path.clone(), name,
            builtin: false, pinned: true, explicit_refs: 1, continuation_owner_refs: 0,
            state: ModuleState::Ready,
            deps: Vec::new(), definition: Some(definition.clone()), loaded: Some(self.loaded.clone()),
            image: image.to_vec(), allocations: vec![header],
            builtin_data_selector: None, builtin_data_exports: None,
            external_application: None, wep_called: false,
            resources_retirement_deferred: false,
        };
        self.modules = module_registry::ModuleRegistry::new(main);
        let mut names = BTreeSet::new();
        // Register only active callable providers and pinned, initialized
        // variable-data providers; formal declarations alone prove neither.
        for descriptor in export_descriptors() {
            names.insert(descriptor.module());
        }
        for (&name, binding) in &self.builtin_data_exports {
            if binding.selector.is_some() && !binding.image.exports.is_empty() {
                names.insert(name);
            }
        }
        for name in names {
            let allocation = ModuleAllocation::allocate(&mut self.heap, &mut self.selectors,
                memory, MODULE_HEADER_BYTES, false)?;
            let handle = allocation.selector.raw().0;
            // Builtin metadata has no synthetic file; data-only identities
            // remain fallbacks while host DLL search can still find a real NE.
            let mut metadata = [0_u8; MODULE_HEADER_BYTES as usize];
            metadata[..2].copy_from_slice(b"NE");
            metadata[12..14].copy_from_slice(&NE_LIBRARY.to_le_bytes());
            self.selectors.write(memory, SegmentedPointer::new(allocation.selector, 0), &metadata)
                .map_err(crate::runtime_error)?;
            let data_binding = self.builtin_data_exports.get(name);
            self.modules.records.insert(handle, ModuleRecord {
                handle, instance: handle, path: name.as_bytes().to_vec(), name: name.as_bytes().to_vec(),
                builtin: true, pinned: true, explicit_refs: 0, continuation_owner_refs: 0,
                state: ModuleState::Ready,
                deps: Vec::new(), definition: None, loaded: None, image: Vec::new(),
                allocations: vec![allocation],
                builtin_data_selector: data_binding.and_then(|binding| binding.selector),
                builtin_data_exports: data_binding.map(|binding| binding.image.clone()),
                external_application: None,
                wep_called: false, resources_retirement_deferred: false,
            });
        }
        let task = self.current_task_handle()?;
        let pointer = self.selectors.pointer_from_raw(Selector(task),
            win16_abi::TASK_DATABASE_HMODULE_OFFSET as u16).map_err(crate::runtime_error)?;
        self.selectors.write(memory, pointer, &self.modules.main.to_le_bytes())
            .map_err(crate::runtime_error)?;
        Ok(())
    }

    pub(super) fn discover_library(&mut self, name: &[u8], memory: &mut Memory,
        host: &mut impl RuntimeHost, created: &mut Vec<u16>, depth: usize)
        -> Result<Result<u16, u16>, RuntimeError> {
        let existing = self.modules.by_name(name);
        let data_only_builtin = existing.filter(|&handle| module_registry::is_data_only_builtin(
            &self.modules.records[&handle],
        ));
        if let Some(handle) = existing {
            if matches!(self.modules.records[&handle].state,
                ModuleState::Unloading | ModuleState::Initializing | ModuleState::Retired) {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 library is still initializing or unloading; recursive load returns failure"));
                return Ok(Err(0));
            }
            if data_only_builtin.is_none() {
                return Ok(Ok(handle));
            }
        }
        if depth >= MAX_MODULE_DEPTH { return Ok(Err(8)); }
        let file = match host.win16_read_module(name, &self.module_path)? {
            Ok(file) => file,
            Err(error) => {
                let simple_name = !name.iter().any(|byte| *byte == b'/' || *byte == b'\\');
                if simple_name && matches!(error, 2 | 3) {
                    if let Some(handle) = data_only_builtin {
                        // A simple data-only module name is a fallback only
                        // after host search confirms no real DLL is available.
                        return Ok(Ok(handle));
                    }
                }
                return Ok(Err(error));
            }
        };
        if let Some(handle) = self.modules.by_name(&file.path) {
            if !module_registry::is_data_only_builtin(&self.modules.records[&handle]) {
                return Ok(Ok(handle));
            }
        }
        let definition = match parse_ne(&file.image) {
            Ok(module) => module,
            Err(error) => return module_format_failure(error, host),
        };
        if definition.header.flags & NE_LIBRARY == 0 { return Ok(Err(11)); }
        if definition.header.flags & NE_MULTIPLE_DATA != 0
            || definition.header.expected_windows_version >= 0x0400 {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "Win16 library requires multiple data instances or Windows 4 DLL initialization; returning bad-format load failure"));
            return Ok(Err(11));
        }
        let record = match self.prepare_library(file, definition, memory) {
            Ok(record) => record,
            Err(error) if error.kind() == Kind::ResourceExhausted => return Ok(Err(8)),
            Err(error) if matches!(error.kind(), Kind::InvalidInput | Kind::CompatibilityGap) => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 library rejected with bad-format load failure: {error}")));
                return Ok(Err(11));
            }
            Err(error) => return Err(error),
        };
        let handle = record.handle;
        let dependencies = record.definition.as_ref().expect("prepared NE definition")
            .imported_modules.iter().map(|entry| entry.name.clone()).collect::<Vec<_>>();
        self.modules.records.insert(handle, record);
        created.push(handle);
        let mut deps = Vec::new();
        for dependency in dependencies {
            match self.discover_library(&dependency, memory, host, created, depth + 1)? {
                Ok(dependency) => { if !deps.contains(&dependency) { deps.push(dependency); } }
                Err(error) => return Ok(Err(error)),
            }
        }
        self.modules.records.get_mut(&handle).expect("discovered module").deps = deps;
        Ok(Ok(handle))
    }

    fn prepare_library(&mut self, file: crate::Win16ModuleImage, definition: NeModule,
        memory: &mut Memory) -> Result<ModuleRecord, RuntimeError> {
        let mut allocations = Vec::new();
        let cleanup_path = file.path.clone();
        let cleanup_name = definition.resident_names.iter().find(|entry| entry.ordinal == 0)
            .map_or_else(|| builtin_name(&file.path), |entry| entry.name.clone());
        let prepared = (|| -> Result<_, RuntimeError> {
            let header = ModuleAllocation::allocate(&mut self.heap, &mut self.selectors,
                memory, MODULE_HEADER_BYTES, false)?;
            let handle = header.selector.raw().0;
            allocations.push(header);
            let start = definition.ne_header_offset;
            self.selectors.write(memory, SegmentedPointer::new(allocations[0].selector, 0),
                &file.image[start..start + MODULE_HEADER_BYTES as usize]).map_err(crate::runtime_error)?;
            let mut assigned = Vec::new();
            for segment in &definition.segments {
                let size = ne_segment_allocation_size(&definition, segment.number).map_err(crate::runtime_error)?;
                let capacity = if segment.number == definition.header.automatic_data_segment
                    && segment.flags & 1 != 0 {
                    crate::win16_loader::AUTOMATIC_DATA_CAPACITY
                } else { size };
                let allocation = ModuleAllocation::allocate_reserved(&mut self.heap, &mut self.selectors,
                    memory, size, capacity, segment.flags & 1 == 0)?;
                assigned.push(allocation.selector.raw());
                allocations.push(allocation);
            }
            let plan = plan_ne_segments(&definition, &assigned).map_err(crate::runtime_error)?;
            let instance = if definition.header.flags & NE_SINGLE_DATA != 0 {
                plan.segment_selector(definition.header.automatic_data_segment).map(|selector| {
                    let segment = &definition.segments[usize::from(definition.header.automatic_data_segment - 1)];
                    if segment.flags & NE_SEGMENT_MOVEABLE != 0 { selector.0 - 1 } else { selector.0 }
                }).unwrap_or(handle)
            } else { handle };
            Ok((handle, instance, plan))
        })();
        let (handle, instance, loaded) = match prepared {
            Ok(result) => result,
            Err(primary) => {
                let mut failure = primary;
                if let Some(cleanup) = self.release_prepared_allocations(&mut allocations) {
                    failure = failure.with_cleanup(
                        "Win16 NE preparation retained its primary failure and allocation rollback failure",
                        cleanup,
                    );
                }
                if !allocations.is_empty() {
                    let handle = allocations[0].selector.raw().0;
                    if self.modules.records.contains_key(&handle) {
                        let collision = RuntimeError::with_source(
                            Kind::InternalInvariant,
                            "private Win16 NE rollback owner collides with a published module identity",
                            RetainedModuleOwnerIdentityConflict { handle, allocations },
                        );
                        failure = failure.with_cleanup(
                            "Win16 NE preparation retained a private rollback owner identity conflict",
                            collision,
                        );
                    } else {
                        self.modules.records.insert(handle, ModuleRecord {
                            handle,
                            instance: handle,
                            path: cleanup_path,
                            name: cleanup_name,
                            builtin: false,
                            pinned: false,
                            explicit_refs: 0,
                            continuation_owner_refs: 0,
                            state: ModuleState::Retired,
                            deps: Vec::new(),
                            definition: None,
                            loaded: None,
                            image: Vec::new(),
                            allocations,
                            builtin_data_selector: None,
                            builtin_data_exports: None,
                            external_application: None,
                            wep_called: true, resources_retirement_deferred: false,
                        });
                        self.module_reap_pending = true;
                    }
                }
                return Err(failure);
            }
        };
        let name = definition.resident_names.iter().find(|entry| entry.ordinal == 0)
            .map_or_else(|| builtin_name(&file.path), |entry| entry.name.clone());
        Ok(ModuleRecord {
            handle, instance, path: file.path, name, builtin: false, pinned: false,
            explicit_refs: 0, continuation_owner_refs: 0, state: ModuleState::Loading,
            deps: Vec::new(),
            definition: Some(definition), loaded: Some(loaded), image: file.image, allocations,
            builtin_data_selector: None, builtin_data_exports: None, wep_called: false,
            external_application: None, resources_retirement_deferred: false,
        })
    }

    pub(super) fn bind_builtin(&mut self, module: &[u8], target: &NeImportTarget,
        allow_missing: bool) -> Result<Option<FarAddress>, FormatError> {
        let lookup = match target {
            NeImportTarget::Ordinal(ordinal) => ExportLookupTarget::Ordinal(*ordinal),
            NeImportTarget::Name(name) => ExportLookupTarget::Name(name),
        };
        let native_thunk = super::thunk_capability::native_thunk_descriptor_for_import(
            module, target,
        );
        let descriptor = if native_thunk.is_some() && !self.native_thunks_available {
            None
        } else {
            lookup_export(module, lookup)
        };
        if descriptor.is_none() && !allow_missing { return Ok(None); }
        let index = if let Some(index) = self.bindings.iter().position(|binding| binding.matches(module, target)) {
            if let Some(descriptor) = native_thunk {
                self.bindings[index] = if self.native_thunks_available {
                    ImportBinding::Supported(descriptor)
                } else {
                    ImportBinding::Unavailable {
                        module: module.to_vec(),
                        target: target.clone(),
                    }
                };
            }
            index
        } else {
            self.bindings.try_reserve(1).map_err(|_| FormatError::AllocationFailed)?;
            self.bindings.push(match descriptor {
                Some(descriptor) => ImportBinding::Supported(descriptor),
                None => ImportBinding::Unavailable { module: module.to_vec(), target: target.clone() },
            });
            self.bindings.len() - 1
        };
        let offset = index.checked_mul(2).and_then(|value| u16::try_from(value).ok())
            .ok_or(FormatError::AllocationFailed)?;
        Ok(Some(FarAddress { selector: self.gate_selector, offset }))
    }

    pub(super) fn module_import_value(&mut self, handle: u16, target: &Win16ProcReference,
        allow_missing: bool) -> Result<Option<NeImportValue>, FormatError> {
        let Some(record) = self.modules.records.get(&handle) else { return Ok(None); };
        if record.state == ModuleState::Retired { return Ok(None); }
        if !record.builtin {
            let Some(definition) = &record.definition else { return Ok(None); };
            let ordinal = match target {
                Win16ProcReference::Ordinal(ordinal) => Some(*ordinal),
                Win16ProcReference::Name(name) => definition.resident_names.iter()
                    .chain(&definition.nonresident_names)
                    .find(|entry| entry.ordinal != 0 && entry.name.eq_ignore_ascii_case(name))
                    .map(|entry| entry.ordinal),
            };
            return Ok(ordinal.and_then(|ordinal| record.loaded.as_ref()?.entry_value(ordinal)));
        }
        let name = record.name.clone();
        let import_target = match target {
            Win16ProcReference::Ordinal(ordinal) => NeImportTarget::Ordinal(*ordinal),
            Win16ProcReference::Name(name) => NeImportTarget::Name(name.clone()),
        };
        let lookup = match target {
            Win16ProcReference::Ordinal(ordinal) => ExportLookupTarget::Ordinal(*ordinal),
            Win16ProcReference::Name(name) => ExportLookupTarget::Name(name),
        };
        if let Some(declaration) = win16_abi::exports::lookup_export_metadata(&name, lookup) {
            let binding = record.builtin_data_exports.as_ref().map(|image|
                crate::win16_builtin_data_exports::BootstrappedBuiltinData {
                    image: image.clone(), selector: record.builtin_data_selector,
                });
            if let Some(value) = crate::win16_builtin_data_exports::lookup_builtin_data_export(
                declaration,
                binding.as_ref(),
                &self.runtime_selector_aliases,
                Some(&self.selectors),
                &name,
                &import_target,
            )? {
                return Ok(Some(value));
            }
        }
        Ok(self.bind_builtin(&name, &import_target, allow_missing)?
            .map(NeImportValue::Address))
    }

    pub(super) fn relocate_libraries(&mut self, created: &[u16], memory: &mut Memory,
        host: &mut impl RuntimeHost) -> Result<Result<(), u16>, RuntimeError> {
        use formats::NeFixupTarget;
        for &handle in created {
            let definition = self.modules.records[&handle].definition.as_ref()
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "NE definition missing before relocation"))?.clone();
            let mut imports = Vec::new();
            for segment in &definition.segments {
                for fixup in &segment.fixups {
                    let (index, target) = match &fixup.target {
                        NeFixupTarget::ImportOrdinal { module_index, ordinal } =>
                            (*module_index, Win16ProcReference::Ordinal(*ordinal)),
                        NeFixupTarget::ImportName { module_index, name } =>
                            (*module_index, Win16ProcReference::Name(name.clone())),
                        _ => continue,
                    };
                    let dependency = definition.imported_modules.iter().find(|entry| entry.index == index)
                        .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "NE import module index is invalid"))?;
                    let owner = self.modules.by_name(&dependency.name)
                        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "discovered NE dependency is missing"))?;
                    let address = match self.module_import_value(owner, &target, true) {
                        Ok(Some(value)) => value,
                        Ok(None) => {
                            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                                format!("Win16 library import from {} is absent; returning bad-format load failure",
                                    String::from_utf8_lossy(&dependency.name))));
                            return Ok(Err(11));
                        }
                        Err(error @ FormatError::NeDataImportFailure { .. }) => {
                            host.report_diagnostic(&Diagnostic::warning(
                                Kind::CompatibilityGap,
                                "Win16 library has an unsupported required data import; returning bad-format load failure",
                            ).with_cause(error));
                            return Ok(Err(11));
                        }
                        Err(FormatError::UnsupportedNeFeature(detail)) => {
                            let symbol = match &target {
                                Win16ProcReference::Ordinal(ordinal) => format!("#{ordinal}"),
                                Win16ProcReference::Name(name) => String::from_utf8_lossy(name).into_owned(),
                            };
                            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                                format!("Win16 library import {}!{symbol} is unsupported ({detail}); returning bad-format load failure",
                                    String::from_utf8_lossy(&dependency.name))));
                            return Ok(Err(11));
                        }
                        Err(error) => return Err(crate::runtime_error(error)),
                    };
                    let target = match target {
                        Win16ProcReference::Ordinal(ordinal) => NeImportTarget::Ordinal(ordinal),
                        Win16ProcReference::Name(name) => NeImportTarget::Name(name),
                    };
                    imports.push((dependency.name.clone(), target, address));
                }
            }
            let record = self.modules.records.get_mut(&handle)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "NE relocation record is missing"))?;
            let plan = record.loaded.as_ref()
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant, "NE segment plan is missing"))?;
            let resolve = |module: &[u8], target: &NeImportTarget| imports.iter()
                .find(|(name, symbol, _)| name.eq_ignore_ascii_case(module) && symbol == target)
                .map(|(_, _, address)| *address)
                .ok_or_else(|| FormatError::UnresolvedNeImport { module: module.to_vec(), target: target.clone() });
            let mut resolver = module_memory::PreparedModuleResolver::new(
                &mut self.heap, &mut self.selectors, &mut record.allocations,
                &definition, plan, memory.len(), resolve).map_err(crate::runtime_error)?;
            let result = load_ne_segments(&record.image, &definition, &mut resolver, memory);
            if let Some(error) = resolver.take_release_error() { return Err(error); }
            drop(resolver);
            match result {
                Ok(loaded) => {
                    for (segment, metadata) in loaded.segments.iter().zip(&definition.segments) {
                        let selector = segment.selector.0;
                        let handle = if metadata.flags & NE_SEGMENT_MOVEABLE != 0 { selector - 1 } else { selector };
                        self.loaded_segment_handles.insert(selector, handle);
                    }
                    record.loaded = Some(loaded);
                }
                Err(error) => return module_format_failure(error, host).map(|result| result.map(|_| ())),
            }
            self.queue_toolhelp_module_segments_loaded(handle)?;
        }
        Ok(Ok(()))
    }

    pub(super) fn module_entry(&mut self, handle: u16, target: &Win16ProcReference,
        allow_missing: bool) -> Result<Option<FarAddress>, FormatError> {
        match self.module_import_value(handle, target, allow_missing)? {
            Some(NeImportValue::Address(address)) => Ok(Some(address)),
            Some(NeImportValue::Selector(_) | NeImportValue::Constant(_)) | None => Ok(None),
        }
    }

    fn release_prepared_allocations(
        &mut self,
        allocations: &mut Vec<ModuleAllocation>,
    ) -> Option<RuntimeError> {
        let mut failure = None;
        let segment_count = allocations.len();
        for index in (1..segment_count).rev() {
            match allocations[index].release_in_place(&mut self.heap, &mut self.selectors) {
                Ok(ModuleAllocationRelease::Released) => { allocations.remove(index); }
                Ok(ModuleAllocationRelease::DeferredByGuestLock) => {
                    failure = Some(append_module_cleanup_error(
                        failure,
                        RuntimeError::new(
                            Kind::ResourceExhausted,
                            "private Win16 NE rollback owner remains guest-locked",
                        ),
                    ));
                }
                Err(error) => {
                    failure = Some(append_module_cleanup_error(failure, error));
                }
            }
        }
        if allocations.len() == 1 {
            match allocations[0].release_in_place(&mut self.heap, &mut self.selectors) {
                Ok(ModuleAllocationRelease::Released) => { allocations.remove(0); }
                Ok(ModuleAllocationRelease::DeferredByGuestLock) => {
                    failure = Some(append_module_cleanup_error(
                        failure,
                        RuntimeError::new(
                            Kind::ResourceExhausted,
                            "private Win16 NE module header remains guest-locked",
                        ),
                    ));
                }
                Err(error) => failure = Some(append_module_cleanup_error(failure, error)),
            }
        }
        failure
    }

    fn release_module_allocations(
        &mut self,
        handle: u16,
        release_header: bool,
    ) -> Result<bool, RuntimeError> {
        let record = self.modules.records.get_mut(&handle).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "retired Win16 module lost its allocation owner",
        ))?;
        let segment_count = record.allocations.len();
        let mut deferred = false;
        let mut failure = None;
        for index in (1..segment_count).rev() {
            let allocation = &mut record.allocations[index];
            match allocation.release_in_place(&mut self.heap, &mut self.selectors) {
                Ok(ModuleAllocationRelease::Released) => {
                    // The selector/handle lookup remains published until the
                    // allocator confirms that this exact block was freed.
                    let selector = allocation.selector.raw().0;
                    record.allocations.remove(index);
                    self.loaded_segment_handles.remove(&selector);
                }
                Ok(ModuleAllocationRelease::DeferredByGuestLock) => deferred = true,
                Err(error) => {
                    failure = Some(append_module_cleanup_error(failure, error.with_context(
                        format!("retiring Win16 module segment selector 0x{:04X}",
                            allocation.selector.raw().0),
                    )));
                }
            }
        }
        // Allocation zero is the private NE-header owner and remains valid
        // until every segment owner has been released and DELMODULE callbacks
        // have returned.
        if release_header && record.allocations.len() == 1 {
            let allocation = &mut record.allocations[0];
            match allocation.release_in_place(&mut self.heap, &mut self.selectors) {
                Ok(ModuleAllocationRelease::Released) => {
                    let selector = allocation.selector.raw().0;
                    record.allocations.remove(0);
                    self.loaded_segment_handles.remove(&selector);
                }
                Ok(ModuleAllocationRelease::DeferredByGuestLock) => deferred = true,
                Err(error) => {
                    failure = Some(append_module_cleanup_error(failure, error.with_context(
                        "retiring Win16 private module header allocation",
                    )));
                }
            }
        }
        let complete = if release_header {
            record.allocations.is_empty()
        } else {
            record.allocations.len() <= 1
        };
        if let Some(error) = failure {
            self.module_reap_pending = true;
            return Err(error);
        }
        Ok(complete && !deferred)
    }

    pub(super) fn remove_module(&mut self, handle: u16) -> Result<ModuleRemoval, RuntimeError> {
        if !self.modules.records.contains_key(&handle) {
            return Ok(ModuleRemoval::Removed);
        }
        // LOADSEG records retain a selector generation and module handle. A
        // rollback or unload drops queued notifications before releasing that
        // exact module's selectors, preventing a delayed callback on reuse.
        let module_generation = self.selectors.reference(Selector(handle))
            .map_err(crate::runtime_error)?;
        self.toolhelp_notify.cancel_module_segments(handle, module_generation);
        let continuation_root = self.modules.continuation_owner_reaches(handle)?;
        let record = self.modules.records.get_mut(&handle).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "module record disappeared during continuation-root preflight"))?;
        // Retired identities stay private to the runtime: they retain owner,
        // mapping, and header state, but public module lookup hides them.
        record.state = ModuleState::Retired;
        record.wep_called = true;
        // Failed-load rollback can enter here directly, outside the normal
        // reachability reaper. A frame-owned module or one of its dependencies
        // still retains real code/data backing, so preserve it for retry.
        if continuation_root {
            self.module_reap_pending = true;
            return Ok(ModuleRemoval::DeferredByGuestLock);
        }
        let builtin_data_selector = self.modules.records.get(&handle)
            .and_then(|record| record.builtin_data_selector);
        if let Some(selector) = builtin_data_selector {
            if self.runtime_arena_backing.primary_has_active_leases(selector)? {
                // Builtin variable data is outside GlobalHeap. Its exact
                // alias/frame leases keep this registered chunk alive.
                self.module_reap_pending = true;
                return Ok(ModuleRemoval::DeferredByGuestLock);
            }
        }
        self.module_reap_pending = true;
        // Resource retirement is retryable. Keep the module record and its
        // private header/cache identity until every segment and data selector
        // has completed physical release.
        if self.retire_module_resources(handle)? {
            if let Some(record) = self.modules.records.get_mut(&handle) {
                record.resources_retirement_deferred = true;
            }
            return Ok(ModuleRemoval::DeferredByGuestLock);
        }
        if let Some(record) = self.modules.records.get_mut(&handle) {
            record.resources_retirement_deferred = false;
        }
        self.queue_toolhelp_module_segments_freed(handle)?;
        if self.toolhelp_notify.has_pending_module_retirement_notifications(handle) {
            self.module_reap_pending = true;
            return Ok(ModuleRemoval::DeferredByGuestLock);
        }
        if !self.release_module_allocations(handle, false)? {
            return Ok(ModuleRemoval::DeferredByGuestLock);
        }
        self.queue_toolhelp_module_deleted(handle)?;
        if self.toolhelp_notify.has_pending_module_retirement_notifications(handle) {
            self.module_reap_pending = true;
            return Ok(ModuleRemoval::DeferredByGuestLock);
        }
        if !self.release_module_allocations(handle, true)? {
            return Ok(ModuleRemoval::DeferredByGuestLock);
        }
        if let Some(selector) = builtin_data_selector {
            match self.runtime_arena_backing.retire_registered_chunk(
                selector, &mut self.selectors,
            )? {
                super::runtime_arena_backing::RuntimeArenaChunkRetirement::NotRegistered => {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "builtin Win16 data selector lost its registered runtime arena owner"));
                }
                super::runtime_arena_backing::RuntimeArenaChunkRetirement::Deferred => {
                    self.module_reap_pending = true;
                    return Ok(ModuleRemoval::DeferredByGuestLock);
                }
                super::runtime_arena_backing::RuntimeArenaChunkRetirement::Retired => {}
            }
        }
        if let Some(record) = self.modules.records.get(&handle) {
            if let Some(loaded) = &record.loaded {
                for segment in &loaded.segments {
                    self.loaded_segment_handles.remove(&segment.selector.0);
                }
            }
        }
        self.resource_handlers.retain(|(owner, _), _| *owner != handle);
        self.forget_module_image_cache(handle);
        self.toolhelp_notify.forget_module_retirement(handle);
        self.modules.records.remove(&handle);
        Ok(ModuleRemoval::Removed)
    }

    pub(super) fn rollback_modules(&mut self, created: &[u16]) -> Result<(), RuntimeError> {
        let mut failure = None;
        for &handle in created.iter().rev() {
            if let Err(error) = self.remove_module(handle) {
                failure = Some(append_module_cleanup_error(failure, error));
            }
        }
        if let Some(error) = failure { Err(error) } else { Ok(()) }
    }

    pub(super) fn module_initialization_order(&self, root: u16, created: &[u16]) -> Vec<u16> {
        fn visit(state: &Win16State, handle: u16, created: &[u16], visited: &mut BTreeSet<u16>, out: &mut Vec<u16>) {
            if !created.contains(&handle) || !visited.insert(handle) { return; }
            if let Some(module) = state.modules.records.get(&handle) {
                for &dependency in &module.deps { visit(state, dependency, created, visited, out); }
            }
            out.push(handle);
        }
        let mut order = Vec::new();
        visit(self, root, created, &mut BTreeSet::new(), &mut order);
        order
    }
}

fn append_module_cleanup_error(
    primary: Option<RuntimeError>,
    additional: RuntimeError,
) -> RuntimeError {
    match primary {
        Some(primary) => primary.with_cleanup(
            "Win16 module allocation cleanup retained all failures",
            additional,
        ),
        None => additional,
    }
}

struct RetainedModuleOwnerIdentityConflict {
    handle: u16,
    allocations: Vec<ModuleAllocation>,
}

impl fmt::Debug for RetainedModuleOwnerIdentityConflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RetainedModuleOwnerIdentityConflict")
            .field("handle", &self.handle)
            .field("allocation_count", &self.allocations.len())
            .finish()
    }
}

impl fmt::Display for RetainedModuleOwnerIdentityConflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter,
            "retained {} private allocation owners for conflicting module handle 0x{:04X}",
            self.allocations.len(), self.handle)
    }
}

impl Error for RetainedModuleOwnerIdentityConflict {}

fn module_format_failure(error: FormatError, host: &mut impl RuntimeHost)
    -> Result<Result<u16, u16>, RuntimeError> {
    if matches!(error, FormatError::GuestMemory(_) | FormatError::GuestMemoryRollback { .. }) {
        return Err(crate::runtime_error(error));
    }
    let code = if error == FormatError::AllocationFailed { 8 } else { 11 };
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
        format!("Win16 library load returns {code}: {error}")));
    Ok(Err(code))
}
