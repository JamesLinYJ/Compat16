//! Win16 resource identities and resource-backed HGLOBAL storage.
//!
//! HRSRC values are module-local offsets of the corresponding NE nameinfo
//! record, measured from the NE header. Resource bytes are copied into the
//! runtime's existing guest GlobalHeap; this module owns no guest RAM.

use std::collections::BTreeMap;
use std::sync::Arc;

use formats::{NeResourceId, NeModule};
use guest_core::{GuestMemory, memory::Memory};
use win16_abi::{GlobalHandle, GlobalHeap, SelectorRef, Win16ResourceName};

use super::module_registry::ModuleState;
use super::{global_memory::GlobalTeardownResult, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const GMEM_MOVEABLE: u16 = 0x0002;
const NE_RESOURCE_MOVEABLE: u16 = 0x0010;
const NE_RESOURCE_DISCARDABLE: u16 = 0x1000;
// NE resource-table record sizes: alignment-shift WORD, TYPEINFO (type ID,
// count, reserved DWORD), and NAMEINFO (six WORD fields). These mirror the
// field reads in `formats::ne::parse_resource_table`.
const NE_RESOURCE_ALIGNMENT_SHIFT_BYTES: usize = 2;
const NE_RESOURCE_TYPEINFO_BYTES: usize = 8;
const NE_RESOURCE_NAMEINFO_BYTES: usize = 12;

pub(super) enum ResourceRelease {
    Return(u16),
    GlobalHeapReturn(u16),
}

/// A canonical resource identity. `info` is the NE-header-relative HRSRC.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ResourceKey {
    pub(super) module: u16,
    pub(super) info: u16,
}

/// Parsed metadata for one resource row. `offset` is a file offset suitable
/// for AccessResource; `length` is the uncompressed resource byte count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResourceMetadata {
    pub(super) key: ResourceKey,
    pub(super) type_index: usize,
    pub(super) offset: usize,
    pub(super) length: usize,
    pub(super) flags: u16,
}

#[derive(Clone)]
struct LoadedResource {
    data: u16,
    identity: GlobalHandle,
    references: u32,
    retirement_cause: Option<Arc<RuntimeError>>,
}

#[derive(Clone)]
struct AllocatedResource {
    key: ResourceKey,
    identity: GlobalHandle,
    retirement_cause: Option<Arc<RuntimeError>>,
}

/// Kernel-owned resource handles. The identity stored with each raw HGLOBAL
/// includes its heap and allocation generation, so reuse of the 16-bit word
/// cannot revive a stale resource cache entry.
pub(super) struct ResourceState {
    loaded: BTreeMap<ResourceKey, LoadedResource>,
    allocations: BTreeMap<u16, AllocatedResource>,
}

impl ResourceState {
    pub(super) fn new() -> Self {
        Self { loaded: BTreeMap::new(), allocations: BTreeMap::new() }
    }

    pub(super) fn module_for_identity(&self, identity: GlobalHandle) -> Option<u16> {
        self.loaded.iter().find_map(|(key, resource)|
            (resource.identity == identity).then_some(key.module))
            .or_else(|| self.allocations.values().find_map(|resource|
                (resource.identity == identity).then_some(resource.key.module)))
    }

    pub(super) fn has_live_teardown_retention(
        &self,
        module: u16,
        handles: &BTreeMap<u16, GlobalHandle>,
        heap: &GlobalHeap,
    ) -> Result<bool, win16_abi::Win16Error> {
        for (&key, resource) in &self.loaded {
            if key.module == module
                && handles.get(&resource.data).copied() == Some(resource.identity)
                && (heap.selector_alias_count(resource.identity)? != 0
                    || heap.page_lock_count(resource.identity)? != 0
                    || heap.internal_pin_count(resource.identity)? != 0)
            {
                return Ok(true);
            }
        }
        for (&data, resource) in &self.allocations {
            if resource.key.module == module
                && handles.get(&data).copied() == Some(resource.identity)
                && (heap.selector_alias_count(resource.identity)? != 0
                    || heap.page_lock_count(resource.identity)? != 0
                    || heap.internal_pin_count(resource.identity)? != 0)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Win16State {
    /// Find a resource by name and type. A zero module selects the task's main
    /// module for the resource APIs that document/use that convention.
    pub(super) fn find_resource(
        &self,
        module: u16,
        name: &Win16ResourceName,
        resource_type: &Win16ResourceName,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(module_handle) = self.resolve_resource_module(module, true) else {
            return Ok(0);
        };
        let Some(record) = self.modules.records.get(&module_handle) else {
            return Ok(0);
        };
        let Some(definition) = record.definition.as_ref() else {
            return Ok(0);
        };

        let mut row_offset = NE_RESOURCE_ALIGNMENT_SHIFT_BYTES;
        for entry in &definition.resource_types {
            row_offset = row_offset.checked_add(NE_RESOURCE_TYPEINFO_BYTES)
                .ok_or_else(|| resource_table_overflow(module_handle))?;
            let type_matches = resource_id_matches(&entry.id, resource_type, host)?;
            for resource in &entry.resources {
                let current_row = row_offset;
                row_offset = row_offset.checked_add(NE_RESOURCE_NAMEINFO_BYTES)
                    .ok_or_else(|| resource_table_overflow(module_handle))?;
                if !type_matches || !resource_id_matches(&resource.id, name, host)? {
                    continue;
                }
                let Some(info) = ne_resource_info(definition, current_row) else {
                    continue;
                };
                return Ok(info);
            }
        }
        Ok(0)
    }

    /// Resolve every resource type matching a SetResourceHandler type name.
    /// The returned pair is (canonical module handle, type-table index).
    pub(super) fn matching_resource_types(
        &self,
        module: u16,
        resource_type: &Win16ResourceName,
        host: &mut impl RuntimeHost,
    ) -> Result<Vec<(u16, usize)>, RuntimeError> {
        // SetResourceHandler's module argument is a real HINSTANCE; unlike
        // FindResource/LoadResource/SizeofResource, zero is not defaulted.
        let Some(module_handle) = self.resolve_resource_module(module, false) else {
            return Ok(Vec::new());
        };
        let Some(definition) = self.modules.records.get(&module_handle)
            .and_then(|record| record.definition.as_ref()) else {
            return Ok(Vec::new());
        };

        let mut matches = Vec::new();
        for (index, entry) in definition.resource_types.iter().enumerate() {
            if resource_id_matches(&entry.id, resource_type, host)? {
                matches.try_reserve(1).map_err(|_| RuntimeError::new(
                    Kind::ResourceExhausted, "Win16 resource type lookup cannot grow"))?;
                matches.push((module_handle, index));
            }
        }
        Ok(matches)
    }

    /// Resolve an HRSRC only within the owning module. Unloading modules remain
    /// addressable while their WEP callback runs; retired modules do not.
    pub(super) fn resource_metadata(&self, module: u16, info: u16) -> Option<ResourceMetadata> {
        let module_handle = self.resolve_resource_module(module, true)?;
        let record = self.modules.records.get(&module_handle)?;
        resource_metadata_for_definition(module_handle, record.definition.as_ref()?, info)
    }

    pub(super) fn size_of_resource(&self, module: u16, info: u16) -> u32 {
        self.resource_metadata(module, info)
            .and_then(|metadata| u32::try_from(metadata.length).ok())
            .unwrap_or(0)
    }

    /// Allocate a resource buffer through the common Win16 GlobalHeap. A
    /// nonzero requested size is the guest-requested allocation size; no
    /// resource bytes are copied by AllocResource itself.
    pub(super) fn alloc_resource(
        &mut self,
        module: u16,
        info: u16,
        requested_size: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if module == 0 { return Ok(0); }
        let Some(metadata) = self.resource_metadata(module, info) else { return Ok(0); };
        let Some(size) = (if requested_size == 0 {
            u32::try_from(metadata.length).ok()
        } else {
            Some(requested_size)
        }) else {
            return Ok(0);
        };

        let flags = if metadata.flags & NE_RESOURCE_MOVEABLE != 0 { GMEM_MOVEABLE } else { 0 };
        let data = self.global_alloc(flags, size, memory, host)?;
        if data == 0 { return Ok(0); }
        let Some(identity) = self.live_global_identity(data) else {
            let _ = self.global_free(data)?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 AllocResource lost its newly allocated global handle"));
        };
        self.resources.allocations.insert(data, AllocatedResource {
            key: metadata.key,
            identity,
            retirement_cause: None,
        });
        Ok(data)
    }

    /// Return an already-loaded resource and increment its LoadResource
    /// reference count. Stale handles are removed before the guest can observe
    /// a raw handle reused for a different GlobalHeap generation.
    pub(super) fn retain_loaded_resource(
        &mut self,
        key: ResourceKey,
    ) -> Result<Option<u16>, RuntimeError> {
        let Some(existing) = self.resources.loaded.get(&key).cloned() else {
            return Ok(None);
        };
        if !self.is_live_global(existing.data, existing.identity) {
            self.resources.loaded.remove(&key);
            self.remove_stale_allocation(existing.data, existing.identity);
            return Ok(None);
        }
        if self.discarded_handles.contains(&existing.data) {
            // Keep the outstanding LoadResource reference count. The caller
            // will reload this same HGLOBAL before returning it to the guest.
            return Ok(None);
        }
        let entry = self.resources.loaded.get_mut(&key).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 resource cache entry disappeared"))?;
        entry.references = entry.references.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 resource reference count overflow"))?;
        Ok(Some(existing.data))
    }

    /// Return the last live HGLOBAL associated with this resource without
    /// changing its LoadResource reference count. This is used for reloads.
    pub(super) fn prior_resource_handle(&mut self, key: ResourceKey) -> u16 {
        if let Some(existing) = self.resources.loaded.get(&key).cloned() {
            if self.is_live_global(existing.data, existing.identity) {
                return existing.data;
            }
            self.resources.loaded.remove(&key);
            self.remove_stale_allocation(existing.data, existing.identity);
        }

        0
    }

    /// Associate a handler/default-loader result with a resource. Each
    /// successful LoadResource contributes one reference, including when a
    /// nested/reentrant load commits the same live HGLOBAL.
    pub(super) fn commit_loaded_resource(
        &mut self,
        key: ResourceKey,
        data: u16,
    ) -> Result<u16, RuntimeError> {
        if data == 0 || self.resource_metadata(key.module, key.info).is_none() {
            return Ok(0);
        }
        let Some(identity) = self.live_global_identity(data) else { return Ok(0); };
        if !self.resource_data_belongs_to(data, key, identity) {
            return Ok(0);
        }
        if let Some(existing) = self.resources.loaded.get(&key).cloned() {
            if !self.is_live_global(existing.data, existing.identity) {
                self.resources.loaded.remove(&key);
            } else if existing.data != data || existing.identity != identity {
                // Two live HGLOBALs cannot simultaneously represent the same
                // resource cache slot. A normal load reaches this method only
                // after a cache miss; reloads use commit_reloaded_resource.
                return Ok(0);
            } else {
                let entry = self.resources.loaded.get_mut(&key).ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "Win16 resource cache entry disappeared"))?;
                entry.references = entry.references.checked_add(1).ok_or_else(|| RuntimeError::new(
                    Kind::ResourceExhausted, "Win16 resource reference count overflow"))?;
                return Ok(data);
            }
        }
        self.resources.loaded.insert(key, LoadedResource {
            data, identity, references: 1, retirement_cause: None,
        });
        Ok(data)
    }

    /// Update a resource cache entry after LockResource reloads a discarded
    /// block. Its LoadResource reference count is preserved.
    pub(super) fn commit_reloaded_resource(
        &mut self,
        key: ResourceKey,
        data: u16,
    ) -> Result<u16, RuntimeError> {
        if data == 0 || self.resource_metadata(key.module, key.info).is_none() {
            return Ok(0);
        }
        let Some(identity) = self.live_global_identity(data) else { return Ok(0); };
        if !self.resource_data_belongs_to(data, key, identity) { return Ok(0); }

        let (references, retirement_cause) = match self.resources.loaded.get(&key).cloned() {
            Some(existing) if self.is_live_global(existing.data, existing.identity) => {
                if existing.data != data || existing.identity != identity {
                    // Preserve the HGLOBAL observed by the caller. Returning a
                    // different raw block would make a later FreeResource on
                    // the original handle release the wrong allocation.
                    return Ok(0);
                }
                (existing.references, existing.retirement_cause)
            }
            Some(_) | None => (0, None),
        };
        self.resources.loaded.insert(key, LoadedResource {
            data, identity, references, retirement_cause,
        });
        self.discarded_handles.remove(&data);
        Ok(data)
    }

    /// Copy the resource's bytes from its owned NE image into the shared guest
    /// global block. For a discarded/undersized block, resize the same
    /// GlobalHeap identity and rebind its selector before writing any bytes.
    pub(super) fn default_resource_load(
        &mut self,
        data: u16,
        key: ResourceKey,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(metadata) = self.resource_metadata(key.module, key.info) else { return Ok(0); };
        let Some(record) = self.modules.records.get(&key.module) else { return Ok(0); };
        let end = metadata.offset.checked_add(metadata.length).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 resource file range overflow"))?;
        host.observe_win16_io(&crate::Win16IoEvent::Resource {
            operation: "resource-load", module: key.module, resource: key.info,
            offset: metadata.offset, length: metadata.length, data,
        });
        let Some(source) = record.image.get(metadata.offset..end) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 resource range is outside its owned module image"));
        };
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(source.len()).map_err(|_| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 resource data cannot be copied into owned staging"))?;
        bytes.extend_from_slice(source);

        let target_size = u32::try_from(bytes.len()).map_err(|_| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 resource is too large for a global block"))?.max(1);
        let (handle, is_new) = if data == 0 {
            let flags = if metadata.flags & NE_RESOURCE_MOVEABLE != 0 { GMEM_MOVEABLE } else { 0 };
            let allocated = self.global_alloc(flags, target_size, memory, host)?;
            if allocated == 0 { return Ok(0); }
            (allocated, true)
        } else {
            (data, false)
        };

        if is_new && self.live_global_identity(handle).is_none() {
            let _ = self.global_free(handle)?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 resource allocation is missing its global identity"));
        }

        let result = self.fill_resource_block(handle, key, &bytes, target_size, memory);
        match result {
            Ok(true) => {
                self.discarded_handles.remove(&handle);
                let Some(identity) = self.live_global_identity(handle) else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 resource loader lost its global handle after copying"));
                };
                self.resources.allocations.insert(handle, AllocatedResource {
                    key, identity, retirement_cause: None,
                });
                Ok(handle)
            }
            Ok(false) => {
                if is_new { let _ = self.global_free(handle)?; }
                Ok(0)
            }
            Err(error) => {
                if is_new { let _ = self.global_free(handle)?; }
                Err(error)
            }
        }
    }

    /// Resolve a live resource data handle to its resource key. Exact
    /// GlobalHandle equality is required; raw HGLOBAL reuse is not enough.
    pub(super) fn resource_key_for_data(&mut self, data: u16) -> Option<ResourceKey> {
        if data == 0 { return None; }
        let identity = self.live_global_identity(data);
        if let Some(existing) = self.resources.loaded.iter()
            .find_map(|(&key, entry)| (entry.data == data).then_some((key, entry.clone()))) {
            if identity == Some(existing.1.identity) { return Some(existing.0); }
            self.resources.loaded.remove(&existing.0);
            self.remove_stale_allocation(data, existing.1.identity);
        }
        if let Some(allocation) = self.resources.allocations.get(&data).cloned() {
            if identity == Some(allocation.identity) { return Some(allocation.key); }
            self.remove_stale_allocation(data, allocation.identity);
        }
        None
    }

    /// Query resource ownership without changing the resource cache. A reused
    /// HGLOBAL cannot acquire the resource type of an earlier allocation.
    pub(super) fn toolhelp_resource_info(
        &self, data: u16, identity: GlobalHandle,
    ) -> Option<(u16, u16)> {
        if self.live_global_identity(data) != Some(identity) { return None; }
        let key = self.resources.loaded.iter().find_map(|(&key, entry)|
            (entry.data == data && entry.identity == identity).then_some(key))
            .or_else(|| self.resources.allocations.get(&data)
                .filter(|entry| entry.identity == identity).map(|entry| entry.key))?;
        let metadata = self.resource_metadata(key.module, key.info)?;
        let definition = self.modules.records.get(&key.module)?.definition.as_ref()?;
        use win16_abi::toolhelp_abi::*;
        let resource_type = match &definition.resource_types.get(metadata.type_index)?.id {
            NeResourceId::Numeric(value @ (GD_CURSORCOMPONENT | GD_BITMAP | GD_ICONCOMPONENT
                | GD_MENU | GD_DIALOG | GD_STRING | GD_FONTDIR | GD_FONT | GD_ACCELERATORS
                | GD_RCDATA | GD_ERRTABLE | GD_CURSOR | GD_ICON | GD_NAMETABLE)) => *value,
            _ => GD_USERDEFINED,
        };
        Some((key.module, resource_type))
    }

    /// Release one resource usage reference. A still-locked final HGLOBAL is
    /// retained with its reference so the caller can unlock and retry safely.
    pub(super) fn release_resource(&mut self, data: u16) -> Result<ResourceRelease, RuntimeError> {
        if data == 0 { return Ok(ResourceRelease::Return(0)); }
        let Some(key) = self.resource_key_for_data(data) else { return Ok(ResourceRelease::Return(data)); };
        let Some(identity) = self.live_global_identity(data) else { return Ok(ResourceRelease::Return(data)); };

        if let Some(entry) = self.resources.loaded.get_mut(&key) {
            if entry.data == data && entry.identity == identity && entry.references > 1 {
                entry.references -= 1;
                return Ok(ResourceRelease::Return(0));
            }
        }

        let discardable = self.resource_metadata(key.module, key.info)
            .is_some_and(|metadata| metadata.flags & NE_RESOURCE_DISCARDABLE != 0
                && metadata.flags & NE_RESOURCE_MOVEABLE != 0);
        if discardable {
            let info = self.heap.info(identity).map_err(crate::runtime_error)?;
            if info.lock_count != 0 { return Ok(ResourceRelease::Return(data)); }
            if let Some(entry) = self.resources.loaded.get_mut(&key) {
                if entry.data == data && entry.identity == identity { entry.references = 0; }
            }
            return Ok(ResourceRelease::Return(0));
        }

        match self.global_free(data)? {
            0 => {
                if self.resources.loaded.get(&key).is_some_and(|entry|
                    entry.data == data && entry.identity == identity)
                {
                    self.resources.loaded.remove(&key);
                }
                self.remove_stale_allocation(data, identity);
                Ok(ResourceRelease::GlobalHeapReturn(0))
            }
            _ => Ok(ResourceRelease::GlobalHeapReturn(data)),
        }
    }

    /// Release every resource-owned global block when the module is retired.
    /// Teardown invalidates outstanding locks through the generation-checked
    /// global-memory teardown path rather than pretending the block was freed.
    pub(super) fn retire_module_resources(&mut self, module: u16) -> Result<bool, RuntimeError> {
        let mut blocks = BTreeMap::<u16, GlobalHandle>::new();
        for (&key, entry) in &self.resources.loaded {
            if key.module == module
                && self.global_handles.get(&entry.data).copied() == Some(entry.identity)
            {
                blocks.insert(entry.data, entry.identity);
            }
        }
        for (&data, entry) in &self.resources.allocations {
            if entry.key.module == module
                && self.global_handles.get(&data).copied() == Some(entry.identity)
            {
                blocks.insert(data, entry.identity);
            }
        }

        let mut deferred = false;
        let mut failure = None;
        for (data, identity) in blocks {
            match self.free_global_on_teardown(data, identity) {
                Ok(GlobalTeardownResult::Freed) => {
                    self.resources.loaded.retain(|key, entry| !(key.module == module
                        && entry.data == data && entry.identity == identity));
                    self.resources.allocations.retain(|handle, entry| !(*handle == data
                        && entry.key.module == module && entry.identity == identity));
                }
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    deferred = true;
                    let error = retained.retained_error("Win16 resource owner")
                        .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                            "resource teardown lost its typed retained result"));
                    let error = self.remember_resource_retirement_failure(
                        module, data, identity, error,
                    );
                    // A live alias/page/internal pin is a normal deferred
                    // module-reaper state. Keep its typed cause on the exact
                    // resource owner, but let FreeLibrary finish so the guest
                    // can later release that pin.
                    drop(error);
                }
                Err(error) => {
                    deferred = true;
                    let error = self.remember_resource_retirement_failure(
                        module, data, identity, error,
                    );
                    remember_resource_cleanup_error(&mut failure, error);
                }
            }
        }
        if deferred {
            self.module_reap_pending = true;
            if let Some(record) = self.modules.records.get_mut(&module) {
                record.resources_retirement_deferred = true;
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        if deferred {
            // Keep the resource identity map and its module record as roots;
            // a later safe-point reaper can retry after guest aliases unlock.
            return Ok(true);
        }
        self.resources.loaded.retain(|key, _| key.module != module);
        self.resources.allocations.retain(|_, entry| entry.key.module != module);
        Ok(false)
    }

    fn remember_resource_retirement_failure(
        &mut self,
        module: u16,
        data: u16,
        identity: GlobalHandle,
        error: RuntimeError,
    ) -> RuntimeError {
        let existing = self.resources.loaded.values()
            .find(|entry| entry.data == data && entry.identity == identity)
            .and_then(|entry| entry.retirement_cause.clone())
            .or_else(|| self.resources.allocations.get(&data)
                .filter(|entry| entry.key.module == module && entry.identity == identity)
                .and_then(|entry| entry.retirement_cause.clone()));
        let (cause, report) = if let Some(cause) = existing {
            let report = RuntimeError::with_source(
                cause.kind().with_cleanup(error.kind()),
                "Win16 resource owner retry retained its first typed cleanup cause",
                Arc::clone(&cause),
            ).with_cleanup("retrying Win16 resource owner retirement", error);
            (cause, report)
        } else {
            let cause = Arc::new(error);
            let report = RuntimeError::with_source(
                cause.kind(),
                "Win16 resource owner retained its initial typed cleanup cause",
                Arc::clone(&cause),
            );
            (cause, report)
        };
        for entry in self.resources.loaded.values_mut().filter(|entry|
            entry.data == data && entry.identity == identity)
        {
            entry.retirement_cause.get_or_insert_with(|| Arc::clone(&cause));
        }
        if let Some(entry) = self.resources.allocations.get_mut(&data)
            .filter(|entry| entry.key.module == module && entry.identity == identity)
        {
            entry.retirement_cause.get_or_insert_with(|| Arc::clone(&cause));
        }
        report
    }

    fn resolve_resource_module(&self, input: u16, zero_is_main: bool) -> Option<u16> {
        let handle = if input == 0 {
            if !zero_is_main { return None; }
            self.modules.main
        } else {
            self.modules.by_handle(input)?
        };
        self.modules.records.get(&handle)
            .filter(|record| record.external_application.is_none()
                && record.state != ModuleState::Retired)
            .map(|record| record.handle)
    }

    fn live_global_identity(&self, data: u16) -> Option<GlobalHandle> {
        let identity = self.global_handles.get(&data).copied()?;
        if self.heap.info(identity).is_err() { return None; }
        let selector = self.global_selectors.get(&data).copied()?;
        self.selectors.describe(selector).ok()?;
        Some(identity)
    }

    fn is_live_global(&self, data: u16, identity: GlobalHandle) -> bool {
        self.live_global_identity(data) == Some(identity)
    }

    fn resource_data_belongs_to(&self, data: u16, key: ResourceKey, identity: GlobalHandle) -> bool {
        if self.resources.allocations.get(&data).is_some_and(|entry|
            entry.identity == identity && entry.key != key)
        {
            return false;
        }
        self.resources.loaded.iter().all(|(existing_key, entry)|
            entry.data != data || entry.identity != identity || *existing_key == key)
    }

    fn remove_stale_allocation(&mut self, data: u16, identity: GlobalHandle) {
        if self.resources.allocations.get(&data).is_some_and(|entry| entry.identity == identity) {
            self.resources.allocations.remove(&data);
        }
    }

    fn fill_resource_block(
        &mut self,
        data: u16,
        key: ResourceKey,
        bytes: &[u8],
        target_size: u32,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some(identity) = self.live_global_identity(data) else {
            return Ok(false);
        };
        if !self.resource_data_belongs_to(data, key, identity) {
            return Ok(false);
        }
        let before = self.heap.info(identity).map_err(crate::runtime_error)?;
        let selector = self.global_selectors.get(&data).copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 resource global selector is missing"))?;

        if before.size < target_size {
            let mut selector_updates = Vec::new();
            let resized = match self.heap.realloc_global(
                identity,
                target_size,
                0,
                Some(selector),
                memory,
                &mut self.selectors,
                &mut selector_updates,
            ) {
                Ok(resized) => resized,
                Err(error) if is_resource_capacity_error(&error) => return Ok(false),
                Err(error) => return Err(crate::runtime_error(error)),
            };
            debug_assert_eq!(resized, identity);
            self.apply_resource_selector_updates(&selector_updates);
        }

        let current = self.heap.info(identity).map_err(crate::runtime_error)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > u64::from(current.size) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 resource copy exceeds its resized global block"));
        }
        memory.validate_write(current.base, bytes.len()).map_err(crate::runtime_error)?;
        memory.write(current.base, bytes).map_err(crate::runtime_error)?;
        Ok(true)
    }

    fn apply_resource_selector_updates(&mut self, updates: &[(SelectorRef, SelectorRef)]) {
        for &(old, replacement) in updates {
            for reference in self.global_selectors.values_mut() {
                if *reference == old { *reference = replacement; }
            }
            for reference in self.allocated_selector_aliases.values_mut() {
                if *reference == old { *reference = replacement; }
            }
            for reference in self.api_allocated_selectors.values_mut() {
                if *reference == old { *reference = replacement; }
            }
            for record in self.modules.records.values_mut() {
                for allocation in &mut record.allocations {
                    if allocation.selector == old { allocation.selector = replacement; }
                }
            }
        }
    }
}

fn resource_metadata_for_definition(
    module: u16,
    definition: &NeModule,
    info: u16,
) -> Option<ResourceMetadata> {
    let mut row_offset = NE_RESOURCE_ALIGNMENT_SHIFT_BYTES;
    let table_offset = usize::from(definition.header.resource_table_offset);
    for (type_index, entry) in definition.resource_types.iter().enumerate() {
        row_offset = row_offset.checked_add(NE_RESOURCE_TYPEINFO_BYTES)?;
        for resource in &entry.resources {
            let header_relative = table_offset.checked_add(row_offset)?;
            if u16::try_from(header_relative).ok()? == info {
                return Some(ResourceMetadata {
                    key: ResourceKey { module, info },
                    type_index,
                    offset: resource.file_offset,
                    length: resource.byte_length,
                    flags: resource.flags,
                });
            }
            row_offset = row_offset.checked_add(NE_RESOURCE_NAMEINFO_BYTES)?;
        }
    }
    None
}

fn ne_resource_info(definition: &NeModule, row_offset: usize) -> Option<u16> {
    let header_relative = usize::from(definition.header.resource_table_offset)
        .checked_add(row_offset)?;
    u16::try_from(header_relative).ok()
}

fn resource_id_matches(
    stored: &NeResourceId,
    requested: &Win16ResourceName,
    host: &mut impl RuntimeHost,
) -> Result<bool, RuntimeError> {
    match requested {
        Win16ResourceName::Id(id) => Ok(matches!(stored, NeResourceId::Numeric(value) if value == id)),
        Win16ResourceName::Name(name) => {
            if let Some(number) = decimal_resource_id(name) {
                return Ok(matches!(stored, NeResourceId::Numeric(value) if *value == number));
            }
            match stored {
                NeResourceId::Numeric(_) => Ok(false),
                NeResourceId::Name(value) => Ok(host.win16_ansi_compare(name, value, true)? == 0),
            }
        }
    }
}

fn decimal_resource_id(value: &[u8]) -> Option<u16> {
    let digits = value.strip_prefix(b"#")?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) { return None; }
    digits.iter().try_fold(0_u16, |number, digit| {
        number.checked_mul(10)?.checked_add(u16::from(*digit - b'0'))
    })
}

fn resource_table_overflow(module: u16) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant,
        format!("Win16 module 0x{module:04X} resource table offset overflow"))
}

fn remember_resource_cleanup_error(
    slot: &mut Option<RuntimeError>,
    error: RuntimeError,
) {
    *slot = Some(match slot.take() {
        None => error,
        Some(primary) => primary.with_cleanup("multiple Win16 resource-owner cleanup failures", error),
    });
}

fn is_resource_capacity_error(error: &win16_abi::Win16Error) -> bool {
    matches!(error,
        win16_abi::Win16Error::OutOfMemory
            | win16_abi::Win16Error::Locked
            | win16_abi::Win16Error::InvalidRange
            | win16_abi::Win16Error::SelectorTableFull
            | win16_abi::Win16Error::SelectorBlockInterior)
}
