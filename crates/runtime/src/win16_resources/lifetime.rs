//! Resource references control the existing GlobalHeap discard/LRU policy.
use super::*;

impl Win16State {
    /// Change heap/LRU policy before publishing a new resource reference count.
    /// A reservation failure retains that count and its exact GlobalHandle.
    fn set_resource_discardability(
        &mut self,
        key: ResourceKey,
        identity: GlobalHandle,
        references: u32,
    ) -> Result<(), RuntimeError> {
        let info = self.heap.info(identity).map_err(crate::runtime_error)?;
        if !info.movable {
            return Ok(());
        }
        let eligible = self
            .resource_metadata(key.module, key.info)
            .is_some_and(ResourceMetadata::discardable);
        if eligible {
            self.heap
                .track_discard_transition_locks(identity)
                .map_err(crate::runtime_error)?;
        }
        let discardable = references == 0 && eligible;
        self.heap
            .set_discardable(identity, discardable)
            .map_err(crate::runtime_error)
    }

    /// Return an already-loaded resource and increment its LoadResource
    /// reference count. Stale handles are removed before the guest can observe
    /// a raw handle reused for a different GlobalHeap generation.
    pub(in crate::win16_runtime) fn retain_loaded_resource(
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
        let references = existing.references.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 resource reference count overflow",
            )
        })?;
        self.set_resource_discardability(key, existing.identity, references)?;
        self.resources
            .loaded
            .get_mut(&key)
            .expect("validated resource cache entry")
            .references = references;
        Ok(Some(existing.data))
    }

    /// Return the last live HGLOBAL associated with this resource without
    /// changing its LoadResource reference count. This is used for reloads.
    pub(in crate::win16_runtime) fn prior_resource_handle(&mut self, key: ResourceKey) -> u16 {
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
    pub(in crate::win16_runtime) fn commit_loaded_resource(
        &mut self,
        key: ResourceKey,
        data: u16,
    ) -> Result<u16, RuntimeError> {
        if data == 0 || self.resource_metadata(key.module, key.info).is_none() {
            return Ok(0);
        }
        let Some(identity) = self.live_global_identity(data) else {
            return Ok(0);
        };
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
                let references = existing.references.checked_add(1).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "Win16 resource reference count overflow",
                    )
                })?;
                self.set_resource_discardability(key, identity, references)?;
                self.resources
                    .loaded
                    .get_mut(&key)
                    .expect("validated resource cache entry")
                    .references = references;
                return Ok(data);
            }
        }
        self.set_resource_discardability(key, identity, 1)?;
        self.resources.loaded.insert(
            key,
            LoadedResource {
                data,
                identity,
                references: 1,
                retirement_cause: None,
            },
        );
        Ok(data)
    }

    /// Update a resource cache entry after LockResource reloads a discarded
    /// block. Its LoadResource reference count is preserved.
    pub(in crate::win16_runtime) fn commit_reloaded_resource(
        &mut self,
        key: ResourceKey,
        data: u16,
    ) -> Result<u16, RuntimeError> {
        if data == 0 || self.resource_metadata(key.module, key.info).is_none() {
            return Ok(0);
        }
        let Some(identity) = self.live_global_identity(data) else {
            return Ok(0);
        };
        if !self.resource_data_belongs_to(data, key, identity) {
            return Ok(0);
        }

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
        self.set_resource_discardability(key, identity, references)?;
        self.resources.loaded.insert(
            key,
            LoadedResource {
                data,
                identity,
                references,
                retirement_cause,
            },
        );
        self.discarded_handles.remove(&data);
        Ok(data)
    }

    pub(in crate::win16_runtime) fn release_resource(
        &mut self,
        data: u16,
    ) -> Result<ResourceRelease, RuntimeError> {
        if data == 0 {
            return Ok(ResourceRelease::Return(0));
        }
        let Some(key) = self.resource_key_for_data(data) else {
            return Ok(ResourceRelease::Return(data));
        };
        let Some(identity) = self.live_global_identity(data) else {
            return Ok(ResourceRelease::Return(data));
        };

        if let Some(entry) = self.resources.loaded.get(&key) {
            if entry.data == data && entry.identity == identity && entry.references > 1 {
                let references = entry.references - 1;
                self.set_resource_discardability(key, identity, references)?;
                self.resources
                    .loaded
                    .get_mut(&key)
                    .expect("validated resource release owner")
                    .references = references;
                return Ok(ResourceRelease::Return(0));
            }
        }

        let info = self.heap.info(identity).map_err(crate::runtime_error)?;
        let discardable = info.movable
            && self
                .resource_metadata(key.module, key.info)
                .is_some_and(ResourceMetadata::discardable);
        if discardable {
            // Reference release and guest locking have independent lifetimes.
            // GlobalHeap pins keep backing live until the last lock is released.
            self.set_resource_discardability(key, identity, 0)?;
            if let Some(entry) = self.resources.loaded.get_mut(&key) {
                if entry.data == data && entry.identity == identity {
                    entry.references = 0;
                }
            }
            return Ok(ResourceRelease::Return(0));
        }

        match self.global_free(data)? {
            0 => {
                if self
                    .resources
                    .loaded
                    .get(&key)
                    .is_some_and(|entry| entry.data == data && entry.identity == identity)
                {
                    self.resources.loaded.remove(&key);
                }
                self.remove_stale_allocation(data, identity);
                Ok(ResourceRelease::GlobalHeapReturn(0))
            }
            _ => Ok(ResourceRelease::GlobalHeapReturn(data)),
        }
    }
}
