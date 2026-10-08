use super::*;

impl Win16AutomationState {
    /// Allocates a descriptor and its data as separate tracked guest blocks.
    /// This permits the Win16 `SafeArrayDestroyData` and
    /// `SafeArrayDestroyDescriptor` lifetimes to remain independent.
    pub(crate) fn allocate_safe_array(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        mut descriptor: SafeArray16,
        data: &[u8],
    ) -> Result<u32, RuntimeError> {
        if descriptor.element_size == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY element size is zero",
            ));
        }
        validate_array_data(&descriptor, data.len())?;
        descriptor.data = 0;
        let mut descriptor_bytes = descriptor.encode().map_err(array_abi_error)?;
        let (descriptor_handle, descriptor_base) =
            allocate_guest_bytes(heap, selectors, memory, owner, &descriptor_bytes)?;
        let data_allocation = if data.is_empty() {
            None
        } else {
            match allocate_safe_array_data_bytes(heap, selectors, memory, owner, data) {
                Ok(allocation) => Some(allocation),
                Err(error) => {
                    free_untracked_allocation(heap, selectors, descriptor_handle)
                        .map_err(|cleanup| {
                            RuntimeError::with_source(
                                Kind::InternalInvariant,
                                "SAFEARRAY construction failed and its descriptor allocation could not be rolled back",
                                cleanup,
                            )
                        })?;
                    return Err(error);
                }
            }
        };
        descriptor.data = data_allocation.map_or(0, |(_, base)| base.far_value());
        if let Err(error) = descriptor.encode_into(&mut descriptor_bytes) {
            let error = array_abi_error(error);
            if let Some((data_handle, _)) = data_allocation {
                free_untracked_allocation(heap, selectors, data_handle).map_err(|cleanup| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "SAFEARRAY descriptor re-encode failed and data rollback also failed",
                        cleanup,
                    )
                })?;
            }
            free_untracked_allocation(heap, selectors, descriptor_handle).map_err(|cleanup| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "SAFEARRAY descriptor re-encode failed and descriptor rollback also failed",
                    cleanup,
                )
            })?;
            return Err(error);
        }
        if let Err(error) =
            write_guest_far_bytes(selectors, memory, descriptor_base, &descriptor_bytes)
        {
            if let Some((data_handle, _)) = data_allocation {
                free_untracked_allocation(heap, selectors, data_handle).map_err(|cleanup| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "SAFEARRAY descriptor write failed and data rollback also failed",
                        cleanup,
                    )
                })?;
            }
            free_untracked_allocation(heap, selectors, descriptor_handle).map_err(|cleanup| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "SAFEARRAY descriptor write failed and descriptor rollback also failed",
                    cleanup,
                )
            })?;
            return Err(error);
        }

        let far = descriptor_base.far_value();
        if self.allocations.contains_key(&far)
            || data_allocation
                .is_some_and(|(_, base)| self.allocations.contains_key(&base.far_value()))
        {
            if let Some((data_handle, _)) = data_allocation {
                free_untracked_allocation(heap, selectors, data_handle)?;
            }
            free_untracked_allocation(heap, selectors, descriptor_handle)?;
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 SAFEARRAY guest FAR value was allocated twice",
            ));
        }
        self.allocations.insert(
            far,
            GuestAllocation {
                owner,
                handle: descriptor_handle,
                kind: AllocationKind::SafeArrayDescriptor,
                retirement_cause: None,
            },
        );
        if let Some((handle, base)) = data_allocation {
            self.allocations.insert(
                base.far_value(),
                GuestAllocation {
                    owner,
                    handle,
                    kind: AllocationKind::SafeArrayData,
                    retirement_cause: None,
                },
            );
        }
        Ok(far)
    }

    /// Copies a descriptor and its data through checked selector accesses.
    /// This also accepts guest arrays not created by this state table.
    pub(crate) fn read_safe_array(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        far: u32,
    ) -> Result<(SafeArray16, Vec<u8>), RuntimeError> {
        let (_, descriptor) = read_safe_array_descriptor(selectors, memory, far)?;
        let data_length = expected_array_data_length(&descriptor)?;
        if data_length > MAX_AUTOMATION_ALLOCATION {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 SAFEARRAY data exceeds the bounded copy size",
            ));
        }
        let data = if data_length == 0 {
            Vec::new()
        } else {
            let data_pointer = selectors
                .pointer_from_far(descriptor.data)
                .map_err(crate::runtime_error)?;
            read_safe_array_huge_bytes(selectors, memory, data_pointer, data_length)?
        };
        Ok((descriptor, data))
    }

    pub(crate) fn read_safe_array_descriptor(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        far: u32,
    ) -> Result<SafeArray16, RuntimeError> {
        read_safe_array_descriptor(selectors, memory, far).map(|(_, descriptor)| descriptor)
    }

    pub(crate) fn safe_array_lock(
        &self,
        selectors: &SelectorTable,
        memory: &mut Memory,
        far: u32,
    ) -> Result<(), RuntimeError> {
        let (pointer, mut descriptor) = read_safe_array_descriptor(selectors, memory, far)?;
        descriptor.locks = descriptor.locks.checked_add(1).ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput, "Win16 SAFEARRAY lock count overflow")
        })?;
        write_safe_array_descriptor(selectors, memory, pointer, &descriptor)
    }

    pub(crate) fn safe_array_unlock(
        &self,
        selectors: &SelectorTable,
        memory: &mut Memory,
        far: u32,
    ) -> Result<(), RuntimeError> {
        let (pointer, mut descriptor) = read_safe_array_descriptor(selectors, memory, far)?;
        descriptor.locks = descriptor.locks.checked_sub(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY has no outstanding lock",
            )
        })?;
        write_safe_array_descriptor(selectors, memory, pointer, &descriptor)
    }

    pub(crate) fn safe_array_access_data(
        &self,
        selectors: &SelectorTable,
        memory: &mut Memory,
        far: u32,
    ) -> Result<u32, RuntimeError> {
        let data = self
            .read_safe_array_descriptor(selectors, memory, far)?
            .data;
        self.safe_array_lock(selectors, memory, far)?;
        Ok(data)
    }

    pub(crate) fn safe_array_alloc_descriptor(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        dimensions: u16,
    ) -> Result<u32, RuntimeError> {
        if dimensions == 0 {
            return Err(array_abi_error(
                AutomationAbiError::InvalidSafeArrayDimensions,
            ));
        }
        let mut bounds = Vec::new();
        bounds
            .try_reserve_exact(usize::from(dimensions))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate Win16 SAFEARRAY bounds",
                    error,
                )
            })?;
        bounds.resize(
            usize::from(dimensions),
            compat_services::automation::SafeArrayBound16 {
                elements: 0,
                lower_bound: 0,
            },
        );
        let descriptor = SafeArray16 {
            dimensions,
            features: 0,
            element_size: 0,
            locks: 0,
            handle: 0,
            data: 0,
            bounds,
        };
        let bytes = descriptor.encode().map_err(array_abi_error)?;
        let (handle, base) = allocate_guest_bytes(heap, selectors, memory, owner, &bytes)?;
        let far = base.far_value();
        self.record_allocation(
            far,
            owner,
            handle,
            AllocationKind::SafeArrayDescriptor,
            heap,
            selectors,
        )?;
        Ok(far)
    }

    pub(crate) fn safe_array_alloc_data(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        far: u32,
    ) -> Result<(), RuntimeError> {
        let (pointer, mut descriptor) = read_safe_array_descriptor(selectors, memory, far)?;
        self.require_owned_allocation(owner, far, AllocationKind::SafeArrayDescriptor)?;
        if descriptor.data != 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY data is already allocated",
            ));
        }
        if descriptor.element_size == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY element size has not been initialized",
            ));
        }
        let length = expected_array_data_length(&descriptor)?;
        if length == 0 {
            return Ok(());
        }
        if length > MAX_AUTOMATION_ALLOCATION {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 SAFEARRAY data exceeds the bounded guest allocation size",
            ));
        }
        let mut zeroes = Vec::new();
        zeroes.try_reserve_exact(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 SAFEARRAY zero-initialized data",
                error,
            )
        })?;
        zeroes.resize(length, 0);
        let (handle, base) =
            allocate_safe_array_data_bytes(heap, selectors, memory, owner, &zeroes)?;
        descriptor.data = base.far_value();
        if let Err(error) = write_safe_array_descriptor(selectors, memory, pointer, &descriptor) {
            free_untracked_allocation(heap, selectors, handle).map_err(|cleanup| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "SAFEARRAY data descriptor write failed and its allocation rollback failed",
                    cleanup,
                )
            })?;
            return Err(error);
        }
        let data_far = base.far_value();
        if self.allocations.contains_key(&data_far) {
            descriptor.data = 0;
            let descriptor_rollback =
                write_safe_array_descriptor(selectors, memory, pointer, &descriptor);
            let allocation_rollback = free_untracked_allocation(heap, selectors, handle);
            if let Err(error) = descriptor_rollback {
                allocation_rollback.map_err(|cleanup| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "duplicate SAFEARRAY data identity caused descriptor rollback and allocation rollback failures",
                        cleanup,
                    )
                })?;
                return Err(RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "duplicate SAFEARRAY data identity left the descriptor rollback incomplete",
                    error,
                ));
            }
            allocation_rollback?;
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 SAFEARRAY data FAR value was allocated twice",
            ));
        }
        self.allocations.insert(
            data_far,
            GuestAllocation {
                owner,
                handle,
                kind: AllocationKind::SafeArrayData,
                retirement_cause: None,
            },
        );
        Ok(())
    }

    pub(crate) fn safe_array_dimensions(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        far: u32,
    ) -> Result<u16, RuntimeError> {
        Ok(self
            .read_safe_array_descriptor(selectors, memory, far)?
            .dimensions)
    }

    pub(crate) fn safe_array_element_size(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        far: u32,
    ) -> Result<u16, RuntimeError> {
        Ok(self
            .read_safe_array_descriptor(selectors, memory, far)?
            .element_size)
    }

    /// SAFEARRAY dimension numbers are one-based. Dimension one addresses the
    /// last bound in the guest descriptor; SafeArrayCreate stores the supplied
    /// bounds in reverse order.
    pub(crate) fn safe_array_bound(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        far: u32,
        dimension: u16,
    ) -> Result<(i32, i32), RuntimeError> {
        if dimension == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY dimension numbers start at one",
            ));
        }
        let descriptor = self.read_safe_array_descriptor(selectors, memory, far)?;
        let index = descriptor
            .dimensions
            .checked_sub(dimension)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "Win16 SAFEARRAY dimension is outside its descriptor",
                )
            })?;
        let bound = descriptor.bounds.get(usize::from(index)).ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY dimension is outside its descriptor",
            )
        })?;
        let upper = i64::from(bound.lower_bound) + i64::from(bound.elements) - 1;
        let upper = i32::try_from(upper).map_err(|error| {
            RuntimeError::with_source(
                Kind::InvalidInput,
                "Win16 SAFEARRAY upper bound exceeds LONG",
                error,
            )
        })?;
        Ok((bound.lower_bound, upper))
    }
}
