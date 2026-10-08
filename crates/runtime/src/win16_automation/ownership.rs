use super::*;

impl Win16AutomationState {
    pub(crate) fn release_safe_array(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &Memory,
        owner: OwnerId,
        far: u32,
    ) -> Result<(), RuntimeError> {
        if far == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY destroy received a null descriptor",
            ));
        }
        let (_, descriptor) = read_safe_array_descriptor(selectors, memory, far)?;
        if descriptor.locks != 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY cannot be destroyed while locked",
            ));
        }
        self.require_owned_allocation(owner, far, AllocationKind::SafeArrayDescriptor)?;
        if descriptor.data != 0 {
            self.release_allocation(
                heap,
                selectors,
                owner,
                descriptor.data,
                AllocationKind::SafeArrayData,
            )?;
        }
        self.release_allocation(
            heap,
            selectors,
            owner,
            far,
            AllocationKind::SafeArrayDescriptor,
        )
    }

    /// Frees this task's tracked guest allocations during task teardown.
    /// Call before the runtime's general owner-wide GlobalHeap cleanup.
    pub(crate) fn release_owner_contents(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &Memory,
        owner: OwnerId,
        warn: &mut impl FnMut(Diagnostic),
    ) -> Result<(), RuntimeError> {
        let mut interface_warning_emitted = false;
        let mut reject_interface =
            |_action: AutomationInterfaceAction, _guest_value: u32| -> Result<(), RuntimeError> {
                if !interface_warning_emitted {
                    warn(Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "Win16 OLE2DISP COM interface values are unsupported during guest teardown",
                    ));
                    interface_warning_emitted = true;
                }
                Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "Win16 OLE2DISP COM interface reference cannot be released",
                ))
            };
        let mut array_fars = Vec::new();
        array_fars
            .try_reserve_exact(self.allocations.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate Win16 Automation teardown list",
                    error,
                )
            })?;
        array_fars.extend(self.allocations.iter().filter_map(|(&far, allocation)| {
            (allocation.owner == owner && allocation.kind == AllocationKind::SafeArrayDescriptor)
                .then_some(far)
        }));

        // SAFEARRAY VARIANT elements can own nested arrays. A guest can also
        // construct aliases or cycles by rewriting its descriptor, so visit
        // every array and BSTR allocation at most once during task teardown.
        let preflight = guest_ops::preflight_owner_array_contents(
            self,
            selectors,
            memory,
            owner,
            &array_fars,
            &mut reject_interface,
        );
        let mut first_error = preflight.err();
        if first_error.is_none() {
            let mut visited_arrays = BTreeSet::new();
            let mut visited_bstrs = BTreeSet::new();
            for far in array_fars {
                if !self.allocations.contains_key(&far) {
                    continue;
                }
                if let Err(error) = guest_ops::release_owner_array_contents(
                    self,
                    heap,
                    selectors,
                    memory,
                    owner,
                    far,
                    &mut visited_arrays,
                    &mut visited_bstrs,
                    &mut reject_interface,
                ) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    pub(crate) fn owner_allocations(
        &self,
        owner: OwnerId,
    ) -> Result<Vec<(u32, GlobalHandle)>, RuntimeError> {
        let mut allocations = Vec::new();
        allocations.try_reserve_exact(self.allocations.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve Win16 Automation owner teardown snapshot", error))?;
        allocations.extend(self.allocations.iter().filter_map(|(&far, allocation)|
            (allocation.owner == owner).then_some((far, allocation.handle))));
        Ok(allocations)
    }

    pub(crate) fn retire_allocation(
        &mut self,
        far: u32,
        expected: GlobalHandle,
    ) -> Result<(), RuntimeError> {
        match self.allocations.get(&far) {
            Some(allocation) if allocation.handle == expected => {
                self.allocations.remove(&far);
                Ok(())
            }
            Some(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 Automation teardown allocation identity changed")),
            None => Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 Automation teardown allocation disappeared before retirement")),
        }
    }

    pub(super) fn record_allocation(
        &mut self,
        far: u32,
        owner: OwnerId,
        handle: GlobalHandle,
        kind: AllocationKind,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
    ) -> Result<(), RuntimeError> {
        if self.allocations.contains_key(&far) {
            free_untracked_allocation(heap, selectors, handle)?;
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 Automation guest FAR value was allocated twice",
            ));
        }
        self.allocations.insert(
            far,
            GuestAllocation {
                owner,
                handle,
                kind,
                retirement_cause: None,
            },
        );
        Ok(())
    }

    pub(crate) fn remember_retirement_failure(
        &mut self,
        far: u32,
        expected: GlobalHandle,
        error: RuntimeError,
    ) -> RuntimeError {
        let Some(allocation) = self.allocations.get_mut(&far)
            .filter(|allocation| allocation.handle == expected)
        else {
            return RuntimeError::new(Kind::InternalInvariant,
                "Win16 Automation cleanup lost its exact allocation owner")
                .with_cleanup("preserving failed Automation allocation retirement", error);
        };
        if let Some(cause) = &allocation.retirement_cause {
            return RuntimeError::with_source(
                cause.kind().with_cleanup(error.kind()),
                "Win16 Automation owner retry retained its first typed cleanup cause",
                std::sync::Arc::clone(cause),
            ).with_cleanup("retrying Win16 Automation allocation retirement", error);
        }
        let cause = std::sync::Arc::new(error);
        let report = RuntimeError::with_source(
            cause.kind(),
            "Win16 Automation owner retained its initial typed cleanup cause",
            std::sync::Arc::clone(&cause),
        );
        allocation.retirement_cause = Some(cause);
        report
    }

    pub(super) fn release_allocation(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        owner: OwnerId,
        far: u32,
        kind: AllocationKind,
    ) -> Result<(), RuntimeError> {
        let allocation = self.require_owned_allocation(owner, far, kind)?;
        heap.free(allocation.handle, selectors)
            .map_err(crate::runtime_error)?;
        self.allocations.remove(&far);
        Ok(())
    }

    pub(super) fn require_owned_allocation(
        &self,
        owner: OwnerId,
        far: u32,
        kind: AllocationKind,
    ) -> Result<GuestAllocation, RuntimeError> {
        let allocation = self.allocations.get(&far).cloned().ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "Win16 Automation FAR value is not owned by the guest allocator",
            )
        })?;
        if allocation.owner != owner || allocation.kind != kind {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 Automation FAR value has the wrong owner or allocation kind",
            ));
        }
        Ok(allocation)
    }
}
