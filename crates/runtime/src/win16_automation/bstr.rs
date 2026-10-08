use super::*;

impl Win16AutomationState {
    pub(crate) fn allocate_bstr(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        value: &[u8],
    ) -> Result<u32, RuntimeError> {
        if value
            .len()
            .checked_add(5)
            .is_none_or(|length| length > MAX_AUTOMATION_ALLOCATION)
        {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 BSTR exceeds the bounded guest allocation size",
            ));
        }
        let allocation = BstrAllocation16::new(value).map_err(bstr_abi_error)?;
        let (handle, base) =
            allocate_guest_bytes(heap, selectors, memory, owner, &allocation.bytes)?;
        let value_pointer = match selectors.add_bytes(base, 4) {
            Ok(pointer) => pointer,
            Err(error) => {
                free_untracked_allocation(heap, selectors, handle).map_err(|cleanup| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "BSTR pointer construction failed and its guest allocation rollback failed",
                        cleanup,
                    )
                })?;
                return Err(crate::runtime_error(error));
            }
        };
        let far = value_pointer.far_value();
        self.record_allocation(far, owner, handle, AllocationKind::Bstr, heap, selectors)?;
        Ok(far)
    }

    /// Reads a BSTR by its byte-length prefix, preserving every payload byte,
    /// including embedded NULs and incomplete multibyte sequences.
    pub(crate) fn read_bstr(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        far: u32,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if far == 0 {
            return Ok(None);
        }
        let prefix_far = bstr_prefix_far(far).ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "Win16 BSTR FAR value has no four-byte length prefix",
            )
        })?;
        let prefix_pointer = selectors
            .pointer_from_far(prefix_far)
            .map_err(crate::runtime_error)?;
        let prefix = read_guest_far_bytes(selectors, memory, prefix_pointer, 4)?;
        let byte_length = compat_services::automation::decode_bstr_byte_length(&prefix)
            .map_err(bstr_abi_error)?;
        let byte_length = usize::try_from(byte_length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Win16 BSTR byte length exceeds host address space",
                error,
            )
        })?;
        if byte_length
            .checked_add(1)
            .is_none_or(|length| length > MAX_AUTOMATION_ALLOCATION)
        {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 BSTR exceeds the bounded guest allocation size",
            ));
        }
        let full_length = byte_length.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 BSTR terminator range overflows",
            )
        })?;
        let body_pointer = selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        let body = read_guest_far_bytes(selectors, memory, body_pointer, full_length)?;
        if body.get(byte_length) != Some(&0) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 BSTR is missing its single-byte terminator",
            ));
        }
        let mut value = Vec::new();
        value.try_reserve_exact(byte_length).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "copy Win16 BSTR bytes", error)
        })?;
        value.extend_from_slice(&body[..byte_length]);
        Ok(Some(value))
    }

    pub(crate) fn release_bstr(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        owner: OwnerId,
        far: u32,
    ) -> Result<(), RuntimeError> {
        if far == 0 {
            return Ok(());
        }
        self.release_allocation(heap, selectors, owner, far, AllocationKind::Bstr)
    }

    /// Check the exact allocator identity and BSTR byte range without copying
    /// its payload. Destruction preflight uses this to avoid allocating a
    /// second copy of every string in a SAFEARRAY before it starts releasing.
    pub(crate) fn validate_owned_bstr(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        owner: OwnerId,
        far: u32,
    ) -> Result<(), RuntimeError> {
        if far == 0 {
            return Ok(());
        }
        self.require_owned_allocation(owner, far, AllocationKind::Bstr)?;
        let prefix_far = bstr_prefix_far(far).ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "Win16 BSTR FAR value has no four-byte length prefix",
            )
        })?;
        let prefix_pointer = selectors
            .pointer_from_far(prefix_far)
            .map_err(crate::runtime_error)?;
        let prefix = read_guest_far_bytes(selectors, memory, prefix_pointer, 4)?;
        let byte_length = usize::try_from(
            compat_services::automation::decode_bstr_byte_length(&prefix)
                .map_err(bstr_abi_error)?,
        )
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Win16 BSTR byte length exceeds host address space",
                error,
            )
        })?;
        let extent = byte_length.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 BSTR terminator range overflows",
            )
        })?;
        if extent > MAX_AUTOMATION_ALLOCATION {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 BSTR exceeds the bounded guest allocation size",
            ));
        }
        let body = selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        validate_readable_range(selectors, memory, body.far_value(), extent)?;
        let terminator_pointer = selectors
            .add_bytes(
                body,
                u32::try_from(byte_length).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "Win16 BSTR offset exceeds DWORD",
                        error,
                    )
                })?,
            )
            .map_err(crate::runtime_error)?;
        let mut terminator = [0];
        selectors
            .read(memory, terminator_pointer, &mut terminator)
            .map_err(crate::runtime_error)?;
        if terminator[0] != 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 BSTR is missing its single-byte terminator",
            ));
        }
        Ok(())
    }
}
