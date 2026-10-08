//! Checked guest output ranges and owned DDE data snapshots.

use super::*;

impl Win16State {
    pub(super) fn capture_dde_output(
        &self,
        memory: &Memory,
        far: u32,
        length: usize,
    ) -> PrepareResult<GuestOutputRange> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        GuestOutputRange::capture(self, memory, pointer, length).map_err(PrepareFailure::Runtime)
    }

    pub(super) fn capture_dde_huge_output(
        &self,
        memory: &Memory,
        far: u32,
        length: usize,
    ) -> PrepareResult<DdeHugeOutputRange> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        DdeHugeOutputRange::capture(self, memory, pointer, length).map_err(PrepareFailure::Runtime)
    }

    pub(in crate::win16_runtime) fn read_dde_snapshot(
        &self,
        memory: &Memory,
        far: u32,
        length: u32,
    ) -> Result<Vec<u8>, RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        let length = usize::try_from(length)
            .map_err(|_| invariant("DDE access snapshot length exceeds host address width"))?;
        let start = self.dde_block_offset(pointer)?;
        let end = start
            .checked_add(u64::try_from(length).map_err(|_| {
                invariant("DDE access snapshot length exceeds selector address width")
            })?)
            .ok_or_else(|| invariant("DDE access snapshot range overflowed"))?;
        let extent = u64::from(self.selectors.allocation_size(pointer.selector()).map_err(
            |error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "DDE access snapshot selector lost its allocation",
                    error,
                )
            },
        )?);
        if end > extent {
            return Err(invariant(
                "DDE access snapshot exceeds its owned guest allocation",
            ));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "copy writable DDE access snapshot",
                error,
            )
        })?;
        // SelectorTable::read validates one descriptor at a time. DDEML
        // handles may be huge objects spanning several 64 KiB selectors, so
        // copy checked chunks through the allocation's selector run.
        let mut cursor = pointer;
        let mut copied = 0usize;
        while copied < length {
            let descriptor = self
                .selectors
                .describe(cursor.selector())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "DDE access snapshot selector run is damaged",
                        error,
                    )
                })?;
            let segment_remaining = usize::try_from(descriptor.limit + 1)
                .ok()
                .and_then(|limit| limit.checked_sub(usize::from(cursor.offset())))
                .filter(|remaining| *remaining != 0)
                .ok_or_else(|| invariant("DDE access snapshot points outside its selector"))?;
            let amount = segment_remaining.min(length - copied);
            let mut chunk = vec![0; amount];
            self.selectors
                .read(memory, cursor, &mut chunk)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "DDE access snapshot guest memory became unreadable",
                        error,
                    )
                })?;
            bytes.extend_from_slice(&chunk);
            copied = copied
                .checked_add(amount)
                .ok_or_else(|| invariant("DDE access snapshot copy length overflowed"))?;
            if copied < length {
                cursor = self
                    .selectors
                    .add_bytes(
                        cursor,
                        u32::try_from(amount).map_err(|_| {
                            invariant("DDE access snapshot segment chunk exceeds DWORD")
                        })?,
                    )
                    .map_err(|error| {
                        RuntimeError::with_source(
                            Kind::InternalInvariant,
                            "DDE access snapshot could not advance to its next selector",
                            error,
                        )
                    })?;
            }
        }
        Ok(bytes)
    }

    fn dde_block_offset(&self, pointer: win16_abi::SegmentedPointer) -> Result<u64, RuntimeError> {
        dde_block_offset_with_selectors(&self.selectors, pointer)
    }
}

impl super::DdeCompletionAccess<'_> {
    pub(in crate::win16_runtime) fn write_dde_snapshot(
        &self,
        memory: &mut Memory,
        far: u32,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        write_dde_snapshot_with_selectors(self.selectors(), memory, far, bytes)
    }
}

fn write_dde_snapshot_with_selectors(
    selectors: &win16_abi::SelectorTable,
    memory: &mut Memory,
    far: u32,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
        let mut cursor = selectors.pointer_from_far(far).map_err(|error| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "DDE access snapshot lost its guest selector",
                error,
            )
        })?;
        let start = dde_block_offset_with_selectors(selectors, cursor)?;
        let end = start
            .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                invariant("DDE access snapshot length exceeds selector address width")
            })?)
            .ok_or_else(|| invariant("DDE access snapshot write range overflowed"))?;
        let extent = u64::from(selectors.allocation_size(cursor.selector()).map_err(
            |error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "DDE access snapshot selector lost its allocation",
                    error,
                )
            },
        )?);
        if end > extent {
            return Err(invariant(
                "DDE access snapshot write exceeds its owned guest allocation",
            ));
        }

        // SelectorTable::write intentionally validates one descriptor at a
        // time. Use checked segment-sized chunks for DDEML huge data handles.
        let mut written = 0usize;
        while written < bytes.len() {
            let descriptor = selectors
                .describe(cursor.selector())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "DDE access snapshot selector run is damaged",
                        error,
                    )
                })?;
            let segment_remaining = usize::try_from(descriptor.limit + 1)
                .ok()
                .and_then(|limit| limit.checked_sub(usize::from(cursor.offset())))
                .filter(|remaining| *remaining != 0)
                .ok_or_else(|| invariant("DDE access snapshot points outside its selector"))?;
            let amount = segment_remaining.min(bytes.len() - written);
            selectors
                .write(memory, cursor, &bytes[written..written + amount])
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "DDE access snapshot guest memory became unwritable",
                        error,
                    )
                })?;
            written = written
                .checked_add(amount)
                .ok_or_else(|| invariant("DDE access snapshot write length overflowed"))?;
            if written < bytes.len() {
                cursor = selectors
                    .add_bytes(
                        cursor,
                        u32::try_from(amount).map_err(|_| {
                            invariant("DDE access snapshot segment chunk exceeds DWORD")
                        })?,
                    )
                    .map_err(|error| {
                        RuntimeError::with_source(
                            Kind::InternalInvariant,
                            "DDE access snapshot could not advance to its next selector",
                            error,
                        )
                    })?;
            }
        }
        Ok(())
}

fn dde_block_offset_with_selectors(
    selectors: &win16_abi::SelectorTable,
    pointer: win16_abi::SegmentedPointer,
) -> Result<u64, RuntimeError> {
        let descriptor = selectors
            .describe(pointer.selector())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "DDE access snapshot selector is no longer valid",
                    error,
                )
            })?;
        let segment_base = u64::try_from(descriptor.segment_index)
            .ok()
            .and_then(|index| index.checked_mul(0x1_0000))
            .ok_or_else(|| invariant("DDE selector segment index overflowed"))?;
        segment_base
            .checked_add(u64::from(pointer.offset()))
            .ok_or_else(|| invariant("DDE selector block offset overflowed"))
}
