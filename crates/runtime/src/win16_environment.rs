//! DOS-owned environment allocation and live protected-PDB environment view.
//!
//! The initial alias spans the complete validated DOS MCB allocation. Later
//! SHELL calls resolve the current PDB selector and rescan its live list; the
//! initial trailer and list lengths are validation metadata, never cached
//! bounds for guest-mutated contents.

use dos_kernel::DosBlockExtent;
use guest_core::memory::Memory;
use guest_core::Selector;
use win16_abi::pdb::PDB_ENVIRONMENT_SELECTOR_OFFSET;
use win16_abi::{Access, AccessRights, SegmentedPointer, SelectorRef, SelectorTable};

use crate::{DiagnosticKind as Kind, RuntimeError};

/// One protected selector alias of the full DOS-owned environment block.
#[derive(Debug)]
pub(crate) struct Win16Environment {
    environment_selector: SelectorRef,
    pdb_selector: Option<SelectorRef>,
    /// DOS MCB extent in bytes, including paragraph padding.
    allocation_bytes: usize,
    /// Exact initial serialization length (list plus DOS trailer).
    #[allow(dead_code)]
    initial_logical_bytes: usize,
    /// Initial list length through its double-NUL terminator. This is retained
    /// as provenance only; live calls always locate their current terminator.
    #[allow(dead_code)]
    initial_list_bytes: usize,
}

impl Win16Environment {
    pub(crate) fn load(
        selectors: &mut SelectorTable,
        extent: DosBlockExtent,
        initial_logical_bytes: usize,
        memory: &mut Memory,
    ) -> Result<Self, RuntimeError> {
        let allocation_bytes = extent.byte_length().ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault, "DOS environment allocation size overflows")
        })?;
        if extent.paragraphs() == 0 || extent.data_segment() == 0
            || extent.owner_psp_segment() == 0 || allocation_bytes == 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 process environment has an invalid DOS allocation extent",
            ));
        }
        if initial_logical_bytes == 0
            || initial_logical_bytes > allocation_bytes
            || initial_logical_bytes > usize::from(u16::MAX) + 1
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "initial Win16 environment bytes exceed the DOS block or one selector span",
            ));
        }
        let base = extent.guest_base().ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault, "DOS environment base address overflows")
        })?;
        // Validate the exact initial serialization before allocating the
        // selector alias. A malformed initial block must not leave a live
        // descriptor behind while process-view creation rolls back its DOS
        // lease. This address comes from the trusted DOS-owned extent, never
        // from a guest PDB selector.
        let mut initial = Vec::new();
        initial
            .try_reserve_exact(initial_logical_bytes)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate initial Win16 environment validation copy",
                    error,
                )
            })?;
        initial.resize(initial_logical_bytes, 0);
        memory.read_physical(base, &mut initial).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "read initial DOS environment within its validated allocation",
                error,
            )
        })?;
        let initial_list_bytes = validate_initial_layout(&initial)?;

        let size = u32::try_from(allocation_bytes).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "DOS environment extent does not fit the selector table",
                error,
            )
        })?;

        // Make exactly one alias, over the complete validated MCB allocation.
        // The DOS lease is owned by Win16ProcessViews and outlives this alias.
        let environment_selector = selectors
            .alloc_block(base, size, AccessRights::read_write(), memory)
            .map_err(crate::runtime_error)?;

        Ok(Self {
            environment_selector,
            pdb_selector: None,
            allocation_bytes,
            initial_logical_bytes,
            initial_list_bytes,
        })
    }

    pub(crate) fn selector(&self) -> SelectorRef {
        self.environment_selector
    }

    pub(crate) fn bind_pdb(&mut self, selector: SelectorRef) {
        self.pdb_selector = Some(selector);
    }

    /// Resolve PDB:2C on every call. The word is a protected selector, not a
    /// DOS paragraph segment; the saved PDB reference and live raw env selector
    /// are both checked against the current selector-table generation.
    pub(crate) fn pointer(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<SegmentedPointer, RuntimeError> {
        let pdb = self.pdb_selector.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 environment view is not bound to its protected PDB",
            )
        })?;
        let mut raw_bytes = [0u8; 2];
        selectors
            .read(
                memory,
                SegmentedPointer::new(pdb, PDB_ENVIRONMENT_SELECTOR_OFFSET),
                &mut raw_bytes,
            )
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "Win16 PDB environment field is no longer readable",
                    error,
                )
            })?;
        let raw_selector = u16::from_le_bytes(raw_bytes);
        if raw_selector == 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 PDB contains a null environment selector",
            ));
        }

        let selector = selectors
            .reference(Selector(raw_selector))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "Win16 PDB environment selector is not allocated",
                    error,
                )
            })?;
        let descriptor = selectors.describe(selector).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "Win16 PDB environment selector is stale",
                error,
            )
        })?;
        if !descriptor.present
            || !descriptor.rights.readable()
            || descriptor.limit > u32::from(u16::MAX)
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 PDB environment selector has no readable 16-bit span",
            ));
        }
        let pointer = SegmentedPointer::new(selector, 0);
        selectors
            .translate(pointer, Access::Read, 1, memory)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "Win16 PDB environment pointer is outside guest memory",
                    error,
                )
            })?;
        Ok(pointer)
    }

    pub(crate) fn find_environment_string(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
        query: &[u8],
    ) -> Result<u32, RuntimeError> {
        if query.is_empty() || query.contains(&0) {
            return Ok(0);
        }
        let (pointer, list) = self.live_list(selectors, memory)?;
        let Some(offset) = compat_services::win16_shell::find_environment_string(&list, query)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "Win16 environment list is malformed",
                    error,
                )
            })?
        else {
            return Ok(0);
        };
        let offset = u16::try_from(offset).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "Win16 environment entry offset exceeds its selector span",
                error,
            )
        })?;
        Ok(SegmentedPointer::new(pointer.selector(), offset).far_value())
    }

    pub(crate) fn list_bytes(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.live_list(selectors, memory).map(|(_, bytes)| bytes)
    }

    fn live_list(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<(SegmentedPointer, Vec<u8>), RuntimeError> {
        let pointer = self.pointer(selectors, memory)?;
        let descriptor = selectors.describe(pointer.selector()).map_err(|error| {
            RuntimeError::with_source(
                Kind::GuestFault,
                "Win16 environment selector became stale during list lookup",
                error,
            )
        })?;
        let descriptor_span = usize::try_from(descriptor.limit)
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .filter(|span| *span <= usize::from(u16::MAX) + 1)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 environment selector exceeds its 16-bit offset span",
                )
            })?;
        let span = if pointer.selector() == self.environment_selector {
            descriptor_span.min(self.allocation_bytes)
        } else {
            descriptor_span
        };
        if span < 2 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 environment selector cannot contain a double-NUL list",
            ));
        }

        // Environment bytes are guest-mutable ANSI/OEM strings, not a fixed
        // wire record. Copy only the selector's current legal span, then find
        // the live terminator; never scan an adjacent selector or DOS block.
        selectors
            .translate(pointer, Access::Read, span, memory)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::GuestFault,
                    "Win16 environment selector span is not backed by guest memory",
                    error,
                )
            })?;
        let mut block = Vec::new();
        block.try_reserve_exact(span).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate live Win16 environment-list copy",
                error,
            )
        })?;
        block.resize(span, 0);
        selectors
            .read(memory, pointer, &mut block)
            .map_err(crate::runtime_error)?;
        let list_length = find_double_nul(&block).ok_or_else(|| {
            RuntimeError::new(
                Kind::GuestFault,
                "Win16 environment list has no double-NUL terminator within its selector",
            )
        })?;
        block.truncate(list_length);
        Ok((pointer, block))
    }
}

fn validate_initial_layout(initial: &[u8]) -> Result<usize, RuntimeError> {
    let list_length = find_double_nul(initial).ok_or_else(|| {
        RuntimeError::new(
            Kind::GuestFault,
            "initial DOS environment has no bounded double-NUL list terminator",
        )
    })?;
    let count_end = list_length.checked_add(2).filter(|end| *end <= initial.len())
        .ok_or_else(|| RuntimeError::new(
            Kind::GuestFault,
            "initial DOS environment trailer has no complete string-count WORD",
        ))?;
    let string_count = usize::from(u16::from_le_bytes([
        initial[list_length], initial[list_length + 1],
    ]));
    let mut cursor = count_end;
    if string_count > initial.len().saturating_sub(cursor) {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "initial DOS environment trailer string count exceeds its logical bytes",
        ));
    }
    for _ in 0..string_count {
        let Some(relative_end) = initial[cursor..].iter().position(|&byte| byte == 0) else {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "initial DOS environment trailer contains an unterminated ASCIIZ string",
            ));
        };
        cursor = cursor.checked_add(relative_end + 1).ok_or_else(|| {
            RuntimeError::new(
                Kind::GuestFault,
                "initial DOS environment trailer offset overflows",
            )
        })?;
    }
    Ok(list_length)
}

fn find_double_nul(bytes: &[u8]) -> Option<usize> {
    let mut previous_zero = false;
    for (offset, &byte) in bytes.iter().enumerate() {
        if byte == 0 && previous_zero {
            return offset.checked_add(1);
        }
        previous_zero = byte == 0;
    }
    None
}
