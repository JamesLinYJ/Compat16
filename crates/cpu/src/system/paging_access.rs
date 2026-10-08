//! Segmented-to-linear checks and planned page-translated guest accesses.
//!
//! This is a nested private module so it can share the CPU bus's private
//! prepared-span representation without widening the crate API.
//! The logic is CPU-specific: a decoder or generic memory crate cannot combine
//! hidden segment-cache checks, CPL-based page permissions, typed #PF state,
//! and the project's checked physical GuestMemory boundary.

use guest_core::{GuestMemory, LinearAddr, MemoryError};
use std::sync::Arc;

use crate::{
    CpuCompatibilityGap, CpuError, CpuExecutionMode, SegmentResolver,
    registers::SegmentRegister,
    system::{CpuFault, ExceptionVector, SegmentCache, TranslationError},
};

use super::{
    AccessKind, AccessOrigin, AccessParts, CpuMemoryAccess, DataAlignment, LogicalSpan,
    PhysicalChunk, PreparedAccess, PreparedGroup,
};

/// Explicit protected/virtual-8086 page-table root and logical privilege context.
/// Construct it from an already validated destination CPU/task state; it has
/// no link to the published CpuSystem fields and cannot change live CR3/CPL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PagingAddressSpace {
    cr3: u32,
    mode: CpuExecutionMode,
    cpl: u8,
}

impl PagingAddressSpace {
    pub(crate) fn for_protected_target(cr3: u32, cpl: u8) -> Option<Self> {
        Self::for_task_target(cr3, CpuExecutionMode::Protected, cpl)
    }

    pub(crate) fn for_task_target(cr3: u32, mode: CpuExecutionMode, cpl: u8) -> Option<Self> {
        let valid_cpl = match mode {
            CpuExecutionMode::Protected => cpl <= 3,
            CpuExecutionMode::Virtual8086 => cpl == 3,
            CpuExecutionMode::RealAddress => false,
        };
        if !valid_cpl {
            return None;
        }
        // Match CpuSystem::write_cr3 for the i486: bits 31:12 are the
        // directory base, bits 4:3 retain PWT/PCD, and the other low bits are
        // ignored. CR4/PSE and later CR3 extensions are outside this target.
        Some(Self {
            cr3: cr3 & (0xffff_f000 | crate::system::CR3_PWT | crate::system::CR3_PCD),
            mode,
            cpl,
        })
    }
}

impl<'a, M: GuestMemory, S: SegmentResolver> CpuMemoryAccess<'a, M, S> {
    pub(super) fn prepare_architectural_logical(
        &mut self,
        span: LogicalSpan,
        kind: AccessKind,
    ) -> Result<AccessParts, CpuError> {
        let cache = *self.system.segment_cache(span.register);
        if span.selector != cache.selector {
            return Err(self.unsupported_mode());
        }
        self.prepare_architectural_logical_with_cache(span, kind, cache)
    }

    pub(super) fn prepare_architectural_logical_with_cache(
        &mut self,
        span: LogicalSpan,
        kind: AccessKind,
        cache: SegmentCache,
    ) -> Result<AccessParts, CpuError> {
        self.prepare_architectural_logical_with_target_context(span, kind, cache, None, None, None)
    }

    pub(super) fn prepare_architectural_logical_with_address_space(
        &mut self,
        span: LogicalSpan,
        kind: AccessKind,
        cache: SegmentCache,
        address_space: PagingAddressSpace,
    ) -> Result<AccessParts, CpuError> {
        if !matches!(
            address_space.mode,
            CpuExecutionMode::Protected | CpuExecutionMode::Virtual8086
        ) {
            return Err(self.unsupported_mode());
        }
        if kind == AccessKind::AddressOnly {
            return Err(self.error_site());
        }
        if span.selector != cache.selector {
            return Err(self.error_site());
        }
        let (linear, cpl) = self.checked_linear_span(
            span,
            kind,
            cache,
            Some(address_space.mode),
            Some(address_space.cpl),
        )?;
        let chunks = self.translate_linear_chunks(
            linear,
            span.len,
            kind,
            cpl,
            Some(address_space.cr3),
            true,
        )?;
        if kind.reads() {
            self.validate_chunks(&chunks, true)?;
        }
        if kind.writes() {
            self.validate_chunks(&chunks, false)?;
        }
        let read_chunks = if kind.reads() {
            clone_chunks(&chunks)?
        } else {
            Vec::new()
        };
        let write_chunks = if kind.writes() { chunks } else { Vec::new() };
        Ok(AccessParts {
            linear_start: Some(linear),
            len: span.len,
            can_read: kind.reads(),
            can_write: kind.writes(),
            read_chunks,
            write_chunks,
        })
    }

    fn prepare_architectural_logical_with_target_context(
        &mut self,
        span: LogicalSpan,
        kind: AccessKind,
        cache: SegmentCache,
        target_mode: Option<CpuExecutionMode>,
        target_cpl: Option<u8>,
        target_cr3: Option<u32>,
    ) -> Result<AccessParts, CpuError> {
        if kind == AccessKind::AddressOnly {
            return Err(self.error_site());
        }
        if span.selector != cache.selector {
            return Err(self.error_site());
        }
        let (linear, cpl) = self.checked_linear_span(span, kind, cache, target_mode, target_cpl)?;
        let chunks = self.translate_linear_chunks(linear, span.len, kind, cpl, target_cr3, true)?;
        if kind.reads() {
            self.validate_chunks(&chunks, true)?;
        }
        if kind.writes() {
            self.validate_chunks(&chunks, false)?;
        }
        let read_chunks = if kind.reads() {
            clone_chunks(&chunks)?
        } else {
            Vec::new()
        };
        let write_chunks = if kind.writes() { chunks } else { Vec::new() };
        Ok(AccessParts {
            linear_start: Some(linear),
            len: span.len,
            can_read: kind.reads(),
            can_write: kind.writes(),
            read_chunks,
            write_chunks,
        })
    }

    fn plan_logical_in_address_space_unchecked_alignment(
        &mut self,
        span: LogicalSpan,
        kind: AccessKind,
        alignment: DataAlignment,
        origin: AccessOrigin,
        cache: SegmentCache,
        address_space: PagingAddressSpace,
    ) -> Result<PreparedAccess, CpuError> {
        if self.uses_legacy_projection() || self.checked_execution_mode()?.is_none() {
            return Err(self.unsupported_mode());
        }
        let parts = self.prepare_architectural_logical_with_address_space(
            span,
            kind,
            cache,
            address_space,
        )?;
        Ok(self.prepared_logical(
            parts,
            kind,
            alignment,
            origin,
            Some(address_space.cpl),
        ))
    }

    pub(super) fn plan_group_for_stack_in_address_space(
        &mut self,
        requests: &[super::AccessRequest],
        temporary_ss: SegmentCache,
        address_space: PagingAddressSpace,
    ) -> Result<PreparedGroup, CpuError> {
        if self.uses_legacy_projection() || self.checked_execution_mode()?.is_none() {
            return Err(self.unsupported_mode());
        }
        if !matches!(
            address_space.mode,
            CpuExecutionMode::Protected | CpuExecutionMode::Virtual8086
        ) {
            return Err(self.unsupported_mode());
        }
        let mut accesses = Vec::new();
        accesses
            .try_reserve_exact(requests.len())
            .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
        for request in requests {
            let super::AccessRequest::Logical {
                span,
                kind,
                alignment,
                origin,
            } = *request else {
                return Err(self.error_site());
            };
            if span.register != SegmentRegister::Ss
                || span.selector != temporary_ss.selector
                || !matches!(kind, AccessKind::StackRead | AccessKind::StackWrite)
            {
                return Err(self.error_site());
            }
            accesses.push(self.plan_logical_in_address_space_unchecked_alignment(
                span,
                kind,
                alignment,
                origin,
                temporary_ss,
                address_space,
            )?);
        }
        for access in &accesses {
            self.check_prepared_alignment(access)?;
        }
        Ok(PreparedGroup { accesses })
    }

    pub(super) fn prepare_system_linear(
        &mut self,
        address: LinearAddr,
        len: usize,
        kind: AccessKind,
    ) -> Result<AccessParts, CpuError> {
        self.prepare_system_linear_with_cr3(address, len, kind, None)
    }

    pub(super) fn plan_system_linear_in_address_space(
        &mut self,
        address: LinearAddr,
        len: usize,
        kind: AccessKind,
        address_space: PagingAddressSpace,
    ) -> Result<PreparedAccess, CpuError> {
        if self.uses_legacy_projection() || self.checked_execution_mode()?.is_none() {
            return Err(self.unsupported_mode());
        }
        if !matches!(
            address_space.mode,
            CpuExecutionMode::Protected | CpuExecutionMode::Virtual8086
        ) {
            return Err(self.unsupported_mode());
        }
        let parts = self.prepare_system_linear_with_cr3(address, len, kind, Some(address_space.cr3))?;
        Ok(PreparedAccess {
            owner: Arc::clone(&self.owner),
            epoch: self.epoch,
            len: parts.len,
            linear_start: parts.linear_start,
            kind,
            alignment: DataAlignment::Unaligned,
            alignment_cpl: None,
            origin: None,
            can_read: parts.can_read,
            can_write: parts.can_write,
            read_chunks: parts.read_chunks,
            write_chunks: parts.write_chunks,
        })
    }

    fn prepare_system_linear_with_cr3(
        &mut self,
        address: LinearAddr,
        len: usize,
        kind: AccessKind,
        cr3: Option<u32>,
    ) -> Result<AccessParts, CpuError> {
        self.checked_execution_mode()?
            .ok_or_else(|| self.unsupported_mode())?;
        if !matches!(
            kind,
            AccessKind::SystemTableRead | AccessKind::SystemTableWrite
        ) {
            return Err(self.error_site());
        }
        let end = u64::from(address.0)
            .checked_add(
                u64::try_from(len).map_err(|_| CpuError::Memory(MemoryError::AddressOverflow))?,
            )
            .filter(|end| *end <= u64::from(u32::MAX) + 1);
        if end.is_none() {
            return Err(CpuError::Memory(MemoryError::AddressOverflow));
        }

        // Descriptor and interrupt-table references are implicit supervisor
        // accesses even if the instruction that caused them ran at CPL 3.
        // SystemLinear callers already provide a linear address rather than a
        // segmented operand; keep their pre-existing checked-range contract.
        let chunks = self.translate_linear_chunks(address, len, kind, 0, cr3, false)?;
        if kind.reads() {
            self.validate_chunks(&chunks, true)?;
        }
        if kind.writes() {
            self.validate_chunks(&chunks, false)?;
        }
        let read_chunks = if kind.reads() {
            clone_chunks(&chunks)?
        } else {
            Vec::new()
        };
        let write_chunks = if kind.writes() { chunks } else { Vec::new() };
        Ok(AccessParts {
            linear_start: Some(address),
            len,
            can_read: kind.reads(),
            can_write: kind.writes(),
            read_chunks,
            write_chunks,
        })
    }

    /// Compute the INVLPG operand's linear address from its selected segment
    /// base and effective offset. INVLPG is not a data read: it does not check
    /// segment type/presence/limit or walk page tables.
    pub(super) fn checked_invlpg_linear_address(
        &self,
        span: LogicalSpan,
    ) -> Result<LinearAddr, CpuError> {
        if self.uses_legacy_projection() {
            return Err(self.unsupported_mode());
        }
        let cache = *self.system.segment_cache(span.register);
        if span.selector != cache.selector {
            return Err(self.unsupported_mode());
        }
        let offset = if span.address32 {
            span.offset
        } else {
            u32::from(span.offset as u16)
        };
        // INVLPG computes the effective linear address but does not transfer
        // operand data, so segment access rights and limits do not apply.
        Ok(LinearAddr(cache.descriptor.base.wrapping_add(offset)))
    }

    fn checked_linear_span(
        &self,
        span: LogicalSpan,
        kind: AccessKind,
        cache: SegmentCache,
        target_mode: Option<CpuExecutionMode>,
        target_cpl: Option<u8>,
    ) -> Result<(LinearAddr, u8), CpuError> {
        let invalid_segment_use = match kind {
            AccessKind::Fetch => span.register != SegmentRegister::Cs,
            AccessKind::StackRead | AccessKind::StackWrite => span.register != SegmentRegister::Ss,
            AccessKind::SystemTableRead | AccessKind::SystemTableWrite => true,
            _ => false,
        };
        if invalid_segment_use {
            return Err(self.error_site());
        }

        let current_mode = self
            .checked_execution_mode()?
            .ok_or_else(|| self.unsupported_mode())?;
        let mode = target_mode.unwrap_or(current_mode);
        if cache.unusable {
            return Err(CpuError::GeneralProtectionFault {
                error_code: 0,
                ip: self.site.ip,
            });
        }
        let offset = if kind == AccessKind::Fetch || span.address32 {
            span.offset
        } else {
            u32::from(span.offset as u16)
        };
        let current_cpl = self.checked_cpl().ok_or_else(|| self.unsupported_mode())?;
        let cpl = match target_cpl {
            Some(target_cpl)
                if (mode == CpuExecutionMode::Protected && target_cpl <= 3)
                    || (mode == CpuExecutionMode::Virtual8086 && target_cpl == 3) =>
            {
                target_cpl
            }
            Some(_) => return Err(self.unsupported_mode()),
            None => current_cpl,
        };
        if mode == CpuExecutionMode::Virtual8086 {
            let expected_base = u32::from(span.selector) << 4;
            if cpl != 3
                || cache.descriptor.base != expected_base
                || cache.descriptor.limit != u32::from(u16::MAX)
                || cache.descriptor.default_big
                || !cache.descriptor.present
            {
                return Err(self.compatibility_gap(CpuCompatibilityGap::Virtual8086Mode));
            }
            let len = u64::try_from(span.len)
                .map_err(|_| CpuError::Memory(MemoryError::AddressOverflow))?;
            if u64::from(offset)
                .checked_add(len)
                .filter(|end| *end <= u64::from(u16::MAX) + 1)
                .is_none()
            {
                return Err(if span.register == SegmentRegister::Ss {
                    CpuError::StackSegmentFault {
                        error_code: 0,
                        ip: self.site.ip,
                    }
                } else {
                    CpuError::GeneralProtectionFault {
                        error_code: 0,
                        ip: self.site.ip,
                    }
                });
            }
        } else if mode == CpuExecutionMode::Protected {
            let access = match kind {
                AccessKind::Fetch => crate::system::SegmentAccess::InstructionFetch,
                AccessKind::DataRead if span.register == SegmentRegister::Ss => {
                    crate::system::SegmentAccess::StackRead
                }
                AccessKind::DataRead => crate::system::SegmentAccess::Read,
                AccessKind::AddressOnly if span.register == SegmentRegister::Ss => {
                    crate::system::SegmentAccess::StackRead
                }
                AccessKind::AddressOnly => crate::system::SegmentAccess::Read,
                AccessKind::DataWrite if span.register == SegmentRegister::Ss => {
                    crate::system::SegmentAccess::StackWrite
                }
                AccessKind::DataWrite => crate::system::SegmentAccess::Write,
                AccessKind::DataReadWrite if span.register == SegmentRegister::Ss => {
                    crate::system::SegmentAccess::StackWrite
                }
                AccessKind::DataReadWrite => crate::system::SegmentAccess::Write,
                AccessKind::StackRead => crate::system::SegmentAccess::StackRead,
                AccessKind::StackWrite => crate::system::SegmentAccess::StackWrite,
                AccessKind::SystemTableRead | AccessKind::SystemTableWrite => {
                    return Err(self.error_site());
                }
            };
            cache
                .descriptor
                .check_access(
                    span.selector,
                    access,
                    cpl,
                    (span.selector & 3) as u8,
                    offset,
                    span.len,
                )
                .map_err(|fault| self.map_cpu_fault(fault))?;
            if kind == AccessKind::DataReadWrite {
                cache
                    .descriptor
                    .check_access(
                        span.selector,
                        if span.register == SegmentRegister::Ss {
                            crate::system::SegmentAccess::StackRead
                        } else {
                            crate::system::SegmentAccess::Read
                        },
                        cpl,
                        (span.selector & 3) as u8,
                        offset,
                        span.len,
                    )
                    .map_err(|fault| self.map_cpu_fault(fault))?;
            }
        } else {
            let len = u64::try_from(span.len)
                .map_err(|_| CpuError::Memory(MemoryError::AddressOverflow))?;
            let end = u64::from(offset)
                .checked_add(len)
                .filter(|end| *end <= u64::from(u32::MAX) + 1);
            if end.is_none() || end.unwrap_or(0) > u64::from(cache.descriptor.limit) + 1 {
                return Err(if span.register == SegmentRegister::Ss {
                    CpuError::StackSegmentFault {
                        error_code: 0,
                        ip: self.site.ip,
                    }
                } else {
                    CpuError::GeneralProtectionFault {
                        error_code: 0,
                        ip: self.site.ip,
                    }
                });
            }
        }

        // Segment offset checks above stay nonwrapping. The Intel 80386
        // System Software Writer's Guide §2.1.6.3 defines linear addition as
        // 32-bit and discards carry out of bit 31; legal references can wrap.
        let linear_start = cache.descriptor.base.wrapping_add(offset);
        Ok((LinearAddr(linear_start), cpl))
    }

    fn translate_linear_chunks(
        &mut self,
        address: LinearAddr,
        len: usize,
        kind: AccessKind,
        cpl: u8,
        cr3: Option<u32>,
        wrap_linear: bool,
    ) -> Result<Vec<PhysicalChunk>, CpuError> {
        let mut chunks = Vec::new();
        if len == 0 {
            return Ok(chunks);
        }
        let first_page_len = 0x1000 - (address.0 as usize & 0x0fff);
        let chunks_needed = 1 + len.saturating_sub(first_page_len).div_ceil(0x1000);
        chunks
            .try_reserve_exact(chunks_needed)
            .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
        let page_access = kind.page_access();
        let mut buffer_offset = 0_usize;
        while buffer_offset < len {
            let byte_offset = u32::try_from(buffer_offset)
                .map_err(|_| CpuError::Memory(MemoryError::AddressOverflow))?;
            // A 32-bit linear operand continues at linear address zero after
            // FFFFFFFFh; SystemLinear ranges retain their checked contract.
            let linear = if wrap_linear {
                address.0.wrapping_add(byte_offset)
            } else {
                address
                    .0
                    .checked_add(byte_offset)
                    .ok_or_else(|| CpuError::Memory(MemoryError::AddressOverflow))?
            };
            let page_remaining = 0x1000 - (linear as usize & 0x0fff);
            let chunk_len = page_remaining.min(len - buffer_offset);
            let translated = match cr3 {
                Some(cr3) => self.system.translate_linear_with_cr3(
                    cr3,
                    LinearAddr(linear),
                    page_access,
                    cpl,
                    self.memory,
                ),
                None => {
                    self.system
                        .translate_linear(LinearAddr(linear), page_access, cpl, self.memory)
                }
            };
            let physical = translated.map_err(|error| self.translate_error(error))?;
            chunks.push(PhysicalChunk {
                address: physical,
                buffer_offset,
                len: chunk_len,
            });
            buffer_offset += chunk_len;
        }
        merge_adjacent_chunks(chunks)
    }

    fn translate_error(&self, error: TranslationError) -> CpuError {
        match error {
            // A page-table access failing in GuestMemory is a physical
            // backend/storage error. Do not forge a guest #PF or overwrite
            // CR2 for it; only architectural walk faults update CR2.
            TranslationError::Memory(error) => CpuError::Memory(error),
            TranslationError::Fault(fault) => self.map_cpu_fault(fault),
        }
    }

    fn map_cpu_fault(&self, fault: CpuFault) -> CpuError {
        let Some(error_code) = fault.error_code else {
            return self.error_site();
        };
        match fault.vector {
            ExceptionVector::GeneralProtection => CpuError::GeneralProtectionFault {
                error_code,
                ip: self.site.ip,
            },
            ExceptionVector::SegmentNotPresent => CpuError::SegmentNotPresentFault {
                error_code,
                ip: self.site.ip,
            },
            ExceptionVector::StackSegment => CpuError::StackSegmentFault {
                error_code,
                ip: self.site.ip,
            },
            ExceptionVector::PageFault => match fault.linear_address {
                Some(linear_address) => CpuError::PageFault {
                    error_code,
                    linear_address: linear_address.0,
                    ip: self.site.ip,
                },
                None => self.error_site(),
            },
        }
    }
}

fn merge_adjacent_chunks(chunks: Vec<PhysicalChunk>) -> Result<Vec<PhysicalChunk>, CpuError> {
    let mut merged: Vec<PhysicalChunk> = Vec::new();
    merged
        .try_reserve_exact(chunks.len())
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    for chunk in chunks {
        if let Some(previous) = merged.last_mut() {
            let physical_end = u64::from(previous.address.0) + previous.len as u64;
            let buffer_end = previous
                .buffer_offset
                .checked_add(previous.len)
                .ok_or(CpuError::Memory(MemoryError::AddressOverflow))?;
            if physical_end == u64::from(chunk.address.0) && buffer_end == chunk.buffer_offset {
                previous.len = previous
                    .len
                    .checked_add(chunk.len)
                    .ok_or(CpuError::Memory(MemoryError::AddressOverflow))?;
                continue;
            }
        }
        merged.push(chunk);
    }
    Ok(merged)
}

fn clone_chunks(chunks: &[PhysicalChunk]) -> Result<Vec<PhysicalChunk>, CpuError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(chunks.len())
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    cloned.extend_from_slice(chunks);
    Ok(cloned)
}
