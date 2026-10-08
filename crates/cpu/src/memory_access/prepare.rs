//! Segment, page, backing-store, and alignment preparation for CPU accesses.

use std::sync::Arc;

use guest_core::{GuestMemory, MemoryError};

use crate::{
    CpuCompatibilityGap, CpuError, CpuExecutionMode, SegmentResolver,
    registers::SegmentRegister,
    system::CR0_PG,
};

use super::{
    AccessKind, AccessOrigin, AccessParts, AccessRequest, CpuMemoryAccess, DataAlignment,
    PreparedAccess,
};

impl<M: GuestMemory, S: SegmentResolver> CpuMemoryAccess<'_, M, S> {
    pub(super) fn prepare_request(
        &mut self,
        request: AccessRequest,
    ) -> Result<PreparedAccess, CpuError> {
        let access = self.prepare_request_unchecked_alignment(request)?;
        self.check_prepared_alignment(&access)?;
        Ok(access)
    }

    pub(super) fn prepare_request_unchecked_alignment(
        &mut self,
        request: AccessRequest,
    ) -> Result<PreparedAccess, CpuError> {
        match request {
            AccessRequest::Logical {
                span,
                kind,
                alignment,
                origin,
            } => self.prepare_logical_unchecked_alignment(span, kind, alignment, origin, None),
            AccessRequest::SystemLinear { address, len, kind } => {
                let parts = self.prepare_system_linear(address, len, kind)?;
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
        }
    }

    pub(super) fn prepare_logical_unchecked_alignment(
        &mut self,
        span: super::LogicalSpan,
        kind: AccessKind,
        alignment: DataAlignment,
        origin: AccessOrigin,
        alignment_cpl: Option<u8>,
    ) -> Result<PreparedAccess, CpuError> {
        if kind == AccessKind::AddressOnly {
            return Err(self.error_site());
        }
        if self.system.cr0 & CR0_PG != 0 && self.uses_legacy_projection() {
            return Err(self.compatibility_gap(CpuCompatibilityGap::PagingAddressTranslation));
        }
        let invalid_segment_use = match kind {
            AccessKind::Fetch => span.register != SegmentRegister::Cs,
            AccessKind::StackRead | AccessKind::StackWrite => span.register != SegmentRegister::Ss,
            AccessKind::SystemTableRead | AccessKind::SystemTableWrite => true,
            _ => false,
        };
        if invalid_segment_use {
            return Err(self.error_site());
        }
        if !self.uses_legacy_projection() {
            let parts = self.prepare_architectural_logical(span, kind)?;
            return Ok(self.prepared_logical(parts, kind, alignment, origin, alignment_cpl));
        }

        // Unknown legacy contexts use the checked resolver without inventing
        // a CPL; alignment/debug contracts stay inactive for that projection.
        let mode = self.checked_execution_mode()?;
        let len32 =
            u32::try_from(span.len).map_err(|_| CpuError::Memory(MemoryError::AddressOverflow))?;
        let offset = if kind == AccessKind::Fetch || span.address32 {
            span.offset
        } else {
            u32::from(span.offset as u16)
        };
        let end = u64::from(offset)
            .checked_add(u64::from(len32))
            .ok_or_else(|| super::segment_faults::limit_fault(span, offset, kind, self.site.ip))?;
        if mode == Some(CpuExecutionMode::RealAddress) && end > 0x1_0000 {
            return Err(self.real_mode_limit_fault(span));
        }
        if end > u64::from(u32::MAX) + 1 {
            return Err(super::segment_faults::limit_fault(span, offset, kind, self.site.ip));
        }

        let mut read_addresses = Vec::new();
        let mut write_addresses = Vec::new();
        if kind.reads() {
            read_addresses
                .try_reserve_exact(span.len)
                .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
        }
        if kind.writes() {
            write_addresses
                .try_reserve_exact(span.len)
                .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
        }

        for index in 0..span.len {
            let byte_offset = offset
                .checked_add(
                    u32::try_from(index)
                        .map_err(|_| CpuError::Memory(MemoryError::AddressOverflow))?,
                )
                .ok_or_else(|| {
                    super::segment_faults::limit_fault(span, offset, kind, self.site.ip)
                })?;
            if kind.reads() {
                read_addresses.push(
                    self.resolve_logical_byte(span.selector, byte_offset, kind, false)
                        .map_err(|error| {
                            super::segment_faults::map_stack_error(
                                error,
                                span.register,
                                self.site.ip,
                            )
                        })?,
                );
            }
            if kind.writes() {
                write_addresses.push(
                    self.resolve_logical_byte(span.selector, byte_offset, kind, true)
                        .map_err(|error| {
                            super::segment_faults::map_stack_error(
                                error,
                                span.register,
                                self.site.ip,
                            )
                        })?,
                );
            }
        }

        if kind == AccessKind::DataReadWrite && read_addresses != write_addresses {
            return Err(self.error_site());
        }

        let read_chunks = super::coalesce_addresses(read_addresses)?;
        let write_chunks = super::coalesce_addresses(write_addresses)?;
        self.validate_chunks(&read_chunks, true)?;
        self.validate_chunks(&write_chunks, false)?;
        Ok(self.prepared_logical(
            AccessParts {
                linear_start: None,
                len: span.len,
                can_read: kind.reads(),
                can_write: kind.writes(),
                read_chunks,
                write_chunks,
            },
            kind,
            alignment,
            origin,
            alignment_cpl,
        ))
    }

    pub(super) fn prepared_logical(
        &self,
        parts: AccessParts,
        kind: AccessKind,
        alignment: DataAlignment,
        origin: AccessOrigin,
        alignment_cpl: Option<u8>,
    ) -> PreparedAccess {
        PreparedAccess {
            owner: Arc::clone(&self.owner),
            epoch: self.epoch,
            len: parts.len,
            linear_start: parts.linear_start,
            kind,
            alignment,
            alignment_cpl,
            origin: Some(origin),
            can_read: parts.can_read,
            can_write: parts.can_write,
            read_chunks: parts.read_chunks,
            write_chunks: parts.write_chunks,
        }
    }
}
