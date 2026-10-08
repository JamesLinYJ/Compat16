use std::ops::Range;

use guest_core::{MemoryError, PhysAddr, memory::Memory};
use x86_cpu::{CpuError, SegmentAccess, SegmentFaultReason, SegmentResolver};

use crate::{DiagnosticKind as Kind, RuntimeError};

const ADDRESS_SPACE_END: u64 = 0x1_0000_0000;

/// A checked, half-open guest linear range containing executable PE bytes.
/// The exclusive end is 64-bit so a range may end exactly at 4 GiB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32GuestCodeRange {
    start: u64,
    end: u64,
}

impl Pe32GuestCodeRange {
    pub(crate) fn from_linear_range(range: Range<u64>) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }

    pub(crate) fn from_rva(base: u32, rva: u32, size: u32) -> Self {
        let start = u64::from(base) + u64::from(rva);
        let end = start + u64::from(size);
        Self { start, end }
    }

    pub(crate) const fn contains(self, address: u32) -> bool {
        (address as u64) >= self.start && (address as u64) < self.end
    }
}

/// Permissions are explicit because a PE32 selector is not a Win16 selector
/// and cannot be resolved through the 16-bit `SelectorTable`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32SegmentAccess {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) execute: bool,
}

impl Pe32SegmentAccess {
    pub(crate) const fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }
}

/// One caller-supplied 32-bit selector mapping with an inclusive byte limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32SegmentMapping {
    pub(crate) selector: u16,
    pub(crate) base: u32,
    pub(crate) limit: u32,
    pub(crate) access: Pe32SegmentAccess,
}

impl Pe32SegmentMapping {
    pub(crate) const fn new(
        selector: u16,
        base: u32,
        limit: u32,
        access: Pe32SegmentAccess,
    ) -> Self {
        Self {
            selector,
            base,
            limit,
            access,
        }
    }

    fn linear_end(self) -> u64 {
        u64::from(self.base) + u64::from(self.limit) + 1
    }
}

/// A stack range expressed as SS offsets; `end_offset` is exclusive and
/// `top_offset` is the empty-stack ESP before arguments are staged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pe32GuestStackRange {
    pub(crate) start_offset: u32,
    pub(crate) end_offset: u32,
    pub(crate) top_offset: u32,
}

impl Pe32GuestStackRange {
    pub(crate) const fn new(start_offset: u32, end_offset: u32, top_offset: u32) -> Self {
        Self {
            start_offset,
            end_offset,
            top_offset,
        }
    }
}

/// Explicit guest32 segment and stack state for one PE32 call.
///
/// This is a checked flat-address projection, not evidence that the emulator
/// owns a Windows GDT, CPL, TEB, or TLS runtime. FS/GS are unmapped unless the
/// caller supplies real guest mappings; absent registers enter as null
/// selectors and any access faults as not-present.
pub(crate) struct Pe32GuestExecutionEnvironment {
    segments: Vec<Pe32SegmentMapping>,
    executable_ranges: Vec<Pe32GuestCodeRange>,
    pub(crate) code_selector: u16,
    pub(crate) stack_selector: u16,
    pub(crate) data_selector: u16,
    pub(crate) es_selector: Option<u16>,
    pub(crate) fs_selector: Option<u16>,
    pub(crate) gs_selector: Option<u16>,
    pub(crate) stack: Pe32GuestStackRange,
    /// Reserved two-byte UD2 slot in the code segment. The caller reserves
    /// this runtime-owned slot outside every guest PE executable section.
    pub(crate) return_gate_offset: u32,
}

impl Pe32GuestExecutionEnvironment {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        segments: Vec<Pe32SegmentMapping>,
        executable_ranges: Vec<Pe32GuestCodeRange>,
        code_selector: u16,
        stack_selector: u16,
        data_selector: u16,
        es_selector: Option<u16>,
        fs_selector: Option<u16>,
        gs_selector: Option<u16>,
        stack: Pe32GuestStackRange,
        return_gate_offset: u32,
    ) -> Self {
        Self {
            segments,
            executable_ranges,
            code_selector,
            stack_selector,
            data_selector,
            es_selector,
            fs_selector,
            gs_selector,
            stack,
            return_gate_offset,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        if self.executable_ranges.is_empty() {
            return Err(invalid_environment(
                "PE32 call environment has no executable guest ranges",
            ));
        }
        for (index, segment) in self.segments.iter().enumerate() {
            if segment.selector == 0 || segment.linear_end() > ADDRESS_SPACE_END {
                return Err(invalid_environment(
                    "PE32 segment selector is null or its linear range overflows",
                ));
            }
            if self.segments[..index]
                .iter()
                .any(|earlier| earlier.selector == segment.selector)
            {
                return Err(invalid_environment(
                    "PE32 segment map contains a duplicate selector",
                ));
            }
        }
        let code = self.required_segment(
            self.code_selector,
            |access| access.execute,
            "PE32 CS is not mapped executable",
        )?;
        let stack = self.required_segment(
            self.stack_selector,
            |access| access.read && access.write,
            "PE32 SS is not mapped readable and writable",
        )?;
        self.required_segment(
            self.data_selector,
            |access| access.read && access.write,
            "PE32 DS is not mapped readable and writable",
        )?;
        for selector in [self.es_selector, self.fs_selector, self.gs_selector]
            .into_iter()
            .flatten()
        {
            self.required_segment(
                selector,
                |access| access.read,
                "PE32 optional data selector is not mapped readable",
            )?;
        }

        let stack_end = u64::from(self.stack.end_offset);
        if self.stack.start_offset >= self.stack.top_offset
            || self.stack.top_offset > self.stack.end_offset
            || self.stack.top_offset & 3 != 0
            || stack_end > u64::from(stack.limit) + 1
        {
            return Err(invalid_environment(
                "PE32 guest stack range/top is outside SS or unaligned",
            ));
        }
        let stack_linear_start = u64::from(stack.base) + u64::from(self.stack.start_offset);
        let stack_linear_end = u64::from(stack.base) + stack_end;
        let stack_linear_top = u64::from(stack.base) + u64::from(self.stack.top_offset);
        if stack_linear_start >= ADDRESS_SPACE_END
            || stack_linear_end > ADDRESS_SPACE_END
            || stack_linear_top & 3 != 0
        {
            return Err(invalid_environment(
                "PE32 guest stack range overflows linear address space",
            ));
        }

        if self
            .return_gate_offset
            .checked_add(1)
            .is_none_or(|last| last > code.limit)
        {
            return Err(invalid_environment(
                "PE32 return gate lies outside the executable CS limit",
            ));
        }
        let gate_linear = u64::from(code.base) + u64::from(self.return_gate_offset);
        if self.executable_ranges.iter().any(|range| {
            range.end > code.linear_end()
                || range.start < u64::from(code.base)
                || (gate_linear < range.end && range.start < gate_linear + 2)
        }) {
            return Err(invalid_environment(
                "PE32 return gate overlaps a guest executable range or CS mapping",
            ));
        }
        for (index, range) in self.executable_ranges.iter().enumerate() {
            if range.start >= range.end || range.end > ADDRESS_SPACE_END {
                return Err(invalid_environment(
                    "PE32 executable code range is malformed",
                ));
            }
            if self.executable_ranges[..index]
                .iter()
                .any(|earlier| range.start < earlier.end && earlier.start < range.end)
            {
                return Err(invalid_environment("PE32 executable ranges overlap"));
            }
        }
        Ok(())
    }

    /// Replace the executable allowlist only at a checked paused service
    /// boundary. The old map remains intact if the new snapshot is invalid.
    pub(crate) fn replace_executable_ranges(
        &mut self,
        ranges: Vec<Pe32GuestCodeRange>,
    ) -> Result<(), RuntimeError> {
        let previous = std::mem::replace(&mut self.executable_ranges, ranges);
        if let Err(error) = self.validate() {
            self.executable_ranges = previous;
            return Err(error);
        }
        Ok(())
    }

    fn required_segment(
        &self,
        selector: u16,
        permits: impl FnOnce(Pe32SegmentAccess) -> bool,
        message: &'static str,
    ) -> Result<Pe32SegmentMapping, RuntimeError> {
        self.segments
            .iter()
            .copied()
            .find(|segment| segment.selector == selector)
            .filter(|segment| permits(segment.access))
            .ok_or_else(|| invalid_environment(message))
    }

    pub(crate) fn resolver(&self) -> Pe32SegmentResolver<'_> {
        Pe32SegmentResolver {
            segments: &self.segments,
            executable_ranges: &self.executable_ranges,
        }
    }

    pub(crate) fn validate_target(
        &self,
        address: u32,
        memory: &Memory,
    ) -> Result<u32, RuntimeError> {
        let code = self.required_segment(
            self.code_selector,
            |access| access.execute,
            "PE32 CS is not executable",
        )?;
        if !self
            .executable_ranges
            .iter()
            .any(|range| range.contains(address))
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 call target is outside the checked executable ranges",
            ));
        }
        let offset = u64::from(address)
            .checked_sub(u64::from(code.base))
            .filter(|offset| *offset <= u64::from(code.limit))
            .and_then(|offset| u32::try_from(offset).ok())
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "PE32 call target cannot be represented by the active CS mapping",
                )
            })?;
        validate_guest_ram(
            memory,
            PhysAddr(address),
            1,
            false,
            "PE32 call target is not backed by guest RAM",
        )?;
        Ok(offset)
    }

    pub(crate) fn stack_segment(&self) -> Result<Pe32SegmentMapping, RuntimeError> {
        self.required_segment(
            self.stack_selector,
            |access| access.read && access.write,
            "PE32 SS is not readable and writable",
        )
    }

    pub(crate) fn code_segment(&self) -> Result<Pe32SegmentMapping, RuntimeError> {
        self.required_segment(
            self.code_selector,
            |access| access.execute,
            "PE32 CS is not executable",
        )
    }
}

/// Resolver for explicit 32-bit flat-projection mappings. It does not claim
/// protected-mode privilege or synthesize a TEB for missing FS/GS mappings.
pub(crate) struct Pe32SegmentResolver<'a> {
    segments: &'a [Pe32SegmentMapping],
    executable_ranges: &'a [Pe32GuestCodeRange],
}

impl Pe32SegmentResolver<'_> {
    fn translate(
        &self,
        selector: u16,
        offset: u32,
        address32: bool,
        access: SegmentAccess,
    ) -> Result<PhysAddr, CpuError> {
        let offset = if address32 {
            offset
        } else {
            u32::from(offset as u16)
        };
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.selector == selector)
            .ok_or_else(|| {
                segment_fault(selector, offset, access, SegmentFaultReason::NotPresent)
            })?;
        let allowed = match access {
            SegmentAccess::Read => segment.access.read,
            SegmentAccess::Write => segment.access.write,
            SegmentAccess::Execute => segment.access.execute,
        };
        if !allowed {
            return Err(segment_fault(
                selector,
                offset,
                access,
                SegmentFaultReason::AccessDenied,
            ));
        }
        if offset > segment.limit {
            return Err(segment_fault(
                selector,
                offset,
                access,
                SegmentFaultReason::Limit,
            ));
        }
        let address = u64::from(segment.base) + u64::from(offset);
        let address = u32::try_from(address)
            .map_err(|_| segment_fault(selector, offset, access, SegmentFaultReason::Limit))?;
        Ok(PhysAddr(address))
    }
}

impl SegmentResolver for Pe32SegmentResolver<'_> {
    fn resolve(&self, selector: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        let effective = if address32 {
            offset
        } else {
            u32::from(offset as u16)
        };
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.selector == selector)
            .ok_or_else(|| {
                segment_fault(
                    selector,
                    effective,
                    SegmentAccess::Read,
                    SegmentFaultReason::NotPresent,
                )
            })?;
        if effective > segment.limit {
            return Err(segment_fault(
                selector,
                effective,
                SegmentAccess::Read,
                SegmentFaultReason::Limit,
            ));
        }
        u32::try_from(u64::from(segment.base) + u64::from(effective))
            .map(PhysAddr)
            .map_err(|_| {
                segment_fault(
                    selector,
                    effective,
                    SegmentAccess::Read,
                    SegmentFaultReason::Limit,
                )
            })
    }

    fn code_bits(&self) -> u32 {
        32
    }
    fn stack32(&self) -> bool {
        true
    }
    fn resolve_read(
        &self,
        selector: u16,
        offset: u32,
        address32: bool,
    ) -> Result<PhysAddr, CpuError> {
        self.translate(selector, offset, address32, SegmentAccess::Read)
    }
    fn resolve_write(
        &self,
        selector: u16,
        offset: u32,
        address32: bool,
    ) -> Result<PhysAddr, CpuError> {
        self.translate(selector, offset, address32, SegmentAccess::Write)
    }
    fn resolve_execute(
        &self,
        selector: u16,
        offset: u32,
        address32: bool,
    ) -> Result<PhysAddr, CpuError> {
        let address = self.translate(selector, offset, address32, SegmentAccess::Execute)?;
        if !self
            .executable_ranges
            .iter()
            .any(|range| range.contains(address.0))
        {
            return Err(segment_fault(
                selector,
                offset,
                SegmentAccess::Execute,
                SegmentFaultReason::AccessDenied,
            ));
        }
        Ok(address)
    }
}

pub(crate) fn validate_guest_ram(
    memory: &Memory,
    address: PhysAddr,
    length: usize,
    writable: bool,
    message: &'static str,
) -> Result<(), RuntimeError> {
    memory
        .validate_ram_range(address, length, writable)
        .map_err(|error| {
            let kind = match &error {
                MemoryError::StorageAccess { .. } => Kind::HostFailure,
                MemoryError::AllocationFailed => Kind::ResourceExhausted,
                _ => Kind::InternalInvariant,
            };
            RuntimeError::with_source(kind, message, error)
        })
}

fn segment_fault(
    selector: u16,
    offset: u32,
    access: SegmentAccess,
    reason: SegmentFaultReason,
) -> CpuError {
    CpuError::SegmentFault {
        selector,
        offset,
        access,
        reason,
    }
}

fn invalid_environment(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
