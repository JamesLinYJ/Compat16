use crate::CpuArchitecturalStateError;

use super::{DescriptorType, SegmentDescriptor};

/// Intel486 hidden state associated with one visible segment selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SegmentCache {
    pub(crate) selector: u16,
    pub(crate) descriptor: SegmentDescriptor,
    pub(crate) unusable: bool,
}

impl SegmentCache {
    pub(crate) const fn real_mode(selector: u16, code: bool) -> Self {
        Self {
            selector,
            descriptor: SegmentDescriptor {
                base: (selector as u32) << 4,
                limit: 0xffff,
                dpl: 0,
                present: true,
                default_big: false,
                granularity: false,
                available: false,
                long_mode: false,
                descriptor_type: if code {
                    DescriptorType::Code {
                        readable: true,
                        conforming: false,
                        accessed: true,
                    }
                } else {
                    DescriptorType::Data {
                        writable: true,
                        expand_down: false,
                        accessed: true,
                    }
                },
            },
            unusable: false,
        }
    }

    pub(crate) fn imported(
        state: CpuSegmentCacheState,
    ) -> Result<Self, CpuArchitecturalStateError> {
        if !state.usable {
            if state.selector & 0xfffc != 0 {
                return Err(CpuArchitecturalStateError::InvalidSegmentCache);
            }
            return Ok(Self::unusable(state.selector));
        }
        let descriptor = SegmentDescriptor::from_cache_fields(
            state.base,
            state.limit,
            state.access,
            state.flags,
        )
        .ok_or(CpuArchitecturalStateError::InvalidSegmentCache)?;
        if state.flags & 0x20 != 0
            || !descriptor.present
            || (!descriptor.granularity && state.limit > 0x000f_ffff)
            || (descriptor.granularity && state.limit & 0x0fff != 0x0fff)
            || !matches!(
                descriptor.descriptor_type,
                DescriptorType::Code { .. } | DescriptorType::Data { .. }
            )
        {
            return Err(CpuArchitecturalStateError::InvalidSegmentCache);
        }
        Ok(Self {
            selector: state.selector,
            descriptor,
            unusable: !state.usable,
        })
    }

    pub(crate) const fn from_descriptor(selector: u16, descriptor: SegmentDescriptor) -> Self {
        Self {
            selector,
            descriptor,
            unusable: false,
        }
    }

    pub(crate) const fn unusable(selector: u16) -> Self {
        Self {
            selector,
            descriptor: SegmentDescriptor {
                base: 0,
                limit: 0,
                dpl: 0,
                present: false,
                default_big: false,
                granularity: false,
                available: false,
                long_mode: false,
                descriptor_type: DescriptorType::Data {
                    writable: false,
                    expand_down: false,
                    accessed: false,
                },
            },
            unusable: true,
        }
    }

}

/// Hidden LDT or task-register descriptor state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SystemSegmentCache {
    pub(crate) selector: u16,
    pub(crate) base: u32,
    pub(crate) limit: u32,
    pub(crate) system_type: u8,
    pub(crate) present: bool,
    pub(crate) valid: bool,
}

impl SystemSegmentCache {
    pub(crate) fn from_import(
        state: CpuSystemSegmentState,
        allowed_types: &[u8],
    ) -> Result<Self, CpuArchitecturalStateError> {
        let invalid_selector = if state.valid {
            state.selector & 0xfffc == 0 || state.selector & 0x04 != 0
        } else {
            state.selector & 0xfffc != 0
        };
        let representable_limit = state.limit <= 0x000f_ffff || state.limit & 0x0fff == 0x0fff;
        if invalid_selector
            || state.valid && !allowed_types.contains(&state.system_type)
            || state.valid && !representable_limit
        {
            return Err(CpuArchitecturalStateError::InvalidSystemSegmentCache);
        }
        Ok(Self {
            selector: state.selector,
            base: state.base,
            limit: state.limit,
            system_type: state.system_type,
            present: state.present,
            valid: state.valid,
        })
    }

}

/// State imported by a machine owner at a deliberate CPU-mode boundary.
/// Segment order is CS, SS, DS, ES, FS, GS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchitecturalContext {
    pub cr0: u32,
    pub cr2: u32,
    pub cr3: u32,
    pub cpl: u8,
    pub segments: [CpuSegmentCacheState; 6],
    pub tables: CpuSystemTables,
    pub ldt: crate::CpuSystemSegmentState,
    pub task: crate::CpuSystemSegmentState,
}

impl ArchitecturalContext {
    pub(crate) fn validate(
        self,
        selectors: [u16; 6],
        mode: crate::CpuExecutionMode,
    ) -> Result<
        ([SegmentCache; 6], SystemSegmentCache, SystemSegmentCache),
        CpuArchitecturalStateError,
    > {
        if self.cpl > 3 {
            return Err(CpuArchitecturalStateError::InvalidPrivilegeLevel);
        }
        let mut segments = [SegmentCache::real_mode(0, false); 6];
        for index in 0..6 {
            if self.segments[index].selector != selectors[index] {
                return Err(CpuArchitecturalStateError::VisibleSelectorMismatch);
            }
            match mode {
                crate::CpuExecutionMode::RealAddress => {
                    // Clearing PE retains the segment hidden caches. Import
                    // those fields verbatim so an unreal-mode cache survives
                    // a scheduler/configuration boundary until a real-mode
                    // segment load replaces it.
                    segments[index] = SegmentCache::imported(self.segments[index])?;
                }
                crate::CpuExecutionMode::Virtual8086 => {
                    let state = self.segments[index];
                    let expected_base = u32::from(selectors[index]) << 4;
                    if !state.usable
                        || state.base != expected_base
                        || state.limit != u32::from(u16::MAX)
                        || state.flags & 0xe0 != 0
                        || state.access & 0x80 == 0
                    {
                        return Err(CpuArchitecturalStateError::InvalidSegmentCache);
                    }
                    segments[index] = SegmentCache::real_mode(selectors[index], index == 0);
                }
                crate::CpuExecutionMode::Protected => {
                    if self.segments[index].selector & 0xfffc == 0
                        && self.segments[index].usable
                    {
                        return Err(CpuArchitecturalStateError::InvalidSegmentCache);
                    }
                    segments[index] = SegmentCache::imported(self.segments[index])?;
                }
            }
        }
        let ldt = SystemSegmentCache::from_import(self.ldt, &[2])?;
        let task = SystemSegmentCache::from_import(self.task, &[3, 0x0b])?;
        if (ldt.valid && !ldt.present) || (task.valid && !task.present) {
            return Err(CpuArchitecturalStateError::InvalidSystemSegmentCache);
        }
        if mode == crate::CpuExecutionMode::RealAddress && self.cpl != 0 {
            return Err(CpuArchitecturalStateError::InvalidPrivilegeLevel);
        }
        if mode == crate::CpuExecutionMode::Virtual8086 && self.cpl != 3 {
            return Err(CpuArchitecturalStateError::InvalidPrivilegeLevel);
        }
        if mode != crate::CpuExecutionMode::Protected {
            return Ok((segments, ldt, task));
        }
        let code_valid = match segments[0].descriptor.descriptor_type {
            DescriptorType::Code {
                conforming: true, ..
            } => segments[0].descriptor.dpl <= self.cpl,
            DescriptorType::Code {
                conforming: false, ..
            } => segments[0].descriptor.dpl == self.cpl,
            _ => false,
        };
        if segments[0].unusable
            || !segments[0].descriptor.present
            || segments[0].selector & 3 != u16::from(self.cpl)
            || !code_valid
        {
            return Err(CpuArchitecturalStateError::InvalidCodeSegmentCache);
        }
        if segments[1].unusable
            || !segments[1].descriptor.present
            || (segments[1].selector & 3 != u16::from(self.cpl)
                || segments[1].descriptor.dpl != self.cpl
                || !matches!(
                    segments[1].descriptor.descriptor_type,
                    DescriptorType::Data { writable: true, .. }
                ))
        {
            return Err(CpuArchitecturalStateError::InvalidStackSegmentCache);
        }
        Ok((segments, ldt, task))
    }
}

/// One IA-32 descriptor-table register. The base is a guest linear address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemTableRegister {
    pub base: u32,
    pub limit: u16,
}

/// Architecturally visible descriptor tables imported at a mode boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuSystemTables {
    pub gdtr: SystemTableRegister,
    pub idtr: SystemTableRegister,
}

/// A visible selector and its validated hidden descriptor-cache fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuSegmentCacheState {
    pub selector: u16,
    pub base: u32,
    pub limit: u32,
    /// Descriptor access byte: type, S, DPL, and P fields.
    pub access: u8,
    /// Descriptor flags nibble in bits 7:4 (G, D/B, L, AVL).
    pub flags: u8,
    pub usable: bool,
}

/// Hidden descriptor-cache fields for LDTR or TR.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuSystemSegmentState {
    pub selector: u16,
    pub base: u32,
    pub limit: u32,
    pub system_type: u8,
    pub present: bool,
    pub valid: bool,
}
