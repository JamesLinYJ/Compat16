//! Protected-mode CPU system state and address checks.
//!
//! This module models architectural state only. Guest physical addresses are
//! indices into the checked `GuestMemory` buffer; they are never host pointers
//! or host physical addresses.

mod descriptor;
mod descriptor_access;
mod paging;
mod segment_state;
#[cfg(test)]
mod tests;

pub(crate) use descriptor::{
    DescriptorType, SegmentAccess, SegmentDescriptor, SegmentTableRegister,
};
pub(crate) use descriptor_access::{
    DescriptorRecord, map_fault, mark_segment_accessed, read_descriptor, read_gdt_descriptor,
    set_system_descriptor_type,
};
pub(crate) use paging::{PageAccess, TranslationError};
pub use segment_state::{
    ArchitecturalContext, CpuSegmentCacheState, CpuSystemSegmentState, CpuSystemTables,
    SystemTableRegister,
};
pub(crate) use segment_state::{SegmentCache, SystemSegmentCache};

use crate::memory::CpuExecutionMode;
use crate::{CpuArchitecturalStateError, registers::SegmentRegister};
use guest_core::LinearAddr;
use guest_core::Registers;

/// IA-32 exception vectors used by system-state checks in this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ExceptionVector {
    SegmentNotPresent = 11,
    StackSegment = 12,
    GeneralProtection = 13,
    PageFault = 14,
}

/// Architectural fault data before the CPU's exception-delivery path runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuFault {
    pub(crate) vector: ExceptionVector,
    pub(crate) error_code: Option<u32>,
    pub(crate) linear_address: Option<LinearAddr>,
}

impl CpuFault {
    pub(crate) const fn general_protection(error_code: u32) -> Self {
        Self {
            vector: ExceptionVector::GeneralProtection,
            error_code: Some(error_code),
            linear_address: None,
        }
    }

    pub(crate) const fn segment_not_present(error_code: u32) -> Self {
        Self {
            vector: ExceptionVector::SegmentNotPresent,
            error_code: Some(error_code),
            linear_address: None,
        }
    }

    pub(crate) const fn stack_segment(error_code: u32) -> Self {
        Self {
            vector: ExceptionVector::StackSegment,
            error_code: Some(error_code),
            linear_address: None,
        }
    }

    pub(crate) const fn page_fault(linear_address: LinearAddr, error_code: u32) -> Self {
        Self {
            vector: ExceptionVector::PageFault,
            error_code: Some(error_code),
            linear_address: Some(linear_address),
        }
    }
}

/// Control-register state needed for protected mode and 32-bit paging.
///
/// Reserved state is checked by the write methods. `cr2` is updated only by
/// page faults generated while translating a linear address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuSystem {
    pub(crate) cr0: u32,
    pub(crate) cr2: u32,
    pub(crate) cr3: u32,
    pub(crate) debug: CpuDebugRegisters,
    pub(crate) cpl: u8,
    pub(crate) segments: [SegmentCache; 6],
    pub(crate) gdtr: SegmentTableRegister,
    pub(crate) idtr: SegmentTableRegister,
    pub(crate) ldtr: SystemSegmentCache,
    pub(crate) task: SystemSegmentCache,
    /// False only while a legacy caller still owns protected-mode selector
    /// projection. A real PE transition or explicit import ends that adapter.
    pub(crate) architectural_context_initialized: bool,
}

/// Persisted Intel486 debug-register state. The reset manual guarantees that
/// DR7 disables breakpoints; unspecified address/status values use a stable
/// zero representation while no debug event delivery is modeled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuDebugRegisters {
    pub(crate) addresses: [u32; 4],
    pub(crate) status: u32,
    pub(crate) control: u32,
}

pub(crate) const CR0_PE: u32 = 1 << 0;
pub(crate) const CR0_MP: u32 = 1 << 1;
pub(crate) const CR0_EM: u32 = 1 << 2;
pub(crate) const CR0_TS: u32 = 1 << 3;
pub(crate) const CR0_ET: u32 = 1 << 4;
pub(crate) const CR0_NE: u32 = 1 << 5;
pub(crate) const CR0_WP: u32 = 1 << 16;
pub(crate) const CR0_AM: u32 = 1 << 18;
pub(crate) const CR0_NW: u32 = 1 << 29;
pub(crate) const CR0_CD: u32 = 1 << 30;
pub(crate) const CR0_PG: u32 = 1 << 31;
pub(crate) const CR3_PWT: u32 = 1 << 3;
pub(crate) const CR3_PCD: u32 = 1 << 4;

pub(crate) const DR6_WRITABLE_MASK: u32 = 0x0000_f00f;
pub(crate) const DR7_WRITABLE_MASK: u32 = 0xffff_33ff;
pub(crate) const DR7_GD: u32 = 1 << 13;

impl Default for CpuSystem {
    fn default() -> Self {
        Self::reset()
    }
}

impl CpuSystem {
    /// The Intel486 reset value: CD and NW are set and ET is hardwired to one.
    pub(crate) fn reset() -> Self {
        Self {
            cr0: CR0_ET | CR0_NW | CR0_CD,
            cr2: 0,
            cr3: 0,
            debug: CpuDebugRegisters {
                addresses: [0; 4],
                status: 0,
                control: 0,
            },
            cpl: 0,
            segments: [
                SegmentCache::real_mode(0, true),
                SegmentCache::real_mode(0, false),
                SegmentCache::real_mode(0, false),
                SegmentCache::real_mode(0, false),
                SegmentCache::real_mode(0, false),
                SegmentCache::real_mode(0, false),
            ],
            gdtr: SegmentTableRegister {
                base: LinearAddr(0),
                limit: u16::MAX as u32,
            },
            idtr: SegmentTableRegister {
                base: LinearAddr(0),
                limit: u16::MAX as u32,
            },
            ldtr: SystemSegmentCache::default(),
            task: SystemSegmentCache::default(),
            architectural_context_initialized: false,
        }
    }

    pub(crate) fn reset_for_registers(registers: &Registers) -> Self {
        let mut system = Self::reset();
        system.initialize_real_mode_segments(registers);
        system
    }

    pub(crate) fn initialize_real_mode_segments(&mut self, registers: &Registers) {
        self.segments = [
            SegmentCache::real_mode(registers.cs, true),
            SegmentCache::real_mode(registers.ss, false),
            SegmentCache::real_mode(registers.ds, false),
            SegmentCache::real_mode(registers.es, false),
            SegmentCache::real_mode(registers.fs, false),
            SegmentCache::real_mode(registers.gs, false),
        ];
        self.cpl = 0;
    }

    pub(crate) fn segment_cache(&self, register: SegmentRegister) -> &SegmentCache {
        &self.segments[segment_index(register)]
    }

    pub(crate) fn segment_cache_mut(&mut self, register: SegmentRegister) -> &mut SegmentCache {
        &mut self.segments[segment_index(register)]
    }

    pub(crate) fn load_real_segment(&mut self, register: SegmentRegister, selector: u16) {
        *self.segment_cache_mut(register) =
            SegmentCache::real_mode(selector, register == SegmentRegister::Cs);
    }

    pub(crate) fn code_bits(&self) -> u32 {
        if self
            .segment_cache(SegmentRegister::Cs)
            .descriptor
            .default_big
        {
            32
        } else {
            16
        }
    }

    pub(crate) fn stack32(&self) -> bool {
        self.segment_cache(SegmentRegister::Ss)
            .descriptor
            .default_big
    }

    pub(crate) fn import_architectural_context(
        &mut self,
        context: ArchitecturalContext,
        selectors: [u16; 6],
        eflags: u32,
    ) -> Result<(), CpuArchitecturalStateError> {
        let mut next = *self;
        next.write_cr0(context.cr0)
            .map_err(|_| CpuArchitecturalStateError::InvalidControlRegister)?;
        next.cr2 = context.cr2;
        next.write_cr3(context.cr3)
            .map_err(|_| CpuArchitecturalStateError::InvalidControlRegister)?;
        let mode = next
            .execution_mode(eflags)
            .ok_or(CpuArchitecturalStateError::InvalidControlRegister)?;
        let (segments, ldtr, task) = context.validate(selectors, mode)?;
        next.cpl = context.cpl;
        next.segments = segments;
        next.gdtr = SegmentTableRegister {
            base: LinearAddr(context.tables.gdtr.base),
            limit: u32::from(context.tables.gdtr.limit),
        };
        next.idtr = SegmentTableRegister {
            base: LinearAddr(context.tables.idtr.base),
            limit: u32::from(context.tables.idtr.limit),
        };
        next.ldtr = ldtr;
        next.task = task;
        next.architectural_context_initialized = true;
        *self = next;
        Ok(())
    }

    /// Derive execution mode from persistent CR0 and the architectural VM flag.
    /// VM is meaningful only while protected mode is enabled.
    pub(crate) fn execution_mode(&self, eflags: u32) -> Option<CpuExecutionMode> {
        const EFLAGS_VM: u32 = 1 << 17;

        if eflags & EFLAGS_VM != 0 {
            (self.cr0 & CR0_PE != 0).then_some(CpuExecutionMode::Virtual8086)
        } else if self.cr0 & CR0_PE != 0 {
            Some(CpuExecutionMode::Protected)
        } else {
            Some(CpuExecutionMode::RealAddress)
        }
    }

    pub(crate) fn write_cr0(&mut self, value: u32) -> Result<(), CpuFault> {
        let implemented = CR0_PE
            | CR0_MP
            | CR0_EM
            | CR0_TS
            | CR0_ET
            | CR0_NE
            | CR0_WP
            | CR0_AM
            | CR0_NW
            | CR0_CD
            | CR0_PG;
        let invalid_mode = value & CR0_PG != 0 && value & CR0_PE == 0;
        let invalid_cache_mode = value & CR0_NW != 0 && value & CR0_CD == 0;
        if invalid_mode || invalid_cache_mode {
            return Err(CpuFault::general_protection(0));
        }
        // Intel documents that reserved CR0 bits remain clear after a load;
        // setting them has no effect. Keep the implemented bits, then apply ET's
        // hardwired-one behavior.
        let next = (value & implemented) | CR0_ET;
        if (self.cr0 ^ next) & CR0_PE != 0 {
            self.architectural_context_initialized = true;
        }
        self.cr0 = next;
        Ok(())
    }

    pub(crate) fn write_cr2(&mut self, value: u32) {
        self.cr2 = value;
    }

    pub(crate) fn write_cr3(&mut self, value: u32) -> Result<(), CpuFault> {
        let allowed = 0xffff_f000 | CR3_PWT | CR3_PCD;
        // On the 486, the low 12 base-address bits are ignored, except for
        // the architected PWT/PCD controls in bits 3 and 4. Do not turn these
        // ignored bits into a #GP merely because software left them set.
        self.cr3 = value & allowed;
        Ok(())
    }

    pub(crate) fn x87_instruction_unavailable(&self) -> bool {
        self.cr0 & (CR0_EM | CR0_TS) != 0
    }

    pub(crate) fn wait_instruction_unavailable(&self) -> bool {
        self.cr0 & (CR0_MP | CR0_TS) == (CR0_MP | CR0_TS)
    }

    pub(crate) fn read_debug_register(&self, index: u8) -> Option<u32> {
        Some(match index {
            0..=3 => self.debug.addresses[usize::from(index)],
            4 | 6 => self.debug.status,
            5 | 7 => self.debug.control,
            _ => return None,
        })
    }

    pub(crate) fn write_debug_register(&mut self, index: u8, value: u32) -> bool {
        match index {
            0..=3 => self.debug.addresses[usize::from(index)] = value,
            4 | 6 => self.debug.status = value,
            5 | 7 => self.debug.control = value,
            _ => return false,
        }
        true
    }
}

const fn segment_index(register: SegmentRegister) -> usize {
    match register {
        SegmentRegister::Cs => 0,
        SegmentRegister::Ss => 1,
        SegmentRegister::Ds => 2,
        SegmentRegister::Es => 3,
        SegmentRegister::Fs => 4,
        SegmentRegister::Gs => 5,
    }
}
