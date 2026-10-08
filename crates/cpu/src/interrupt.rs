//! Explicit 16-bit real-mode IVT interrupt entry.

use guest_core::{GuestMemory, LinearAddr};

use crate::memory_access::{
    AccessKind, AccessOrigin, AccessRequest, AccessSite, CpuBus, CpuMemoryAccess, DataAlignment,
    LogicalSpan,
};
use crate::memory_values::write_prepared_width;
use crate::registers::SegmentRegister;
use crate::system::SegmentCache;
use crate::{Cpu, CpuError, IF, RealModeSegments, SegmentResolver, TF};
use crate::interrupt_delivery::EventSource;

const EFLAGS_RF: u32 = 1 << 16;
const EFLAGS_AC: u32 = 1 << 18;

impl Cpu {
    /// Enter a host-scheduled real-address far call through checked CPU state.
    /// A caller without imported CPU-owned caches keeps its existing legacy
    /// resolver path and receives `Ok(false)` without changing guest state.
    pub fn enter_real_mode_far_call16(
        &mut self,
        handler_cs: u16,
        handler_ip: u16,
        return_cs: u16,
        return_ip: u16,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<Option<bool>, CpuError> {
        self.normalize_model_eflags();
        if !self.system.architectural_context_initialized {
            return Ok(None);
        }
        if self.system.execution_mode(self.regs.eflags)
            != Some(crate::CpuExecutionMode::RealAddress)
        {
            return Err(CpuError::CompatibilityGap {
                opcode: 0,
                ip: self.regs.eip,
                feature: crate::CpuCompatibilityGap::ProtectedExceptionDelivery,
            });
        }
        let registers = self.regs.clone();
        let site = AccessSite {
            opcode: 0,
            ip: registers.eip,
            eflags: registers.eflags,
        };
        let mut bus = CpuMemoryAccess::new(memory, segments, &mut self.system, site);
        let mut handler_byte = [0_u8; 1];
        let handler_cache = SegmentCache::real_mode(handler_cs, true);
        let handler_access = bus.prepare_logical_with_cache(
            LogicalSpan {
                register: SegmentRegister::Cs,
                selector: handler_cs,
                offset: u32::from(handler_ip),
                len: 1,
                address32: false,
            },
            AccessKind::Fetch,
            DataAlignment::Unaligned,
            AccessOrigin::GuestInstruction,
            handler_cache,
        )?;
        bus.read_prepared(&handler_access, &mut handler_byte)?;

        let address32 = bus.stack32();
        let old_pointer = if address32 {
            registers.esp
        } else {
            u32::from(registers.sp())
        };
        let first_pointer = if address32 {
            old_pointer.wrapping_sub(2)
        } else {
            u32::from((old_pointer as u16).wrapping_sub(2))
        };
        let second_pointer = if address32 {
            first_pointer.wrapping_sub(2)
        } else {
            u32::from((first_pointer as u16).wrapping_sub(2))
        };
        let frame_limit = if address32 {
            u64::from(u32::MAX) + 1
        } else {
            u64::from(u16::MAX) + 1
        };
        if u64::from(second_pointer) + 4 > frame_limit {
            return Err(CpuError::StackSegmentFault {
                error_code: 0,
                ip: site.ip,
            });
        }
        let requests = [first_pointer, second_pointer].map(|offset| AccessRequest::Logical {
            span: LogicalSpan {
                register: SegmentRegister::Ss,
                selector: registers.ss,
                offset,
                len: 2,
                address32,
            },
            kind: AccessKind::StackWrite,
            alignment: DataAlignment::Natural(2),
            origin: AccessOrigin::GuestInstruction,
        });
        let mut accesses = bus.prepare_group(&requests)?.into_accesses();
        if accesses.len() != 2 {
            return Err(CpuError::InvalidMemoryAccessPlan { ip: registers.eip });
        }
        for (access, value) in accesses.drain(..).zip([return_cs, return_ip]) {
            write_prepared_width(&mut bus, access, 2, u32::from(value))?;
        }
        bus.system_mut()
            .load_real_segment(SegmentRegister::Cs, handler_cs);
        drop(bus);

        self.regs.cs = handler_cs;
        self.regs.eip = u32::from(handler_ip);
        if address32 {
            self.regs.esp = second_pointer;
        } else {
            self.regs.set_sp(second_pointer as u16);
        }
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        Ok(Some(address32))
    }

    /// Enter a 16-bit interrupt handler using the supplied segment resolver.
    ///
    /// The handler entry must resolve as executable and readable. The current
    /// CS:IP and 16-bit FLAGS are pushed as one preflighted stack frame. This
    /// delivers the stack frame only; it does not implement IDT lookup or
    /// privilege-level transitions.
    pub fn enter_interrupt16(
        &mut self,
        handler_cs: u16,
        handler_ip: u16,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<(), CpuError> {
        self.normalize_model_eflags();
        if self.system.architectural_context_initialized
            && self.system.execution_mode(self.regs.eflags)
                != Some(crate::CpuExecutionMode::RealAddress)
        {
            return Err(CpuError::CompatibilityGap {
                opcode: 0,
                ip: self.regs.eip,
                feature: crate::CpuCompatibilityGap::ProtectedExceptionDelivery,
            });
        }
        let regs = self.regs.clone();
        let site = AccessSite {
            opcode: 0,
            ip: self.regs.eip,
            eflags: self.regs.eflags,
        };
        let (stack_pointer, address32) = {
            let mut bus = CpuMemoryAccess::new(memory, segments, &mut self.system, site);
            bus.set_processor_event_error_ext(true);
            let mut handler_byte = [0_u8; 1];
            let target = LogicalSpan {
                register: SegmentRegister::Cs,
                selector: handler_cs,
                offset: u32::from(handler_ip),
                len: 1,
                address32: false,
            };
            let access = if bus.architectural_mode_active()
                && bus.execution_mode() == Some(crate::CpuExecutionMode::RealAddress)
            {
                bus.prepare_logical_with_cache(
                    target,
                    AccessKind::Fetch,
                    DataAlignment::Unaligned,
                    AccessOrigin::ProcessorEvent,
                    SegmentCache::real_mode(handler_cs, true),
                )?
            } else {
                bus.prepare(AccessRequest::Logical {
                    span: LogicalSpan {
                        address32: bus.code_bits() == 32,
                        ..target
                    },
                    kind: AccessKind::Fetch,
                    alignment: DataAlignment::Unaligned,
                    origin: AccessOrigin::ProcessorEvent,
                })?
            };
            bus.read_prepared(&access, &mut handler_byte)?;
            let address32 = bus.stack32();
            (push_interrupt_frame16(&regs, &mut bus)?, address32)
        };
        self.commit_interrupt16(handler_cs, handler_ip, stack_pointer, address32);
        Ok(())
    }

    /// Enter a real-mode interrupt handler through the guest IVT.
    ///
    /// The current CS:IP is treated as the resume address at the interrupt
    /// boundary. The guest-owned IVT entry and all three stack slots are
    /// accessed through the checked CPU memory bus. Register state is committed
    /// only after the full stack plan and every write succeed.
    pub fn enter_real_mode_interrupt(
        &mut self,
        vector: u8,
        memory: &mut impl GuestMemory,
    ) -> Result<(), CpuError> {
        let resume_eip = self.regs.eip;
        self.enter_real_mode_interrupt_for_event(
            vector,
            EventSource::ExternalInterrupt,
            resume_eip,
            resume_eip,
            0,
            memory,
        )
    }

    pub(crate) fn enter_real_mode_interrupt_for_event(
        &mut self,
        vector: u8,
        source: EventSource,
        resume_eip: u32,
        instruction_ip: u32,
        instruction_opcode: u8,
        memory: &mut impl GuestMemory,
    ) -> Result<(), CpuError> {
        self.normalize_model_eflags();
        if self.system.execution_mode(self.regs.eflags)
            != Some(crate::CpuExecutionMode::RealAddress)
        {
            return Err(CpuError::CompatibilityGap {
                opcode: instruction_opcode,
                ip: instruction_ip,
                feature: crate::CpuCompatibilityGap::ProtectedExceptionDelivery,
            });
        }
        let mut regs = self.regs.clone();
        regs.eip = resume_eip;
        let site = AccessSite {
            opcode: instruction_opcode,
            ip: instruction_ip,
            eflags: self.regs.eflags,
        };
        let resolver = RealModeSegments;
        let table = self.system.idtr;
        let (handler_cs, handler_ip, stack_pointer, address32) = {
            let mut bus = CpuMemoryAccess::new(memory, &resolver, &mut self.system, site);
            bus.set_processor_event_error_ext(source.sets_error_code_ext());
            let vector_offset = u32::from(vector) * 4;
            if vector_offset + 3 > table.limit {
                return Err(CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip: instruction_ip,
                });
            }
            let address = table.base.0.checked_add(vector_offset).ok_or(
                CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip: instruction_ip,
                },
            )?;
            address
                .checked_add(3)
                .ok_or(CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip: instruction_ip,
                })?;
            let mut entry = [0_u8; 4];
            let access = bus.prepare(AccessRequest::SystemLinear {
                address: LinearAddr(address),
                len: entry.len(),
                kind: AccessKind::SystemTableRead,
            })?;
            bus.read_prepared(&access, &mut entry)?;
            let handler_ip = u16::from_le_bytes([entry[0], entry[1]]);
            let handler_cs = u16::from_le_bytes([entry[2], entry[3]]);
            let mut handler_byte = [0_u8; 1];
            let handler_fetch = bus.prepare_logical_with_cache(
                LogicalSpan {
                    register: SegmentRegister::Cs,
                    selector: handler_cs,
                    offset: u32::from(handler_ip),
                    len: handler_byte.len(),
                    address32: false,
                },
                AccessKind::Fetch,
                DataAlignment::Unaligned,
                AccessOrigin::ProcessorEvent,
                SegmentCache::real_mode(handler_cs, true),
            )?;
            bus.read_prepared(&handler_fetch, &mut handler_byte)?;
            let address32 = bus.stack32();
            let stack_pointer = push_interrupt_frame16(&regs, &mut bus)?;
            (handler_cs, handler_ip, stack_pointer, address32)
        };
        self.commit_interrupt16(handler_cs, handler_ip, stack_pointer, address32);
        Ok(())
    }

    fn commit_interrupt16(
        &mut self,
        handler_cs: u16,
        handler_ip: u16,
        stack_pointer: u32,
        address32: bool,
    ) {
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        if address32 {
            self.regs.esp = stack_pointer;
        } else {
            self.regs.set_sp(stack_pointer as u16);
        }
        self.regs.cs = handler_cs;
        self.system
            .load_real_segment(SegmentRegister::Cs, handler_cs);
        self.regs.eip = u32::from(handler_ip);
        self.regs.eflags = (self.regs.eflags & !(IF | TF | EFLAGS_AC | EFLAGS_RF)) | 2;
        self.halted = false;
        self.maskable_interrupt_shadow = false;
        self.debug_exception_shadow = false;
        self.deferred_data_breakpoint_hits = crate::memory_access::DataBreakpointHits::default();
        self.intermediate_rep_boundary = false;
    }
}

fn push_interrupt_frame16(
    regs: &guest_core::Registers,
    bus: &mut impl CpuBus,
) -> Result<u32, CpuError> {
    let values = [(regs.eflags as u16) | 2, regs.cs, regs.ip()];
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(values.len())
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    let address32 = bus.stack32();
    let mut offset = if address32 {
        regs.esp
    } else {
        u32::from(regs.sp())
    };
    for _ in 0..values.len() {
        offset = if address32 {
            offset.wrapping_sub(2)
        } else {
            u32::from((offset as u16).wrapping_sub(2))
        };
        requests.push(AccessRequest::Logical {
            span: LogicalSpan {
                register: SegmentRegister::Ss,
                selector: regs.ss,
                offset,
                len: 2,
                address32,
            },
            kind: AccessKind::StackWrite,
            alignment: DataAlignment::Natural(2),
            origin: AccessOrigin::ProcessorEvent,
        });
    }
    let stack_limit = if address32 {
        u64::from(u32::MAX) + 1
    } else {
        u64::from(u16::MAX) + 1
    };
    if u64::from(offset) + 6 > stack_limit {
        return Err(CpuError::StackSegmentFault {
            error_code: 0,
            ip: bus.instruction_site().ip,
        });
    }
    let accesses = bus.prepare_group(&requests)?.into_accesses();
    for (access, value) in accesses.into_iter().zip(values) {
        write_prepared_width(bus, access, 2, u32::from(value))?;
    }
    Ok(offset)
}
