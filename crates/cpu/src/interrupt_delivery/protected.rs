//! Protected-mode IDT gate validation and staged event-frame commit.

use guest_core::{GuestMemory, LinearAddr};

use crate::{Cpu, CpuError, CpuExecutionMode, CpuModel, SegmentResolver};
use crate::{
    memory_access::{
        AccessKind, AccessOrigin, AccessRequest, AccessSite, CpuBus, CpuMemoryAccess,
        DataAlignment, LogicalSpan,
    },
    memory_values::write_prepared_width,
    registers::SegmentRegister,
    system::{
        DescriptorRecord, DescriptorType, SegmentCache, map_fault, mark_segment_accessed,
        read_descriptor,
    },
};

use super::CpuEvent;

const EFLAGS_TF: u32 = 1 << 8;
const EFLAGS_IF: u32 = 1 << 9;
const EFLAGS_NT: u32 = 1 << 14;
const EFLAGS_RF: u32 = 1 << 16;
const EFLAGS_VM: u32 = 1 << 17;
const EFLAGS_IOPL: u32 = 3 << 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateKind {
    Task,
    Interrupt16,
    Trap16,
    Interrupt32,
    Trap32,
}

impl GateKind {
    const fn width(self) -> u8 {
        match self {
            Self::Interrupt16 | Self::Trap16 => 2,
            Self::Interrupt32 | Self::Trap32 => 4,
            Self::Task => 0,
        }
    }

    const fn is_interrupt(self) -> bool {
        matches!(self, Self::Interrupt16 | Self::Interrupt32)
    }
}

#[derive(Clone, Copy, Debug)]
struct Gate {
    kind: GateKind,
    selector: u16,
    offset: u32,
    dpl: u8,
    present: bool,
}

#[derive(Clone, Copy, Debug)]
struct StackPlan {
    cache: SegmentCache,
    selector: u16,
    pointer: u32,
    cpl: u8,
    descriptor_record: Option<DescriptorRecord>,
}

pub(super) fn deliver_protected<M: GuestMemory, S: SegmentResolver>(
    cpu: &mut Cpu,
    event: CpuEvent,
    memory: &mut M,
    segments: &S,
    model: CpuModel,
) -> Result<(), CpuError> {
    let regs = cpu.regs.clone();
    let site = AccessSite {
        opcode: event.instruction_opcode,
        ip: event.instruction_ip,
        eflags: regs.eflags,
    };
    let mut bus = CpuMemoryAccess::new(memory, segments, &mut cpu.system, site);
    bus.set_processor_event_error_ext(event.source.sets_error_code_ext());
    let mode = bus
        .execution_mode()
        .ok_or(CpuError::UnsupportedSystemMode {
            opcode: event.instruction_opcode,
            ip: event.instruction_ip,
        })?;
    let old_cpl = bus
        .current_privilege_level()
        .filter(|level| *level <= 3)
        .ok_or(CpuError::UnsupportedSystemMode {
            opcode: event.instruction_opcode,
            ip: event.instruction_ip,
        })?;
    if mode == CpuExecutionMode::Virtual8086
        && event.source.checks_virtual_8086_iopl()
        && regs.eflags & EFLAGS_IOPL != EFLAGS_IOPL
    {
        return Err(general_protection(0, event));
    }
    let gate = read_gate(&mut bus, event)?;
    if event.source.checks_software_interrupt_privilege() && old_cpl > gate.dpl {
        return Err(general_protection(
            idt_error_code(event.vector, false),
            event,
        ));
    }
    if !gate.present {
        return Err(CpuError::SegmentNotPresentFault {
            error_code: idt_error_code(event.vector, event.source.sets_error_code_ext()),
            ip: event.instruction_ip,
        });
    }
    if gate.kind == GateKind::Task {
        drop(bus);
        let site = AccessSite {
            opcode: event.instruction_opcode,
            ip: event.instruction_ip,
            eflags: cpu.regs.eflags,
        };
        let mut task_bus = CpuMemoryAccess::new(memory, segments, &mut cpu.system, site);
        task_bus.set_processor_event_error_ext(event.source.sets_error_code_ext());
        let result = crate::task_switch::switch_from_event_task_gate(
            &mut cpu.regs,
            &mut task_bus,
            gate.selector,
            event.saved_eip,
            event.instruction_ip,
            event.error_code,
            event.saved_eflags(regs.eflags, cpu.intermediate_rep_boundary),
            event.source.sets_error_code_ext(),
            &mut cpu.pending_task_debug_trap,
            model,
        );
        drop(task_bus);
        if result.is_ok() {
            cpu.debug_exception_shadow = false;
            cpu.deferred_data_breakpoint_hits =
                crate::memory_access::DataBreakpointHits::default();
        }
        return result;
    }
    if mode == CpuExecutionMode::Virtual8086 && gate.kind.width() != 4 {
        return Err(general_protection(
            idt_error_code(event.vector, event.source.sets_error_code_ext()),
            event,
        ));
    }
    if gate.selector & 0xfffc == 0 {
        return Err(general_protection(
            event_selector_error_code(gate.selector, event),
            event,
        ));
    }
    let code_record = read_descriptor(&mut bus, gate.selector)
        .map_err(|error| include_external_bit(error, event))?;
    let code = code_record.descriptor;
    let DescriptorType::Code { conforming, .. } = code.descriptor_type else {
        return Err(general_protection(
            event_selector_error_code(gate.selector, event),
            event,
        ));
    };
    let target_cpl = if conforming {
        if code.dpl > old_cpl {
            return Err(general_protection(
                event_selector_error_code(gate.selector, event),
                event,
            ));
        }
        old_cpl
    } else {
        if code.dpl > old_cpl {
            return Err(general_protection(
                event_selector_error_code(gate.selector, event),
                event,
            ));
        }
        code.dpl
    };
    if !code.present {
        return Err(CpuError::SegmentNotPresentFault {
            error_code: event_selector_error_code(gate.selector, event),
            ip: event.instruction_ip,
        });
    }
    if gate.offset > code.limit {
        // Intel's interrupt-delivery operation reports a null selector plus
        // EXT for an out-of-limit gate offset; the gate's code selector is
        // not encoded in this #GP error code.
        return Err(general_protection(
            u32::from(event.source.sets_error_code_ext()),
            event,
        ));
    }
    if code.long_mode {
        return Err(general_protection(
            event_selector_error_code(gate.selector, event),
            event,
        ));
    }
    let code_selector = (gate.selector & !3) | u16::from(target_cpl);
    let switched = target_cpl < old_cpl;
    if mode == CpuExecutionMode::Virtual8086 && (conforming || target_cpl != 0) {
        return Err(general_protection(
            event_selector_error_code(gate.selector, event),
            event,
        ));
    }

    let stack = if switched {
        read_privilege_stack(&mut bus, target_cpl, event)?
    } else {
        StackPlan {
            cache: *bus.system().segment_cache(SegmentRegister::Ss),
            selector: regs.ss,
            pointer: if bus.stack32() {
                regs.esp
            } else {
                u32::from(regs.sp())
            },
            cpl: old_cpl,
            descriptor_record: None,
        }
    };
    let pushes = frame_pushes(
        &regs,
        event,
        gate.kind.width(),
        switched,
        mode,
        cpu.intermediate_rep_boundary,
    )?;
    let width = gate.kind.width();
    let address32 = stack.cache.descriptor.default_big;
    let pushed_bytes = pushes
        .len()
        .checked_mul(usize::from(width))
        .ok_or(CpuError::Memory(guest_core::MemoryError::AddressOverflow))?;
    let stack_limit = if address32 {
        u64::from(u32::MAX) + 1
    } else {
        u64::from(u16::MAX) + 1
    };
    let frame_start = if address32 {
        let decrement = u32::try_from(pushed_bytes)
            .map_err(|_| stack_fault(event, switched, stack.selector))?;
        stack.pointer.wrapping_sub(decrement)
    } else {
        let decrement = u16::try_from(pushed_bytes)
            .map_err(|_| stack_fault(event, switched, stack.selector))?;
        u32::from((stack.pointer as u16).wrapping_sub(decrement))
    };
    if u64::from(frame_start) + pushed_bytes as u64 > stack_limit {
        // Current-stack limit failure uses a null selector plus EXT; a
        // privilege switch identifies the newly selected stack segment.
        let error_code = if switched {
            event_selector_error_code(stack.selector, event)
        } else {
            u32::from(event.source.sets_error_code_ext())
        };
        return Err(CpuError::StackSegmentFault {
            error_code,
            ip: event.instruction_ip,
        });
    }
    let mut pointer = stack.pointer;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(pushes.len())
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    for _ in &pushes {
        pointer = decrement_stack_pointer(pointer, width, address32);
        requests.push(AccessRequest::Logical {
            span: LogicalSpan {
                register: SegmentRegister::Ss,
                selector: stack.selector,
                offset: if address32 { pointer } else { u32::from(pointer as u16) },
                len: usize::from(width),
                address32,
            },
            kind: AccessKind::StackWrite,
            alignment: DataAlignment::Natural(width),
            origin: AccessOrigin::ProcessorEvent,
        });
    }
    let mut prepared = if switched {
        bus.prepare_group_for_stack(&requests, stack.cache, stack.cpl)
    } else {
        bus.prepare_group(&requests)
    }
    .map_err(|error| {
        if switched {
            map_new_privilege_stack_access_error(error, stack.selector, event)
        } else {
            include_external_bit(error, event)
        }
    })?
    .into_accesses();
    if prepared.len() != pushes.len() {
        return Err(CpuError::InvalidMemoryAccessPlan {
            ip: event.instruction_ip,
        });
    }
    // Delay accessed-bit writes until the destination frame has passed its
    // complete segment, page, and backing-store preflight.
    let code_descriptor = mark_segment_accessed(&mut bus, code_record)
        .map_err(|error| include_external_bit(error, event))?;
    let code_cache = SegmentCache::from_descriptor(code_selector, code_descriptor);
    let stack_cache = if let Some(record) = stack.descriptor_record {
        let descriptor = mark_segment_accessed(&mut bus, record)
            .map_err(|error| include_external_bit(error, event))?;
        Some(SegmentCache::from_descriptor(stack.selector, descriptor))
    } else {
        None
    };
    let stack = stack_cache.map_or(stack, |cache| StackPlan { cache, ..stack });
    for (access, value) in prepared.drain(..).zip(pushes) {
        write_prepared_width(&mut bus, access, width, value)?;
    }

    let mut next_flags = regs.eflags & !(EFLAGS_TF | EFLAGS_VM | EFLAGS_RF | EFLAGS_NT);
    if gate.kind.is_interrupt() {
        next_flags &= !EFLAGS_IF;
    }
    let system = bus.system_mut();
    system.segments[0] = code_cache;
    if switched {
        system.segments[1] = stack.cache;
    }
    system.cpl = target_cpl;
    if mode == CpuExecutionMode::Virtual8086 {
        system.segments[2] = SegmentCache::unusable(0);
        system.segments[3] = SegmentCache::unusable(0);
        system.segments[4] = SegmentCache::unusable(0);
        system.segments[5] = SegmentCache::unusable(0);
    }
    drop(bus);

    cpu.regs.cs = code_selector;
    cpu.regs.eip = gate.offset;
    cpu.regs.eflags = next_flags | 2;
    cpu.halted = false;
    if switched {
        cpu.regs.ss = stack.selector;
    }
    if switched && !address32 {
        // A 32-bit TSS loads ESP independently of the new SS.B stack-address
        // size. SP pushes update only its low word and retain TSS ESP[31:16].
        cpu.regs.esp = (stack.pointer & 0xffff_0000) | u32::from(pointer as u16);
    } else {
        set_stack_register(&mut cpu.regs, pointer, address32);
    }
    if mode == CpuExecutionMode::Virtual8086 {
        cpu.regs.es = 0;
        cpu.regs.ds = 0;
        cpu.regs.fs = 0;
        cpu.regs.gs = 0;
    }
    cpu.maskable_interrupt_shadow = false;
    cpu.debug_exception_shadow = false;
    cpu.deferred_data_breakpoint_hits = crate::memory_access::DataBreakpointHits::default();
    Ok(())
}

fn stack_fault(event: CpuEvent, switched: bool, selector: u16) -> CpuError {
    CpuError::StackSegmentFault {
        error_code: if switched {
            event_selector_error_code(selector, event)
        } else {
            u32::from(event.source.sets_error_code_ext())
        },
        ip: event.instruction_ip,
    }
}

fn read_gate(bus: &mut impl CpuBus, event: CpuEvent) -> Result<Gate, CpuError> {
    let table = bus.system().idtr;
    let offset = u32::from(event.vector) * 8;
    let end = offset + 7;
    if end > table.limit {
        return Err(general_protection(
            idt_error_code(event.vector, event.source.sets_error_code_ext()),
            event,
        ));
    }
    let address = table.base.0.checked_add(offset).ok_or_else(|| {
        general_protection(
            idt_error_code(event.vector, event.source.sets_error_code_ext()),
            event,
        )
    })?;
    address.checked_add(7).ok_or_else(|| {
        general_protection(
            idt_error_code(event.vector, event.source.sets_error_code_ext()),
            event,
        )
    })?;
    let access = bus.prepare(AccessRequest::SystemLinear {
        address: LinearAddr(address),
        len: 8,
        kind: AccessKind::SystemTableRead,
    })?;
    let mut bytes = [0_u8; 8];
    bus.read_prepared(&access, &mut bytes)?;
    let raw = u64::from_le_bytes(bytes);
    let access_byte = ((raw >> 40) & 0xff) as u8;
    if access_byte & 0x10 != 0 {
        return Err(general_protection(
            idt_error_code(event.vector, event.source.sets_error_code_ext()),
            event,
        ));
    }
    let kind = match access_byte & 0x0f {
        0x05 if bytes[0] == 0
            && bytes[1] == 0
            && bytes[4] == 0
            && bytes[6] == 0
            && bytes[7] == 0 =>
        {
            GateKind::Task
        }
        0x06 if bytes[4] == 0 && bytes[6] == 0 && bytes[7] == 0 => GateKind::Interrupt16,
        0x07 if bytes[4] == 0 && bytes[6] == 0 && bytes[7] == 0 => GateKind::Trap16,
        0x0e if bytes[4] == 0 => GateKind::Interrupt32,
        0x0f if bytes[4] == 0 => GateKind::Trap32,
        _ => {
            return Err(general_protection(
                idt_error_code(event.vector, event.source.sets_error_code_ext()),
                event,
            ));
        }
    };
    let selector = u16::from_le_bytes([bytes[2], bytes[3]]);
    let offset = if kind.width() == 2 {
        u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))
    } else if kind == GateKind::Task {
        0
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[6], bytes[7]])
    };
    Ok(Gate {
        kind,
        selector,
        offset,
        dpl: (access_byte >> 5) & 3,
        present: access_byte & 0x80 != 0,
    })
}

fn read_privilege_stack(
    bus: &mut impl CpuBus,
    cpl: u8,
    event: CpuEvent,
) -> Result<StackPlan, CpuError> {
    let task = bus.system().task;
    let task_error =
        u32::from(task.selector & 0xfffc) | u32::from(event.source.sets_error_code_ext());
    if !task.valid || !task.present || !matches!(task.system_type, 0x03 | 0x0b) {
        return Err(invalid_tss(task_error, event));
    }
    let is_32 = task.system_type == 0x0b;
    let sp_offset = if is_32 {
        4_u32 + u32::from(cpl) * 8
    } else {
        2_u32 + u32::from(cpl) * 4
    };
    let selector_offset = sp_offset + if is_32 { 4 } else { 2 };
    let read_len = if is_32 { 6_usize } else { 4_usize };
    let end = selector_offset + 1;
    if end > task.limit {
        return Err(invalid_tss(task_error, event));
    }
    let address = task
        .base
        .checked_add(sp_offset)
        .ok_or_else(|| invalid_tss(task_error, event))?;
    let access = bus.prepare(AccessRequest::SystemLinear {
        address: LinearAddr(address),
        len: read_len,
        kind: AccessKind::SystemTableRead,
    })?;
    let mut bytes = [0_u8; 6];
    bus.read_prepared(&access, &mut bytes[..read_len])?;
    let pointer = if is_32 {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let selector_index = if is_32 { 4 } else { 2 };
    let selector = u16::from_le_bytes([bytes[selector_index], bytes[selector_index + 1]]);
    if selector & 0xfffc == 0 {
        return Err(invalid_tss(
            u32::from(event.source.sets_error_code_ext()),
            event,
        ));
    }
    let record = read_descriptor(bus, selector)
        .map_err(|error| map_interrupt_stack_selector_error(error, selector, event))?;
    record
        .descriptor
        .validate_stack_load(selector, cpl)
        .map_err(|fault| {
            map_interrupt_stack_selector_error(map_fault(fault, bus), selector, event)
        })?;
    let cache_selector = (selector & !3) | u16::from(cpl);
    let cache = SegmentCache::from_descriptor(cache_selector, record.descriptor);
    Ok(StackPlan {
        cache,
        selector: cache_selector,
        pointer,
        cpl,
        descriptor_record: Some(record),
    })
}

fn frame_pushes(
    regs: &guest_core::Registers,
    event: CpuEvent,
    width: u8,
    switched: bool,
    mode: CpuExecutionMode,
    intermediate_rep_boundary: bool,
) -> Result<Vec<u32>, CpuError> {
    let mut values = Vec::new();
    let max = if mode == CpuExecutionMode::Virtual8086 && switched {
        10
    } else if switched {
        6
    } else {
        4
    };
    values
        .try_reserve_exact(max)
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    if mode == CpuExecutionMode::Virtual8086 && switched {
        values.extend([
            u32::from(regs.gs),
            u32::from(regs.fs),
            u32::from(regs.ds),
            u32::from(regs.es),
        ]);
    }
    if switched {
        values.push(u32::from(regs.ss));
        values.push(if width == 2 {
            u32::from(regs.sp())
        } else {
            regs.esp
        });
    }
    let saved_flags = event.saved_eflags(regs.eflags, intermediate_rep_boundary);
    values.push(if width == 2 {
        saved_flags & 0xffff
    } else {
        saved_flags
    });
    values.push(u32::from(regs.cs));
    values.push(if width == 2 {
        event.saved_eip & 0xffff
    } else {
        event.saved_eip
    });
    if let Some(error_code) = event.error_code {
        values.push(if width == 2 {
            error_code & 0xffff
        } else {
            error_code
        });
    }
    Ok(values)
}

fn decrement_stack_pointer(pointer: u32, width: u8, address32: bool) -> u32 {
    if address32 {
        pointer.wrapping_sub(u32::from(width))
    } else {
        (pointer & 0xffff_0000)
            | u32::from((pointer as u16).wrapping_sub(u16::from(width)))
    }
}

fn set_stack_register(regs: &mut guest_core::Registers, pointer: u32, address32: bool) {
    if address32 {
        regs.esp = pointer;
    } else {
        regs.set_sp(pointer as u16);
    }
}

fn selector_error_code(selector: u16) -> u32 {
    u32::from(selector & 0xfffc)
}

fn event_selector_error_code(selector: u16, event: CpuEvent) -> u32 {
    selector_error_code(selector) | u32::from(event.source.sets_error_code_ext())
}

fn include_external_bit(error: CpuError, event: CpuEvent) -> CpuError {
    if !event.source.sets_error_code_ext() {
        return error;
    }
    match error {
        CpuError::GeneralProtectionFault { error_code, ip } => CpuError::GeneralProtectionFault {
            error_code: error_code | 1,
            ip,
        },
        CpuError::SegmentNotPresentFault { error_code, ip } => CpuError::SegmentNotPresentFault {
            error_code: error_code | 1,
            ip,
        },
        CpuError::StackSegmentFault { error_code, ip } => CpuError::StackSegmentFault {
            error_code: error_code | 1,
            ip,
        },
        CpuError::InvalidTssFault { error_code, ip } => CpuError::InvalidTssFault {
            error_code: error_code | 1,
            ip,
        },
        CpuError::AlignmentCheckFault { error_code, ip } => CpuError::AlignmentCheckFault {
            error_code: error_code | 1,
            ip,
        },
        other => other,
    }
}

fn map_interrupt_stack_selector_error(error: CpuError, selector: u16, event: CpuEvent) -> CpuError {
    match error {
        CpuError::GeneralProtectionFault { ip, .. } => CpuError::InvalidTssFault {
            error_code: u32::from(selector & 0xfffc)
                | u32::from(event.source.sets_error_code_ext()),
            ip,
        },
        other => include_external_bit(other, event),
    }
}

fn map_new_privilege_stack_access_error(
    error: CpuError,
    selector: u16,
    event: CpuEvent,
) -> CpuError {
    match error {
        CpuError::StackSegmentFault { ip, .. } | CpuError::GeneralProtectionFault { ip, .. } => {
            CpuError::StackSegmentFault {
                error_code: event_selector_error_code(selector, event),
                ip,
            }
        }
        other => include_external_bit(other, event),
    }
}

fn idt_error_code(vector: u8, external: bool) -> u32 {
    (u32::from(vector) << 3) | 2 | u32::from(external)
}

fn general_protection(error_code: u32, event: CpuEvent) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code,
        ip: event.instruction_ip,
    }
}

fn invalid_tss(error_code: u32, event: CpuEvent) -> CpuError {
    CpuError::InvalidTssFault {
        error_code,
        ip: event.instruction_ip,
    }
}
