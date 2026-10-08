//! Task-switch validation, state writes, commit, and incoming-task checks.

use guest_core::{LinearAddr, Registers};

use crate::{
    CpuError, CpuExecutionMode, CpuModel,
    memory_access::{AccessKind, CpuBus, PagingAddressSpace},
    memory_values::write_prepared_width,
    system::{
        CR0_PG, CR0_TS, DescriptorRecord, DescriptorType, SegmentCache, SystemSegmentCache,
    },
    x86_decode::NormalizedInstruction,
};

use super::{
    faults::{
        committed_fault, general_protection_code, invalid_tss, not_present,
        remap_descriptor_lookup, target_descriptor_fault, task_error_stack_access,
        unsupported_mode, with_external,
    },
    memory::{
        general_protection, prepare_system_write, prepare_tss_write, read_gdt_descriptor,
        read_system_bytes, read_system_bytes_into, selector_error_code,
    },
    segments::{load_incoming_segments, load_ldt},
    wire::{TaskWidth, TssImage},
};

const EFLAGS_NT: u32 = 1 << 14;
const EFLAGS_VM: u32 = 1 << 17;
const DR6_BT: u32 = 1 << 15;
// i486 clears L0-L3 and the local exact-match LE bit on task switches.
const DR7_LOCAL_ENABLES: u32 = 0x155;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SwitchReason {
    Call,
    Jump,
    Return,
}

impl SwitchReason {
    const fn nests(self) -> bool {
        matches!(self, Self::Call)
    }

    const fn clears_current_busy(self) -> bool {
        matches!(self, Self::Jump | Self::Return)
    }

    const fn expects_busy_target(self) -> bool {
        matches!(self, Self::Return)
    }
}

/// Execute a far CALL/JMP whose selected descriptor is a direct available TSS.
pub(crate) fn execute_direct_tss(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    record: DescriptorRecord,
    jump: bool,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let selector = record.selector;
    let reason = if jump {
        SwitchReason::Jump
    } else {
        SwitchReason::Call
    };
    if selector & 4 != 0 {
        return Err(general_protection(selector, instruction.decoded.start_ip));
    }
    let cpl = bus
        .current_privilege_level()
        .ok_or_else(|| unsupported_mode(instruction))?;
    if cpl.max((selector & 3) as u8) > record.descriptor.dpl {
        return Err(general_protection(selector, instruction.decoded.start_ip));
    }
    if !matches!(
        record.descriptor.descriptor_type,
        DescriptorType::System { system_type: 1 | 9 }
    ) {
        return Err(general_protection(selector, instruction.decoded.start_ip));
    }
    if !record.descriptor.present {
        return Err(not_present(selector, instruction.decoded.start_ip, false));
    }
    let saved_eip = *next_ip;
    switch_task(
        bus,
        registers,
        next_ip,
        selector,
        reason,
        saved_eip,
        instruction.decoded.start_ip,
        None,
        None,
        false,
        pending_task_debug,
        model,
    )
}

/// Execute a far CALL/JMP through a task gate.
pub(crate) fn execute_task_gate(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    gate: DescriptorRecord,
    cpl: u8,
    jump: bool,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let gate_selector = gate.selector;
    let rpl = (gate_selector & 3) as u8;
    if cpl.max(rpl) > gate.descriptor.dpl {
        return Err(general_protection(
            gate_selector,
            instruction.decoded.start_ip,
        ));
    }
    if !gate.descriptor.present {
        return Err(not_present(
            gate_selector,
            instruction.decoded.start_ip,
            false,
        ));
    }
    let DescriptorType::System { system_type: 5 } = gate.descriptor.descriptor_type else {
        return Err(general_protection(
            gate_selector,
            instruction.decoded.start_ip,
        ));
    };
    let target_selector = ((gate.raw >> 16) & 0xffff) as u16;
    let saved_eip = *next_ip;
    switch_task(
        bus,
        registers,
        next_ip,
        target_selector,
        if jump {
            SwitchReason::Jump
        } else {
            SwitchReason::Call
        },
        saved_eip,
        instruction.decoded.start_ip,
        None,
        None,
        false,
        pending_task_debug,
        model,
    )
}

/// Route an IDT task gate. The caller has already applied IDT DPL/presence rules.
pub(crate) fn switch_from_event_task_gate(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    target_selector: u16,
    saved_eip: u32,
    instruction_ip: u32,
    error_code: Option<u32>,
    saved_eflags: u32,
    external: bool,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let mut next_ip = saved_eip;
    switch_task(
        bus,
        registers,
        &mut next_ip,
        target_selector,
        SwitchReason::Call,
        saved_eip,
        instruction_ip,
        error_code,
        Some(saved_eflags),
        external,
        pending_task_debug,
        model,
    )
}

/// IRET with NT set follows the backlink in the current TSS.
pub(crate) fn return_from_nested_task(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let fault_ip = instruction.decoded.start_ip;
    let current_task = bus.system().task;
    let space = current_task_space(bus, fault_ip, false)?;
    current_task_width(current_task, fault_ip, false)?;
    let backlink_bytes = read_system_bytes::<2>(bus, current_task.base, 0, space)?;
    let backlink = u16::from_le_bytes(backlink_bytes);
    if backlink & 0xfffc == 0 || backlink & 4 != 0 {
        return Err(invalid_tss(backlink, fault_ip, false));
    }
    let mut task_ip = *next_ip;
    switch_task(
        bus,
        registers,
        &mut task_ip,
        backlink,
        SwitchReason::Return,
        *next_ip,
        fault_ip,
        None,
        None,
        false,
        pending_task_debug,
        model,
    )?;
    *next_ip = task_ip;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn switch_task(
    bus: &mut impl CpuBus,
    registers: &mut Registers,
    next_ip: &mut u32,
    target_selector: u16,
    reason: SwitchReason,
    saved_eip: u32,
    fault_ip: u32,
    error_code: Option<u32>,
    event_saved_eflags: Option<u32>,
    external: bool,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let old_mode = bus
        .execution_mode()
        .ok_or(CpuError::UnsupportedSystemMode {
            opcode: bus.instruction_site().opcode,
            ip: fault_ip,
        })?;
    if !bus.architectural_mode_active()
        || !matches!(
            old_mode,
            CpuExecutionMode::Protected | CpuExecutionMode::Virtual8086
        )
    {
        return Err(CpuError::UnsupportedSystemMode {
            opcode: bus.instruction_site().opcode,
            ip: fault_ip,
        });
    }
    let old_cpl = bus
        .current_privilege_level()
        .filter(|level| *level <= 3)
        .ok_or(CpuError::UnsupportedSystemMode {
            opcode: bus.instruction_site().opcode,
            ip: fault_ip,
        })?;
    let old_system = *bus.system();
    let old_space = PagingAddressSpace::for_task_target(old_system.cr3, old_mode, old_cpl).ok_or(
        CpuError::UnsupportedSystemMode {
            opcode: bus.instruction_site().opcode,
            ip: fault_ip,
        },
    )?;
    let current_task = old_system.task;
    let current_width = current_task_width(current_task, fault_ip, external)?;
    let current_record =
        read_gdt_descriptor(bus, current_task.selector, old_space).map_err(|error| {
            remap_descriptor_lookup(error, current_task.selector, false, external, fault_ip)
        })?;
    let current_busy_type = busy_type(current_task.system_type)
        .ok_or_else(|| invalid_tss(current_task.selector, fault_ip, external))?;
    if !matches!(current_record.descriptor.descriptor_type, DescriptorType::System { system_type } if system_type == current_busy_type)
        || !current_record.descriptor.present
    {
        return Err(invalid_tss(current_task.selector, fault_ip, external));
    }
    // Intel SDM Vol. 3A §§10.2.1 and 10.3 classify these as outgoing dynamic
    // fields. Build their image from CPU state and leave static/reserved bytes
    // untouched; no old full-TSS image is needed to save the task.
    let current_bytes = allocate_tss_bytes(current_width)?;
    let mut current_image = TssImage::read(current_task.system_type, &current_bytes)
        .ok_or_else(|| invalid_tss(current_task.selector, fault_ip, external))?;
    let current_eflags = event_saved_eflags.unwrap_or_else(|| {
        if reason == SwitchReason::Return {
            registers.eflags & !EFLAGS_NT
        } else {
            registers.eflags
        }
    });
    current_image.save_registers(
        registers,
        saved_eip,
        current_eflags,
    );

    if target_selector & 4 != 0 || target_selector & 0xfffc == 0 {
        return Err(target_descriptor_fault(
            target_selector,
            reason.expects_busy_target(),
            external,
            fault_ip,
        ));
    }
    if target_selector == current_task.selector {
        return Err(target_descriptor_fault(
            target_selector,
            reason.expects_busy_target(),
            external,
            fault_ip,
        ));
    }
    let target_record = read_gdt_descriptor(bus, target_selector, old_space).map_err(|error| {
        remap_descriptor_lookup(
            error,
            target_selector,
            reason.expects_busy_target(),
            external,
            fault_ip,
        )
    })?;
    let DescriptorType::System {
        system_type: target_type,
    } = target_record.descriptor.descriptor_type
    else {
        return Err(target_descriptor_fault(
            target_selector,
            reason.expects_busy_target(),
            external,
            fault_ip,
        ));
    };
    let available = matches!(target_type, 1 | 9);
    let busy = matches!(target_type, 3 | 0x0b);
    if (reason.expects_busy_target() && !busy) || (!reason.expects_busy_target() && !available) {
        return Err(target_descriptor_fault(
            target_selector,
            reason.expects_busy_target(),
            external,
            fault_ip,
        ));
    }
    if !target_record.descriptor.present {
        return Err(not_present(target_selector, fault_ip, external));
    }
    if target_record.descriptor.long_mode {
        return Err(target_descriptor_fault(
            target_selector,
            reason.expects_busy_target(),
            external,
            fault_ip,
        ));
    }
    let target_width = width_for_type(target_type)
        .ok_or_else(|| {
            target_descriptor_fault(
                target_selector,
                reason.expects_busy_target(),
                external,
                fault_ip,
            )
        })?;
    if target_record.descriptor.limit < target_width.minimum_tss_limit() {
        return Err(invalid_tss(target_selector, fault_ip, external));
    }
    let mut target_image = read_incoming_tss_image(
        bus,
        target_record.descriptor.base,
        target_type,
        target_width,
        old_space,
        target_selector,
        fault_ip,
        external,
    )?;
    let mut task_registers = target_image.load_registers(registers);
    task_registers.registers.eflags = model.normalize_eflags(task_registers.registers.eflags);
    match reason {
        SwitchReason::Call => task_registers.registers.eflags |= EFLAGS_NT,
        // JMP and IRET load NT from the incoming TSS image. Only CALL and
        // event-driven task switches force it on for a newly nested task.
        SwitchReason::Jump | SwitchReason::Return => {}
    }

    // Intel SDM Vol. 3A 253668-082US (Dec. 2023), §8.3 step 9 (printed
    // p. 8-12) reads the TSS PDBR but does not load CR3 when paging is off.
    // Earlier 253668 editions number this operation §7.3, step 12. Keep the
    // target address space separate until commit.
    let mut next_system = old_system;
    if target_width == TaskWidth::Bits32 && old_system.cr0 & CR0_PG != 0 {
        let next_cr3 = task_registers
            .cr3
            .ok_or_else(|| invalid_tss(target_selector, fault_ip, external))?;
        next_system.write_cr3(next_cr3).map_err(|_| {
            general_protection_code(with_external(target_selector, external), fault_ip)
        })?;
    }
    let target_cr3 = next_system.cr3;
    let target_mode = if task_registers.registers.eflags & EFLAGS_VM != 0 {
        CpuExecutionMode::Virtual8086
    } else {
        CpuExecutionMode::Protected
    };
    if target_mode == CpuExecutionMode::Virtual8086 && target_width != TaskWidth::Bits32 {
        return Err(invalid_tss(target_selector, fault_ip, external));
    }
    let target_cpl = if target_mode == CpuExecutionMode::Virtual8086 {
        3
    } else {
        (task_registers.registers.cs & 3) as u8
    };
    let target_space = PagingAddressSpace::for_task_target(target_cr3, target_mode, target_cpl)
        .ok_or_else(|| invalid_tss(target_selector, fault_ip, external))?;

    if reason.nests() {
        target_image.set_backlink(current_task.selector);
    }

    // Preflight the outgoing dynamic state, optional backlink, and descriptor
    // bytes before the first write. Static/reserved TSS bytes are not written.
    let mut current_writes = Vec::new();
    current_writes
        .try_reserve_exact(6)
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    for (offset, bytes) in current_image.dynamic_fields().into_iter().flatten() {
        let write = prepare_tss_write(bus, current_task.base, offset, bytes.len(), old_space)?;
        current_writes.push((write, bytes));
    }
    let target_backlink_write = if reason.nests() {
        Some(prepare_tss_write(
            bus,
            target_record.descriptor.base,
            0,
            target_image.backlink_bytes().len(),
            old_space,
        )?)
    } else {
        None
    };
    let old_access_write = if reason.clears_current_busy() {
        Some(prepare_system_write(
            bus,
            descriptor_access_address(current_record, fault_ip)?,
            1,
            old_space,
        )?)
    } else {
        None
    };
    let target_access_write = if !reason.expects_busy_target() {
        Some(prepare_system_write(
            bus,
            descriptor_access_address(target_record, fault_ip)?,
            1,
            old_space,
        )?)
    } else {
        None
    };

    for (write, bytes) in current_writes {
        bus.write_prepared(write, bytes)?;
    }
    if let Some(write) = target_backlink_write {
        bus.write_prepared(write, target_image.backlink_bytes())?;
    }
    if let Some(write) = old_access_write {
        let value = descriptor_with_type(current_record, available_type(current_busy_type));
        bus.write_prepared(write, &[value])?;
    }
    if let Some(write) = target_access_write {
        bus.write_prepared(
            write,
            &[descriptor_with_type(
                target_record,
                busy_type(target_type).unwrap_or(target_type),
            )],
        )?;
    }

    let target_eip = task_registers.registers.eip;
    next_system.task = SystemSegmentCache {
        selector: target_selector,
        base: target_record.descriptor.base,
        limit: target_record.descriptor.limit,
        system_type: if reason.expects_busy_target() {
            target_type
        } else {
            busy_type(target_type).unwrap_or(target_type)
        },
        present: true,
        valid: true,
    };
    next_system.ldtr = SystemSegmentCache::default();
    next_system.cpl = target_cpl;
    next_system.cr0 |= CR0_TS;
    // Intel SDM Vol. 3B §18.2.4 clears DR7.L0-L3 on each task switch;
    // global breakpoint enables and the remaining DR7 fields persist.
    next_system.debug.control &= !DR7_LOCAL_ENABLES;
    let retained_fs = next_system.segments[4];
    let retained_gs = next_system.segments[5];
    next_system.segments = [
        SegmentCache::unusable(task_registers.registers.cs),
        SegmentCache::unusable(task_registers.registers.ss),
        SegmentCache::unusable(task_registers.registers.ds),
        SegmentCache::unusable(task_registers.registers.es),
        retained_fs,
        retained_gs,
    ];
    if target_width == TaskWidth::Bits32 {
        next_system.segments[4] = SegmentCache::unusable(task_registers.registers.fs);
        next_system.segments[5] = SegmentCache::unusable(task_registers.registers.gs);
    }
    *bus.system_mut() = next_system;
    *registers = task_registers.registers;
    *next_ip = target_eip;

    let ldt = load_ldt(bus, task_registers.ldt, target_space, target_eip, external)
        .map_err(|error| committed_fault(error, target_eip))?;
    bus.system_mut().ldtr = ldt;
    load_incoming_segments(
        bus,
        registers,
        ldt,
        target_width == TaskWidth::Bits32,
        target_mode,
        target_space,
        target_eip,
        external,
    )
    .map_err(|error| committed_fault(error, target_eip))?;

    if let Some(error_code) = error_code {
        push_task_error_code(
            bus,
            registers,
            error_code,
            target_width,
            target_space,
            target_eip,
            external,
        )
        .map_err(|error| committed_fault(error, target_eip))?;
    }
    if task_registers.debug_trap {
        *pending_task_debug = true;
        bus.system_mut().debug.status |= DR6_BT;
    }
    Ok(())
}

fn push_task_error_code(
    bus: &mut impl CpuBus,
    registers: &mut Registers,
    error_code: u32,
    width: TaskWidth,
    target_space: PagingAddressSpace,
    target_ip: u32,
    external: bool,
) -> Result<(), CpuError> {
    let slot_width = width.word_bytes();
    let stack32 = bus.stack32();
    let pointer = if stack32 {
        registers.esp
    } else {
        u32::from(registers.sp())
    };
    let offset = if stack32 {
        pointer.wrapping_sub(u32::from(slot_width))
    } else {
        u32::from((pointer as u16).wrapping_sub(u16::from(slot_width)))
    };
    let stack_limit = if stack32 {
        u64::from(u32::MAX) + 1
    } else {
        u64::from(u16::MAX) + 1
    };
    if u64::from(offset) + u64::from(slot_width) > stack_limit {
        return Err(CpuError::StackSegmentFault {
            // A task-gate error-code push that exceeds the new current stack
            // reports #SS(EXT), with no selector index.
            error_code: u32::from(external),
            ip: target_ip,
        });
    }
    let request = [crate::memory_access::AccessRequest::processor_event(
        crate::memory_access::LogicalSpan {
            register: crate::registers::SegmentRegister::Ss,
            selector: registers.ss,
            offset,
            len: usize::from(slot_width),
            address32: stack32,
        },
        AccessKind::StackWrite,
        crate::memory_access::DataAlignment::Natural(slot_width),
    )];
    // Keep the initiating event's site/EXT provenance, but gate #AC with the
    // EFLAGS loaded from the task receiving this error-code stack write.
    bus.set_access_context_eflags(registers.eflags);
    let mut accesses = bus
        .prepare_group_for_stack_in_address_space(&request, bus.system().segments[1], target_space)
        .map_err(|error| task_error_stack_access(error, target_ip, external))?
        .into_accesses();
    let access = accesses
        .pop()
        .ok_or(CpuError::InvalidMemoryAccessPlan { ip: target_ip })?;
    write_prepared_width(bus, access, slot_width, error_code)?;
    if stack32 {
        registers.esp = offset;
    } else {
        registers.set_sp(offset as u16);
    }
    Ok(())
}

fn descriptor_access_address(record: DescriptorRecord, ip: u32) -> Result<LinearAddr, CpuError> {
    record
        .address
        .0
        .checked_add(5)
        .map(LinearAddr)
        .ok_or(CpuError::Memory(guest_core::MemoryError::AddressOverflow))
        .map_err(|_| general_protection_code(selector_error_code(record.selector), ip))
}

fn descriptor_with_type(record: DescriptorRecord, system_type: u8) -> u8 {
    (((record.raw >> 40) as u8) & 0xf0) | (system_type & 0x0f)
}

fn current_task_width(
    task: SystemSegmentCache,
    ip: u32,
    external: bool,
) -> Result<TaskWidth, CpuError> {
    if !task.valid || !task.present {
        return Err(invalid_tss(task.selector, ip, external));
    }
    let width = width_for_type(task.system_type)
        .filter(|_| matches!(task.system_type, 3 | 0x0b))
        .ok_or_else(|| invalid_tss(task.selector, ip, external))?;
    if task.limit < width.minimum_tss_limit() {
        return Err(invalid_tss(task.selector, ip, external));
    }
    Ok(width)
}

fn width_for_type(system_type: u8) -> Option<TaskWidth> {
    match system_type {
        1 | 3 => Some(TaskWidth::Bits16),
        9 | 0x0b => Some(TaskWidth::Bits32),
        _ => None,
    }
}

fn busy_type(system_type: u8) -> Option<u8> {
    match system_type {
        1 => Some(3),
        9 => Some(0x0b),
        3 => Some(3),
        0x0b => Some(0x0b),
        _ => None,
    }
}

fn available_type(system_type: u8) -> u8 {
    match system_type {
        3 => 1,
        0x0b => 9,
        other => other,
    }
}

fn allocate_tss_bytes(width: TaskWidth) -> Result<Vec<u8>, CpuError> {
    let len = match width {
        TaskWidth::Bits16 => core::mem::size_of::<super::wire::Tss16Wire>(),
        TaskWidth::Bits32 => core::mem::size_of::<super::wire::Tss32Wire>(),
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    bytes.resize(len, 0);
    Ok(bytes)
}

fn read_incoming_tss_image(
    bus: &mut impl CpuBus,
    base: u32,
    system_type: u8,
    width: TaskWidth,
    space: PagingAddressSpace,
    selector: u16,
    ip: u32,
    external: bool,
) -> Result<TssImage, CpuError> {
    let mut bytes = allocate_tss_bytes(width)?;
    match width {
        TaskWidth::Bits16 => {
            // The 16-bit image fields loaded on a task switch are contiguous:
            // IP through the LDT selector. The backlink and privilege stacks
            // are not inputs to restoring the task's register state.
            read_system_bytes_into(bus, base, 14, &mut bytes[14..44], space)?;
        }
        TaskWidth::Bits32 => {
            // Intel SDM Vol. 3A §§10.2.1 and 10.3: load CR3, EIP/EFLAGS/GPRs,
            // segment selectors, LDTR, and the T debug flag. The I/O-map base,
            // backlink, privilege stacks, and selector reserved halves are not
            // consumed while loading a task and are not read here.
            let fields: &[(usize, usize)] = &[
                (28, 4),
                (32, 40),
                (72, 2),
                (76, 2),
                (80, 2),
                (84, 2),
                (88, 2),
                (92, 2),
                (96, 2),
                (100, 1),
            ];
            for &(offset, length) in fields {
                read_system_bytes_into(
                    bus,
                    base,
                    offset as u32,
                    &mut bytes[offset..offset + length],
                    space,
                )?;
            }
        }
    }
    TssImage::read(system_type, &bytes).ok_or_else(|| invalid_tss(selector, ip, external))
}

fn current_task_space(
    bus: &impl CpuBus,
    ip: u32,
    external: bool,
) -> Result<PagingAddressSpace, CpuError> {
    let mode = bus
        .execution_mode()
        .ok_or(CpuError::UnsupportedSystemMode {
            opcode: bus.instruction_site().opcode,
            ip,
        })?;
    let cpl = bus
        .current_privilege_level()
        .ok_or(CpuError::UnsupportedSystemMode {
            opcode: bus.instruction_site().opcode,
            ip,
        })?;
    PagingAddressSpace::for_task_target(bus.system().cr3, mode, cpl)
        .ok_or_else(|| invalid_tss(bus.system().task.selector, ip, external))
}
