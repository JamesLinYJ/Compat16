//! Intel486 PUSHF/POPF flag-image transfer and privilege rules.

use guest_core::Registers;

use super::super::{
    memory_access::CpuBus, x86_decode::NormalizedInstruction, CpuError, CpuExecutionMode,
    CpuModel, AF, CF,
    DF, IF, OF, PF, SF, TF, ZF,
};
use super::stack::{pop_stack, push_stack, stack_width};

const IOPL: u32 = 0x0000_3000;
const NT: u32 = 1 << 14;
const RF: u32 = 1 << 16;
const VM: u32 = 1 << 17;
const AC: u32 = 1 << 18;
const ID: u32 = 1 << 21;
const FIXED_ONE: u32 = 1 << 1;

const LOW_IMAGE_FLAGS: u32 = CF | PF | AF | ZF | SF | TF | IF | DF | OF | IOPL | NT;
const LEGACY_TRANSFER_FLAGS: u32 = CF | PF | AF | ZF | SF | TF | IF | DF | OF;
const COMMON_POP_FLAGS: u32 = CF | PF | AF | ZF | SF | TF | DF | OF | NT;
const EFLAGS_486_IMAGE_FLAGS: u32 = LOW_IMAGE_FLAGS | AC;
const IRET_32_DEFINED_FLAGS: u32 = LOW_IMAGE_FLAGS | RF | VM | AC;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FlagContext {
    /// Checked selector translation without imported architectural mode/CPL.
    LegacyProjection,
    Architectural {
        mode: CpuExecutionMode,
        cpl: u8,
    },
}

pub(super) fn execute_push_flags(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    model: CpuModel,
) -> Result<(), CpuError> {
    let context = flag_context(registers, bus, instruction)?;
    if let FlagContext::Architectural { mode, .. } = context {
        check_v86_iopl(registers, mode, instruction)?;
    }
    let width = stack_width(instruction);
    check_v86_stack_span(registers, bus, width, 1, true, context, instruction)?;

    // Intel486 saves reserved flag positions as zero and fixes EFLAGS bit 1.
    // In the 32-bit image, VM and RF read as zero even when set internally.
    let mask = if width == 2 {
        LOW_IMAGE_FLAGS
    } else {
        EFLAGS_486_IMAGE_FLAGS | if model.has_cpuid() { ID } else { 0 }
    };
    let image = (registers.eflags & mask) | FIXED_ONE;
    let mut next = registers.clone();
    push_stack(&mut next, bus, image, width)?;
    *registers = next;
    Ok(())
}

pub(super) fn execute_pop_flags(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    model: CpuModel,
) -> Result<(), CpuError> {
    let context = flag_context(registers, bus, instruction)?;
    if let FlagContext::Architectural { mode, .. } = context {
        check_v86_iopl(registers, mode, instruction)?;
    }
    let width = stack_width(instruction);
    check_v86_stack_span(registers, bus, width, 1, false, context, instruction)?;

    // Keep the architectural register context unchanged if the checked stack
    // read or privilege-state validation fails.
    let mut next = registers.clone();
    let image = pop_stack(&mut next, bus, width)?;
    next.eflags = merge_pop_flag_image(registers.eflags, image, width, context, model);
    *registers = next;
    Ok(())
}

pub(super) fn flag_context(
    registers: &Registers,
    bus: &impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<FlagContext, CpuError> {
    if !bus.architectural_mode_active() {
        return Ok(FlagContext::LegacyProjection);
    }
    let mode = bus
        .execution_mode()
        .ok_or_else(|| unsupported_mode(instruction))?;
    let cpl = bus
        .current_privilege_level()
        .filter(|level| *level <= 3)
        .ok_or_else(|| unsupported_mode(instruction))?;

    if (mode == CpuExecutionMode::RealAddress && cpl != 0)
        || (mode == CpuExecutionMode::Virtual8086 && cpl != 3)
    {
        return Err(unsupported_mode(instruction));
    }
    if bus.system().execution_mode(registers.eflags) != Some(mode) {
        return Err(unsupported_mode(instruction));
    }
    Ok(FlagContext::Architectural { mode, cpl })
}

pub(super) fn check_v86_iopl(
    registers: &Registers,
    mode: CpuExecutionMode,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    if mode == CpuExecutionMode::Virtual8086 && (registers.eflags & IOPL) != IOPL {
        return Err(general_protection_fault(instruction));
    }
    Ok(())
}

pub(super) fn merge_pop_flag_image(
    old: u32,
    image: u32,
    width: u8,
    context: FlagContext,
    model: CpuModel,
) -> u32 {
    let FlagContext::Architectural { cpl, .. } = context else {
        let mut writable = LEGACY_TRANSFER_FLAGS;
        if width == 4 {
            writable |= AC;
            if model.has_cpuid() {
                writable |= ID;
            }
        }
        // A selector-only projection has no architectural privilege level.
        // Keep IOPL, NT, VM and reserved positions from its prior flag image.
        return ((old & !writable) | (image & writable) | FIXED_ONE) & !RF;
    };
    let old_iopl = ((old & IOPL) >> 12) as u8;
    let mut writable = COMMON_POP_FLAGS;
    if cpl <= old_iopl {
        writable |= IF;
    }
    if cpl == 0 {
        writable |= IOPL;
    }
    if width == 4 {
        writable |= AC;
        if model.has_cpuid() {
            writable |= ID;
        }
    }
    // POPF/POPFD do not load RF from the image. Intel's instruction operation
    // semantics specify that a successful POPF family instruction clears it.
    ((old & !writable) | (image & writable) | FIXED_ONE) & !RF
}

pub(super) fn merge_iret_flag_image(
    old: u32,
    image: u32,
    width: u8,
    context: FlagContext,
    model: CpuModel,
) -> u32 {
    let FlagContext::Architectural { mode, cpl } = context else {
        let mut writable = LEGACY_TRANSFER_FLAGS;
        if width == 4 {
            writable |= AC | RF;
            if model.has_cpuid() {
                writable |= ID;
            }
        }
        // Legacy selectors do not supply CPL or task/mode state. Apply only
        // the ordinary flag image while preserving IOPL, NT, VM and reserved
        // positions; 16-bit IRET leaves the high half untouched.
        return (old & !writable) | (image & writable) | FIXED_ONE;
    };
    let old_iopl = ((old & IOPL) >> 12) as u8;
    let mut writable = COMMON_POP_FLAGS;
    if cpl <= old_iopl {
        writable |= IF;
    }
    if cpl == 0 {
        writable |= IOPL;
    }
    if width == 4 {
        writable |= AC;
        if model.has_cpuid() {
            writable |= ID;
        }
        if matches!(
            mode,
            CpuExecutionMode::RealAddress | CpuExecutionMode::Virtual8086
        ) {
            // These supported 32-bit paths restore RF. Protected-mode IRET
            // has a distinct descriptor/task plan and does not reach here.
            writable |= RF;
        }
    }
    let merged = (old & !writable) | (image & writable) | FIXED_ONE;
    if width == 4 {
        // A 32-bit IRET image normalizes this CPU model's reserved positions;
        // a 16-bit IRET does not write the high half of EFLAGS at all.
        let defined = IRET_32_DEFINED_FLAGS | if model.has_cpuid() { ID } else { 0 };
        (merged & (defined | FIXED_ONE)) | FIXED_ONE
    } else {
        merged
    }
}

pub(super) fn check_v86_stack_span(
    registers: &Registers,
    bus: &impl CpuBus,
    width: u8,
    slots: usize,
    push: bool,
    context: FlagContext,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    if !matches!(
        context,
        FlagContext::Architectural {
            mode: CpuExecutionMode::Virtual8086,
            ..
        }
    ) {
        return Ok(());
    }
    if bus.stack32() {
        return Err(unsupported_mode(instruction));
    }
    let current = registers.sp();
    if !push {
        let total = width
            .checked_mul(u8::try_from(slots).map_err(|_| unsupported_mode(instruction))?)
            .ok_or_else(|| unsupported_mode(instruction))?;
        let end = u32::from(current) + u32::from(total);
        if end > 0x1_0000 {
            return Err(CpuError::StackSegmentFault {
                error_code: 0,
                ip: instruction.decoded.start_ip,
            });
        }
        return Ok(());
    }
    for slot in 0..slots {
        let offset =
            current.wrapping_sub((slot as u16).wrapping_add(1).wrapping_mul(u16::from(width)));
        let end = u32::from(offset) + u32::from(width);
        if end > 0x1_0000 {
            return Err(CpuError::StackSegmentFault {
                error_code: 0,
                ip: instruction.decoded.start_ip,
            });
        }
    }
    Ok(())
}

fn unsupported_mode(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedSystemMode {
        opcode: instruction.decoded.opcode,
        ip: instruction.decoded.start_ip,
    }
}

fn general_protection_fault(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code: 0,
        ip: instruction.decoded.start_ip,
    }
}
