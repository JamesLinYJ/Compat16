//! Instruction dispatcher for the decoded real-mode integer subset.

mod arithmetic;
mod atomic;
mod bit;
mod control;
mod cpuid;
mod data;
mod extensions;
mod event_transfer;
mod family_a;
mod far_transfer;
mod flags_transfer;
mod io;
mod io_permission;
mod jit_memory;
pub(super) use jit_memory::execute as execute_jit_memory;
mod operand;
mod privilege;
mod protected_iret;
mod segment_load;
mod stack;
mod string;
mod system;
mod system_registers;

use crate::memory_access::{CpuBus, DataBreakpointHits};
use guest_core::Registers;
use x86_decoder::Mnemonic;

use super::{
    AF, CF, CpuError, CpuModel, DF, IF, OF, PF, SF, StepOutcome, ZF, condition, decimal_adjust,
};
use crate::x86_decode::{DecodedInstruction, NormalizedInstruction};
use arithmetic::{
    execute_alu, execute_ascii_base, execute_cmpxchg, execute_inc_dec, execute_mul_div,
    execute_not_neg, execute_setcc, execute_shift,
};
use bit::{execute_bit, execute_bit_scan, execute_double_shift};
use control::{
    execute_call, execute_iret, execute_jump, execute_loop, execute_return, jump_condition_code,
};
use data::{
    execute_bswap, execute_far_load, execute_lea, execute_mov, execute_mov_extend, execute_xchg,
};
use extensions::{execute_cmov, execute_cmpxchg8b, execute_xadd, execute_xlat};
use cpuid::execute as execute_cpuid;
use flags_transfer::{execute_pop_flags, execute_push_flags};
use operand::{branch_target, read_immediate};
use stack::{
    execute_enter, execute_leave, execute_pop, execute_popa, execute_push, execute_pusha,
};
use string::{execute_string, is_implicit_string};

pub(super) use io::execute as execute_io;
pub(super) use system::execute as execute_system;

/// Merge a 16-bit real-address IRET image with the existing EFLAGS state.
/// Keep the same reserved-bit and privilege rules as instruction execution.
pub(crate) fn merge_real_mode_iret16_flags(old: u32, image: u16, model: CpuModel) -> u32 {
    flags_transfer::merge_iret_flag_image(
        old,
        u32::from(image),
        2,
        flags_transfer::FlagContext::Architectural {
            mode: crate::CpuExecutionMode::RealAddress,
            cpl: 0,
        },
        model,
    )
}

/// Merge a 16-bit return image without claiming architectural mode or CPL.
pub(crate) fn merge_legacy_iret16_flags(old: u32, image: u16, model: CpuModel) -> u32 {
    flags_transfer::merge_iret_flag_image(
        old,
        u32::from(image),
        2,
        flags_transfer::FlagContext::LegacyProjection,
        model,
    )
}

pub(crate) use event_transfer::{
    Guest16BitReturnImage, apply_16bit_return_image,
    apply_legacy_16bit_return_image, enter_checked_16bit_callback,
    prepare_guest_16bit_stack_cache,
};

pub(super) fn is_string_instruction(decoded: DecodedInstruction) -> bool {
    is_implicit_string(&NormalizedInstruction::new(decoded))
}

pub(super) fn execute_string_boundary(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    decoded: DecodedInstruction,
) -> Result<(u32, bool, DataBreakpointHits), CpuError> {
    let mut next_ip = decoded.next_ip;
    let (unfinished_repeat, data_breakpoint_hits) = execute_string(
        regs,
        bus,
        &NormalizedInstruction::new(decoded),
        &mut next_ip,
    )?;
    Ok((next_ip, unfinished_repeat, data_breakpoint_hits))
}

pub(super) fn execute(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    decoded: DecodedInstruction,
    model: CpuModel,
) -> Result<(StepOutcome, u32, bool), CpuError> {
    let instruction = NormalizedInstruction::new(decoded);
    atomic::validate_lock_prefix(&instruction)?;
    let mut next_ip = decoded.next_ip;
    let mut pending_task_debug = false;
    if far_transfer::handles(bus, &instruction) {
        far_transfer::execute(
            regs,
            bus,
            &instruction,
            &mut next_ip,
            &mut pending_task_debug,
            model,
        )?;
        return Ok((StepOutcome::Continue, next_ip, pending_task_debug));
    }
    let outcome = execute_instruction(
        regs,
        bus,
        &instruction,
        &mut next_ip,
        &mut pending_task_debug,
        model,
    )?;
    Ok((outcome, next_ip, pending_task_debug))
}

pub(super) fn execute_instruction(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<StepOutcome, CpuError> {
    use Mnemonic as M;

    if let Some(code) = jump_condition_code(instruction.mnemonic) {
        if condition(regs, code) {
            let target = branch_target(instruction, 0)?;
            bus.validate_near_code_target(regs.cs, target)?;
            *next_ip = target;
        }
        return Ok(StepOutcome::Continue);
    }

    match instruction.mnemonic {
        M::Nop | M::Pause => {}
        M::Hlt => {
            privilege::require_hlt(regs, bus, instruction)?;
            return Ok(StepOutcome::Halt);
        }
        M::Int => return Ok(StepOutcome::Interrupt(read_immediate(instruction, 0)? as u8)),
        M::Int3 => return Ok(StepOutcome::Interrupt(3)),
        M::Int1 => return Ok(StepOutcome::Interrupt(1)),
        M::Into => {
            if regs.eflags & OF != 0 {
                return Ok(StepOutcome::Interrupt(4));
            }
        }
        M::Iret | M::Iretd => {
            execute_iret(regs, bus, instruction, next_ip, pending_task_debug, model)?
        }
        M::Call => execute_call(regs, bus, instruction, next_ip)?,
        M::Jmp => execute_jump(regs, bus, instruction, next_ip)?,
        M::Ret | M::Retf => execute_return(regs, bus, instruction, next_ip)?,
        M::Jcxz | M::Jecxz => {
            let count = if instruction.mnemonic == M::Jecxz {
                regs.ecx
            } else {
                u32::from(regs.cx())
            };
            if count == 0 {
                let target = branch_target(instruction, 0)?;
                bus.validate_near_code_target(regs.cs, target)?;
                *next_ip = target;
            }
        }
        M::Loop | M::Loope | M::Loopne => {
            execute_loop(regs, bus, instruction, next_ip)?;
        }
        M::Mov => execute_mov(regs, bus, instruction)?,
        M::Movzx | M::Movsx => execute_mov_extend(regs, bus, instruction)?,
        M::Lea => execute_lea(regs, instruction)?,
        M::Lds | M::Les | M::Lss | M::Lfs | M::Lgs => {
            execute_far_load(regs, bus, instruction)?;
        }
        M::Push => execute_push(regs, bus, instruction)?,
        M::Pop => execute_pop(regs, bus, instruction)?,
        M::Pushf | M::Pushfd => {
            execute_push_flags(regs, bus, instruction, model)?;
        }
        M::Popf | M::Popfd => {
            execute_pop_flags(regs, bus, instruction, model)?;
        }
        M::Pusha | M::Pushad => execute_pusha(regs, bus, instruction)?,
        M::Popa | M::Popad => execute_popa(regs, bus, instruction)?,
        M::Enter => execute_enter(regs, bus, instruction)?,
        M::Leave => execute_leave(regs, bus, instruction)?,
        M::Add | M::Or | M::Adc | M::Sbb | M::And | M::Sub | M::Xor | M::Cmp | M::Test => {
            execute_alu(regs, bus, instruction)?;
        }
        M::Inc | M::Dec => execute_inc_dec(regs, bus, instruction)?,
        M::Not | M::Neg => execute_not_neg(regs, bus, instruction)?,
        M::Mul | M::Imul | M::Div | M::Idiv => {
            execute_mul_div(regs, bus, instruction)?;
        }
        M::Xchg => execute_xchg(regs, bus, instruction)?,
        M::Cmpxchg => execute_cmpxchg(regs, bus, instruction)?,
        M::Cmpxchg8b => execute_cmpxchg8b(regs, bus, instruction)?,
        M::Xadd => execute_xadd(regs, bus, instruction)?,
        M::Xlatb => execute_xlat(regs, bus, instruction)?,
        M::Bt | M::Bts | M::Btr | M::Btc => execute_bit(regs, bus, instruction)?,
        M::Bsf | M::Bsr => execute_bit_scan(regs, bus, instruction)?,
        M::Shld | M::Shrd => execute_double_shift(regs, bus, instruction)?,
        M::Cmovo
        | M::Cmovno
        | M::Cmovb
        | M::Cmovae
        | M::Cmove
        | M::Cmovne
        | M::Cmovbe
        | M::Cmova
        | M::Cmovs
        | M::Cmovns
        | M::Cmovp
        | M::Cmovnp
        | M::Cmovl
        | M::Cmovge
        | M::Cmovle
        | M::Cmovg => execute_cmov(regs, bus, instruction)?,
        M::Seto
        | M::Setno
        | M::Setb
        | M::Setae
        | M::Sete
        | M::Setne
        | M::Setbe
        | M::Seta
        | M::Sets
        | M::Setns
        | M::Setp
        | M::Setnp
        | M::Setl
        | M::Setge
        | M::Setle
        | M::Setg => {
            execute_setcc(regs, bus, instruction)?;
        }
        M::Rol | M::Ror | M::Rcl | M::Rcr | M::Shl | M::Sal | M::Shr | M::Sar => {
            execute_shift(regs, bus, instruction)?;
        }
        M::Movsb
        | M::Movsw
        | M::Movsd
        | M::Cmpsb
        | M::Cmpsw
        | M::Cmpsd
        | M::Stosb
        | M::Stosw
        | M::Stosd
        | M::Lodsb
        | M::Lodsw
        | M::Lodsd
        | M::Scasb
        | M::Scasw
        | M::Scasd
            if is_implicit_string(instruction) =>
        {
            let _unfinished_repeat = execute_string(regs, bus, instruction, next_ip)?;
        }
        M::Cbw => regs.set_ax(regs.al() as i8 as i16 as u16),
        M::Cwde => regs.eax = regs.ax() as i16 as i32 as u32,
        M::Cwd => regs.set_dx(if (regs.ax() as i16) < 0 { u16::MAX } else { 0 }),
        M::Cdq => regs.edx = if (regs.eax as i32) < 0 { u32::MAX } else { 0 },
        M::Daa => decimal_adjust(regs, false),
        M::Das => decimal_adjust(regs, true),
        M::Aaa => super::ascii_adjust(regs, false),
        M::Aas => super::ascii_adjust(regs, true),
        M::Aam | M::Aad => execute_ascii_base(regs, instruction)?,
        M::Sahf => {
            let ah = u32::from(regs.ah());
            regs.eflags = (regs.eflags & !(SF | ZF | AF | PF | CF)) | (ah & 0xd5) | 2;
        }
        M::Lahf => {
            let ah = ((regs.eflags & (SF | ZF | AF | PF | CF)) | 2) as u8;
            regs.set_ah(ah);
        }
        M::Clc => regs.eflags &= !CF,
        M::Stc => regs.eflags |= CF,
        M::Cmc => regs.eflags ^= CF,
        M::Cld => regs.eflags &= !DF,
        M::Std => regs.eflags |= DF,
        M::Cli => {
            privilege::require_cli_sti(regs, bus, instruction)?;
            regs.eflags &= !IF;
        }
        M::Sti => {
            privilege::require_cli_sti(regs, bus, instruction)?;
            regs.eflags |= IF;
        }
        M::Bswap => execute_bswap(regs, instruction)?,
        M::Cpuid => execute_cpuid(regs, model),
        _ => {
            return Err(CpuError::UnsupportedOpcode {
                opcode: instruction.decoded.opcode,
                ip: instruction.decoded.start_ip,
            });
        }
    }
    Ok(StepOutcome::Continue)
}
