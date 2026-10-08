use x86_decoder::Mnemonic as M;
use guest_core::Registers;

use crate::memory_access::{CpuBus, DataAlignment};
use crate::x86_decode::{NormalizedInstruction, Operand};
use crate::x87_state::{Ext80, X87State, X87Tag};
use crate::{registers::write_register, CpuError};

use super::{memory_location, read_bytes, write_bytes};

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;

pub(super) fn execute(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
) -> Result<bool, CpuError> {
    use M as Mnemonic;
    let memory_operand = instruction.operands[..usize::from(instruction.operand_count)]
        .iter()
        .find_map(|operand| if let Operand::Memory(mem) = operand { Some(*mem) } else { None });
    let mnemonic = instruction.mnemonic;
    match mnemonic {
        // Intel documents FENI/FDISI as 8087-only and FSETPM as 80287-only;
        // the Intel486's 32-bit x87 treats all of them as NOPs with no x87
        // state changes (SDM Vol. 1, §8.3.13).
        Mnemonic::Fnop | Mnemonic::Wait |
        Mnemonic::Fndisi | Mnemonic::Fneni | Mnemonic::Fnsetpm |
        Mnemonic::Fdisi | Mnemonic::Feni | Mnemonic::Fsetpm => Ok(true),
        Mnemonic::Finit | Mnemonic::Fninit => { state.reset(); Ok(true) }
        Mnemonic::Fclex | Mnemonic::Fnclex => { state.clear_exceptions(); Ok(true) }
        Mnemonic::Fldcw => {
            let mem = memory_operand.ok_or_else(|| unsupported(instruction))?;
            let location = memory_location(regs, mem, 2)?;
            let bytes = read_bytes(bus, location, DataAlignment::Natural(2))?;
            state.set_control_word(u16::from_le_bytes([bytes[0], bytes[1]]));
            Ok(true)
        }
        Mnemonic::Fnstcw | Mnemonic::Fstcw => {
            let mem = memory_operand.ok_or_else(|| unsupported(instruction))?;
            let location = memory_location(regs, mem, 2)?;
            write_bytes(bus, location, DataAlignment::Natural(2), &state.control_word.to_le_bytes())?;
            Ok(true)
        }
        Mnemonic::Fnstsw | Mnemonic::Fstsw => {
            if matches!(instruction.operand(0), Operand::Memory(_)) {
                let location = memory_location(
                    regs,
                    memory_operand.ok_or_else(|| unsupported(instruction))?,
                    2,
                )?;
                write_bytes(bus, location, DataAlignment::Natural(2), &state.status_word.to_le_bytes())?;
            } else {
                write_register(regs, 0, 2, u32::from(state.status_word));
            }
            Ok(true)
        }
        Mnemonic::Fldenv => {
            let mem = memory_operand.ok_or_else(|| unsupported(instruction))?;
            let width = environment_width(instruction);
            let location = memory_location(regs, mem, width)?;
            let bytes = read_bytes(bus, location, environment_alignment(width))?;
            restore_environment(state, &bytes, width == 28, bus.protected_mode_format_hint());
            Ok(true)
        }
        Mnemonic::Fnstenv | Mnemonic::Fstenv => {
            let mem = memory_operand.ok_or_else(|| unsupported(instruction))?;
            let width = environment_width(instruction);
            let location = memory_location(regs, mem, width)?;
            let bytes = save_environment(state, width == 28, bus.protected_mode_format_hint());
            write_bytes(bus, location, environment_alignment(width), &bytes)?;
            // Saving the environment masks all six exceptions, as specified.
            state.control_word |= 0x003f;
            state.status_word &= !((1 << 7) | (1 << 15));
            Ok(true)
        }
        Mnemonic::Frstor => {
            let mem = memory_operand.ok_or_else(|| unsupported(instruction))?;
            let env_width = environment_width(instruction);
            let total_width = env_width + 80;
            let location = memory_location(regs, mem, total_width)?;
            let bytes = read_bytes(bus, location, environment_alignment(env_width))?;
            restore_environment(
                state,
                &bytes[..env_width],
                env_width == 28,
                bus.protected_mode_format_hint(),
            );
            restore_registers(state, &bytes[env_width..]);
            Ok(true)
        }
        Mnemonic::Fnsave | Mnemonic::Fsave => {
            let mem = memory_operand.ok_or_else(|| unsupported(instruction))?;
            let env_width = environment_width(instruction);
            let total_width = env_width + 80;
            let location = memory_location(regs, mem, total_width)?;
            let mut bytes = save_environment(
                state,
                env_width == 28,
                bus.protected_mode_format_hint(),
            );
            bytes.extend(save_registers(state));
            write_bytes(bus, location, environment_alignment(env_width), &bytes)?;
            state.reset();
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn environment_width(instruction: &NormalizedInstruction) -> usize {
    environment_width_for_size(instruction.memory_width)
}

fn environment_width_for_size(size: usize) -> usize {
    match size {
        28 | 108 => 28,
        _ => 14,
    }
}

fn environment_alignment(width: usize) -> DataAlignment {
    if width == 28 {
        DataAlignment::Natural(4)
    } else {
        DataAlignment::Natural(2)
    }
}

fn save_environment(state: &X87State, wide: bool, protected: bool) -> Vec<u8> {
    let mut bytes = vec![0; if wide { 28 } else { 14 }];
    put_u16(&mut bytes, 0, state.control_word);
    put_u16(&mut bytes, if wide { 4 } else { 2 }, state.status_word);
    put_u16(&mut bytes, if wide { 8 } else { 4 }, state.tag_word);
    if wide && protected {
        put_u32(&mut bytes, 12, state.instruction_pointer);
        put_u16(&mut bytes, 16, state.instruction_segment);
        put_u16(&mut bytes, 18, state.opcode & 0x07ff);
        put_u32(&mut bytes, 20, state.data_pointer);
        put_u16(&mut bytes, 24, state.data_segment);
    } else if wide {
        let fip = real_linear_pointer(state.instruction_segment, state.instruction_pointer);
        let fdp = real_linear_pointer(state.data_segment, state.data_pointer);
        put_u16(&mut bytes, 12, fip as u16);
        put_u32(&mut bytes, 16, (((fip >> 16) & 0xffff) << 12) | u32::from(state.opcode & 0x07ff));
        put_u16(&mut bytes, 20, fdp as u16);
        put_u32(&mut bytes, 24, ((fdp >> 16) & 0xffff) << 12);
    } else if protected {
        put_u16(&mut bytes, 6, state.instruction_pointer as u16);
        put_u16(&mut bytes, 8, state.instruction_segment);
        put_u16(&mut bytes, 10, state.data_pointer as u16);
        put_u16(&mut bytes, 12, state.data_segment);
    } else {
        let fip = real_linear_pointer(state.instruction_segment, state.instruction_pointer) & 0x000f_ffff;
        let fdp = real_linear_pointer(state.data_segment, state.data_pointer) & 0x000f_ffff;
        put_u16(&mut bytes, 6, fip as u16);
        put_u16(&mut bytes, 8, (((fip >> 16) as u16 & 0x000f) << 12) | (state.opcode & 0x07ff));
        put_u16(&mut bytes, 10, fdp as u16);
        put_u16(&mut bytes, 12, ((fdp >> 16) as u16 & 0x000f) << 12);
    }
    bytes
}

fn restore_environment(state: &mut X87State, bytes: &[u8], wide: bool, protected: bool) {
    state.control_word = get_u16(bytes, 0);
    state.status_word = get_u16(bytes, if wide { 4 } else { 2 });
    state.tag_word = get_u16(bytes, if wide { 8 } else { 4 });
    // FLDENV restores only the empty/non-empty meaning of each tag bit on
    // this 32-bit x87 target; non-empty tags are classified from the physical
    // register payload already present in the CPU context (Intel SDM Vol. 3B,
    // x87 environment save/restore semantics). FRSTOR replaces those payloads
    // immediately afterward and reclassifies them again in restore_registers.
    reclassify_nonempty_tags(state);
    if wide && protected {
        state.instruction_pointer = get_u32(bytes, 12);
        state.instruction_segment = get_u16(bytes, 16);
        state.opcode = get_u16(bytes, 18) & 0x07ff;
        state.data_pointer = get_u32(bytes, 20);
        state.data_segment = get_u16(bytes, 24);
    } else if wide {
        let ip_opcode = get_u32(bytes, 16);
        let dp_high = get_u32(bytes, 24);
        state.instruction_pointer = u32::from(get_u16(bytes, 12))
            | (((ip_opcode >> 12) & 0xffff) << 16);
        state.instruction_segment = 0;
        state.opcode = (ip_opcode & 0x07ff) as u16;
        state.data_pointer = u32::from(get_u16(bytes, 20)) | (((dp_high >> 12) & 0xffff) << 16);
        state.data_segment = 0;
    } else if protected {
        state.instruction_pointer = u32::from(get_u16(bytes, 6));
        state.instruction_segment = get_u16(bytes, 8);
        state.data_pointer = u32::from(get_u16(bytes, 10));
        state.data_segment = get_u16(bytes, 12);
    } else {
        let ip_hi_opcode = get_u16(bytes, 8);
        let dp_hi = get_u16(bytes, 12);
        state.instruction_pointer = u32::from(get_u16(bytes, 6))
            | (u32::from((ip_hi_opcode >> 12) & 0x000f) << 16);
        state.instruction_segment = 0;
        state.opcode = ip_hi_opcode & 0x07ff;
        state.data_pointer = u32::from(get_u16(bytes, 10))
            | (u32::from((dp_hi >> 12) & 0x000f) << 16);
        state.data_segment = 0;
    }
}

fn real_linear_pointer(segment: u16, offset: u32) -> u32 {
    u32::from(segment).wrapping_mul(16).wrapping_add(offset)
}

fn save_registers(state: &X87State) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(80);
    for logical in 0..8 {
        let physical = state.physical_register(logical);
        bytes.extend_from_slice(&state.registers[physical].to_le_bytes());
    }
    bytes
}

fn restore_registers(state: &mut X87State, bytes: &[u8]) {
    for logical in 0..8 {
        let start = usize::from(logical) * 10;
        let raw: [u8; 10] = bytes[start..start + 10].try_into().unwrap_or([0; 10]);
        let physical = state.physical_register(logical);
        let value = Ext80::from_le_bytes(raw);
        state.registers[physical] = value;
        if state.tag(physical) != X87Tag::Empty {
            state.set_tag(physical, value.tag());
        }
    }
}

fn reclassify_nonempty_tags(state: &mut X87State) {
    for physical in 0..8 {
        if state.tag(physical) != X87Tag::Empty {
            let tag = state.registers[physical].tag();
            state.set_tag(physical, tag);
        }
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn unsupported(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedOpcode { opcode: instruction.decoded.opcode, ip: instruction.decoded.start_ip }
}
