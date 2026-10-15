//! Keep the logical x87 register file in SSA across a linear hot block. A
//! shared cold exit publishes only its completed prefix, including tags/TOP,
//! sticky precision, C1, and an unmasked precision exception's deferred state.
mod instructions;
mod memory;
mod state;
use crate::{Float80, FloatBlock, FloatRegisters, floating::FloatPlan};
use cranelift_codegen::ir::{InstBuilder, MemFlagsData, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;
use state::State;
pub(super) fn emit(b: &mut FunctionBuilder<'_>, block: &FloatBlock, plan: FloatPlan) {
    let entry = b.current_block().expect("float block entry");
    let params = b.block_params(entry).to_vec();
    let pointer = params[0];
    let memory = params[1];
    // Byte windows have alignment one; their constant RAM offsets may also
    // be unaligned. Only typed state fields may assert aligned access.
    let budget = params[2];
    let live = block.input_register_mask();
    let written = block.output_register_mask();
    let zero = b.ins().iconst(types::I64, 0);
    let values = std::array::from_fn(|i| {
        if live & (1 << (i / 2)) != 0 {
            let (ty, offset) = if i % 2 == 0 {
                (types::I64, std::mem::offset_of!(Float80, significand))
            } else {
                (types::I16, std::mem::offset_of!(Float80, sign_exponent))
            };
            let offset = std::mem::offset_of!(FloatRegisters, values)
                + i / 2 * std::mem::size_of::<Float80>()
                + offset;
            let value = b
                .ins()
                .load(ty, MemFlagsData::trusted(), pointer, offset as i32);
            if ty == types::I16 {
                b.ins().uextend(types::I64, value)
            } else {
                value
            }
        } else {
            zero
        }
    });
    let status_offset = std::mem::offset_of!(FloatRegisters, status) as i32;
    let tags_offset = std::mem::offset_of!(FloatRegisters, tags) as i32;
    let control_offset = std::mem::offset_of!(FloatRegisters, control) as i32;
    let status = b
        .ins()
        .load(types::I16, MemFlagsData::trusted(), pointer, status_offset);
    let status = b.ins().uextend(types::I64, status);
    let tags = b
        .ins()
        .load(types::I16, MemFlagsData::trusted(), pointer, tags_offset);
    let tags = b.ins().uextend(types::I64, tags);
    let control = b
        .ins()
        .load(types::I16, MemFlagsData::trusted(), pointer, control_offset);
    let control = b.ins().uextend(types::I64, control);
    let origin = b.ins().ushr_imm_u(status, 11);
    let state = State {
        values,
        status,
        tags,
        origin,
        top: 0,
        occupied: [None; 8],
        supported: [false; 8],
        written,
    };
    let exit = b.create_block();
    b.set_cold_block(exit);
    let payload_words = written.count_ones() as usize * 2;
    for _ in 0..payload_words + 2 {
        b.append_block_param(exit, types::I64);
    }
    b.append_block_param(exit, types::I32);
    // Ordinary programs mask PE. Validate that control and the complete
    // budget once, keeping per-instruction prefix/PE checks on a cold path.
    // Operand/range/stack exits remain precise on both paths.
    let full = b.ins().icmp_imm_s(
        IntCC::UnsignedGreaterThanOrEqual,
        budget,
        block.len() as i64,
    );
    let masked = b.ins().band_imm_u(control, 0x20);
    let masked = b.ins().icmp_imm_s(IntCC::NotEqual, masked, 0);
    let hot = b.ins().band(full, masked);
    let complete = b.create_block();
    let prefix = b.create_block();
    b.set_cold_block(prefix);
    b.ins().brif(hot, complete, &[], prefix, &[]);
    b.switch_to_block(complete);
    instructions::emit(
        b,
        block,
        plan,
        state.clone(),
        memory,
        budget,
        control,
        exit,
        true,
    );
    b.switch_to_block(prefix);
    instructions::emit(b, block, plan, state, memory, budget, control, exit, false);
    b.switch_to_block(exit);
    let output = b.block_params(exit).to_vec();
    // Unwritten payloads retain their original bytes in FloatRegisters. Keeping
    // them out of the shared exit also removes their liveness at every guard.
    let mut word = 0;
    for slot in 0..8 {
        if written & (1 << slot) == 0 {
            continue;
        }
        for half in 0..2 {
            let (value, offset) = if half == 0 {
                (output[word], std::mem::offset_of!(Float80, significand))
            } else {
                (
                    b.ins().ireduce(types::I16, output[word]),
                    std::mem::offset_of!(Float80, sign_exponent),
                )
            };
            let offset = std::mem::offset_of!(FloatRegisters, values)
                + slot * std::mem::size_of::<Float80>()
                + offset;
            b.ins()
                .store(MemFlagsData::trusted(), value, pointer, offset as i32);
            word += 1;
        }
    }
    for (value, offset) in [
        (output[word], status_offset),
        (output[word + 1], tags_offset),
    ] {
        let value = b.ins().ireduce(types::I16, value);
        b.ins()
            .store(MemFlagsData::trusted(), value, pointer, offset);
    }
    b.ins().return_(&[output[word + 2]]);
    b.seal_all_blocks();
}
