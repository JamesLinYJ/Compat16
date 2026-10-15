//! Keep the logical x87 register file in SSA across a linear hot block. A
//! shared cold exit publishes only its completed prefix, including tags/TOP,
//! sticky precision, C1, and an unmasked precision exception's deferred state.
mod instructions;
mod memory;
mod state;
use crate::{FloatBlock, floating::FloatPlan};
use cranelift_codegen::ir::{InstBuilder, MemFlagsData, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;
use state::State;
pub(super) fn emit(b: &mut FunctionBuilder<'_>, block: &FloatBlock, plan: FloatPlan) {
    let entry = b.current_block().expect("float block entry");
    let params = b.block_params(entry).to_vec();
    let pointer = params[0];
    let memory = params[1];
    // Byte windows have alignment one; their constant RAM offsets may also
    // be unaligned. Only BlockState loads/stores may assert aligned access.
    let budget = params[2];
    let values = std::array::from_fn(|i| {
        b.ins()
            .load(types::I64, MemFlagsData::trusted(), pointer, (i * 8) as i32)
    });
    let status = b
        .ins()
        .load(types::I64, MemFlagsData::trusted(), pointer, 128);
    let tags = b
        .ins()
        .load(types::I64, MemFlagsData::trusted(), pointer, 136);
    let control = b
        .ins()
        .load(types::I64, MemFlagsData::trusted(), pointer, 144);
    let origin = b.ins().ushr_imm_u(status, 11);
    let state = State {
        values,
        status,
        tags,
        origin,
        top: 0,
        occupied: [None; 8],
        supported: [false; 8],
    };
    let exit = b.create_block();
    b.set_cold_block(exit);
    for _ in 0..18 {
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
    for (i, value) in output[..18].iter().enumerate() {
        b.ins()
            .store(MemFlagsData::trusted(), *value, pointer, (i * 8) as i32);
    }
    b.ins().return_(&[output[18]]);
    b.seal_all_blocks();
}
