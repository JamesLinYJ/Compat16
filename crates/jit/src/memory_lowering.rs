//! Guarded loads/stores into independent owned RAM buffers, with precise exits.

use crate::{BlockInstruction, MemoryLoop, Operation, ValueOperand, lowering};
use cranelift_codegen::ir::{
    Block, BlockArg, InstBuilder, MemFlagsData, Value, condcodes::IntCC, types,
};
use cranelift_frontend::FunctionBuilder;

fn args(state: &lowering::State, left: Value, position: Value) -> Vec<BlockArg> {
    state
        .words
        .into_iter()
        .chain([left, position])
        .map(Into::into)
        .collect()
}
fn budget_guard(
    b: &mut FunctionBuilder<'_>,
    exit: Block,
    state: &lowering::State,
    left: Value,
    index: usize,
) {
    let proceed = b.create_block();
    let position = b.ins().iconst(types::I32, index as i64);
    let more = b.ins().icmp_imm_s(IntCC::NotEqual, left, 0);
    let values = args(state, left, position);
    b.ins().brif(more, proceed, &[], exit, &values);
    b.switch_to_block(proceed);
    b.seal_block(proceed);
}
pub(super) fn emit(b: &mut FunctionBuilder<'_>, plan: &MemoryLoop) {
    let entry = b.current_block().expect("function entry");
    let params = b.block_params(entry).to_vec();
    let [state_pointer, buffer, start, length, budget]: [Value; 5] =
        params.try_into().expect("memory signature");
    let initial = lowering::State::load(b, state_pointer);
    let head = b.create_block();
    let exit = b.create_block();
    for _ in 0..10 {
        b.append_block_param(head, types::I32);
    }
    for _ in 0..11 {
        b.append_block_param(exit, types::I32);
    }
    let incoming: Vec<_> = initial
        .words
        .into_iter()
        .chain([budget])
        .map(Into::into)
        .collect();
    b.ins().jump(head, &incoming);
    b.switch_to_block(head);
    let mut state = lowering::State {
        words: std::array::from_fn(|i| b.block_params(head)[i]),
    };
    let mut left = b.block_params(head)[9];
    for (index, instruction) in plan.instructions.iter().enumerate() {
        budget_guard(b, exit, &state, left, index);
        match instruction {
            BlockInstruction::Integer(instruction) => lowering::emit(b, &mut state, *instruction),
            BlockInstruction::Memory(instruction) => {
                let address = instruction.address();
                let zero = b.ins().iconst(types::I32, 0);
                let base = address.base.map_or(zero, |r| lowering::load(b, &state, r));
                let offset = address.index.map_or(zero, |r| lowering::load(b, &state, r));
                let offset = b.ins().ishl_imm_u(offset, i64::from(address.shift));
                let offset = b.ins().iadd(base, offset);
                let offset = b.ins().iadd_imm_u(offset, i64::from(address.displacement));
                let offset = if address.bits == 16 {
                    b.ins().band_imm_u(offset, 0xffff)
                } else {
                    offset
                };
                let wide = b.ins().uextend(types::I64, offset);
                let window_start = b.ins().uextend(types::I64, start);
                let window_length = b.ins().uextend(types::I64, length);
                let relative = b.ins().isub(wide, window_start);
                let width = match (instruction.destination, instruction.source) {
                    (ValueOperand::Memory { bytes, .. }, _)
                    | (_, ValueOperand::Memory { bytes, .. }) => bytes,
                    _ => unreachable!("validated instruction"),
                };
                let below = b
                    .ins()
                    .icmp(IntCC::UnsignedGreaterThanOrEqual, wide, window_start);
                let end = b.ins().iadd_imm_u(relative, i64::from(width));
                let fits = b
                    .ins()
                    .icmp(IntCC::UnsignedLessThanOrEqual, end, window_length);
                let valid = b.ins().band(below, fits);
                let access = b.create_block();
                let position = b.ins().iconst(types::I32, index as i64);
                let values = args(&state, left, position);
                b.ins().brif(valid, access, &[], exit, &values);
                b.switch_to_block(access);
                b.seal_block(access);
                let pointer = b.ins().iadd(buffer, relative);
                let ty = match width {
                    1 => types::I8,
                    2 => types::I16,
                    _ => types::I32,
                };
                let read_destination = !matches!(
                    instruction.operation,
                    Operation::Move
                        | Operation::ZeroExtend
                        | Operation::SignExtend
                        | Operation::SetCondition(_)
                );
                let mut read_value = |operand: ValueOperand, read: bool| -> Value {
                    if !read {
                        return zero;
                    }
                    match operand {
                        ValueOperand::Register(r) => lowering::load(b, &state, r),
                        ValueOperand::Immediate(v) => b.ins().iconst(types::I32, i64::from(v)),
                        ValueOperand::Memory { .. } => {
                            let value = b.ins().load(ty, MemFlagsData::new(), pointer, 0);
                            if width == 4 {
                                value
                            } else {
                                b.ins().uextend(types::I32, value)
                            }
                        }
                    }
                };
                let lhs = read_value(instruction.destination, read_destination);
                let rhs = read_value(
                    instruction.source,
                    !matches!(instruction.operation, Operation::SetCondition(_)),
                );
                let mut temporary = lowering::State { words: state.words };
                temporary.words[0] = lhs;
                temporary.words[1] = rhs;
                lowering::emit(b, &mut temporary, instruction.arithmetic);
                if !matches!(instruction.operation, Operation::Compare | Operation::Test) {
                    let value = temporary.words[0];
                    match instruction.destination {
                        ValueOperand::Register(r) => lowering::store(b, &mut state, r, value),
                        ValueOperand::Memory { .. } => {
                            let value = if width == 4 {
                                value
                            } else {
                                b.ins().ireduce(ty, value)
                            };
                            b.ins().store(MemFlagsData::new(), value, pointer, 0);
                        }
                        _ => unreachable!("validated destination"),
                    }
                }
                state.words[8] = temporary.words[8];
            }
        }
        left = b.ins().iadd_imm_s(left, -1);
    }
    budget_guard(b, exit, &state, left, plan.instructions.len());
    left = b.ins().iadd_imm_s(left, -1);
    if let Some(condition) = plan.condition {
        let condition = lowering::condition_value(b, state.words[8], condition);
        let position = b
            .ins()
            .iconst(types::I32, (plan.instructions.len() + 1) as i64);
        let values = args(&state, left, position);
        let backedge: Vec<_> = state
            .words
            .into_iter()
            .chain([left])
            .map(Into::into)
            .collect();
        b.ins().brif(condition, head, &backedge, exit, &values);
    } else {
        let values: Vec<_> = state
            .words
            .into_iter()
            .chain([left])
            .map(Into::into)
            .collect();
        b.ins().jump(head, &values);
    }
    b.seal_block(head);
    b.switch_to_block(exit);
    b.seal_block(exit);
    let final_state = lowering::State {
        words: std::array::from_fn(|i| b.block_params(exit)[i]),
    };
    final_state.write_back(b, state_pointer);
    let remaining = b.block_params(exit)[9];
    let position = b.block_params(exit)[10];
    let retired = b.ins().isub(budget, remaining);
    let retired = b.ins().uextend(types::I64, retired);
    let retired = b.ins().ishl_imm_u(retired, 32);
    let position = b.ins().uextend(types::I64, position);
    let packed = b.ins().bor(retired, position);
    b.ins().return_(&[packed]);
}
