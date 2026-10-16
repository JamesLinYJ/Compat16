//! One generated loop carries extended payloads, tags, status and integer
//! registers across the backedge. Only a precise side exit writes them out.
use super::{instructions, state::State};
use crate::{FloatLoop, floating::FloatPlan, lowering};
use cranelift_codegen::ir::{BlockArg, InstBuilder, Value, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;

pub(crate) fn emit_loop(b: &mut FunctionBuilder<'_>, loop_: &FloatLoop, plan: FloatPlan) {
    let entry = b.current_block().expect("floating loop entry");
    let params = b.block_params(entry).to_vec();
    let (pointer, integer_pointer, memory, budget) = (params[0], params[1], params[2], params[3]);
    let block = &loop_.body;
    let (initial, control) = super::load(b, block, pointer);
    let integers = lowering::State::load(b, integer_pointer);
    let live = block.input_register_mask();
    let header = b.create_block();
    for _ in 0..live.count_ones() * 2 + 2 {
        b.append_block_param(header, types::I64);
    }
    for _ in 0..10 {
        b.append_block_param(header, types::I32);
    }
    let incoming = arguments(&initial, &integers, budget, live);
    b.ins().jump(header, &incoming);
    b.switch_to_block(header);
    let incoming = b.block_params(header).to_vec();
    let mut word = 0;
    let mut state = initial.clone();
    for slot in 0..8 {
        if live & (1 << slot) != 0 {
            state.values[slot * 2..slot * 2 + 2].copy_from_slice(&incoming[word..word + 2]);
            word += 2;
        }
    }
    state.status = incoming[word];
    state.tags = incoming[word + 1];
    let integer_state = lowering::State {
        words: std::array::from_fn(|i| incoming[word + 2 + i]),
    };
    let remaining = incoming[word + 11];
    let exit = super::exit(b, state.written);
    let complete = b.create_block();
    let prefix = b.create_block();
    b.set_cold_block(prefix);
    let full = b.ins().icmp_imm_s(
        IntCC::UnsignedGreaterThanOrEqual,
        remaining,
        i64::from(loop_.instructions_per_iteration()),
    );
    b.ins().brif(full, complete, &[], prefix, &[]);
    b.switch_to_block(complete);
    let next = instructions::emit(
        b,
        block,
        plan,
        state.clone(),
        memory,
        remaining,
        control,
        exit,
        true,
    );
    debug_assert_eq!(next.top, 0);
    let mut next_integers = lowering::State {
        words: integer_state.words,
    };
    for (&instruction, flags) in loop_
        .tail
        .instructions
        .iter()
        .zip(lowering::live_flags(&loop_.tail.instructions))
    {
        lowering::emit_live(b, &mut next_integers, instruction, flags);
    }
    let again = match loop_.tail.condition {
        Some(condition) => lowering::condition_value(b, next_integers.words[8], condition),
        None => b.ins().iconst(types::I8, 1),
    };
    let left = b
        .ins()
        .iadd_imm_s(remaining, -i64::from(loop_.instructions_per_iteration()));
    let finished = b.create_block();
    b.set_cold_block(finished);
    let incoming = arguments(&next, &next_integers, left, live);
    b.ins().brif(again, header, &incoming, finished, &[]);

    // All instruction guards arrive with a prefix in this iteration. The
    // integer header state and remaining budget dominate every such exit.
    b.switch_to_block(prefix);
    let partial = instructions::emit(
        b, block, plan, state, memory, remaining, control, exit, false,
    );
    let args = partial.arguments(b, block.len());
    b.ins().jump(exit, &args);
    b.switch_to_block(exit);
    let output = b.block_params(exit).to_vec();
    let position_word = output.len() - 1;
    let completed = b.ins().isub(budget, remaining);
    let retired = b.ins().iadd(completed, output[position_word]);
    let publish = super::exit(b, block.output_register_mask());
    for _ in 0..10 {
        b.append_block_param(publish, types::I32);
    }
    let mut args: Vec<BlockArg> = output.iter().copied().map(Into::into).collect();
    args.extend(integer_state.words.map(BlockArg::from));
    args.push(retired.into());
    b.ins().jump(publish, &args);

    b.switch_to_block(finished);
    let retired = b.ins().isub(budget, left);
    let mut args = next.arguments(b, block.len() + 1);
    args.extend(next_integers.words.map(BlockArg::from));
    args.push(retired.into());
    b.ins().jump(publish, &args);

    b.switch_to_block(publish);
    let output = b.block_params(publish).to_vec();
    super::write(b, pointer, block.output_register_mask(), &output);
    let integers = lowering::State {
        words: std::array::from_fn(|i| output[position_word + 1 + i]),
    };
    integers.write_back(b, integer_pointer);
    let retired = b.ins().uextend(types::I64, output[position_word + 10]);
    let position = b.ins().uextend(types::I64, output[position_word]);
    let position = b.ins().ishl_imm_u(position, 32);
    let result = b.ins().bor(retired, position);
    b.ins().return_(&[result]);
    b.seal_all_blocks();
}

fn arguments(
    state: &State,
    integers: &lowering::State,
    remaining: Value,
    live: u8,
) -> Vec<BlockArg> {
    state
        .values
        .iter()
        .enumerate()
        .filter(|(word, _)| live & (1 << (word / 2)) != 0)
        .map(|(_, value)| (*value).into())
        .chain([state.status.into(), state.tags.into()])
        .chain(integers.words.map(BlockArg::from))
        .chain([remaining.into()])
        .collect()
}
