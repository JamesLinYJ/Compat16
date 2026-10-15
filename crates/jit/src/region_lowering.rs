//! Direct SSA links retain guest values across blocks. Full-block budget
//! guards keep hot paths compact; cold prefixes preserve every boundary.

use crate::{Region, RegionBranch, RegionPosition, RegionTarget, lowering};
use cranelift_codegen::ir::{
    Block, BlockArg, InstBuilder, MemFlagsData, Value, condcodes::IntCC, types,
};
use cranelift_frontend::{FunctionBuilder, Switch};

fn parameters(b: &mut FunctionBuilder<'_>, block: Block, position: bool) {
    for _ in 0..11 + usize::from(position) {
        b.append_block_param(block, types::I32);
    }
}
fn args(state: &lowering::State, left: Value, profile: Value) -> Vec<BlockArg> {
    state
        .words
        .into_iter()
        .chain([left, profile])
        .map(Into::into)
        .collect()
}
fn input(b: &FunctionBuilder<'_>, block: Block) -> (lowering::State, Value, Value) {
    let p = b.block_params(block);
    (
        lowering::State {
            words: std::array::from_fn(|i| p[i]),
        },
        p[9],
        p[10],
    )
}
fn exit_args(
    b: &mut FunctionBuilder<'_>,
    state: &lowering::State,
    left: Value,
    profile: Value,
    position: RegionPosition,
) -> Vec<BlockArg> {
    let mut values = args(state, left, profile);
    values.push(
        b.ins()
            .iconst(types::I32, i64::from(position.encode()))
            .into(),
    );
    values
}
fn target_args(
    b: &mut FunctionBuilder<'_>,
    heads: &[Block],
    exit: Block,
    target: RegionTarget,
    state: &lowering::State,
    control: (Value, Value),
    branch_profile: i64,
) -> (Block, Vec<BlockArg>) {
    let (left, profile) = control;
    let count = branch_profile + i64::from(matches!(target, RegionTarget::Block(_)));
    let profile = b.ins().iadd_imm_u(profile, count);
    match target {
        RegionTarget::Block(i) => (heads[usize::from(i)], args(state, left, profile)),
        RegionTarget::Exit(i) => (
            exit,
            exit_args(b, state, left, profile, RegionPosition::Exit(i)),
        ),
    }
}
fn branch(
    b: &mut FunctionBuilder<'_>,
    heads: &[Block],
    exit: Block,
    branch: RegionBranch,
    state: &lowering::State,
    left: Value,
    profile: Value,
) {
    match branch {
        RegionBranch::Continue(target) | RegionBranch::Jump(target) => {
            let count = if matches!(branch, RegionBranch::Jump(_)) {
                1 << 10
            } else {
                0
            };
            let (target, values) =
                target_args(b, heads, exit, target, state, (left, profile), count);
            b.ins().jump(target, &values);
        }
        RegionBranch::Conditional {
            condition,
            taken,
            fallthrough,
            prefer_taken,
        } => {
            let condition = lowering::condition_value(b, state.words[8], condition);
            let a = target_args(b, heads, exit, taken, state, (left, profile), 1 << 10);
            let c = target_args(b, heads, exit, fallthrough, state, (left, profile), 1 << 20);
            // Put the observed likely successor first for backend layout.
            // Both successors remain direct branches, with complete state.
            if prefer_taken {
                b.ins().brif(condition, a.0, &a.1, c.0, &c.1);
            } else {
                let inverse = b.ins().icmp_imm_s(IntCC::Equal, condition, 0);
                b.ins().brif(inverse, c.0, &c.1, a.0, &a.1);
            }
        }
    }
}
pub(super) fn emit(b: &mut FunctionBuilder<'_>, plan: &Region) {
    let entry = b.current_block().expect("region entry");
    let p = b.block_params(entry).to_vec();
    let [pointer, budget, position, counters]: [Value; 4] = p.try_into().expect("region signature");
    let initial = lowering::State::load(b, pointer);
    let zero = b.ins().iconst(types::I32, 0);
    let exit = b.create_block();
    parameters(b, exit, true);
    b.set_cold_block(exit);
    let heads: Vec<_> = plan
        .blocks
        .iter()
        .map(|_| {
            let head = b.create_block();
            parameters(b, head, false);
            head
        })
        .collect();
    let prefixes: Vec<Vec<_>> = plan
        .blocks
        .iter()
        .map(|block| {
            (0..=block.instructions.len())
                .map(|_| {
                    let prefix = b.create_block();
                    parameters(b, prefix, false);
                    b.set_cold_block(prefix);
                    prefix
                })
                .collect()
        })
        .collect();
    let mut switch = Switch::new();
    let mut entries = Vec::new();
    for (block, positions) in prefixes.iter().enumerate() {
        for (instruction, &prefix) in positions.iter().enumerate() {
            let wrapper = b.create_block();
            if block != 0 || instruction != 0 {
                b.set_cold_block(wrapper);
            }
            switch.set_entry((block * 32 + instruction) as u128, wrapper);
            entries.push((
                wrapper,
                if instruction == 0 {
                    heads[block]
                } else {
                    prefix
                },
            ));
        }
    }
    // The safe entrypoint rejects invalid positions. A defensive default
    // still exits without executing, rather than exposing a code pointer.
    let invalid = b.create_block();
    b.set_cold_block(invalid);
    switch.emit(b, position, invalid);
    for (wrapper, destination) in entries {
        b.switch_to_block(wrapper);
        b.ins().jump(destination, &args(&initial, budget, zero));
    }
    b.switch_to_block(invalid);
    let values = exit_args(
        b,
        &initial,
        budget,
        zero,
        RegionPosition::Block {
            block: 0,
            instruction: 0,
        },
    );
    b.ins().jump(exit, &values);
    for (index, block) in plan.blocks.iter().enumerate() {
        b.switch_to_block(heads[index]);
        let (mut state, left, profile) = input(b, heads[index]);
        let cost = block.instructions.len() as u32 + block.branch.retires();
        let enough = b
            .ins()
            .icmp_imm_s(IntCC::UnsignedGreaterThanOrEqual, left, i64::from(cost));
        let hot = b.create_block();
        b.ins().brif(
            enough,
            hot,
            &[],
            prefixes[index][0],
            &args(&state, left, profile),
        );
        b.switch_to_block(hot);
        let live = lowering::live_flags(&block.instructions);
        for (&instruction, live) in block.instructions.iter().zip(live) {
            lowering::emit_live(b, &mut state, instruction, live);
        }
        let left = b.ins().iadd_imm_s(left, -i64::from(cost));
        branch(b, &heads, exit, block.branch, &state, left, profile);
        for instruction in 0..=block.instructions.len() {
            b.switch_to_block(prefixes[index][instruction]);
            let (mut state, left, profile) = input(b, prefixes[index][instruction]);
            let has_body = instruction < block.instructions.len();
            if has_body || block.branch.retires() != 0 {
                let proceed = b.create_block();
                b.set_cold_block(proceed);
                let more = b.ins().icmp_imm_s(IntCC::NotEqual, left, 0);
                let values = exit_args(
                    b,
                    &state,
                    left,
                    profile,
                    RegionPosition::Block {
                        block: index as u8,
                        instruction: instruction as u8,
                    },
                );
                b.ins().brif(more, proceed, &[], exit, &values);
                b.switch_to_block(proceed);
            }
            if has_body {
                lowering::emit(b, &mut state, block.instructions[instruction]);
                let left = b.ins().iadd_imm_s(left, -1);
                b.ins().jump(
                    prefixes[index][instruction + 1],
                    &args(&state, left, profile),
                );
            } else {
                let left = b.ins().iadd_imm_s(left, -i64::from(block.branch.retires()));
                branch(b, &heads, exit, block.branch, &state, left, profile);
            }
        }
    }
    b.switch_to_block(exit);
    let (state, left, profile) = input(b, exit);
    let position = b.block_params(exit)[11];
    state.write_back(b, pointer);
    b.ins().store(MemFlagsData::trusted(), profile, counters, 0);
    let retired = b.ins().isub(budget, left);
    let retired = b.ins().uextend(types::I64, retired);
    let high = b.ins().ishl_imm_u(retired, 32);
    let low = b.ins().uextend(types::I64, position);
    let result = b.ins().bor(high, low);
    b.ins().return_(&[result]);
    b.seal_all_blocks();
}
