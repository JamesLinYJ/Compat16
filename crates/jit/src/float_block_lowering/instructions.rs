//! Emit each x87 operation against block-local facts. Facts follow physical
//! slots relative to entry TOP; every side exit publishes its exact prefix.
use super::{memory as input, state::State};
use crate::{FloatBlock, FloatInstruction as I, float_lowering, floating::FloatPlan};
use cranelift_codegen::ir::{Block, InstBuilder, MemFlagsData, Value, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;
pub(super) fn emit(
    b: &mut FunctionBuilder<'_>,
    block: &FloatBlock,
    plan: FloatPlan,
    mut state: State,
    memory: Value,
    budget: Value,
    control: Value,
    exit: Block,
    complete_masked: bool,
) -> State {
    for (index, instruction) in block.instructions().iter().enumerate() {
        if !complete_masked {
            let enough = b
                .ins()
                .icmp_imm_s(IntCC::UnsignedGreaterThan, budget, index as i64);
            state.guard(b, enough, exit, index);
        }
        match *instruction {
            I::Binary { .. } | I::BinaryMemory { .. } => {
                let (operation, dst, left, right, known, pop, source_slot) = match *instruction {
                    I::Binary {
                        operation,
                        destination,
                        source,
                        reverse,
                        pop,
                    } => {
                        let dst = state.slot(destination);
                        let src = state.slot(source);
                        let operands = [dst, src, state.top];
                        state.require_nonempty(
                            b,
                            &operands[..if pop { 3 } else { 2 }],
                            exit,
                            index,
                        );
                        let (left, right) = if reverse { (src, dst) } else { (dst, src) };
                        (
                            operation,
                            dst,
                            (state.values[left * 2], state.values[left * 2 + 1]),
                            (state.values[right * 2], state.values[right * 2 + 1]),
                            [state.supported[left], state.supported[right]],
                            pop,
                            Some(src),
                        )
                    }
                    I::BinaryMemory {
                        operation,
                        format,
                        offset,
                        reverse,
                    } => {
                        let dst = state.top;
                        state.require_nonempty(b, &[dst], exit, index);
                        let (sig, field, valid) = input::load(b, memory, offset, format);
                        state.guard(b, valid, exit, index);
                        let top = (state.values[dst * 2], state.values[dst * 2 + 1]);
                        let (left, right, known) = if reverse {
                            ((sig, field), top, [true, state.supported[dst]])
                        } else {
                            (top, (sig, field), [state.supported[dst], true])
                        };
                        (operation, dst, left, right, known, false, None)
                    }
                    _ => unreachable!(),
                };
                let result = float_lowering::arithmetic_with_known_inputs(
                    b,
                    FloatPlan { operation, ..plan },
                    left.0,
                    right.0,
                    left.1,
                    right.1,
                    known,
                );
                state.guard(b, result.valid, exit, index);
                if let Some(src) = source_slot {
                    state.supported[src] = true;
                }
                state.write(b, dst, result.significand, result.field);
                state.clear_c1(b);
                // Arithmetic refreshes ES/B even for zero exception flags.
                // FLDENV may have restored an inconsistent summary verbatim.
                state.status = b.ins().band_imm_u(state.status, !0x8080);
                let pe = b.ins().band_imm_u(result.flags, 0x20);
                state.status = b.ins().bor(state.status, pe);
                let c1 = b.ins().ushr_imm_u(result.flags, 7); // result bit16 -> SW bit9
                let c1 = b.ins().band_imm_u(c1, 0x200);
                state.status = b.ins().bor(state.status, c1);
                if pop {
                    state.pop(b);
                }
                if !complete_masked {
                    let unmasked = b.ins().bnot(control);
                    let pending = b.ins().band(pe, unmasked);
                    let okay = b.ins().icmp_imm_s(IntCC::Equal, pending, 0);
                    let summary = b.ins().bor_imm_u(state.status, 0x8080);
                    state.status = b.ins().select(okay, state.status, summary);
                    state.guard(b, okay, exit, index + 1);
                }
            }
            I::Load80 { offset } | I::LoadRegister(offset) | I::LoadMemory { offset, .. } => {
                let (sig, field) = if let I::LoadMemory { format, .. } = *instruction {
                    let (sig, field, valid) = input::load(b, memory, offset, format);
                    state.guard(b, valid, exit, index);
                    (sig, field)
                } else if matches!(instruction, I::Load80 { .. }) {
                    (
                        b.ins().load(
                            types::I64,
                            MemFlagsData::new().with_notrap(),
                            memory,
                            i32::from(offset),
                        ),
                        b.ins().load(
                            types::I16,
                            MemFlagsData::new().with_notrap(),
                            memory,
                            i32::from(offset) + 8,
                        ),
                    )
                } else {
                    let src = state.slot(offset);
                    state.require_nonempty(b, &[src], exit, index);
                    state.require_supported(b, src, exit, index);
                    (state.values[src * 2], state.values[src * 2 + 1])
                };
                let field = if matches!(instruction, I::Load80 { .. }) {
                    b.ins().uextend(types::I64, field)
                } else {
                    field
                };
                if matches!(instruction, I::Load80 { .. }) {
                    let valid = float_lowering::supported(b, sig, field);
                    state.guard(b, valid, exit, index);
                }
                let top = (state.top + 7) & 7;
                state.require_empty(b, top, exit, index);
                state.top = top;
                state.write(b, top, sig, field);
                state.clear_c1(b);
                // FLD's ordinary operand-flag boundary refreshes ES/B. Literal
                // constant loads below do not use that boundary.
                state.status = b.ins().band_imm_u(state.status, !0x8080);
            }
            I::One | I::Zero => {
                let top = (state.top + 7) & 7;
                state.require_empty(b, top, exit, index);
                let sig = b.ins().iconst(
                    types::I64,
                    if matches!(instruction, I::One) {
                        i64::MIN
                    } else {
                        0
                    },
                );
                let field = b.ins().iconst(
                    types::I64,
                    if matches!(instruction, I::One) {
                        0x3fff
                    } else {
                        0
                    },
                );
                state.top = top;
                state.write(b, top, sig, field);
                state.clear_c1(b);
            }
            I::Store80 { offset, pop } => {
                let top = state.top;
                state.require_nonempty(b, &[top], exit, index);
                state.require_supported(b, top, exit, index);
                b.ins().store(
                    MemFlagsData::new().with_notrap(),
                    state.values[top * 2],
                    memory,
                    i32::from(offset),
                );
                let field = b.ins().ireduce(types::I16, state.values[top * 2 + 1]);
                b.ins().store(
                    MemFlagsData::new().with_notrap(),
                    field,
                    memory,
                    i32::from(offset) + 8,
                );
                if pop {
                    state.pop(b);
                }
            }
            I::StoreRegister { destination, pop } => {
                let top = state.top;
                state.require_nonempty(b, &[top], exit, index);
                state.require_supported(b, top, exit, index);
                let dst = state.slot(destination);
                state.write(b, dst, state.values[top * 2], state.values[top * 2 + 1]);
                if pop {
                    state.pop(b);
                }
            }
            I::Exchange(other) => {
                let top = state.top;
                let src = state.slot(other);
                state.require_nonempty(b, &[top, src], exit, index);
                for slot in [top, src] {
                    state.require_supported(b, slot, exit, index);
                }
                let a = (state.values[top * 2], state.values[top * 2 + 1]);
                let c = (state.values[src * 2], state.values[src * 2 + 1]);
                state.write(b, top, c.0, c.1);
                state.write(b, src, a.0, a.1);
                state.clear_c1(b);
            }
            I::Negate | I::Absolute => {
                let top = state.top;
                state.require_nonempty(b, &[top], exit, index);
                state.require_supported(b, top, exit, index);
                let field = if matches!(instruction, I::Negate) {
                    b.ins().bxor_imm_u(state.values[top * 2 + 1], 0x8000)
                } else {
                    b.ins().band_imm_u(state.values[top * 2 + 1], 0x7fff)
                };
                state.write(b, top, state.values[top * 2], field);
            }
        }
    }
    state
}
