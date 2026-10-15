//! Keep the logical x87 register file in SSA across a linear hot block. A
//! shared cold exit publishes only its completed prefix, including tags/TOP,
//! sticky precision, C1, and an unmasked precision exception's deferred state.
use crate::{FloatBlock, FloatInstruction as I, float_lowering, floating::FloatPlan};
use cranelift_codegen::ir::{
    Block, BlockArg, InstBuilder, MemFlagsData, Value, condcodes::IntCC, types,
};
use cranelift_frontend::FunctionBuilder;
struct State {
    values: [Value; 16],
    status: Value,
    tags: Value,
    origin: Value,
    top: usize,
}
impl State {
    fn arguments(&self, b: &mut FunctionBuilder<'_>, retired: usize) -> Vec<BlockArg> {
        let top = b.ins().iadd_imm_s(self.origin, self.top as i64);
        let top = b.ins().band_imm_u(top, 7);
        let top = b.ins().ishl_imm_u(top, 11);
        let status = b.ins().band_imm_u(self.status, !0x3800);
        let status = b.ins().bor(status, top);
        let count = b.ins().iconst(types::I32, retired as i64);
        self.values
            .iter()
            .copied()
            .chain([status, self.tags, count])
            .map(Into::into)
            .collect()
    }
    fn guard(&self, b: &mut FunctionBuilder<'_>, valid: Value, exit: Block, retired: usize) {
        let next = b.create_block();
        let args = self.arguments(b, retired);
        b.ins().brif(valid, next, &[], exit, &args);
        b.switch_to_block(next);
    }
    fn slot(&self, index: u8) -> usize {
        (self.top + usize::from(index)) & 7
    }
    fn tag(&self, b: &mut FunctionBuilder<'_>, slot: usize) -> Value {
        let tag = b.ins().ushr_imm_u(self.tags, (slot * 2) as i64);
        b.ins().band_imm_u(tag, 3)
    }
    fn nonempty(&self, b: &mut FunctionBuilder<'_>, slot: usize) -> Value {
        let tag = self.tag(b, slot);
        b.ins().icmp_imm_s(IntCC::NotEqual, tag, 3)
    }
    fn set_tag(&mut self, b: &mut FunctionBuilder<'_>, slot: usize, tag: Value) {
        let cleared = b.ins().band_imm_u(self.tags, !(3i64 << (slot * 2)));
        let tag = b.ins().ishl_imm_u(tag, (slot * 2) as i64);
        self.tags = b.ins().bor(cleared, tag);
    }
    fn write(&mut self, b: &mut FunctionBuilder<'_>, slot: usize, sig: Value, field: Value) {
        self.values[slot * 2] = sig;
        self.values[slot * 2 + 1] = field;
        let exp = b.ins().band_imm_u(field, 0x7fff);
        let zero_exp = b.ins().icmp_imm_s(IntCC::Equal, exp, 0);
        let zero_sig = b.ins().icmp_imm_s(IntCC::Equal, sig, 0);
        let is_zero = b.ins().band(zero_exp, zero_sig);
        let tag = b.ins().uextend(types::I64, is_zero);
        self.set_tag(b, slot, tag);
    }
    fn clear_c1(&mut self, b: &mut FunctionBuilder<'_>) {
        self.status = b.ins().band_imm_u(self.status, !0x200);
    }
    fn pop(&mut self, b: &mut FunctionBuilder<'_>) {
        let empty = b.ins().iconst(types::I64, 3);
        self.set_tag(b, self.top, empty);
        self.top = (self.top + 1) & 7;
    }
}
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
    let mut state = State {
        values,
        status,
        tags,
        origin,
        top: 0,
    };
    let exit = b.create_block();
    b.set_cold_block(exit);
    for _ in 0..18 {
        b.append_block_param(exit, types::I64);
    }
    b.append_block_param(exit, types::I32);
    for (index, instruction) in block.instructions().iter().enumerate() {
        let enough = b
            .ins()
            .icmp_imm_s(IntCC::UnsignedGreaterThan, budget, index as i64);
        state.guard(b, enough, exit, index);
        match *instruction {
            I::Binary {
                operation,
                destination,
                source,
                reverse,
                pop,
            } => {
                let dst = state.slot(destination);
                let src = state.slot(source);
                let d = state.nonempty(b, dst);
                let s = state.nonempty(b, src);
                let mut valid = b.ins().band(d, s);
                if pop {
                    let top = state.nonempty(b, state.top);
                    valid = b.ins().band(valid, top);
                }
                state.guard(b, valid, exit, index);
                let (left, right) = if reverse { (src, dst) } else { (dst, src) };
                let result = float_lowering::arithmetic(
                    b,
                    FloatPlan { operation, ..plan },
                    state.values[left * 2],
                    state.values[right * 2],
                    state.values[left * 2 + 1],
                    state.values[right * 2 + 1],
                );
                state.guard(b, result.valid, exit, index);
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
                let unmasked = b.ins().bnot(control);
                let pending = b.ins().band(pe, unmasked);
                let okay = b.ins().icmp_imm_s(IntCC::Equal, pending, 0);
                let summary = b.ins().bor_imm_u(state.status, 0x8080);
                state.status = b.ins().select(okay, state.status, summary);
                state.guard(b, okay, exit, index + 1);
            }
            I::Load80 { offset } | I::LoadRegister(offset) => {
                let (sig, field) = if matches!(instruction, I::Load80 { .. }) {
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
                    let valid = state.nonempty(b, src);
                    state.guard(b, valid, exit, index);
                    (state.values[src * 2], state.values[src * 2 + 1])
                };
                let field = if matches!(instruction, I::Load80 { .. }) {
                    b.ins().uextend(types::I64, field)
                } else {
                    field
                };
                let valid = float_lowering::supported(b, sig, field);
                state.guard(b, valid, exit, index);
                let top = (state.top + 7) & 7;
                let tag = state.tag(b, top);
                let empty = b.ins().icmp_imm_s(IntCC::Equal, tag, 3);
                state.guard(b, empty, exit, index);
                state.top = top;
                state.write(b, top, sig, field);
                state.clear_c1(b);
                // FLD's ordinary operand-flag boundary refreshes ES/B. Literal
                // constant loads below do not use that boundary.
                state.status = b.ins().band_imm_u(state.status, !0x8080);
            }
            I::One | I::Zero => {
                let top = (state.top + 7) & 7;
                let tag = state.tag(b, top);
                let empty = b.ins().icmp_imm_s(IntCC::Equal, tag, 3);
                state.guard(b, empty, exit, index);
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
                let valid = state.nonempty(b, top);
                state.guard(b, valid, exit, index);
                let valid =
                    float_lowering::supported(b, state.values[top * 2], state.values[top * 2 + 1]);
                state.guard(b, valid, exit, index);
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
                let valid = state.nonempty(b, top);
                state.guard(b, valid, exit, index);
                let valid =
                    float_lowering::supported(b, state.values[top * 2], state.values[top * 2 + 1]);
                state.guard(b, valid, exit, index);
                let dst = state.slot(destination);
                state.write(b, dst, state.values[top * 2], state.values[top * 2 + 1]);
                if pop {
                    state.pop(b);
                }
            }
            I::Exchange(other) => {
                let top = state.top;
                let src = state.slot(other);
                let a = state.nonempty(b, top);
                let c = state.nonempty(b, src);
                let valid = b.ins().band(a, c);
                state.guard(b, valid, exit, index);
                for slot in [top, src] {
                    let valid = float_lowering::supported(
                        b,
                        state.values[slot * 2],
                        state.values[slot * 2 + 1],
                    );
                    state.guard(b, valid, exit, index);
                }
                let a = (state.values[top * 2], state.values[top * 2 + 1]);
                let c = (state.values[src * 2], state.values[src * 2 + 1]);
                state.write(b, top, c.0, c.1);
                state.write(b, src, a.0, a.1);
                state.clear_c1(b);
            }
            I::Negate | I::Absolute => {
                let top = state.top;
                let valid = state.nonempty(b, top);
                state.guard(b, valid, exit, index);
                let valid =
                    float_lowering::supported(b, state.values[top * 2], state.values[top * 2 + 1]);
                state.guard(b, valid, exit, index);
                let field = if matches!(instruction, I::Negate) {
                    b.ins().bxor_imm_u(state.values[top * 2 + 1], 0x8000)
                } else {
                    b.ins().band_imm_u(state.values[top * 2 + 1], 0x7fff)
                };
                state.write(b, top, state.values[top * 2], field);
            }
        }
    }
    let args = state.arguments(b, block.len());
    b.ins().jump(exit, &args);
    b.switch_to_block(exit);
    let output = b.block_params(exit).to_vec();
    for (i, value) in output[..18].iter().enumerate() {
        b.ins()
            .store(MemFlagsData::trusted(), *value, pointer, (i * 8) as i32);
    }
    b.ins().return_(&[output[18]]);
    b.seal_all_blocks();
}
