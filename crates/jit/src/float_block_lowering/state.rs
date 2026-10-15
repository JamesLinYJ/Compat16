//! Guard-derived facts are local to one generated path. They are never cached
//! across calls, and a write/pop updates the affected physical slot's facts.
use crate::float_lowering;
use cranelift_codegen::ir::{Block, BlockArg, InstBuilder, Value, condcodes::IntCC, types};
use cranelift_frontend::FunctionBuilder;
#[derive(Clone)]
pub(super) struct State {
    pub values: [Value; 16],
    pub status: Value,
    pub tags: Value,
    pub origin: Value,
    pub top: usize,
    pub occupied: [Option<bool>; 8],
    pub supported: [bool; 8],
}
impl State {
    pub fn arguments(&self, b: &mut FunctionBuilder<'_>, retired: usize) -> Vec<BlockArg> {
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
    pub fn guard(&self, b: &mut FunctionBuilder<'_>, valid: Value, exit: Block, retired: usize) {
        let next = b.create_block();
        let args = self.arguments(b, retired);
        b.ins().brif(valid, next, &[], exit, &args);
        b.switch_to_block(next);
    }
    pub fn slot(&self, index: u8) -> usize {
        (self.top + usize::from(index)) & 7
    }
    fn tag(&self, b: &mut FunctionBuilder<'_>, slot: usize) -> Value {
        let tag = b.ins().ushr_imm_u(self.tags, (slot * 2) as i64);
        b.ins().band_imm_u(tag, 3)
    }
    pub fn require_nonempty(
        &mut self,
        b: &mut FunctionBuilder<'_>,
        slots: &[usize],
        exit: Block,
        retired: usize,
    ) {
        let mut valid = None;
        // Merge unknown stack checks into one branch; repeated slots need no
        // second check once the first predicate has been included.
        for &slot in slots {
            if self.occupied[slot] == Some(true) {
                continue;
            }
            let tag = self.tag(b, slot);
            let check = b.ins().icmp_imm_s(IntCC::NotEqual, tag, 3);
            valid = Some(valid.map_or(check, |previous| b.ins().band(previous, check)));
            self.occupied[slot] = Some(true);
        }
        if let Some(valid) = valid {
            self.guard(b, valid, exit, retired);
        }
    }
    pub fn require_empty(
        &mut self,
        b: &mut FunctionBuilder<'_>,
        slot: usize,
        exit: Block,
        retired: usize,
    ) {
        if self.occupied[slot] == Some(false) {
            return;
        }
        let tag = self.tag(b, slot);
        let empty = b.ins().icmp_imm_s(IntCC::Equal, tag, 3);
        self.guard(b, empty, exit, retired);
        self.occupied[slot] = Some(false);
    }
    pub fn require_supported(
        &mut self,
        b: &mut FunctionBuilder<'_>,
        slot: usize,
        exit: Block,
        retired: usize,
    ) {
        if self.supported[slot] {
            return;
        }
        let valid = float_lowering::supported(b, self.values[slot * 2], self.values[slot * 2 + 1]);
        self.guard(b, valid, exit, retired);
        self.supported[slot] = true;
    }
    fn set_tag(&mut self, b: &mut FunctionBuilder<'_>, slot: usize, tag: Value) {
        let cleared = b.ins().band_imm_u(self.tags, !(3i64 << (slot * 2)));
        let tag = b.ins().ishl_imm_u(tag, (slot * 2) as i64);
        self.tags = b.ins().bor(cleared, tag);
    }
    /// Every caller has checked the new payload's class (or constructs an
    /// exact constant). Range failures must branch out before this write.
    pub fn write(&mut self, b: &mut FunctionBuilder<'_>, slot: usize, sig: Value, field: Value) {
        self.values[slot * 2] = sig;
        self.values[slot * 2 + 1] = field;
        let exp = b.ins().band_imm_u(field, 0x7fff);
        let zero_exp = b.ins().icmp_imm_s(IntCC::Equal, exp, 0);
        let zero_sig = b.ins().icmp_imm_s(IntCC::Equal, sig, 0);
        let is_zero = b.ins().band(zero_exp, zero_sig);
        let tag = b.ins().uextend(types::I64, is_zero);
        self.set_tag(b, slot, tag);
        self.occupied[slot] = Some(true);
        self.supported[slot] = true;
    }
    pub fn clear_c1(&mut self, b: &mut FunctionBuilder<'_>) {
        self.status = b.ins().band_imm_u(self.status, !0x200);
    }
    pub fn pop(&mut self, b: &mut FunctionBuilder<'_>) {
        let empty = b.ins().iconst(types::I64, 3);
        self.set_tag(b, self.top, empty);
        self.occupied[self.top] = Some(false);
        self.top = (self.top + 1) & 7;
    }
}
