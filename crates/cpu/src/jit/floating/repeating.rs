//! Certify a pure integer tail whose branch returns to the floating body.
use super::*;
use compat16_jit::{FloatLoop, IntegerLoop};
use x86_decoder::OpKind;
pub(super) struct Tail {
    pub plan: FloatLoop,
    pub start: u32,
    pub next: u32,
}
impl Tail {
    pub fn decode(
        bytes: &[u8],
        ip: u32,
        mut cursor: usize,
        bits: u32,
        protected: bool,
        model: CpuModel,
        body: &FloatBlock,
    ) -> Option<(Self, usize)> {
        let start = ip + cursor as u32;
        let mut instructions = Vec::new();
        for _ in 0..=compat16_jit::MAX_BLOCK_INSTRUCTIONS {
            let decoded =
                x86_decode::decode_plain(&bytes[cursor..], ip + cursor as u32, bits, protected)?;
            if !model.supports_instruction_features(decoded.required_cpu_features())
                || decoded.instruction.has_lock_prefix()
                || decoded.next_ip <= decoded.start_ip
            {
                return None;
            }
            cursor += decoded.instruction.len();
            let branch = decoded.instruction;
            let condition = super::super::loops::branch_condition(branch.mnemonic());
            if branch.mnemonic() == M::Jmp || condition.is_some() {
                if !matches!(
                    branch.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32
                ) || branch.near_branch_target() != u64::from(ip)
                {
                    return None;
                }
                let tail = IntegerLoop::new(instructions, condition)?;
                return Some((
                    Self {
                        plan: FloatLoop::new(body.clone(), tail)?,
                        start,
                        next: decoded.next_ip,
                    },
                    cursor,
                ));
            }
            instructions.push(super::super::translation::translate(decoded)?);
        }
        None
    }
}
