//! Prefix legality and serialized guest read-modify-write transactions.

use guest_core::Registers;
use x86_decoder::Mnemonic;

use super::super::{
    CpuError,
    memory_access::{AccessKind, AccessRequest, CpuBus, DataAlignment},
    x86_decode::{MemoryOperand, NormalizedInstruction, Operand},
};
use super::operand::logical_span;

pub(super) fn validate_lock_prefix(
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    if !instruction.decoded.instruction.has_lock_prefix() {
        return Ok(());
    }
    let destination_is_memory = matches!(instruction.operand(0), Operand::Memory(_));
    let lockable = destination_is_memory
        && matches!(
            instruction.mnemonic,
            Mnemonic::Add
                | Mnemonic::Adc
                | Mnemonic::And
                | Mnemonic::Btc
                | Mnemonic::Btr
                | Mnemonic::Bts
                | Mnemonic::Cmpxchg
                | Mnemonic::Cmpxchg8b
                | Mnemonic::Dec
                | Mnemonic::Inc
                | Mnemonic::Neg
                | Mnemonic::Not
                | Mnemonic::Or
                | Mnemonic::Sbb
                | Mnemonic::Sub
                | Mnemonic::Xadd
                | Mnemonic::Xchg
                | Mnemonic::Xor
        );
    if lockable {
        Ok(())
    } else {
        Err(CpuError::InvalidOpcode {
            opcode: instruction.decoded.opcode,
            ip: instruction.decoded.start_ip,
        })
    }
}

/// Run the provider's one serialized read/transform/write operation. The
/// transform runs against owned bytes before any CPU register or flag commit.
pub(super) fn update_atomically<T>(
    regs: &Registers,
    bus: &mut impl CpuBus,
    reference: MemoryOperand,
    width: usize,
    transform: impl FnMut(&mut [u8]) -> T,
) -> Result<T, CpuError> {
    let alignment = atomic_alignment(bus, width)?;
    let request = AccessRequest::instruction(
        logical_span(regs, reference, width)?,
        AccessKind::DataReadWrite,
        alignment,
    );
    update_request_atomically(bus, request, width, transform)
}

pub(super) fn update_span_atomically<T>(
    bus: &mut impl CpuBus,
    span: super::super::memory_access::LogicalSpan,
    transform: impl FnMut(&mut [u8]) -> T,
) -> Result<T, CpuError> {
    let width = span.len;
    let alignment = atomic_alignment(bus, width)?;
    let request = AccessRequest::instruction(
        span,
        AccessKind::DataReadWrite,
        alignment,
    );
    update_request_atomically(bus, request, width, transform)
}

fn atomic_alignment(bus: &impl CpuBus, width: usize) -> Result<DataAlignment, CpuError> {
    // IA-32 atomic operands in this engine are byte, word, dword, or the
    // CMPXCHG8B qword. Check the provider length before narrowing it.
    u8::try_from(width)
        .ok()
        .filter(|width| matches!(width, 1 | 2 | 4 | 8))
        .map(DataAlignment::Natural)
        .ok_or(CpuError::InvalidMemoryAccessPlan {
            ip: bus.instruction_site().ip,
        })
}

fn update_request_atomically<T>(
    bus: &mut impl CpuBus,
    request: AccessRequest,
    width: usize,
    mut transform: impl FnMut(&mut [u8]) -> T,
) -> Result<T, CpuError> {
    if width == 0 || width > 8 {
        return Err(CpuError::InvalidMemoryAccessPlan {
            ip: bus.instruction_site().ip,
        });
    }
    let mut called = false;
    let mut outcome = None;
    let mut update = |bytes: &mut [u8]| {
        if called {
            return;
        }
        called = true;
        outcome = Some(transform(bytes));
    };
    bus.atomic_update(request, &mut update)?;
    outcome.ok_or(CpuError::InvalidMemoryAccessPlan {
        ip: bus.instruction_site().ip,
    })
}

pub(super) fn read_unsigned_le(bytes: &[u8]) -> u64 {
    let mut value = [0_u8; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(value)
}

pub(super) fn write_unsigned_le(bytes: &mut [u8], value: u64) {
    bytes.copy_from_slice(&value.to_le_bytes()[..bytes.len()]);
}
