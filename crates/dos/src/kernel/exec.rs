use crate::caller_address_space::{DosCallAddressSpace, DosSpanPolicy};
use crate::{DosAction, DosError, DosErrorCode, DosExecRequest, DosHostError};
use guest_core::Registers;

use super::DosKernel;

const EXEC_PARAMETER_BLOCK_BYTES: usize = 14;
const EXEC_COMMAND_TAIL_BYTES: usize = 128;
const EXEC_COMMAND_MAX: usize = 126;
const FCB_BYTES: usize = 16;
const FCB_NAME_BYTES: usize = 12;

impl DosKernel {
    pub(super) fn execute_program(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
    ) -> Result<DosAction, DosError> {
        if regs.al() != 0 {
            self.failure(regs, DosHostError::new(DosErrorCode::InvalidFunction));
            return Ok(DosAction::Continue);
        }

        let program_path = match read_asciiz(memory, regs.ds, regs.dx()) {
            Ok(path) if !path.is_empty() => path,
            Ok(_) | Err(DosError::MalformedGuestInput(_) | DosError::Memory(_)) => {
                self.failure(regs, DosHostError::new(DosErrorCode::InvalidData));
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(error),
        };

        let mut parameter_block = [0; EXEC_PARAMETER_BLOCK_BYTES];
        let parameter_pointer = match memory.resolve_caller_pointer(regs.es, regs.bx()) {
            Ok(pointer) => pointer,
            Err(error) => return invalid_exec_input(self, regs, error),
        };
        if let Err(error) = memory.read_caller_range(
            parameter_pointer,
            0,
            &mut parameter_block,
            DosSpanPolicy::OffsetWrap,
        ) {
            return invalid_exec_input(self, regs, error);
        }

        let environment_segment = read_word(&parameter_block, 0);
        let command_tail_pointer = read_far_pointer(&parameter_block, 2);
        let first_fcb_pointer = read_far_pointer(&parameter_block, 6);
        let second_fcb_pointer = read_far_pointer(&parameter_block, 10);

        let command_tail = match read_command_tail(memory, command_tail_pointer) {
            Ok(tail) => tail,
            Err(error) => return invalid_exec_input(self, regs, error),
        };
        let first_fcb = match read_optional_fcb(memory, first_fcb_pointer) {
            Ok(fcb) => fcb,
            Err(error) => return invalid_exec_input(self, regs, error),
        };
        let second_fcb = match read_optional_fcb(memory, second_fcb_pointer) {
            Ok(fcb) => fcb,
            Err(error) => return invalid_exec_input(self, regs, error),
        };

        self.success(regs);
        Ok(DosAction::Execute(DosExecRequest {
            program_path,
            environment_segment,
            command_tail,
            first_fcb,
            second_fcb,
        }))
    }
}

fn invalid_exec_input(
    kernel: &DosKernel,
    regs: &mut Registers,
    error: DosError,
) -> Result<DosAction, DosError> {
    match error {
        DosError::MalformedGuestInput(_) | DosError::Memory(_) => {
            kernel.complete_exec_failure(regs, DosErrorCode::InvalidData);
            // The DOS ABI reports malformed pointers and buffers as an
            // ordinary service error instead of terminating the runtime.
            Ok(DosAction::Continue)
        }
        other => Err(other),
    }
}

fn read_asciiz(
    memory: &mut impl DosCallAddressSpace,
    segment: u16,
    offset: u16,
) -> Result<Vec<u8>, DosError> {
    let pointer = memory.resolve_caller_pointer(segment, offset)?;
    memory.read_caller_terminated(pointer, 0, 260, DosSpanPolicy::OffsetWrap)
}

fn read_command_tail(
    memory: &mut impl DosCallAddressSpace,
    pointer: (u16, u16),
) -> Result<[u8; EXEC_COMMAND_TAIL_BYTES], DosError> {
    let (segment, offset) = pointer;
    if segment == 0 && offset == 0 {
        let mut empty = [0; EXEC_COMMAND_TAIL_BYTES];
        empty[1] = b'\r';
        return Ok(empty);
    }

    let mut input = [0; EXEC_COMMAND_TAIL_BYTES];
    let pointer = memory.resolve_caller_pointer(segment, offset)?;
    memory.read_caller_range(pointer, 0, &mut input, DosSpanPolicy::OffsetWrap)?;
    let length = usize::from(input[0]);
    if length > EXEC_COMMAND_MAX || input[1 + length] != b'\r' {
        return Err(DosError::MalformedGuestInput(
            "INT 21h/4Bh command tail length or terminator is invalid",
        ));
    }

    // Copy only the declared tail and its CR terminator. Unused bytes in the
    // caller's buffer are not part of the child's PSP and may contain stale
    // guest data.
    let mut output = [0; EXEC_COMMAND_TAIL_BYTES];
    let copied = length + 2;
    output[..copied].copy_from_slice(&input[..copied]);
    Ok(output)
}

fn read_optional_fcb(
    memory: &mut impl DosCallAddressSpace,
    pointer: (u16, u16),
) -> Result<[u8; FCB_BYTES], DosError> {
    let (segment, offset) = pointer;
    if segment == 0 && offset == 0 {
        return Ok([0; FCB_BYTES]);
    }

    let mut fcb = [0; FCB_BYTES];
    let pointer = memory.resolve_caller_pointer(segment, offset)?;
    // MS-DOS 4.0 EXEC.ASM, exec_build_header: copy the drive, eight-byte
    // filename and three-byte extension, then zero the current-block and
    // record-size words. Those four output bytes are not caller input.
    memory.read_caller_range(
        pointer,
        0,
        &mut fcb[..FCB_NAME_BYTES],
        DosSpanPolicy::OffsetWrap,
    )?;
    Ok(fcb)
}

fn read_word(bytes: &[u8; EXEC_PARAMETER_BLOCK_BYTES], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_far_pointer(bytes: &[u8; EXEC_PARAMETER_BLOCK_BYTES], offset: usize) -> (u16, u16) {
    (read_word(bytes, offset + 2), read_word(bytes, offset))
}
