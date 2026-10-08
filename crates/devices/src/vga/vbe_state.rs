//! INT 10h VBE save/restore dispatch.

#[path = "vbe_state_codec.rs"]
mod codec;

use super::VgaDevice;
use crate::DeviceError;
use guest_core::{GuestMemory, Registers};

use codec::{apply_state, block_count, encode_state, read_and_decode_state};

const SUCCESS: u16 = 0x004f;
const FAILURE: u16 = 0x014f;

/// Handle INT 10h AX=4F04h. The VBE interface preserves all registers except
/// AX, and returns BX only for the DL=00h size query. Invalid masks,
/// unsupported subfunctions, and malformed save buffers are ordinary VBE
/// failures; guest-memory faults retain their typed `DeviceError::Memory`.
pub(super) fn dispatch_state(
    vga: &VgaDevice,
    regs: &mut Registers,
    memory: &mut impl GuestMemory,
) -> Result<(), DeviceError> {
    let requested = regs.cx();
    if requested & !codec::SUPPORTED_STATE_MASK != 0 {
        regs.set_ax(FAILURE);
        return Ok(());
    }

    match regs.dl() {
        0 => {
            let Some(blocks) = block_count(requested) else {
                regs.set_ax(FAILURE);
                return Ok(());
            };
            regs.set_bx(blocks);
            regs.set_ax(SUCCESS);
        }
        1 => {
            if requested == 0 {
                regs.set_ax(SUCCESS);
                return Ok(());
            }
            let encoded = {
                let state = vga.borrow();
                let Some(bytes) = encode_state(&state, requested, memory)? else {
                    regs.set_ax(FAILURE);
                    return Ok(());
                };
                bytes
            };
            codec::write_far_buffer(memory, regs.es, regs.bx(), &encoded)?;
            regs.set_ax(SUCCESS);
        }
        2 => {
            if requested == 0 {
                regs.set_ax(SUCCESS);
                return Ok(());
            }
            let Some(snapshot) = read_and_decode_state(memory, regs.es, regs.bx(), requested)? else {
                regs.set_ax(FAILURE);
                return Ok(());
            };
            apply_state(vga, memory, requested, snapshot)?;
            regs.set_ax(SUCCESS);
        }
        _ => regs.set_ax(FAILURE),
    }
    Ok(())
}

#[cfg(test)]
#[path = "vbe_state_tests.rs"]
mod tests;
