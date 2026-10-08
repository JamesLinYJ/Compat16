use guest_core::{real_address, GuestHandle, GuestMemory, OwnerId, Registers};

use crate::model::{GuestFarPointer, MoveRequest, PreparedCallMismatch, PreparedXmsCall, XmsError};
use crate::service::XmsService;

/// Handle the XMS installation check and driver-entrypoint query on INT 2Fh.
/// Returns `true` only for AX=4300h and AX=4310h.
pub fn handle_int2f(regs: &mut Registers, entrypoint: GuestFarPointer) -> bool {
    match regs.ax() {
        0x4300 => {
            regs.set_al(0x80);
            true
        }
        0x4310 => {
            regs.es = entrypoint.segment;
            regs.set_bx(entrypoint.offset);
            true
        }
        _ => false,
    }
}

impl XmsService {
    /// Dispatch a physical-memory XMS call. Function 0Bh interprets DS:SI as
    /// a raw physical descriptor address; runtime code with an A20-aware bus
    /// must use [`Self::handle_prepared_call`] instead.
    ///
    /// This updates only the registers defined by the XMS 2.0 result contract
    /// for the selected function. A20 changes update `A20State`; the runtime
    /// applies its enabled value to the shared memory's A20 bus gate after
    /// this call. The service itself never owns a second byte buffer.
    pub fn handle_call(
        &mut self,
        owner: OwnerId,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) {
        let function = regs.ah();
        match function {
            0x00 => {
                regs.set_ax(0x0200);
                regs.set_bx(self.version().driver_revision);
                regs.set_dx(if Self::memory_has_hma(memory) { 1 } else { 0 });
            }
            0x01 => {
                let requested_bytes = regs.dx();
                let result = self.request_hma(owner, requested_bytes, memory);
                set_call_result(regs, result);
            }
            0x02 => set_call_result(regs, self.release_hma(owner, memory)),
            0x03 => set_call_result(regs, self.set_global_a20(true).map(|_| ())),
            0x04 => set_call_result(regs, self.set_global_a20(false).map(|_| ())),
            0x05 => set_call_result(regs, self.enable_local_a20().map(|_| ())),
            0x06 => set_call_result(regs, self.disable_local_a20().map(|_| ())),
            0x07 => {
                regs.set_ax(if self.a20_state().enabled { 1 } else { 0 });
                regs.set_bl(0);
            }
            0x08 => {
                let free = self.free_space();
                regs.set_ax(free.largest_kb);
                regs.set_dx(free.total_kb);
                regs.set_bl(if free.total_kb == 0 { 0xa0 } else { 0 });
            }
            0x09 => match self.allocate(owner, regs.dx(), memory) {
                Ok(handle) => {
                    regs.set_ax(1);
                    regs.set_bl(0);
                    regs.set_dx(handle.0);
                }
                Err(error) => {
                    set_call_error(regs, error);
                    regs.set_dx(0);
                }
            },
            0x0a => {
                let handle = GuestHandle(regs.dx());
                let result = self.free(handle);
                set_call_result(regs, result);
            }
            0x0b => {
                let descriptor = real_address(regs.ds, regs.si());
                set_call_result(regs, self.move_from_descriptor(descriptor, memory));
            }
            0x0c => match self.lock(GuestHandle(regs.dx())) {
                Ok(address) => {
                    regs.set_ax(1);
                    regs.set_dx((address.0 >> 16) as u16);
                    regs.set_bx(address.0 as u16);
                }
                Err(error) => set_call_error(regs, error),
            },
            0x0d => {
                let handle = GuestHandle(regs.dx());
                let result = self.unlock(handle);
                set_call_result(regs, result);
            }
            0x0e => match self.handle_info(GuestHandle(regs.dx())) {
                Ok(info) => {
                    regs.set_ax(1);
                    regs.set_bh(info.lock_count);
                    regs.set_bl(info.free_handles as u8);
                    regs.set_dx(info.size_kb);
                }
                Err(error) => set_call_error(regs, error),
            },
            0x0f => {
                let handle = GuestHandle(regs.dx());
                let size_kb = regs.bx();
                let result = self.reallocate(handle, size_kb, memory);
                set_call_result(regs, result);
            }
            0x10 => match self.request_umb(regs.dx()) {
                Ok((segment, paragraphs)) => {
                    regs.set_ax(1);
                    regs.set_bx(segment);
                    regs.set_dx(paragraphs);
                }
                Err(error) => set_call_error(regs, error),
            },
            0x11 => {
                let segment = regs.dx();
                let result = self.release_umb(segment);
                set_call_result(regs, result);
            }
            _ => set_call_error(regs, XmsError::UnsupportedFunction(function)),
        }
    }

    /// Dispatch a runtime-prepared call. For function 0Bh, the runtime must
    /// read DS:SI through its A20-aware bus and supply `PreparedXmsCall::Move`;
    /// data movement then uses this same memory owner's raw physical view.
    /// All other AH functions use `OtherFunction` with the matching function
    /// number. A mismatched prepared variant is an adapter bug and leaves
    /// registers untouched.
    pub fn handle_prepared_call(
        &mut self,
        owner: OwnerId,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        prepared: PreparedXmsCall,
    ) -> Result<(), PreparedCallMismatch> {
        let register_function = regs.ah();
        match prepared {
            PreparedXmsCall::OtherFunction(prepared_function) => {
                if prepared_function == 0x0b {
                    return Err(PreparedCallMismatch::MoveDescriptorRequired);
                }
                if register_function != prepared_function {
                    return Err(PreparedCallMismatch::FunctionNumber {
                        register_function,
                        prepared_function,
                    });
                }
                self.handle_call(owner, regs, memory);
            }
            PreparedXmsCall::Move(descriptor) => {
                if register_function != 0x0b {
                    return Err(PreparedCallMismatch::UnexpectedMoveDescriptor {
                        register_function,
                    });
                }
                self.handle_prepared_move(regs, memory, descriptor);
            }
        }
        Ok(())
    }

    fn handle_prepared_move(
        &self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        descriptor: Result<MoveRequest, XmsError>,
    ) {
        let result = descriptor.and_then(|request| self.move_block(request, memory));
        set_call_result(regs, result);
    }
}

fn set_call_result(regs: &mut Registers, result: Result<(), XmsError>) {
    match result {
        Ok(()) => {
            regs.set_ax(1);
            regs.set_bl(0);
        }
        Err(error) => set_call_error(regs, error),
    }
}

fn set_call_error(regs: &mut Registers, error: XmsError) {
    regs.set_ax(0);
    regs.set_bl(error.error_code());
}
