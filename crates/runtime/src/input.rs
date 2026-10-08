//! Bridge host mouse events into the guest's real-mode mouse device.

use std::collections::VecDeque;

use devices::mouse::{EVENT_MOVEMENT, GuestCallbackRequest, MouseInput};
use guest_core::memory::Memory;
use guest_core::{GuestMemory, MemoryError, Registers, real_address};
use x86_cpu::{Cpu, CpuContext, RealModeSegments};

use crate::{DiagnosticKind, RuntimeError};

const RETURN_SEGMENT: u16 = 0xf000;
const RETURN_OFFSET: u16 = 0x1400;
const INTERRUPT_FLAG: u32 = 1 << 9;

/// The far-return address used by guest mouse callbacks. Runtime recognizes it
/// only while a callback frame is active, before the ordinary NOP can execute.
pub(crate) fn install_mouse_return_stub(memory: &mut Memory) -> Result<(), RuntimeError> {
    memory
        .initialize_rom(real_address(RETURN_SEGMENT, RETURN_OFFSET), &[0x90])
        .map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::InternalInvariant,
                "install guest mouse callback return stub",
                error,
            )
        })
}

#[derive(Default)]
pub(crate) struct MouseInputBridge {
    pending_callbacks: VecDeque<GuestCallbackRequest>,
    #[cfg(test)]
    saved_registers: Option<Registers>,
    saved_cpu_callback: Option<SavedCpuCallback>,
}

struct SavedCpuCallback {
    context: CpuContext,
    stack_selector: u16,
    stack_pointer: u32,
    stack32: bool,
}

impl MouseInputBridge {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn queue_input(
        &mut self,
        devices: &mut devices::BiosDevices,
        input: MouseInput,
    ) -> Result<(), RuntimeError> {
        if let Some(request) = devices.push_mouse_input(input) {
            if request.event_mask == EVENT_MOVEMENT {
                if let Some(last) = self.pending_callbacks.back_mut() {
                    if last.entry == request.entry
                        && last.event_mask == EVENT_MOVEMENT
                        && last.buttons == request.buttons
                    {
                        last.x = request.x;
                        last.y = request.y;
                        last.motion_x = request.motion_x;
                        last.motion_y = request.motion_y;
                        return Ok(());
                    }
                }
            }
            self.pending_callbacks.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::ResourceExhausted,
                    "reserve guest mouse callback queue",
                    error,
                )
            })?;
            self.pending_callbacks.push_back(request);
        }
        Ok(())
    }

    /// Restore the interrupted register frame after the callback's guest RETF
    /// reaches the controlled return address. Guest memory writes are retained.
    #[cfg(test)]
    pub(crate) fn restore_returned_callback(&mut self, regs: &mut Registers) -> bool {
        let Some(saved) = self.saved_registers.as_ref() else {
            return false;
        };
        let returned_to_stub = real_address(regs.cs, regs.ip())
            == real_address(RETURN_SEGMENT, RETURN_OFFSET)
            && regs.ss == saved.ss
            && regs.sp() == saved.sp();
        if !returned_to_stub {
            return false;
        }
        if let Some(saved) = self.saved_registers.take() {
            *regs = saved;
            true
        } else {
            false
        }
    }

    /// Restore the complete CPU context after a scheduler-owned callback has
    /// returned through the controlled FAR-return address.
    pub(crate) fn restore_returned_cpu_callback(
        &mut self,
        cpu: &mut Cpu,
    ) -> Result<bool, RuntimeError> {
        if !cpu.allows_real_mode_service_intercepts() {
            return Ok(false);
        }
        let Some(saved) = self.saved_cpu_callback.as_ref() else {
            return Ok(false);
        };
        let returned_to_stub = cpu.regs.cs == RETURN_SEGMENT
            && cpu.regs.ip() == RETURN_OFFSET
            && cpu.regs.ss == saved.stack_selector
            && if saved.stack32 {
                cpu.regs.esp == saved.stack_pointer
            } else {
                cpu.regs.sp() == saved.stack_pointer as u16
        };
        if !returned_to_stub {
            return Ok(false);
        }
        cpu.restore_context(&saved.context)?;
        self.saved_cpu_callback = None;
        Ok(true)
    }

    /// Begin one guest callback when IF permits it. The guest callback runs
    /// through the normal instruction engine and returns through RETF; no host
    /// code interprets or invokes the callback body.
    #[cfg(test)]
    pub(crate) fn start_callback_if_enabled(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
    ) -> Result<bool, RuntimeError> {
        if self.saved_registers.is_some() || regs.eflags & INTERRUPT_FLAG == 0 {
            return Ok(false);
        }
        let Some(request) = self.pending_callbacks.front().copied() else {
            return Ok(false);
        };
        if request.entry.is_null() {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "mouse device queued a null guest callback",
            ));
        }

        let callback_registers = far_call_registers(regs, memory, request)?;
        let Some(_queued) = self.pending_callbacks.pop_front() else {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "guest mouse callback queue changed while scheduling",
            ));
        };
        self.saved_registers = Some(regs.clone());
        *regs = callback_registers;
        Ok(true)
    }

    /// Start a callback while preserving the complete CPU state, including
    /// when real-mode segment caches have not yet been imported.
    pub(crate) fn start_cpu_callback_if_enabled(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut impl GuestMemory,
    ) -> Result<bool, RuntimeError> {
        if !cpu.allows_real_mode_service_intercepts() {
            return Ok(false);
        }
        if self.saved_cpu_callback.is_some()
            || cpu.regs.eflags & INTERRUPT_FLAG == 0
        {
            return Ok(false);
        }
        #[cfg(test)]
        if self.saved_registers.is_some() {
            return Ok(false);
        }
        let Some(request) = self.pending_callbacks.front().copied() else {
            return Ok(false);
        };
        if request.entry.is_null() {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "mouse device queued a null guest callback",
            ));
        }

        let before = cpu.regs.clone();
        let context = cpu.capture_context();
        let stack32 = if cpu.has_architectural_context() {
            cpu.enter_real_mode_far_call16(
                request.entry.segment,
                request.entry.offset,
                RETURN_SEGMENT,
                RETURN_OFFSET,
                memory,
                &RealModeSegments,
            )
            .map_err(|error| {
                RuntimeError::from(error).with_context("checked CPU entry for mouse callback")
            })?
            .ok_or_else(|| {
                RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "architectural mouse callback entry lost its CPU context",
                )
            })?
        } else {
            cpu.regs = far_call_registers(&before, memory, request)?;
            false
        };
        let Some(_queued) = self.pending_callbacks.pop_front() else {
            let queue_error = RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "guest mouse callback queue changed while scheduling",
            );
            if let Err(restore_error) = cpu.restore_context(&context) {
                self.saved_cpu_callback = Some(SavedCpuCallback {
                    context,
                    stack_selector: before.ss,
                    stack_pointer: before.esp,
                    stack32,
                });
                return Err(queue_error.with_cleanup(
                    "restore the interrupted CPU after mouse callback queue corruption",
                    RuntimeError::from(restore_error),
                ));
            }
            return Err(queue_error);
        };
        cpu.regs.set_ax(request.event_mask);
        cpu.regs.set_bx(request.buttons);
        cpu.regs.set_cx(request.x);
        cpu.regs.set_dx(request.y);
        cpu.regs.set_si(request.motion_x as u16);
        cpu.regs.set_di(request.motion_y as u16);
        self.saved_cpu_callback = Some(SavedCpuCallback {
            context,
            stack_selector: before.ss,
            stack_pointer: before.esp,
            stack32,
        });
        Ok(true)
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending_callbacks.len()
    }
}

fn far_call_registers(
    regs: &Registers,
    memory: &mut impl GuestMemory,
    request: GuestCallbackRequest,
) -> Result<Registers, RuntimeError> {
    let old_sp = regs.sp();
    let return_sp = old_sp.wrapping_sub(4);
    let return_ip = RETURN_OFFSET.to_le_bytes();
    let return_cs = RETURN_SEGMENT.to_le_bytes();
    let frame = [return_ip[0], return_ip[1], return_cs[0], return_cs[1]];
    let frame_end = u32::from(return_sp) + 4;
    if frame_end > u32::from(u16::MAX) + 1 {
        return Err(stack_fault(MemoryError::AddressOverflow));
    }

    // Keep the pre-import branch's frame readable by the checked RETF path:
    // both validate and write the complete, non-wrapping 16-bit stack span.
    // An exclusive end at 64 KiB is valid, so an original SP of zero wraps
    // back to zero after RETF without wrapping any byte inside the frame.
    let address = real_address(regs.ss, return_sp);
    memory
        .validate_write(address, frame.len())
        .map_err(stack_fault)?;
    memory.write(address, &frame).map_err(stack_fault)?;

    let mut callback = regs.clone();
    callback.set_sp(return_sp);
    callback.set_ax(request.event_mask);
    callback.set_bx(request.buttons);
    callback.set_cx(request.x);
    callback.set_dx(request.y);
    callback.set_si(request.motion_x as u16);
    callback.set_di(request.motion_y as u16);
    callback.cs = request.entry.segment;
    callback.eip = u32::from(request.entry.offset);
    Ok(callback)
}

fn stack_fault(error: MemoryError) -> RuntimeError {
    RuntimeError::from(error).with_context("guest mouse callback stack")
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;
