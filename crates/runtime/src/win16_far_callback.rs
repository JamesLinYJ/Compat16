//! Shared, checked Win16 FAR-callback call-frame construction.
//!
//! Family modules own callback lifetime, temporary data and continuation
//! policy. This module only validates the guest procedure and constructs the
//! segmented call frame; it never calls guest code on the host stack.

use dos_kernel::DosKernel;
use guest_core::{memory::Memory, Registers, Selector};
use win16_abi::Access;
use x86_cpu::{CallEffectPolicy, CallResumeBoundary, ControlTransfer, Cpu,
    LegacyRegisterTransfer, LegacyStackPointerTarget};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

/// Argument values are copied into the guest stack in Win16 stack order.
/// Pointer arguments must refer to already-owned guest memory, whose access
/// and extent are checked before the callback is entered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16FarCallbackArgument {
    Word(u16),
    Dword(u32),
    GuestPointer { far: u32, access: Access, bytes: u32 },
    HugeGuestPointer { far: u32, access: Access, bytes: u32 },
}

/// For arguments listed in prototype order, Pascal places the last parameter
/// nearest the FAR return and callee-cleans with `RETF n`. Physical layout and
/// cleanup are one ABI choice and must stay paired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16FarCallbackConvention {
    Pascal,
}

/// Guest return-register interpretation. Void callbacks ignore AX and DX.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16FarCallbackReturn {
    Void,
    Word,
    Dword,
}

/// Per-invocation state retained by the family continuation while guest code
/// is running. It contains guest addresses and registers only.
#[derive(Clone, Debug)]
pub(super) struct Win16FarCallbackFrame {
    saved: Registers,
    procedure: u32,
    return_kind: Win16FarCallbackReturn,
    cpu_owner: Option<u64>,
    cpu_restored: bool,
    returned_value: Option<u32>,
    terminal_aborted: bool,
}

impl Win16FarCallbackFrame {
    pub(in crate::win16_runtime) fn is_terminal_aborted(&self) -> bool {
        self.terminal_aborted
    }

    /// Keep the callback, interrupted guest code and the original FAR return
    /// site alive while the callback continuation is suspended.
    pub(super) fn code_references(&self) -> [u32; 2] {
        [
            self.procedure,
            (u32::from(self.saved.cs) << 16) | u32::from(self.saved.ip()),
        ]
    }
}

impl Win16State {
    /// Build a guest FAR call frame and enter the callback on the emulated
    /// CPU. `arguments` are listed in prototype order; this method applies the
    /// physical parameter order required by the selected ABI.
    pub(super) fn enter_guest_far_callback(
        &self,
        registers: &mut Registers,
        memory: &mut Memory,
        procedure: u32,
        arguments: &[Win16FarCallbackArgument],
        convention: Win16FarCallbackConvention,
        return_kind: Win16FarCallbackReturn,
    ) -> Result<Win16FarCallbackFrame, RuntimeError> {
        let callback = self.selectors.pointer_from_far(procedure)
            .map_err(crate::runtime_error)?;
        self.selectors.translate(callback, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;

        let argument_bytes = arguments.iter().try_fold(0_u16, |total, argument| {
            total.checked_add(argument.stack_size())
        }).ok_or_else(|| RuntimeError::new(Kind::GuestFault,
            "Win16 callback arguments exceed the segmented stack limit"))?;
        let frame_bytes = argument_bytes.checked_add(4).ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault,
                "Win16 callback frame exceeds the segmented stack limit")
        })?;
        let callback_sp = registers.sp().checked_sub(frame_bytes).ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault, "Win16 callback stack underflow")
        })?;
        let stack = self.selectors.pointer_from_raw(Selector(registers.ss), callback_sp)
            .map_err(crate::runtime_error)?;
        self.selectors.translate(stack, Access::Write, usize::from(frame_bytes), memory)
            .map_err(crate::runtime_error)?;

        for argument in arguments {
            if let Win16FarCallbackArgument::HugeGuestPointer { far, access, bytes } = *argument {
                self.validate_callback_buffer(memory, far, access, bytes)?;
            }
            if let Win16FarCallbackArgument::GuestPointer { far, access, bytes } = *argument {
                let pointer = self.selectors.pointer_from_far(far)
                    .map_err(crate::runtime_error)?;
                let bytes = usize::try_from(bytes).map_err(|_| RuntimeError::new(
                    Kind::GuestFault, "Win16 callback buffer extent exceeds host address width"))?;
                self.selectors.translate(pointer, access, bytes, memory)
                    .map_err(crate::runtime_error)?;
            }
        }

        let mut bytes = vec![0_u8; usize::from(frame_bytes)];
        // The synthetic FAR return address targets the common callback gate.
        bytes[2..4].copy_from_slice(&self.callback_gate_selector.0.to_le_bytes());
        let mut cursor = 4_usize;
        let mut write_argument = |argument: &Win16FarCallbackArgument| {
            match *argument {
                Win16FarCallbackArgument::Word(value) => {
                    bytes[cursor..cursor + 2].copy_from_slice(&value.to_le_bytes());
                    cursor += 2;
                }
                Win16FarCallbackArgument::Dword(value)
                | Win16FarCallbackArgument::HugeGuestPointer { far: value, .. }
                | Win16FarCallbackArgument::GuestPointer { far: value, .. } => {
                    bytes[cursor..cursor + 4].copy_from_slice(&value.to_le_bytes());
                    cursor += 4;
                }
            }
        };
        match convention {
            Win16FarCallbackConvention::Pascal => {
                for argument in arguments.iter().rev() { write_argument(argument); }
            }
        }
        self.selectors.write(memory, stack, &bytes).map_err(crate::runtime_error)?;

        let frame = Win16FarCallbackFrame {
            saved: registers.clone(),
            procedure,
            return_kind,
            cpu_owner: None,
            cpu_restored: false,
            returned_value: None,
            terminal_aborted: false,
        };
        registers.set_sp(callback_sp);
        registers.cs = (procedure >> 16) as u16;
        registers.set_ip(procedure as u16);
        Ok(frame)
    }

    /// Validate the synthetic FAR return and callback-specific stack cleanup,
    /// capture AX or DX:AX, and restore the interrupted guest register state.
    pub(super) fn finish_guest_far_callback(
        &self,
        registers: &mut Registers,
        frame: Win16FarCallbackFrame,
    ) -> Result<u32, RuntimeError> {
        let expected_sp = frame.saved.sp();
        if registers.cs != self.callback_gate_selector.0 || registers.ip() != 0
            || registers.ss != frame.saved.ss || registers.sp() != expected_sp
        {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 FAR callback returned with an invalid gate or stack"));
        }
        let value = match frame.return_kind {
            Win16FarCallbackReturn::Void => 0,
            Win16FarCallbackReturn::Word => u32::from(registers.ax()),
            Win16FarCallbackReturn::Dword => {
                u32::from(registers.ax()) | (u32::from(registers.dx()) << 16)
            }
        };
        *registers = frame.saved;
        Ok(value)
    }

    /// Enter a standalone family callback under a checked CPU continuation.
    /// The unowned variant above is reserved for a callback nested in a USER
    /// operation whose exact outer frame already owns its return proof.
    pub(super) fn enter_guest_far_callback_checked(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        procedure: u32,
        arguments: &[Win16FarCallbackArgument],
        convention: Win16FarCallbackConvention,
        return_kind: Win16FarCallbackReturn,
    ) -> Result<Win16FarCallbackFrame, RuntimeError> {
        let entry = cpu.regs.clone();
        self.enter_guest_far_callback_checked_with_registers(
            cpu, dos, memory, procedure, arguments, convention, return_kind, entry,
        )
    }

    /// Register-argument entries (such as NE LibMain/WEP) retain the original
    /// caller separately from the prepared callee register image. Control and
    /// stack registers cannot be replaced by this argument projection.
    pub(super) fn enter_guest_far_callback_checked_with_registers(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        procedure: u32,
        arguments: &[Win16FarCallbackArgument],
        convention: Win16FarCallbackConvention,
        return_kind: Win16FarCallbackReturn,
        entry: Registers,
    ) -> Result<Win16FarCallbackFrame, RuntimeError> {
        let caller = cpu.regs.clone();
        if entry.cs != caller.cs || entry.eip != caller.eip
            || entry.ss != caller.ss || entry.esp != caller.esp
            || entry.eflags != caller.eflags
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 FAR callback register arguments changed control or stack state"));
        }

        let owner = self.capture_legacy_cpu_call_frame(cpu, dos, memory)?;
        let setup = (|| {
            let argument_bytes = arguments.iter().try_fold(0_u16, |total, argument| {
                total.checked_add(argument.stack_size())
            }).ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 callback arguments exceed the segmented stack limit"))?;
            let frame_bytes = argument_bytes.checked_add(4).ok_or_else(|| RuntimeError::new(
                Kind::GuestFault, "Win16 callback frame exceeds the segmented stack limit"))?;
            let callback_sp = caller.sp().checked_sub(frame_bytes).ok_or_else(||
                RuntimeError::new(Kind::GuestFault, "Win16 callback stack underflow"))?;
            let mut callback = entry.clone();
            callback.set_sp(callback_sp);
            callback.cs = (procedure >> 16) as u16;
            callback.set_ip(procedure as u16);
            let returned_sp = caller.sp();
            let mut gate = callback.clone();
            gate.cs = self.callback_gate_selector.0;
            gate.set_ip(0);
            gate.set_sp(returned_sp);
            self.retain_legacy_cpu_frame_roots(owner, &callback, dos, memory)?;
            self.retain_legacy_cpu_frame_roots(owner, &gate, dos, memory)?;
            let mut entered = entry;
            let mut frame = self.enter_guest_far_callback(&mut entered, memory, procedure,
                arguments, convention, return_kind)?;
            frame.saved = caller.clone();
            Ok((frame, entered))
        })();
        match setup {
            Ok((mut frame, entered)) => {
                frame.cpu_owner = Some(owner);
                cpu.regs = entered;
                Ok(frame)
            }
            Err(primary) => {
                let target = LegacyRegisterTransfer {
                    registers: caller,
                    stack_pointer: LegacyStackPointerTarget::RegisterValue,
                };
                let cleanup = self.restore_legacy_cpu_call_frame(owner, cpu, memory,
                    CallEffectPolicy::PreserveX87, CallResumeBoundary::NoGuestExecution,
                    target).and_then(|()| self.release_legacy_cpu_frame(owner, dos, memory));
                match cleanup {
                    Ok(()) => Err(primary),
                    Err(cleanup) => {
                        let cause = std::sync::Arc::new(primary.with_cleanup(
                            "rollback Win16 callback setup while retaining its first cause", cleanup));
                        let failure = RuntimeError::with_source(cause.kind(),
                            "Win16 callback pre-entry rollback retains its CPU roots",
                            std::sync::Arc::clone(&cause));
                        match self.record_failed_legacy_cpu_setup(owner, cpu, cause) {
                            Ok(()) => Err(failure),
                            Err(retain) => Err(failure.with_cleanup(
                                "retain the exact failed callback setup owner", retain)),
                        }
                    }
                }
            }
        }
    }

    /// Validate the exact guest far return, commit the caller transfer once, and
    /// cache the projected value while leaving the backing owner live for ACK.
    pub(super) fn finish_guest_far_callback_checked(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        frame: &mut Win16FarCallbackFrame,
    ) -> Result<u32, RuntimeError> {
        self.finish_guest_far_callback_checked_with_policy(
            cpu, dos, memory, frame, CallEffectPolicy::PreserveX87,
        )
    }

    pub(super) fn finish_guest_far_callback_checked_with_policy(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        frame: &mut Win16FarCallbackFrame,
        policy: CallEffectPolicy,
    ) -> Result<u32, RuntimeError> {
        self.finish_guest_far_callback_return(cpu, dos, memory, frame, policy, false)
    }

    /// Compose a proved callback RETF with its enclosing native API owner.
    /// The CPU issues AdapterReturn only after the checked restore commits;
    /// the outer continuation must not reuse the consumed raw RETF marker.
    pub(super) fn finish_native_function_far_callback(
        &mut self, cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory,
        frame: &mut Win16FarCallbackFrame,
    ) -> Result<u32, RuntimeError> {
        self.finish_guest_far_callback_return(cpu, dos, memory, frame, CallEffectPolicy::PreserveX87, true)
    }

    fn finish_guest_far_callback_return(
        &mut self, cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory,
        frame: &mut Win16FarCallbackFrame, policy: CallEffectPolicy, parent_return: bool,
    ) -> Result<u32, RuntimeError> {
        if frame.terminal_aborted {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "terminally aborted Win16 callback cannot take a normal guest-return path"));
        }
        if let Some(value) = frame.returned_value { return Ok(value); }
        let (value, transfer) = self.validate_guest_far_callback_return(
            &cpu.regs, cpu.control_transfer(), frame,
        )?;
        if let Some(owner) = frame.cpu_owner {
            // The callback may legally load different volatile segments. The
            // checked CPU restore validates both its current and caller roots;
            // retain the actual return-state roots after proving RETF, rather
            // than assuming they still match the predicted entry registers.
            self.retain_legacy_cpu_frame_roots(owner, &cpu.regs, dos, memory)?;
            let target = LegacyRegisterTransfer {
                registers: frame.saved.clone(),
                stack_pointer: LegacyStackPointerTarget::RegisterValue,
            };
            if parent_return {
                self.return_legacy_cpu_call_frame(owner, cpu, memory, policy,
                    CallResumeBoundary::GuestCallReturn { transfer }, target)?;
            } else {
                self.restore_legacy_cpu_call_frame(owner, cpu, memory, policy,
                    CallResumeBoundary::GuestCallReturn { transfer }, target)?;
            }
        } else {
            cpu.regs = frame.saved.clone();
        }
        frame.cpu_restored = true;
        frame.returned_value = Some(value);
        Ok(value)
    }

    pub(super) fn release_guest_far_callback_owner(
        &mut self,
        frame: &mut Win16FarCallbackFrame,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if let Some(owner) = frame.cpu_owner {
            self.release_legacy_cpu_frame(owner, dos, memory)?;
            frame.cpu_owner = None;
        }
        Ok(())
    }

    /// Abort an entered FAR callback only after the owning Win16 execution
    /// loop has ended. An unfinished CPU frame restores the complete captured
    /// architecture state and retires its roots without claiming a guest RETF.
    /// An already-returned, released owner only seals terminal payload cleanup.
    pub(in crate::win16_runtime) fn abort_guest_far_callback_after_task_execution_ended(
        &mut self,
        ended: &super::execute::Win16TaskExecutionEnded,
        callback_kind: super::CallbackKind,
        callback_id: super::CallbackFrameId,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        frame: &mut Win16FarCallbackFrame,
    ) -> Result<(), RuntimeError> {
        if self.require_callback_top(callback_kind)? != callback_id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal FAR callback abort does not own the exact shared callback top"));
        }
        if frame.terminal_aborted {
            return if frame.cpu_owner.is_none() {
                Ok(())
            } else {
                Err(RuntimeError::new(Kind::InternalInvariant,
                    "terminally aborted FAR callback retained its CPU owner identity"))
            };
        }
        // A checked guest return can release its CPU owner before family
        // payload cleanup fails. Its cached result remains needed for a normal
        // finish retry, but terminal cleanup must not restore that CPU twice.
        if frame.cpu_restored && frame.returned_value.is_some() && frame.cpu_owner.is_none() {
            frame.terminal_aborted = true;
            return Ok(());
        }
        let owner = frame.cpu_owner.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "entered Win16 FAR callback has no exact legacy CPU owner to abort",
        ))?;
        self.abort_legacy_cpu_frame_after_task_execution_ended(
            ended, owner, cpu, dos, memory,
        )?;
        frame.cpu_owner = None;
        frame.cpu_restored = true;
        frame.terminal_aborted = true;
        Ok(())
    }

    fn validate_guest_far_callback_return(
        &self,
        registers: &Registers,
        transfer: Option<ControlTransfer>,
        frame: &Win16FarCallbackFrame,
    ) -> Result<(u32, ControlTransfer), RuntimeError> {
        let expected_sp = frame.saved.sp();
        let transfer = transfer.filter(|transfer| transfer.is_far_return()).ok_or_else(||
            RuntimeError::new(Kind::GuestFault,
                "Win16 FAR callback lacks a completed far-return event"))?;
        if registers.cs != self.callback_gate_selector.0 || registers.ip() != 0
            || registers.ss != frame.saved.ss || registers.sp() != expected_sp
        {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 FAR callback lacks its exact return gate and stack proof"));
        }
        let value = match frame.return_kind {
            Win16FarCallbackReturn::Void => 0,
            Win16FarCallbackReturn::Word => u32::from(registers.ax()),
            Win16FarCallbackReturn::Dword => {
                u32::from(registers.ax()) | (u32::from(registers.dx()) << 16)
            }
        };
        Ok((value, transfer))
    }
}

impl Win16FarCallbackArgument {
    fn stack_size(self) -> u16 {
        match self {
            Self::Word(_) => 2,
            Self::Dword(_) | Self::GuestPointer { .. } | Self::HugeGuestPointer { .. } => 4,
        }
    }
}

#[cfg(test)]
#[path = "win16_far_callback_tests.rs"]
mod tests;
