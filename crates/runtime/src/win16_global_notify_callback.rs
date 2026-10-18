//! Checked guest entry, API return and terminal ownership for GlobalNotify.
use super::*;
use x86_cpu::{CallEffectPolicy, CallResumeBoundary};

impl Win16State {
    pub(super) fn enter_global_notify(
        &mut self,
        procedure: SegmentedPointer,
        handle: u16,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        // KERNEL gnotify supplies the current stack selector in AX/DS/ES.
        // A MakeProcInstance thunk can project its own instance afterwards.
        let mut entry = cpu.regs.clone();
        entry.set_ax(entry.ss);
        entry.ds = entry.ss;
        entry.es = entry.ss;
        let call = self.enter_guest_far_callback_checked_with_registers(
            cpu,
            dos,
            memory,
            procedure.far_value(),
            &[Win16FarCallbackArgument::Word(handle)],
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
            entry,
        )?;
        self.global_notify
            .frames
            .last_mut()
            .ok_or_else(|| invariant("missing heap owner"))?
            .call = Some(call);
        Ok(())
    }

    pub(in crate::win16_runtime) fn finish_global_notify_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::GlobalNotify)?;
        let frame = self
            .global_notify
            .frames
            .last()
            .filter(|frame| frame.id == id && !frame.terminal)
            .ok_or_else(|| invariant("GlobalNotify return has no matching heap owner"))?;
        if frame.owner != self.current_task_owner()? {
            return Err(invariant("GlobalNotify crossed its task owner"));
        }
        let mut call = frame
            .call
            .clone()
            .ok_or_else(|| invariant("GlobalNotify has no checked FAR call"))?;
        let result = self
            .finish_guest_far_callback_checked(cpu, dos, memory, &mut call)
            .and_then(|value| {
                self.release_guest_far_callback_owner(&mut call, dos, memory)
                    .map(|()| value)
            });
        self.global_notify
            .frames
            .last_mut()
            .expect("heap owner")
            .call = Some(call);
        let allowed = result? != 0;
        let frame = self.global_notify.frames.last_mut().expect("heap owner");
        frame.call = None;
        let (handle, identity) = frame
            .candidate
            .take()
            .ok_or_else(|| invariant("GlobalNotify lost its allocation identity"))?;
        let operation = frame.operation;
        if matches!(operation, GlobalHeapOperation::Reallocate { size: 0, .. }) {
            let value = if allowed && self.global_handles.get(&handle).copied() == Some(identity) {
                self.try_global_heap_operation(operation, memory, host)?
            } else {
                0
            };
            self.global_notify
                .frames
                .last_mut()
                .expect("heap owner")
                .completed = Some(value);
        } else if allowed && self.global_handles.get(&handle).copied() == Some(identity) {
            // Guest reentry can free, resize, pin or replace this block.
            // The allocator rechecks its full generation and current locks.
            self.commit_global_discard(identity)?;
        }
        self.drive_global_heap_operation(cpu, dos, memory, host)
    }

    pub(super) fn return_global_heap_operation(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::GlobalNotify)?;
        let frame = self
            .global_notify
            .frames
            .last()
            .filter(|frame| frame.id == id && !frame.terminal)
            .ok_or_else(|| invariant("heap return has no matching owner"))?;
        let value = frame
            .completed
            .ok_or_else(|| invariant("heap return precedes completion"))?;
        if let Some(parked) = frame.parked {
            let caller = frame
                .caller
                .ok_or_else(|| invariant("heap parked context has no caller"))?;
            self.restore_legacy_cpu_parked_frame_for_call(
                parked,
                caller,
                cpu,
                CallEffectPolicy::PreserveX87,
                memory,
            )?;
            self.release_legacy_cpu_frame(parked, dos, memory)?;
            self.global_notify
                .frames
                .last_mut()
                .expect("heap owner")
                .parked = None;
        }
        let frame = self.global_notify.frames.last().expect("heap owner");
        if !frame.returned {
            let caller = frame
                .caller
                .ok_or_else(|| invariant("heap return has no caller"))?;
            let kind = if matches!(frame.operation, GlobalHeapOperation::Compact { .. }) {
                Win16ReturnKind::Dword
            } else {
                Win16ReturnKind::Word
            };
            let mut target = super::super::call_return::checked_return_target(
                &frame.saved,
                frame.return_to,
                value,
                kind,
            );
            match frame.operation {
                GlobalHeapOperation::Allocate { .. } => {
                    target.registers.eax = value;
                    target.registers.ebx = value;
                    target.registers.ecx = value;
                    target.registers.es = 0;
                }
                GlobalHeapOperation::Reallocate { .. } => {
                    super::super::dispatch_kernel::finish_global_heap_call(&mut target.registers)
                }
                GlobalHeapOperation::Compact { .. } => {}
            }
            self.retain_legacy_cpu_frame_roots(caller, &target.registers, dos, memory)?;
            self.return_legacy_cpu_call_frame(
                caller,
                cpu,
                memory,
                CallEffectPolicy::PreserveX87,
                CallResumeBoundary::NoGuestExecution,
                target,
            )?;
            let frame = self.global_notify.frames.last_mut().expect("heap owner");
            frame.returned = true;
            let (cs, ip, _) = frame.return_to;
            let ss = frame.saved.ss;
            self.retire_far_return(cs, u32::from(ip), ss);
        }
        if let Some(caller) = self.global_notify.frames.last().expect("heap owner").caller {
            self.release_legacy_cpu_frame(caller, dos, memory)?;
            self.global_notify
                .frames
                .last_mut()
                .expect("heap owner")
                .caller = None;
        }
        self.retire_callback_binding(CallbackKind::GlobalNotify, id)?;
        self.global_notify.frames.pop().expect("retired heap owner");
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_global_notify_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::GlobalNotify)?;
        let frame = self
            .global_notify
            .frames
            .last_mut()
            .filter(|frame| frame.id == id)
            .ok_or_else(|| invariant("terminal heap cancellation has no matching owner"))?;
        frame.terminal = true;
        if let Some(mut call) = frame.call.clone() {
            let result = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::GlobalNotify,
                id,
                cpu,
                dos,
                memory,
                &mut call,
            );
            self.global_notify
                .frames
                .last_mut()
                .expect("terminal heap owner")
                .call = Some(call);
            result?;
            self.global_notify
                .frames
                .last_mut()
                .expect("terminal heap owner")
                .call = None;
        }
        for parked in [true, false] {
            let frame = self
                .global_notify
                .frames
                .last()
                .expect("terminal heap owner");
            if let Some(owner) = if parked { frame.parked } else { frame.caller } {
                self.abort_legacy_cpu_frame_after_task_execution_ended(
                    ended, owner, cpu, dos, memory,
                )?;
                let frame = self
                    .global_notify
                    .frames
                    .last_mut()
                    .expect("terminal heap owner");
                if parked {
                    frame.parked = None;
                } else {
                    frame.caller = None;
                }
            }
        }
        self.retire_callback_binding(CallbackKind::GlobalNotify, id)?;
        self.global_notify
            .frames
            .pop()
            .expect("terminal heap owner");
        Ok(())
    }
}
