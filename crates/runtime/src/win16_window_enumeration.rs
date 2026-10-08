//! USER window enumeration, SDK 3.1 Reference Vol. 2 pp. 263, 282–284.
//! Native snapshots retain ordering; guest FAR callbacks execute on the CPU.

use dos_kernel::DosKernel;
use guest_core::{memory::Memory, Registers};
use win16_abi::{Access, Win16ReturnKind, Win16WindowEnumerationRequest as Request};
use x86_cpu::Cpu;
use super::{CallbackKind, Win16State, far_callback::{Win16FarCallbackArgument as Argument,
    Win16FarCallbackConvention, Win16FarCallbackFrame, Win16FarCallbackReturn}};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostWindow,
    Win16WindowEnumerationQuery as Query, Win16WindowEnumerationReply as Reply,
    Win16WindowEnumerationScope as Scope, Win16WindowTarget};

pub(super) struct WindowEnumerationFrame {
    callback_id: super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    callback: u32,
    data: u32,
    windows: Vec<Win16HostWindow>,
    next_index: usize,
    active_call: Option<Win16FarCallbackFrame>,
}

impl Win16State {
    pub(super) fn begin_window_enumeration(
        &mut self, cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory,
        host: &mut impl RuntimeHost, request: Request, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let (scope, callback, data) = match request {
            Request::Desktop { callback, data } => (Scope::Desktop, callback, data),
            Request::Children { parent, callback, data } => {
                let target = if parent == 0 { Win16WindowTarget::Null } else {
                    self.window_handles.get(&parent).copied().map(Win16WindowTarget::Mapped)
                        .unwrap_or(Win16WindowTarget::Invalid)
                };
                (Scope::Children(target), callback, data)
            }
            Request::Task { task, callback, data } => {
                if self.kernel_is_task(task) == 0 {
                    return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                }
                if task != self.current_task_handle()? {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        "EnumTaskWindows task has no separately bound USER queue"));
                    return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                }
                let Some(queue) = self.ensure_user_queue(host)? else {
                    return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Word);
                };
                (Scope::TaskQueue(queue), callback, data)
            }
        };
        if callback == 0 {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        }
        let pointer = self.selectors.pointer_from_far(callback).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Execute, 1, memory).map_err(crate::runtime_error)?;
        let Reply::Snapshot { success, windows } = host.win16_window_enumeration(Query::Snapshot(scope))?
            else { return Err(invariant("window enumeration snapshot reply has the wrong shape")); };
        if !success || windows.is_empty() {
            return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                return_to.2, u32::from(success), Win16ReturnKind::Word);
        }
        self.window_enumerations.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "retain Win16 window enumeration continuation", error))?;
        let callback_id = self.reserve_callback_frame_id()?;
        // Install the fallible shared binding first; the reserved family push
        // cannot leave a half-installed continuation on allocation failure.
        self.push_callback_kind(CallbackKind::WindowEnumeration, callback_id)?;
        self.window_enumerations.push(WindowEnumerationFrame {
            callback_id, saved: cpu.regs.clone(), return_to, callback, data,
            windows, next_index: 0, active_call: None,
        });
        self.schedule_window_enumeration(cpu, dos, memory, host)?;
        Ok(None)
    }

    fn schedule_window_enumeration(&mut self, cpu: &mut Cpu, dos: &mut DosKernel,
        memory: &mut Memory, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        loop {
            let frame = self.window_enumerations.last_mut().ok_or_else(|| invariant(
                "window enumeration continuation disappeared"))?;
            let Some(window) = frame.windows.get(frame.next_index).copied() else {
                return self.complete_window_enumeration(cpu, 1);
            };
            frame.next_index += 1;
            let (callback, data) = (frame.callback, frame.data);
            let Reply::IsCurrent(current) = host.win16_window_enumeration(Query::IsCurrent(window))?
                else { return Err(invariant("window enumeration liveness reply has the wrong shape")); };
            if !current { continue; }
            let guest = self.map_window_handle(window, false)?;
            let active = self.enter_guest_far_callback_checked(cpu, dos, memory, callback,
                &[Argument::Word(guest), Argument::Dword(data)],
                Win16FarCallbackConvention::Pascal, Win16FarCallbackReturn::Word)?;
            self.window_enumerations.last_mut().ok_or_else(|| invariant(
                "window enumeration frame disappeared after entry"))?.active_call = Some(active);
            return Ok(());
        }
    }

    pub(super) fn finish_window_enumeration(&mut self, cpu: &mut Cpu, dos: &mut DosKernel,
        memory: &mut Memory, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        self.check_window_enumeration_top()?;
        let mut active = self.window_enumerations.last_mut().and_then(|frame| frame.active_call.take())
            .ok_or_else(|| invariant("window enumeration return has no entered callback"))?;
        let result = self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active)
            .and_then(|value| self.release_guest_far_callback_owner(&mut active, dos, memory)
                .map(|()| value));
        match result {
            Ok(0) => self.complete_window_enumeration(cpu, 0),
            Ok(_) => self.schedule_window_enumeration(cpu, dos, memory, host),
            Err(error) => {
                // The checked frame caches its AX result before owner release,
                // so a cleanup retry cannot replay the guest callback.
                self.window_enumerations.last_mut().expect("top checked").active_call = Some(active);
                Err(error)
            }
        }
    }

    fn check_window_enumeration_top(&self) -> Result<super::CallbackFrameId, RuntimeError> {
        let id = self.require_callback_top(CallbackKind::WindowEnumeration)?;
        if self.window_enumerations.last().is_none_or(|frame| frame.callback_id != id) {
            return Err(invariant("window enumeration identity differs from shared callback top"));
        }
        Ok(id)
    }

    fn complete_window_enumeration(&mut self, cpu: &mut Cpu, result: u32) -> Result<(), RuntimeError> {
        let id = self.check_window_enumeration_top()?;
        let frame = self.window_enumerations.last().expect("top checked");
        let return_to = frame.return_to;
        cpu.regs = frame.saved.clone();
        self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
            return_to.2, result, Win16ReturnKind::Word)?;
        self.retire_callback_binding(CallbackKind::WindowEnumeration, id)?;
        self.window_enumerations.pop();
        Ok(())
    }

    pub(super) fn cancel_window_enumeration(&mut self, ended: &super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory) -> Result<(), RuntimeError> {
        let id = self.check_window_enumeration_top()?;
        if let Some(mut active) = self.window_enumerations.last_mut().expect("top checked").active_call.take() {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended, CallbackKind::WindowEnumeration, id, cpu, dos, memory, &mut active) {
                self.window_enumerations.last_mut().expect("top checked").active_call = Some(active);
                return Err(error);
            }
        }
        self.retire_callback_binding(CallbackKind::WindowEnumeration, id)?;
        self.window_enumerations.pop();
        Ok(())
    }

    pub(super) fn window_enumeration_code_references(&self) -> Vec<u32> {
        let mut references = Vec::new();
        for frame in &self.window_enumerations {
            references.extend([frame.callback, (u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()),
                (u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1)]);
            if let Some(active) = &frame.active_call { references.extend(active.code_references()); }
        }
        references
    }
}
fn invariant(message: &str) -> RuntimeError { RuntimeError::new(Kind::InternalInvariant, message) }
