//! Scheduling and checked callback completion for queued ToolHelp events.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;

use super::{Win16ToolhelpNotifyEvent, Win16State};
use super::super::CallbackKind;
use super::Win16ToolhelpNotifyProgress;
use super::Win16ToolhelpModuleEntryScope;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    /// Enter one real queued notification only at an ordinary instruction
    /// boundary where no other callback or service gate owns the live CPU.
    pub(in crate::win16_runtime) fn dispatch_pending_toolhelp_notify(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        self.dispatch_pending_toolhelp_notify_internal(cpu, dos, memory, false, None)
    }

    pub(in crate::win16_runtime) fn dispatch_pending_toolhelp_notify_for_termination(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        self.dispatch_pending_toolhelp_notify_internal(cpu, dos, memory, true, None)
    }

    pub(in crate::win16_runtime) fn dispatch_pending_toolhelp_notify_for_module_entry(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some(scope) = self.toolhelp_notify_module_entry_scope_at(
            cpu.regs.cs, cpu.regs.ip(),
        )? else {
            return Ok(false);
        };
        if !self.toolhelp_notify.has_module_entry_event(scope)? {
            return Ok(false);
        }
        self.dispatch_pending_toolhelp_notify_internal(cpu, dos, memory, true, Some(scope))
    }

    fn dispatch_pending_toolhelp_notify_internal(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        allow_nested: bool,
        module_entry_scope: Option<Win16ToolhelpModuleEntryScope>,
    ) -> Result<bool, RuntimeError> {
        if (!allow_nested && !self.callback_kinds.is_empty())
            || cpu.interrupt_shadow_active()
            || self.is_service_gate(cpu.regs.cs)
            || self.is_native_procedure_gate(cpu.regs.cs)
            || self.is_callback_gate(cpu.regs.cs)
        {
            return Ok(false);
        }
        // At an exact LibMain boundary, consuming a now-unregistered or stale
        // scoped event is also progress: no guest callback is owed for it,
        // so LibMain may proceed once the exact scope is empty. A requeued
        // event still returns false from its blocking branch below.
        let mut module_entry_progress = false;
        loop {
            let event = match module_entry_scope {
                Some(scope) => self.toolhelp_notify.pop_module_entry_event(scope),
                None => self.toolhelp_notify.pop_pending(),
            };
            let Some(event) = event else {
                if let Some(scope) = module_entry_scope {
                    self.toolhelp_notify.remove_empty_module_entry_queue(scope);
                }
                return Ok(module_entry_progress);
            };
            let current_task = match self.current_task_handle() {
                Ok(task) => task,
                Err(error) => {
                    self.requeue_toolhelp_notify_event(event, module_entry_scope);
                    return Err(error);
                }
            };
            if event.task != current_task {
                self.requeue_toolhelp_notify_event(event, module_entry_scope);
                return Ok(false);
            }
            if event.termination_id.is_some()
                && self.toolhelp_task_exit.has_active_notification_callback()
            {
                self.requeue_toolhelp_notify_event(event, module_entry_scope);
                return Ok(false);
            }
            if !self.toolhelp_notify_event_owner_is_live(&event) {
                self.discard_toolhelp_notify_event(event)?;
                if let Some(scope) = module_entry_scope {
                    module_entry_progress = true;
                    self.toolhelp_notify.remove_empty_module_entry_queue(scope);
                }
                continue;
            }
            // Capture the exact Module continuation while it is still the
            // central callback top. The callback we publish below becomes its
            // immediate child, so the same pre-publication probe cannot be
            // repeated after pushing ToolhelpNotify.
            let module_entry_parent = if let Some(scope) = module_entry_scope {
                match self.capture_toolhelp_module_entry_parent(scope, &event, cpu) {
                    Ok(parent) => Some(parent),
                    Err(error) => {
                        self.requeue_toolhelp_notify_event(event, module_entry_scope);
                        return Err(error);
                    }
                }
            } else {
                None
            };
            let live_count = event.registrations.iter().filter(|registration|
                self.toolhelp_notify.contains(**registration)).count();
            let mut registrations = Vec::new();
            if let Err(error) = registrations.try_reserve_exact(live_count) {
                self.requeue_toolhelp_notify_event(event, module_entry_scope);
                return Err(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "snapshot live Win16 ToolHelp notification recipients",
                    error,
                ));
            }
            registrations.extend(event.registrations.iter().copied().filter(|registration|
                self.toolhelp_notify.contains(*registration)));
            if registrations.is_empty() {
                self.discard_toolhelp_notify_event(event)?;
                if let Some(scope) = module_entry_scope {
                    module_entry_progress = true;
                    self.toolhelp_notify.remove_empty_module_entry_queue(scope);
                }
                continue;
            }

            let callback_id = match self.reserve_callback_frame_id() {
                Ok(callback_id) => callback_id,
                Err(error) => {
                    self.requeue_toolhelp_notify_event(event, module_entry_scope);
                    return Err(error);
                }
            };
            if let Err(error) = self.toolhelp_notify_frames.try_reserve(1) {
                self.requeue_toolhelp_notify_event(event, module_entry_scope);
                return Err(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain Win16 ToolHelp notification continuation",
                    error,
                ));
            }
            if let Err(error) = self.push_callback_kind(CallbackKind::ToolhelpNotify, callback_id) {
                self.requeue_toolhelp_notify_event(event, module_entry_scope);
                return Err(error);
            }
            let task_exit_id = event.termination_id.or_else(|| self.toolhelp_task_exit.pending_id());
            let entered_exit_callback = if let Some(id) = task_exit_id {
                if event.termination_id.is_some() {
                    self.toolhelp_task_exit.notification_callback_entered(
                        id, event.notification, callback_id,
                    )
                } else {
                    self.toolhelp_task_exit.drain_callback_entered(id, callback_id)
                }
            } else {
                Ok(())
            };
            if let Err(error) = entered_exit_callback {
                self.requeue_toolhelp_notify_event(event, module_entry_scope);
                self.retire_callback_binding(CallbackKind::ToolhelpNotify, callback_id)?;
                return Err(error);
            }
            match self.begin_toolhelp_notify_event(
                callback_id,
                &event,
                registrations,
                module_entry_parent,
                cpu,
                dos,
                memory,
                ) {
                Ok(Some(frame)) => {
                    self.toolhelp_notify_frames.push(frame);
                    if let Some(scope) = module_entry_scope {
                        self.toolhelp_notify.remove_empty_module_entry_queue(scope);
                    }
                    // Retirement queue roots transfer to the retained callback
                    // frame only after guest entry was constructed successfully.
                    if let Some(module) = event.module_root {
                        if let Err(error) = self.release_toolhelp_notify_module_root(module) {
                            return Err(error);
                        }
                    }
                    return Ok(true);
                }
                Ok(None) => {
                    if let Some(id) = task_exit_id {
                        if let Err(error) = self.toolhelp_task_exit.event_callback_aborted(
                            id, callback_id, event.termination_id.is_some(),
                        ) {
                            self.requeue_toolhelp_notify_event(event, module_entry_scope);
                            if let Err(cleanup) = self.retire_callback_binding(
                                CallbackKind::ToolhelpNotify, callback_id,
                            ) {
                                return Err(error.with_cleanup(
                                    "ToolHelp empty callback entry retained its primary failure and callback binding retirement failure",
                                    cleanup,
                                ));
                            }
                            return Err(error);
                        }
                    }
                    if let Err(error) = self.retire_callback_binding(
                        CallbackKind::ToolhelpNotify, callback_id,
                    ) {
                        self.requeue_toolhelp_notify_event(event, module_entry_scope);
                        return Err(error);
                    }
                    self.discard_toolhelp_notify_event(event)?;
                    if let Some(scope) = module_entry_scope {
                        module_entry_progress = true;
                        self.toolhelp_notify.remove_empty_module_entry_queue(scope);
                    }
                }
                Err(primary) => {
                    let mut failure = primary;
                    if let Some(id) = task_exit_id {
                        if let Err(cleanup) = self.toolhelp_task_exit.event_callback_aborted(
                            id, callback_id, event.termination_id.is_some(),
                        ) {
                            failure = failure.with_cleanup(
                                "ToolHelp callback entry retained its primary failure and task-exit drain rollback failure",
                                cleanup,
                            );
                        }
                    }
                    if let Err(cleanup) = self.retire_callback_binding(
                        CallbackKind::ToolhelpNotify, callback_id,
                    ) {
                        failure = failure.with_cleanup(
                            "ToolHelp callback entry retained its primary failure and callback binding retirement failure",
                            cleanup,
                        );
                    }
                    self.requeue_toolhelp_notify_event(event, module_entry_scope);
                    return Err(failure);
                }
            }
        }
    }

    fn requeue_toolhelp_notify_event(
        &mut self,
        event: Win16ToolhelpNotifyEvent,
        module_entry_scope: Option<Win16ToolhelpModuleEntryScope>,
    ) {
        if let Some(scope) = module_entry_scope {
            self.toolhelp_notify.push_module_entry_front(scope, event);
        } else {
            self.toolhelp_notify.push_pending_front(event);
        }
    }

    pub(in crate::win16_runtime) fn finish_toolhelp_notify_callback_frame(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(super::super::CallbackKind::ToolhelpNotify)?;
        let mut frame = self.toolhelp_notify_frames.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp notification callback has no retained event frame",
        ))?;
        if frame.callback_id != callback_id {
            self.toolhelp_notify_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp notification event does not own the exact shared callback top",
            ));
        }
        if let Some(parent) = frame.module_entry_parent
            && let Err(error) = self.validate_published_toolhelp_module_entry_parent(
                callback_id, parent, frame.task,
            )
        {
            self.toolhelp_notify_frames.push(frame);
            return Err(error);
        }
        let mut still_registered = Vec::new();
        let active_count = frame.registrations.iter().filter(|registration|
            self.toolhelp_notify.contains(**registration)).count();
        if let Err(error) = still_registered.try_reserve_exact(active_count) {
            self.toolhelp_notify_frames.push(frame);
            return Err(RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot live ToolHelp notification callbacks",
                error,
            ));
        }
        still_registered.extend(frame.registrations.iter().copied().filter(|registration|
            self.toolhelp_notify.contains(*registration)));
        let progress = match self.finish_toolhelp_notify_event_callback(
            &mut frame,
            cpu,
            dos,
            memory,
            &still_registered,
        ) {
            Ok(progress) => progress,
            Err(error) => {
                self.toolhelp_notify_frames.push(frame);
                return Err(error);
            }
        };
        let handled_rip_cancellation = if frame.notification == super::NFY_RIP
            && frame.termination_id.is_some()
            && matches!(progress, Win16ToolhelpNotifyProgress::Complete { handled: true })
        {
            let id = match frame.termination_id {
                Some(id) => id,
                None => {
                    self.toolhelp_notify_frames.push(frame);
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "handled ToolHelp RIP lost its exact termination identity"));
                }
            };
            let queued = match self.toolhelp_notify.validate_rip_cancellation_events(id) {
                Ok(queued) => queued,
                Err(error) => {
                    self.toolhelp_notify_frames.push(frame);
                    return Err(error);
                }
            };
            if let Err(error) = self.toolhelp_task_exit.validate_handled_rip_cancellation(
                id, callback_id, queued,
            ) {
                self.toolhelp_notify_frames.push(frame);
                return Err(error);
            }
            Some((id, queued))
        } else {
            if matches!(progress, Win16ToolhelpNotifyProgress::Complete { .. })
                && let Some(id) = frame.termination_id
            {
                if let Err(error) = self.toolhelp_task_exit
                    .validate_notification_completion(id, callback_id)
                {
                    self.toolhelp_notify_frames.push(frame);
                    return Err(error);
                }
            }
            None
        };
        match progress {
            Win16ToolhelpNotifyProgress::CallbackEntered => {
                self.toolhelp_notify_frames.push(frame);
                Ok(())
            }
            Win16ToolhelpNotifyProgress::Complete { .. } => {
                if let Err(error) = self.release_callback_buffers(&mut frame.payload_buffers) {
                    self.toolhelp_notify_frames.push(frame);
                    return Err(error.with_context(
                        "retiring Win16 ToolHelp notification payload owners",
                    ));
                }
                if let Some(module) = frame.module_retirement.take() {
                    if let Err(error) = self.complete_toolhelp_module_retirement_callback(module) {
                        frame.module_retirement = Some(module);
                        self.toolhelp_notify_frames.push(frame);
                        return Err(error);
                    }
                    frame.module_root = None;
                } else if let Some(module) = frame.module_root.take()
                    && let Err(error) = self.release_toolhelp_notify_module_root(module)
                {
                    frame.module_root = Some(module);
                    self.toolhelp_notify_frames.push(frame);
                    return Err(error);
                }
                if let Err(error) = self.retire_callback_binding(
                    CallbackKind::ToolhelpNotify, callback_id,
                ) {
                    self.toolhelp_notify_frames.push(frame);
                    return Err(error);
                }
                if let Some((id, queued)) = handled_rip_cancellation {
                    if let Err(error) = self.toolhelp_notify.cancel_termination_events(id, queued) {
                        self.toolhelp_notify_frames.push(frame);
                        return Err(error);
                    }
                    if let Err(error) = self.toolhelp_task_exit
                        .cancel_handled_rip(id, callback_id, queued)
                    {
                        self.toolhelp_notify_frames.push(frame);
                        return Err(error);
                    }
                } else {
                    self.toolhelp_task_exit.notification_callback_completed(callback_id);
                }
                if handled_rip_cancellation.is_none()
                    && let Some(id) = frame.termination_id
                {
                    self.toolhelp_task_exit.notification_completed(id)?;
                }
                Ok(())
            }
        }
    }

    pub(in crate::win16_runtime) fn cancel_toolhelp_notify_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(super::super::CallbackKind::ToolhelpNotify)?;
        let mut frame = self.toolhelp_notify_frames.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "terminal ToolHelp callback lost its event frame",
        ))?;
        if frame.callback_id != callback_id {
            self.toolhelp_notify_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "terminal ToolHelp callback does not own the exact shared LIFO frame",
            ));
        }
        if let Some(active_call) = frame.active_call.as_mut() {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                super::super::CallbackKind::ToolhelpNotify,
                callback_id,
                cpu,
                dos,
                memory,
                active_call,
            ) {
                self.toolhelp_notify_frames.push(frame);
                return Err(error);
            }
            frame.active_call = None;
        }
        if let Some((mut returned_call, handled)) = frame.returned_call.take() {
            if let Err(error) = self.release_guest_far_callback_owner(
                &mut returned_call, dos, memory,
            ) {
                frame.returned_call = Some((returned_call, handled));
                self.toolhelp_notify_frames.push(frame);
                return Err(error);
            }
        }
        if let Err(error) = self.release_callback_buffers(&mut frame.payload_buffers) {
            self.toolhelp_notify_frames.push(frame);
            return Err(error.with_context(
                "retiring terminal Win16 ToolHelp notification payload owners",
            ));
        }
        if let Some(module) = frame.module_retirement.take() {
            if let Err(error) = self.complete_toolhelp_module_retirement_callback(module) {
                frame.module_retirement = Some(module);
                self.toolhelp_notify_frames.push(frame);
                return Err(error);
            }
            frame.module_root = None;
        } else if let Some(module) = frame.module_root.take()
            && let Err(error) = self.release_toolhelp_notify_module_root(module)
        {
            frame.module_root = Some(module);
            self.toolhelp_notify_frames.push(frame);
            return Err(error);
        }
        self.retire_callback_binding(super::super::CallbackKind::ToolhelpNotify, callback_id)?;
        self.toolhelp_task_exit.notification_callback_completed(callback_id);
        if let Some(id) = frame.termination_id {
            self.toolhelp_task_exit.notification_completed(id)?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn toolhelp_notify_active_code_references(&self) -> impl Iterator<Item = u32> + '_ {
        self.toolhelp_notify_frames.iter().flat_map(|frame| frame.code_references())
    }

}
