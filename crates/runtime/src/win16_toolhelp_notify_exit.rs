//! Checked task-exit notification sequencing for ToolHelp callbacks.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;

use super::toolhelp_notify::{Win16ToolhelpNotifyData, Win16ToolhelpNotifyEvent};
use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16ToolhelpRip {
    pub(super) instruction_pointer: u16,
    pub(super) code_segment: u16,
    pub(super) stack_segment: u16,
    pub(super) base_pointer: u16,
    pub(super) exit_code: u16,
}

#[derive(Default)]
pub(super) struct Win16ToolhelpTaskExitState {
    next_id: u64,
    pending: Option<PendingTaskExit>,
}

#[derive(Clone, Copy, Debug)]
struct PendingTaskExit {
    id: u64,
    task: u16,
    status: u16,
    rip: Option<Win16ToolhelpRip>,
    outstanding_notifications: usize,
    active_dispatch_callback: Option<super::CallbackFrameId>,
    // The callback currently holding the FIFO drain at task-exit time. This
    // includes ordinary events queued before RIP/EXITTASK, while
    // `active_dispatch_callback` remains the exact terminal event identity
    // used by RIP/EXITTASK completion validation.
    active_drain_callback: Option<super::CallbackFrameId>,
}

impl Win16ToolhelpTaskExitState {
    fn next_id(&self) -> Result<u64, RuntimeError> {
        let id = self.next_id.max(1);
        id.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 ToolHelp task-exit notification identity exhausted",
        ))?;
        Ok(id)
    }

    fn publish(
        &mut self,
        id: u64,
        task: u16,
        status: u16,
        rip: Option<Win16ToolhelpRip>,
        outstanding: usize,
        active_drain_callback: Option<super::CallbackFrameId>,
    ) {
        self.next_id = id + 1;
        self.pending = Some(PendingTaskExit {
            id,
            task,
            status,
            rip,
            outstanding_notifications: outstanding,
            active_dispatch_callback: None,
            active_drain_callback,
        });
    }

    pub(super) fn notification_completed(&mut self, id: u64) -> Result<(), RuntimeError> {
        let Some(pending) = self.pending.as_mut() else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp terminal notification completed without a task-exit request"));
        };
        if pending.id != id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp terminal notification belongs to a stale task-exit generation"));
        }
        pending.outstanding_notifications = pending.outstanding_notifications.checked_sub(1)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp terminal notification completion underflowed"))?;
        Ok(())
    }

    pub(super) fn validate_notification_completion(
        &self,
        id: u64,
        callback: super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.pending.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp terminal callback lost its task-exit continuation",
        ))?;
        if pending.id != id || pending.active_dispatch_callback != Some(callback)
            || pending.outstanding_notifications == 0
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp terminal callback completion does not match its exact active generation"));
        }
        Ok(())
    }

    pub(super) fn validate_handled_rip_cancellation(
        &self,
        id: u64,
        callback: super::CallbackFrameId,
        queued: usize,
    ) -> Result<(), RuntimeError> {
        self.validate_notification_completion(id, callback)?;
        let pending = self.pending.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "validated ToolHelp exit continuation disappeared during RIP preflight",
        ))?;
        let expected = queued.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp RIP cancellation event count overflowed",
        ))?;
        if pending.rip.is_none() || pending.outstanding_notifications != expected {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "handled ToolHelp RIP does not own the exact remaining terminal notification batch"));
        }
        Ok(())
    }

    pub(super) fn cancel_handled_rip(
        &mut self,
        id: u64,
        callback: super::CallbackFrameId,
        queued: usize,
    ) -> Result<(), RuntimeError> {
        let pending = self.pending.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "handled ToolHelp RIP lost its task-exit continuation",
        ))?;
        let expected = queued.checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp RIP cancellation event count overflowed",
        ))?;
        if pending.id != id || pending.rip.is_none()
            || pending.active_dispatch_callback != Some(callback)
            || pending.outstanding_notifications != expected
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "handled ToolHelp RIP cancellation changed after its exact preflight"));
        }
        self.pending = None;
        Ok(())
    }

    pub(super) fn notification_callback_entered(
        &mut self,
        id: u64,
        notification: u16,
        callback: super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.pending.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp callback entry lost its terminal continuation",
        ))?;
        let notification_matches_request = match notification {
            super::toolhelp_notify::NFY_RIP => pending.rip.is_some(),
            super::toolhelp_notify::NFY_EXITTASK => true,
            _ => false,
        };
        if pending.id != id || !notification_matches_request
            || pending.outstanding_notifications == 0
            || pending.active_dispatch_callback.is_some()
            || pending.active_drain_callback.is_some()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp terminal drain entered a second callback before the first returned"));
        }
        pending.active_dispatch_callback = Some(callback);
        pending.active_drain_callback = Some(callback);
        Ok(())
    }

    /// Keep the first callback entered while a task-exit drain is in flight
    /// as its FIFO barrier. Nested ordinary callbacks must not replace that
    /// outer callback identity.
    pub(super) fn drain_callback_entered(
        &mut self,
        id: u64,
        callback: super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.pending.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp FIFO callback entry lost its task-exit continuation",
        ))?;
        if pending.id != id
            || (pending.active_dispatch_callback.is_some()
                && pending.active_drain_callback.is_none())
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp FIFO callback entry does not match the active task-exit drain"));
        }
        if pending.active_drain_callback.is_none() {
            pending.active_drain_callback = Some(callback);
        }
        Ok(())
    }

    pub(super) fn notification_callback_aborted(
        &mut self,
        id: u64,
        callback: super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.pending.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "aborted ToolHelp terminal entry lost its task-exit continuation",
        ))?;
        if pending.id != id || pending.active_dispatch_callback != Some(callback) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "aborted ToolHelp terminal entry does not match the exact active callback"));
        }
        pending.active_dispatch_callback = None;
        if pending.active_drain_callback == Some(callback) {
            pending.active_drain_callback = None;
        }
        Ok(())
    }

    pub(super) fn drain_callback_aborted(
        &mut self,
        id: u64,
        callback: super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.pending.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "aborted ToolHelp FIFO entry lost its task-exit continuation",
        ))?;
        if pending.id != id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "aborted ToolHelp FIFO entry belongs to a stale task-exit generation"));
        }
        if pending.active_drain_callback == Some(callback) {
            pending.active_drain_callback = None;
        }
        Ok(())
    }

    pub(super) fn event_callback_aborted(
        &mut self,
        id: u64,
        callback: super::CallbackFrameId,
        terminal: bool,
    ) -> Result<(), RuntimeError> {
        if terminal {
            self.notification_callback_aborted(id, callback)
        } else {
            self.drain_callback_aborted(id, callback)
        }
    }

    pub(super) fn has_active_notification_callback(&self) -> bool {
        self.pending.is_some_and(|pending|
            pending.active_dispatch_callback.is_some() || pending.active_drain_callback.is_some())
    }

    pub(super) fn notification_callback_completed(
        &mut self,
        callback: super::CallbackFrameId,
    ) {
        if let Some(pending) = self.pending.as_mut()
            && pending.active_dispatch_callback == Some(callback)
        {
            pending.active_dispatch_callback = None;
        }
        if let Some(pending) = self.pending.as_mut()
            && pending.active_drain_callback == Some(callback)
        {
            pending.active_drain_callback = None;
        }
    }

    pub(super) fn pending_id(&self) -> Option<u64> {
        self.pending.map(|pending| pending.id)
    }

    fn pending(&self) -> Option<PendingTaskExit> {
        self.pending
    }

    fn clear(&mut self, id: u64) -> Result<(), RuntimeError> {
        if self.pending.is_none_or(|pending| pending.id != id
            || pending.outstanding_notifications != 0)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 task exit finalized before its exact ToolHelp callbacks completed"));
        }
        self.pending = None;
        Ok(())
    }
}

impl Win16State {
    pub(super) fn request_toolhelp_task_termination(
        &mut self,
        status: u16,
        rip: Option<Win16ToolhelpRip>,
    ) -> Result<(), RuntimeError> {
        let task = self.current_task_handle()?;
        if let Some(pending) = self.toolhelp_task_exit.pending() {
            if pending.task == task && pending.status == status && pending.rip == rip {
                return Ok(());
            }
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "a different Win16 task-exit request replaced the active terminal continuation"));
        }

        let id = self.toolhelp_task_exit.next_id()?;
        let event_count = usize::from(rip.is_some()) + 1;
        let mut events = Vec::new();
        events.try_reserve_exact(event_count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 ToolHelp terminal notifications",
            error,
        ))?;
        if let Some(rip) = rip {
            events.push(Win16ToolhelpNotifyEvent {
                task,
                notification: super::toolhelp_notify::NFY_RIP,
                data: Win16ToolhelpNotifyData::Rip {
                    instruction_pointer: rip.instruction_pointer,
                    code_segment: rip.code_segment,
                    stack_segment: rip.stack_segment,
                    base_pointer: rip.base_pointer,
                    exit_code: rip.exit_code,
                },
                registrations: Vec::new(),
                termination_id: Some(id),
                module_root: None,
            });
        }
        events.push(Win16ToolhelpNotifyEvent {
            task,
            notification: super::toolhelp_notify::NFY_EXITTASK,
            data: Win16ToolhelpNotifyData::Scalar(u32::from(status as u8)),
            registrations: Vec::new(),
            termination_id: Some(id),
            module_root: None,
        });
        let outstanding = self.toolhelp_notify.enqueue_batch(events)?;
        // An exit request can be raised from inside a ToolHelp callback that
        // was already running before the terminal batch was published. Keep
        // the outermost exact event as the FIFO barrier so terminal callbacks
        // cannot overtake that active event or its nested module-entry work.
        let active_drain_callback = self.toolhelp_notify_frames.iter()
            .find(|frame| frame.task == task)
            .map(|frame| frame.callback_id);
        self.toolhelp_task_exit.publish(
            id, task, status, rip, outstanding, active_drain_callback,
        );
        Ok(())
    }

    /// Drain terminal notifications on a CPU boundary. When the exact
    /// callbacks have returned, finalize the requested exit before another
    /// caller instruction can execute.
    pub(super) fn service_pending_toolhelp_task_exit(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(pending) = self.toolhelp_task_exit.pending() else { return Ok(None); };
        if self.current_task_handle()? != pending.task {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 terminal continuation changed its exact guest task owner"));
        }
        if pending.active_dispatch_callback.is_some()
            || pending.active_drain_callback.is_some()
            || self.toolhelp_notify_frames.iter().any(|frame|
                frame.termination_id == Some(pending.id))
        {
            return Ok(None);
        }
        if pending.outstanding_notifications != 0 {
            let dispatched = self.dispatch_pending_toolhelp_notify_for_termination(
                cpu, dos, memory,
            )?;
            if self.toolhelp_task_exit.pending()
                .is_some_and(|current| current.outstanding_notifications != 0)
            {
                if !dispatched {
                    return Err(RuntimeError::new(Kind::CompatibilityGap,
                        "Win16 terminal ToolHelp callbacks are pending at a CPU boundary where checked guest entry is unsafe"));
                }
                return Ok(None);
            }
        }
        let owner = self.tasks.current().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 task-exit continuation has no exact runtime owner",
        ))?;
        if !self.classic_dde_task_exit_quiesced(owner) {
            return Ok(None);
        }
        let status = self.finalize_task_termination(cpu, dos, memory, host, pending.status)?;
        self.toolhelp_task_exit.clear(pending.id)?;
        Ok(Some(status))
    }

    /// Keep the exact task-exit continuation on the outer CPU/DOS callback
    /// pump until classic DDE ownership has retired. A live guest callback is
    /// allowed to run to its checked return; otherwise the main loop must
    /// service host DDE cleanup instead of executing another application
    /// instruction.
    pub(super) fn toolhelp_task_exit_requires_classic_dde_pump(&self) -> bool {
        self.toolhelp_task_exit.pending_id().is_some() && self.callback_kinds.is_empty()
    }
}
