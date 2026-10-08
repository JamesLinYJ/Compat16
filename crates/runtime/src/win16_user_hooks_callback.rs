//! Checked guest-call continuations for task-local USER hooks.

use dos_kernel::DosKernel;
use guest_core::{Registers, memory::Memory};
use win16_abi::Win16ReturnKind;
use x86_cpu::Cpu;

use super::{HookNodeId, Win16UserHooks};
use crate::{DiagnosticKind as Kind, RuntimeError};

pub(super) type HookArgument = super::super::far_callback::Win16FarCallbackArgument;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HookCallbackReturn {
    CallMsgFilter,
    DefHookProc,
    CallNextHookEx,
}

pub(super) struct HookCallbackFrame {
    callback_id: super::super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    hook_node: HookNodeId,
    continuation: HookCallbackReturn,
    active_call: Option<super::super::far_callback::Win16FarCallbackFrame>,
}

impl HookCallbackFrame {
    pub(super) fn new(
        callback_id: super::super::CallbackFrameId,
        saved: Registers,
        return_to: (u16, u16, u32),
        hook_node: HookNodeId,
        continuation: HookCallbackReturn,
    ) -> Self {
        Self {
            callback_id,
            saved,
            return_to,
            hook_node,
            continuation,
            active_call: None,
        }
    }
}

#[derive(Default)]
pub(super) struct HookCallbackStack {
    frames: Vec<HookCallbackFrame>,
}

impl HookCallbackStack {
    pub(super) fn reserve_frame(&mut self) -> Result<(), RuntimeError> {
        self.frames.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain Win16 USER hook callback continuation",
                error,
            )
        })
    }

    pub(super) fn push(&mut self, frame: HookCallbackFrame) {
        self.frames.push(frame);
    }

    pub(super) fn set_active_call(
        &mut self,
        call: super::super::far_callback::Win16FarCallbackFrame,
    ) -> Result<(), RuntimeError> {
        let frame = self.frames.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 hook callback frame disappeared after guest entry",
            )
        })?;
        if frame.active_call.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 hook callback frame already owns a guest FAR call",
            ));
        }
        frame.active_call = Some(call);
        Ok(())
    }

    pub(super) fn take_active_call(
        &mut self,
    ) -> Option<super::super::far_callback::Win16FarCallbackFrame> {
        self.frames.last_mut()?.active_call.take()
    }

    pub(super) fn restore_active_call(
        &mut self,
        call: super::super::far_callback::Win16FarCallbackFrame,
    ) -> Result<(), RuntimeError> {
        let frame = self.frames.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 hook callback frame disappeared while retaining a failed return",
            )
        })?;
        if frame.active_call.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 hook callback return would replace a retained FAR-call frame",
            ));
        }
        frame.active_call = Some(call);
        Ok(())
    }

    pub(super) fn active_hook_node(&self) -> Option<HookNodeId> {
        let frame = self.frames.last()?;
        frame.active_call.as_ref().map(|_| frame.hook_node)
    }

    pub(super) fn active_callback_id(&self) -> Option<super::super::CallbackFrameId> {
        let frame = self.frames.last()?;
        frame.active_call.as_ref().map(|_| frame.callback_id)
    }

    pub(super) fn references_node(&self, id: HookNodeId) -> bool {
        self.frames.iter().any(|frame| frame.hook_node == id)
    }

    pub(super) fn pop_expected(
        &mut self,
        id: super::super::CallbackFrameId,
    ) -> Result<HookCallbackFrame, RuntimeError> {
        if self
            .frames
            .last()
            .is_none_or(|frame| frame.callback_id != id)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 hook callback identity differs from its family frame",
            ));
        }
        self.frames.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 hook callback frame disappeared before retirement",
            )
        })
    }

    pub(super) fn code_references(&self, hooks: &Win16UserHooks) -> Vec<u32> {
        let mut references = Vec::new();
        for frame in &self.frames {
            if let Some(entry) = hooks.entry(frame.hook_node) {
                references.push(entry.procedure);
            }
            references.push((u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()));
            references.push((u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1));
            if let Some(active) = &frame.active_call {
                references.extend(active.code_references());
            }
        }
        references
    }
}

impl super::super::Win16State {
    /// Enter the next hook from a guest DefHookProc call. All message payload
    /// bits remain guest values; no pointer is interpreted by the host.
    pub(super) fn begin_hook_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        entry: super::HookRegistration,
        arguments: &[HookArgument],
        return_to: (u16, u16, u32),
        continuation: HookCallbackReturn,
    ) -> Result<Option<u8>, RuntimeError> {
        self.user_hooks.callbacks.reserve_frame()?;
        let callback_id = self.reserve_callback_frame_id()?;
        self.push_callback_kind(super::super::CallbackKind::UserHook, callback_id)?;
        self.user_hooks.callbacks.push(HookCallbackFrame::new(
            callback_id,
            cpu.regs.clone(),
            return_to,
            entry.id,
            continuation,
        ));
        let call = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            entry.procedure,
            arguments,
            super::super::far_callback::Win16FarCallbackConvention::Pascal,
            super::super::far_callback::Win16FarCallbackReturn::Dword,
        );
        match call {
            Ok(call) => {
                self.user_hooks.callbacks.set_active_call(call)?;
                Ok(None)
            }
            Err(primary) => {
                self.user_hooks.callbacks.pop_expected(callback_id)?;
                if let Err(cleanup) =
                    self.retire_callback_binding(super::super::CallbackKind::UserHook, callback_id)
                {
                    return Err(primary.with_cleanup(
                        "retire Win16 hook callback binding after checked entry failure",
                        cleanup,
                    ));
                }
                Err(primary)
            }
        }
    }

    pub(in crate::win16_runtime) fn finish_user_hook_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(super::super::CallbackKind::UserHook)?;
        let frame = self.user_hooks.callbacks.frames.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "top Win16 USER hook callback has no family frame",
            )
        })?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "top Win16 USER hook identity differs from its family frame",
            ));
        }
        let mut active = self
            .user_hooks
            .callbacks
            .take_active_call()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 callback gate has no active USER hook call",
                )
            })?;
        let value = match self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active) {
            Ok(value) => value,
            Err(error) => {
                self.user_hooks.callbacks.restore_active_call(active)?;
                return Err(error);
            }
        };
        if let Err(error) = self.release_guest_far_callback_owner(&mut active, dos, memory) {
            self.user_hooks.callbacks.restore_active_call(active)?;
            return Err(error);
        }
        self.user_hooks.callbacks.restore_active_call(active)?;
        let frame = self.user_hooks.callbacks.frames.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 USER hook callback frame disappeared before return projection",
            )
        })?;
        let saved = frame.saved.clone();
        let return_to = frame.return_to;
        let (return_value, return_kind) = match frame.continuation {
            HookCallbackReturn::CallMsgFilter => (u32::from(value != 0), Win16ReturnKind::Word),
            HookCallbackReturn::DefHookProc | HookCallbackReturn::CallNextHookEx => {
                (value, Win16ReturnKind::Dword)
            }
        };
        cpu.regs = saved;
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            return_value,
            return_kind,
        )?;
        let frame = self.user_hooks.callbacks.pop_expected(callback_id)?;
        if let Err(error) =
            self.retire_callback_binding(super::super::CallbackKind::UserHook, callback_id)
        {
            self.user_hooks.callbacks.push(frame);
            return Err(error);
        }
        self.prune_retired_user_hook_nodes();
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_user_hook_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(super::super::CallbackKind::UserHook)?;
        let frame = self.user_hooks.callbacks.frames.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "top USER hook callback has no family frame during teardown",
            )
        })?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "top USER hook callback identity differs during teardown",
            ));
        }
        if let Some(mut active) = self.user_hooks.callbacks.take_active_call() {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                super::super::CallbackKind::UserHook,
                callback_id,
                cpu,
                dos,
                memory,
                &mut active,
            ) {
                self.user_hooks.callbacks.restore_active_call(active)?;
                return Err(error);
            }
            self.user_hooks.callbacks.restore_active_call(active)?;
        }
        let frame = self.user_hooks.callbacks.pop_expected(callback_id)?;
        if let Err(error) =
            self.retire_callback_binding(super::super::CallbackKind::UserHook, callback_id)
        {
            self.user_hooks.callbacks.push(frame);
            return Err(error);
        }
        self.prune_retired_user_hook_nodes();
        Ok(())
    }
}
