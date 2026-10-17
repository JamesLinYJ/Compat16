//! Guest OPENFILENAME hook entry.
//!
//! The procedure address remains the guest FAR from `lpfnHook`. This module
//! builds a Pascal dialog-procedure frame and never stores a host window
//! procedure in guest memory. The decoded NE template, when one was requested,
//! stays on the callback frame as an owned layout.

use dos_kernel::DosKernel;
use guest_core::Registers;
use guest_core::memory::Memory;
use win16_abi::{Access, Win16ReturnKind, commdlg_abi::OpenFileName16};
use x86_cpu::Cpu;

use super::super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::super::{CallbackKind, Win16State};
use super::{OpenFileHookCall, report_common_dialog_gap};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

/// Windows 3.1 SDK: the common-dialog hook receives `WM_INITDIALOG` with
/// `lParam` pointing at the `OPENFILENAME` the caller passed.
const WM_INITDIALOG: u16 = 0x0110;

pub(in crate::win16_runtime) struct OpenFileHookFrame {
    callback_id: super::super::CallbackFrameId,
    dispatch_owner: Option<u64>,
    saved: Registers,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
    procedure: u32,
    structure_far: u32,
    template: Option<crate::Win16HostDialogTemplate>,
    active_call: Option<Win16FarCallbackFrame>,
}

impl Win16State {
    pub(super) fn begin_open_file_hook(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        _host: &mut impl RuntimeHost,
        call: OpenFileHookCall,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let callback_id = self.reserve_callback_frame_id()?;
        self.open_file_hooks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain Win16 OPENFILENAME hook frame",
                error,
            )
        })?;
        let dispatch_owner = self.active_dispatch_call_owner.take();
        self.open_file_hooks.push(OpenFileHookFrame {
            callback_id,
            dispatch_owner,
            saved: cpu.regs.clone(),
            return_to,
            return_kind: call.return_kind,
            procedure: call.procedure,
            structure_far: call.structure_far,
            template: call.template,
            active_call: None,
        });
        if let Err(error) = self.push_callback_kind(CallbackKind::OpenFileHook, callback_id) {
            return Err(self.abandon_open_file_hook(dos, memory, callback_id, false, error));
        }
        if let Err(error) = self.enter_open_file_hook(cpu, dos, memory) {
            return Err(self.abandon_open_file_hook(dos, memory, callback_id, true, error));
        }
        Ok(None)
    }

    pub(crate) fn finish_open_file_hook(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::OpenFileHook)?;
        if self
            .open_file_hooks
            .last()
            .is_none_or(|frame| frame.callback_id != callback_id)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 OPENFILENAME hook identity changed before guest return",
            ));
        }
        let mut active_call = self
            .open_file_hooks
            .last_mut()
            .and_then(|frame| frame.active_call.take())
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 callback gate has no active OPENFILENAME hook",
                )
            })?;
        if let Err(error) =
            self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active_call)
        {
            self.open_file_hooks
                .last_mut()
                .expect("frame checked")
                .active_call = Some(active_call);
            return Err(error);
        }
        if let Err(error) = self.release_guest_far_callback_owner(&mut active_call, dos, memory) {
            self.open_file_hooks
                .last_mut()
                .expect("frame checked")
                .active_call = Some(active_call);
            return Err(error);
        }
        let frame = self.open_file_hooks.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 OPENFILENAME hook frame disappeared",
            )
        })?;
        let saved = frame.saved.clone();
        let return_to = frame.return_to;
        let return_kind = frame.return_kind;
        cpu.regs = saved;
        // The hook's UINT is not the file-dialog BOOL. No dialog was opened,
        // so the SDK cancel result is FALSE and CommDlgExtendedError stays 0.
        self.common_dialog_state.last_extended_error = 0;
        if let Err(error) = self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            0,
            return_kind,
        ) {
            self.open_file_hooks
                .last_mut()
                .expect("frame checked")
                .active_call = Some(active_call);
            return Err(error);
        }
        let mut frame = self.open_file_hooks.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 OPENFILENAME hook frame disappeared",
            )
        })?;
        if let Some(owner) = frame.dispatch_owner.take() {
            if let Err(error) = self.release_legacy_cpu_frame(owner, dos, memory) {
                frame.dispatch_owner = Some(owner);
                self.open_file_hooks.push(frame);
                return Err(error);
            }
        }
        if let Err(error) = self.retire_callback_binding(CallbackKind::OpenFileHook, callback_id) {
            self.open_file_hooks.push(frame);
            return Err(error);
        }
        report_common_dialog_gap(
            host,
            "Win16 OPENFILENAME guest hook returned without a file dialog; the call returns FALSE",
        );
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_open_file_hook_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::OpenFileHook)?;
        let frame = self.open_file_hooks.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "top OPENFILENAME hook has no family frame",
            )
        })?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "top OPENFILENAME hook identity differs from its family frame",
            ));
        }
        if let Some(mut active_call) = self
            .open_file_hooks
            .last_mut()
            .and_then(|frame| frame.active_call.take())
        {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::OpenFileHook,
                callback_id,
                cpu,
                dos,
                memory,
                &mut active_call,
            ) {
                self.open_file_hooks
                    .last_mut()
                    .expect("frame checked")
                    .active_call = Some(active_call);
                return Err(error);
            }
        }
        let owner = self
            .open_file_hooks
            .last_mut()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OPENFILENAME hook frame disappeared during teardown",
                )
            })?
            .dispatch_owner
            .take();
        if let Some(owner) = owner {
            if let Err(error) = self
                .abort_legacy_cpu_frame_after_task_execution_ended(ended, owner, cpu, dos, memory)
            {
                self.open_file_hooks
                    .last_mut()
                    .expect("frame checked")
                    .dispatch_owner = Some(owner);
                return Err(error);
            }
        }
        let frame = self.open_file_hooks.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OPENFILENAME hook frame disappeared during teardown",
            )
        })?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::OpenFileHook, callback_id) {
            self.open_file_hooks.push(frame);
            return Err(error);
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn open_file_hook_code_references(&self) -> Vec<u32> {
        let mut references = Vec::with_capacity(self.open_file_hooks.len().saturating_mul(4));
        for frame in &self.open_file_hooks {
            references.push(frame.procedure);
            references.push((u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()));
            references.push((u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1));
            if let Some(active) = &frame.active_call {
                references.extend(active.code_references());
            }
        }
        references
    }

    fn enter_open_file_hook(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let frame = self.open_file_hooks.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 OPENFILENAME hook frame is missing",
            )
        })?;
        let procedure = frame.procedure;
        let structure_far = frame.structure_far;
        let saved = frame.saved.clone();
        cpu.regs = saved;
        let active_call = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            procedure,
            &[
                Win16FarCallbackArgument::Word(0),
                Win16FarCallbackArgument::Word(WM_INITDIALOG),
                Win16FarCallbackArgument::Word(0),
                Win16FarCallbackArgument::GuestPointer {
                    far: structure_far,
                    access: Access::Write,
                    bytes: OpenFileName16::SIZE as u32,
                },
            ],
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        )?;
        let frame = self.open_file_hooks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 OPENFILENAME hook frame disappeared",
            )
        })?;
        frame.active_call = Some(active_call);
        Ok(())
    }

    fn abandon_open_file_hook(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
        callback_id: super::super::CallbackFrameId,
        kind_pushed: bool,
        error: RuntimeError,
    ) -> RuntimeError {
        let Some(mut frame) = self.open_file_hooks.pop() else {
            return error;
        };
        if frame.callback_id != callback_id {
            self.open_file_hooks.push(frame);
            return error;
        }
        if kind_pushed {
            if let Err(cleanup) =
                self.retire_callback_binding(CallbackKind::OpenFileHook, callback_id)
            {
                self.open_file_hooks.push(frame);
                return error.with_cleanup("retire failed OPENFILENAME hook binding", cleanup);
            }
        }
        if let Some(owner) = frame.dispatch_owner.take() {
            if let Err(cleanup) = self.release_legacy_cpu_frame(owner, dos, memory) {
                frame.dispatch_owner = Some(owner);
                self.open_file_hooks.push(frame);
                return error.with_cleanup("release OPENFILENAME hook dispatch owner", cleanup);
            }
        }
        error
    }
}

#[cfg(test)]
#[path = "win16_commdlg_hook_tests.rs"]
mod tests;
