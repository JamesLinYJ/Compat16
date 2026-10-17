//! Native window operations suspended across checked guest WndProc calls.
//!
//! Windows owns message order and the native call stack. The runtime owns the
//! guest CPU, callback frames and HWND16 identities. Nested guest API calls
//! push separate operation frames and complete before their caller resumes.

#[path = "win16_window_timers.rs"]
mod timer_callbacks;
#[path = "win16_window_completion.rs"]
mod completion;
#[path = "win16_window_completion_driver.rs"]
mod completion_driver;
#[path = "win16_window_completion_state.rs"]
mod completion_state;
#[path = "win16_window_completion_common_dialog.rs"]
mod completion_common_dialog;
#[path = "win16_window_completion_control.rs"]
mod completion_control;
#[path = "win16_window_completion_api.rs"]
mod completion_api;
#[path = "win16_window_completion_native_api.rs"]
mod completion_native_api;
#[path = "win16_window_completion_gdi.rs"]
mod completion_gdi;
#[path = "win16_window_create_completion.rs"]
mod create_completion;
#[path = "win16_window_dde_completion_driver.rs"]
mod dde_completion_driver;
#[path = "win16_window_step_driver.rs"]
mod step_driver;
#[path = "win16_windows_dde_route.rs"]
mod dde_route;
#[path = "win16_windows_dde_return_transfer.rs"]
mod dde_return_transfer;
#[path = "win16_window_callback_finish.rs"]
mod callback_finish;
#[path = "win16_window_creation.rs"]
mod creation;
#[path = "win16_window_dialog_callbacks.rs"]
mod dialog_callbacks;
#[path = "win16_window_callback_lifecycle.rs"]
mod callback_lifecycle;
#[path = "win16_window_teardown.rs"]
mod teardown;
#[path = "win16_window_terminal_operations.rs"]
mod terminal_operations;
#[path = "win16_window_terminal_dde.rs"]
mod terminal_dde;
#[path = "win16_window_terminal_resources.rs"]
mod terminal_resources;
#[path = "win16_window_callback_terminal.rs"]
mod callback_terminal;
pub(super) use callback_terminal::window_callback_host_token;
pub(super) use terminal_operations::WindowTerminalRetirementStep;
#[path = "win16_window_operation_frame.rs"]
mod operation_frame;
#[path = "win16_window_completion_access.rs"]
mod completion_access;
pub(super) use completion_access::WindowProjectionAccess;
pub(super) use operation_frame::{
    TerminalWindowCallbackRetirement, WindowApiProjectionJournal, WindowCompletionJournal,
    DdeWindowCompletionPhase, DdeWindowCompletionJournal,
    NativeModalCancellationFailure, WindowOperationCompletion,
    WindowOperationPriorSourceRetirement,
    WindowOperationCompletionPhase, WindowOperationCompletionSource, WindowOperationFrame,
    WindowOperationLifecycle, WindowProjectionJournal,
    modal_error_matches,
};
#[path = "win16_window_callback_continuation.rs"]
mod callback_continuation;
pub(super) use callback_continuation::{ForwardedWindowMessage, WindowCallbackContinuation};
#[path = "win16_window_callback_frame.rs"]
mod callback_frame;
pub(super) use callback_frame::{WindowCallbackEntryPhase, WindowCallbackFrame, WindowCallbackSetupJournal, WindowCallbackSetupPhase, WindowClassRoot};
#[path = "win16_window_payload_retirement.rs"]
mod payload_retirement;
pub(super) use payload_retirement::{RetainedWindowPayloadCounts, RetiredWindowPayloadOwner, WindowCallbackPayloadCleanup};
#[path = "win16_window_callback_entry.rs"]
mod callback_entry;

#[path = "win16_window_dde_pending.rs"]
mod dde_pending;

use std::sync::Arc;

use guest_core::{Registers, Selector};
use guest_core::memory::Memory;
use win16_abi::{Access, Msg16, Win16ClassName, Win16ReturnKind};

use super::{CallbackFrameId, CallbackKind, Win16State, Win16DdeCallbackOrigin};
use super::window_payloads::GuestWindowPayload;
use super::messages::MessageOutput;
use super::user_services_controls::{
    Win16UserFamilyContinuation,
};
use crate::win16_host_window_ops::Win16WindowCallContinuation;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16CreationId, Win16HostCallback,
    Win16HostClass, Win16HostCreationData, Win16HostDc, Win16HostMessage,
    Win16HostWindow, Win16HostDialogMessage,
    Win16NativeWindowApiReturn,
    Win16ScalarMessage, Win16WindowCreationApi, Win16WindowCreationPhase,
    Win16WindowCreationRejection,
    Win16WindowOperation, Win16WindowReply, Win16WindowResult,
    Win16WindowStep,
};
use super::menu_calls::MenuCall;

const WS_CHILD: u32 = 0x4000_0000;
const WM_COMMAND: u16 = 0x0111;
// FAR return address, LPARAM32, WPARAM16, UINT16, HWND16.
const WNDPROC_STACK_BYTES: u16 = 14;

#[derive(Clone)]
pub(super) struct WindowCreateRequest {
    pub class_name: Win16ClassName,
    pub window_name: Option<Vec<u8>>,
    pub ex_style: u32,
    pub style: u32,
    pub x: i16,
    pub y: i16,
    pub width: i16,
    pub height: i16,
    pub parent: u16,
    pub menu: u16,
    pub instance: u16,
    pub parameter: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct WindowProcedure {
    pub(super) class: Win16HostClass,
    pub(super) address: u32,
    pub(super) instance: u16,
}

#[path = "win16_window_returns.rs"]
mod returns;
pub(super) use returns::WindowReturn;

impl Win16State {
    pub(in crate::win16_runtime) fn allocate_window_handle(&mut self, native: Win16HostWindow) -> Option<u16> {
        for _ in 0..u16::MAX {
            let handle = self.next_window_handle;
            self.next_window_handle = if handle >= 0xfffd { 2 } else { handle + 1 };
            // HWND_BOTTOM and the TOPMOST pseudo handles are valid USER
            // arguments, so keep them out of the ordinary token namespace.
            if matches!(handle, 0 | 1 | 0xfffe | u16::MAX) { continue; }
            if let std::collections::btree_map::Entry::Vacant(slot) =
                self.window_handles.entry(handle) {
                slot.insert(native);
                self.owned_window_handles.insert(handle);
                return Some(handle);
            }
        }
        None
    }

    pub(super) fn map_window_handle(
        &mut self,
        native: Win16HostWindow,
        owned: bool,
    ) -> Result<u16, RuntimeError> {
        if let Some((&guest, _)) = self.window_handles.iter()
            .find(|(_, existing)| **existing == native)
        {
            if owned { self.owned_window_handles.insert(guest); }
            return Ok(guest);
        }
        let guest = self.allocate_window_handle(native).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 window handle table is full"))?;
        if !owned { self.owned_window_handles.remove(&guest); }
        Ok(guest)
    }

    pub(super) fn associate_window_creation(
        &mut self,
        guest: u16,
        native: Win16HostWindow,
        creation: crate::Win16CreationId,
    ) -> Result<(), RuntimeError> {
        if self.window_handles.get(&guest) != Some(&native) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "window creation identity does not match its live guest HWND mapping",
            ));
        }
        if let Some((&other_guest, _)) = self.window_creations.iter()
            .find(|(candidate, existing)| **candidate != guest && **existing == creation)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                format!("one window creation generation is attached to guest HWND 0x{other_guest:04X} and 0x{guest:04X}"),
            ));
        }
        match self.window_creations.get(&guest).copied() {
            Some(existing) if existing == creation => Ok(()),
            Some(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "live guest HWND is already associated with a different creation generation",
            )),
            None => {
                self.window_creations.insert(guest, creation);
                Ok(())
            }
        }
    }

    pub(super) fn retire_window_handle(&mut self, guest: u16) -> Result<(), RuntimeError> {
        if let Some(native) = self.window_handles.get(&guest).copied() {
            self.retire_queued_drop_files_for_window(native)?;
            for jobs in self.network_print_jobs.values_mut() {
                jobs.record_retired_window(guest, native)?;
            }
            self.retire_common_dialog_window(native)?;
            self.window_parent_observations.retain(|child, parent| {
                *child != native && *parent != Some(native)
            });
        }
        self.window_handles.remove(&guest);
        self.window_system_classes.remove(&guest);
        self.mdi_children.remove(&guest);
        if self.sysmodal_window == Some(guest) {
            self.sysmodal_window = None;
        }
        self.window_creations.remove(&guest);
        self.window_procedures.remove(&guest);
        self.dialog_procedures.remove(&guest);
        self.window_data.remove(&guest);
        self.owned_window_handles.remove(&guest);
        self.timers.remove_window(guest);
        // The edge belongs to this guest window incarnation. Retire it only
        // after common-dialog and timer cleanup succeeded so a retry can still
        // discover the same child in its parent's retained tree.
        self.window_parents.remove(&guest);
        Ok(())
    }

    /// Consume only host-proven dead incarnations. Ownership and runtime
    /// parent edges cannot prove that any additional native HWND was destroyed.
    /// Revalidate the whole batch on retry: completed aliases disappear, and
    /// a reused guest slot names a different never-reused host token.
    pub(super) fn retire_exact_window_retirement_batch(
        &mut self,
        batch: &crate::Win16HostWindowRetirementBatch,
    ) -> Result<(), RuntimeError> {
        let claims = self.prevalidate_window_retirement_batch(&batch.receipts)?;
        // Cleanup cannot enter guest code, so the prevalidated token-to-alias
        // claims remain exact until this projection attempt returns.
        for guest in claims {
            self.retire_window_handle(guest)?;
            // Unreceipted aliases survive, but their old parent slot no longer
            // denotes a live incarnation. Do not let later HWND16 reuse attach
            // them to an unrelated replacement parent.
            self.window_parents.retain(|_, parent| *parent != guest);
        }
        self.guest_menus.invalidate(&batch.invalidated_menus);
        Ok(())
    }

    pub(super) fn retire_window_tree(&mut self, root: u16) -> Result<(), RuntimeError> {
        let mut pending = vec![(root, false)];
        let mut visited = std::collections::BTreeSet::new();
        while let Some((window, children_complete)) = pending.pop() {
            if children_complete {
                // Keep every parent edge until its child has retired. If a
                // child's common-dialog or timer cleanup is retained, the
                // original tree still identifies it for the next attempt.
                self.retire_window_handle(window)?;
                continue;
            }
            if !visited.insert(window) {
                continue;
            }
            pending.push((window, true));
            let children: Vec<_> = self.window_parents.iter().filter_map(|(child, parent)| {
                (*parent == window).then_some(*child)
            }).collect();
            pending.extend(children.into_iter().map(|child| (child, false)));
        }
        Ok(())
    }

    pub(super) fn link_window_parent(&mut self, child: u16, parent: u16)
        -> Result<(), RuntimeError> {
        if child == 0 || parent == 0 || child == parent {
            return Ok(());
        }
        if let Some(existing) = self.window_parents.get(&child) {
            if *existing == parent {
                return Ok(());
            }
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 child window was assigned to a different guest parent"));
        }
        let mut current = parent;
        let mut visited = std::collections::BTreeSet::new();
        loop {
            if current == child {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 window parent assignment would create a cycle"));
            }
            if !visited.insert(current) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 window parent table already contains a cycle"));
            }
            let Some(next) = self.window_parents.get(&current).copied() else { break; };
            current = next;
        }
        self.window_parents.insert(child, parent);
        Ok(())
    }

    fn record_native_command_parent(
        &mut self,
        payload: &GuestWindowPayload,
    ) -> Result<(), RuntimeError> {
        if payload.message != WM_COMMAND {
            return Ok(());
        }
        let (Some(control), Some(native_parent)) =
            (payload.command_control, payload.command_parent)
        else {
            return Ok(());
        };
        let child = self.map_window_handle(control, false)?;
        if child != payload.l_param as u16 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 WM_COMMAND control token differs from its LPARAM"));
        }
        let parent = self.map_window_handle(native_parent, false)?;
        self.set_window_parent_from_host(child, parent)
    }

    pub(super) fn set_window_parent_from_host(
        &mut self,
        child: u16,
        parent: u16,
    ) -> Result<(), RuntimeError> {
        if child == 0 || child == parent {
            return Ok(());
        }
        // A synchronous SetParent/GetParent completion can run while the
        // CreateWindow continuation is suspended. Remember even a move to
        // the desktop (parent zero), so creation cannot restore stale ancestry.
        self.note_pending_create_parent_update(child);
        if parent == 0 {
            self.window_parents.remove(&child);
            self.record_window_parent_observation(child, parent);
            return Ok(());
        }
        let mut current = parent;
        let mut visited = std::collections::BTreeSet::new();
        loop {
            if current == child {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native Win16 parent metadata would create a guest HWND cycle"));
            }
            if !visited.insert(current) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 window parent table already contains a cycle"));
            }
            let Some(next) = self.window_parents.get(&current).copied() else { break; };
            current = next;
        }
        // This relation came from the host's copied GetParent result. Replace
        // stale ancestry if native code has reparented the child.
        self.window_parents.insert(child, parent);
        self.record_window_parent_observation(child, parent);
        Ok(())
    }

    fn record_window_parent_observation(&mut self, child: u16, parent: u16) {
        let Some(native_child) = self.window_handles.get(&child).copied() else {
            return;
        };
        let native_parent = if parent == 0 {
            Some(None)
        } else {
            self.window_handles.get(&parent).copied().map(Some)
        };
        if let Some(native_parent) = native_parent {
            self.window_parent_observations
                .insert(native_child, native_parent);
        }
    }

    pub(super) fn note_pending_create_parent_update(&mut self, child: u16) {
        for frame in &mut self.window_operations {
            let Some(continuation) = frame.continuation_mut() else { continue; };
            if let WindowReturn::Create {
                window: Some(created), parent_was_updated, ..
            } = continuation {
                if *created == child {
                    *parent_was_updated = true;
                }
            }
        }
    }

    pub(super) fn begin_show_window(
        &mut self, registers: &mut Registers, memory: &mut Memory,
        host: &mut impl RuntimeHost, window: u16, command: i16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(&native) = self.window_handles.get(&window) else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        self.begin_window_operation(registers, memory, host,
            Win16WindowOperation::Show { window: native, command },
            WindowReturn::Show, return_to)
    }

    pub(super) fn begin_window_operation(
        &mut self, registers: &mut Registers, memory: &mut Memory,
        host: &mut impl RuntimeHost, operation: Win16WindowOperation,
        result: WindowReturn, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let source = operation.native_operation_kind();
        self.push_window_operation(registers.clone(), return_to, result)?;
        self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 USER operation disappeared before native begin",
        ))?.native_source = Some(source);
        self.mark_window_begin_pending(source)?;
        let step = match host.win16_window_begin(operation) {
            Ok(step) => step,
            Err(error) => {
                let error = std::sync::Arc::new(error);
                self.mark_window_begin_rejected(std::sync::Arc::clone(&error))?;
                return Err(super::callback_lifo::shared_runtime_error(error));
            }
        };
        self.advance_window_operation(registers, memory, host, step)?;
        Ok(None)
    }

    /// Capture the exact retired GetDlgItem source while its result is ready
    /// to prepare a SendMessage follow-up.
    pub(super) fn dialog_item_follow_up_source_proof(
        &self,
        frame_id: u64,
    ) -> Result<Option<Arc<crate::Win16WindowSourceRetiredProof>>, RuntimeError> {
        let Some(frame) = self.window_operations.last().filter(|frame| frame.id == frame_id)
        else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "dialog-item follow-up lost its exact outer top frame"));
        };
        let Some(completion) = frame.completion.as_ref() else { return Ok(None); };
        let is_dialog_item_child = matches!(
            (&completion.continuation, &completion.result),
            (WindowReturn::DialogItemMessage { .. },
                Win16WindowResult::UserService(
                    crate::Win16HostUserServiceResult::DialogControl(
                        crate::Win16HostDialogControlResult::Item(Some(_)),
                    ),
                )),
        );
        if !is_dialog_item_child { return Ok(None); }

        self.window_follow_up_source_proof(frame_id).map(Some)
    }

    pub(super) fn window_follow_up_source_proof(
        &self,
        frame_id: u64,
    ) -> Result<Arc<crate::Win16WindowSourceRetiredProof>, RuntimeError> {
        let Some(frame) = self.window_operations.last().filter(|frame| frame.id == frame_id)
        else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "USER follow-up lost its exact outer top frame"));
        };
        let completion = frame.completion.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "USER follow-up has no retained completion",
        ))?;
        let proof = frame.source_retired.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::HostFailure,
            "USER follow-up has no retired exact source",
        ))?;
        let exact_source = frame.host_operation == Some(proof.operation.operation_id)
            && frame.native_source == Some(proof.operation.kind)
            && frame.worker_generation == Some(proof.worker_generation)
            && proof.operation.operation_id.0 != 0
            && proof.worker_generation != 0
            && proof.state == crate::Win16NativeWindowOperationState::Returned;
        if completion.source != WindowOperationCompletionSource::NativeUser
            || completion.journal.phase != WindowOperationCompletionPhase::Received
            || frame.lifecycle != WindowOperationLifecycle::Returned
            || frame.native_state != Some(crate::Win16NativeWindowOperationState::Returned)
            || !exact_source
            || frame.source_retirement_consumed
            || frame.prior_source_retirement.is_some()
            || frame.cpu_call_owner.is_none()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "USER result does not match a live, retired native source"));
        }
        Ok(Arc::clone(proof))
    }

    /// Begin an already-prepared follow-up USER operation on the same outer
    /// frame. The prior USER source remains pinned until final caller
    /// restoration; this path never pushes another CPU owner.
    pub(super) fn begin_prepared_window_follow_up_on_top(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        frame_id: u64,
        prior_proof: Arc<crate::Win16WindowSourceRetiredProof>,
        operation: Win16WindowOperation,
        result: Option<WindowReturn>,
    ) -> Result<(), RuntimeError> {
        let exact_prior_proof = self.window_follow_up_source_proof(frame_id)?;
        if !Arc::ptr_eq(&exact_prior_proof, &prior_proof) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "USER source proof changed during follow-up preparation"));
        }

        let source = operation.native_operation_kind();
        let prior = WindowOperationPriorSourceRetirement {
            proof: prior_proof,
            consumed: false,
        };
        let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "prepared USER follow-up frame changed before stage binding"))?;
        let result = match result {
            Some(result) => result,
            None => {
                let cleanup_ready = frame.completion.as_ref().is_some_and(|completion|
                    match (&completion.continuation, &completion.journal.projection) {
                        (WindowReturn::CleanupPaint { .. },
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::CleanupPaint(owner)))
                        | (WindowReturn::CleanupWindowDc { .. },
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::CleanupWindowDc(owner))) =>
                            owner.phase == operation_frame::CompensationProjectionPhase::Ready,
                        _ => false,
                    });
                if !cleanup_ready {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "same-continuation follow-up is not a prepared GDI compensation"));
                }
                let completion = frame.completion.take().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "prepared compensation lost its retained completion",
                ))?;
                completion.continuation
            }
        };
        frame.prior_source_retirement = Some(prior);
        frame.completion = None;
        frame.result = Some(result);
        frame.source_retired = None;
        frame.source_retirement_consumed = false;
        frame.native_source = Some(source);
        frame.native_state = None;
        frame.host_operation = None;
        frame.worker_generation = None;
        frame.lifecycle = WindowOperationLifecycle::GuestOnly;
        frame.terminal_started_failure = None;
        frame.terminal_error = None;
        frame.terminal_retained_error = None;
        frame.terminal_ack = None;
        frame.terminal_ack_attempted = false;
        frame.terminal_source_acknowledged = false;

        self.mark_window_begin_pending(source)?;
        let step = match host.win16_window_begin(operation) {
            Ok(step) => step,
            Err(error) => {
                let error = Arc::new(error);
                self.mark_window_begin_rejected(Arc::clone(&error))?;
                return Err(super::callback_lifo::shared_runtime_error(error));
            }
        };
        self.advance_window_operation(registers, memory, host, step)
    }

    pub(super) fn pending_window_property_enum(&self) -> Option<(u32, u16)> {
        match self.window_operations.last().and_then(|frame| frame.continuation()) {
            Some(WindowReturn::WindowProperties(
                super::window_properties::WindowPropertyReturn::Enum {
                    procedure, guest_window,
                },
            )) => Some((*procedure, *guest_window)),
            _ => None,
        }
    }

}

impl Win16State {
    fn check_window_callback(&self, registers: &Registers, address: u32,
        memory: &Memory) -> Result<(), RuntimeError> {
        let callback = self.selectors.pointer_from_far(address).map_err(crate::runtime_error)?;
        self.selectors.translate(callback, Access::Execute, 1, memory).map_err(crate::runtime_error)?;
        let sp = registers.sp().checked_sub(WNDPROC_STACK_BYTES).ok_or_else(||
            RuntimeError::new(Kind::GuestFault, "Win16 window callback has insufficient stack space"))?;
        let stack = self.selectors.pointer_from_raw(Selector(registers.ss), sp)
            .map_err(crate::runtime_error)?;
        self.selectors.translate(stack, Access::Write, usize::from(WNDPROC_STACK_BYTES), memory)
            .map_err(crate::runtime_error)?;
        Ok(())
    }

    fn pending_dialog_procedure_for(
        &mut self,
        native_window: Win16HostWindow,
    ) -> Option<(Option<(u32, u16)>, u16, WindowClassRoot)> {
        self.window_operations.iter_mut().rev().find_map(|frame| {
            let Some(WindowReturn::UserFamily(continuation)) = frame.continuation_mut() else {
                return None;
            };
            if !continuation.bind_pending_dialog_window(native_window) { return None; }
            continuation.pending_dialog_instance().map(|instance|
                (continuation.pending_dialog_procedure(), instance, continuation.pending_dialog_class_root()))
        })
    }

    fn mark_pending_dialog_destroyed(&mut self, native_window: Win16HostWindow) {
        for frame in self.window_operations.iter_mut().rev() {
            let Some(WindowReturn::UserFamily(continuation)) = frame.continuation_mut() else {
                continue;
            };
            if continuation.mark_pending_dialog_window_destroyed(native_window) {
                break;
            }
        }
    }

    fn write_window_callback_stack(&self, registers: &Registers, window: u16,
        payload: &GuestWindowPayload, memory: &mut Memory) -> Result<(), RuntimeError> {
        let sp = registers.sp().checked_sub(WNDPROC_STACK_BYTES).ok_or_else(||
            RuntimeError::new(Kind::GuestFault, "Win16 window callback stack underflow"))?;
        let stack = self.selectors.pointer_from_raw(Selector(registers.ss), sp)
            .map_err(crate::runtime_error)?;
        let mut bytes = [0_u8; WNDPROC_STACK_BYTES as usize];
        bytes[2..4].copy_from_slice(&self.callback_gate_selector.0.to_le_bytes());
        bytes[4..8].copy_from_slice(&payload.l_param.to_le_bytes());
        bytes[8..10].copy_from_slice(&payload.w_param.to_le_bytes());
        bytes[10..12].copy_from_slice(&payload.message.to_le_bytes());
        bytes[12..14].copy_from_slice(&window.to_le_bytes());
        self.selectors.write(memory, stack, &bytes).map_err(crate::runtime_error)
    }

    pub(super) fn begin_guest_dispatch_callback(
        &mut self, registers: &mut Registers, memory: &mut Memory,
        message: Msg16, timer: bool, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let (procedure, continuation, instance, class_root) = if timer {
            (message.l_param, WindowCallbackContinuation::GuestTimer, None,
                WindowClassRoot::NoRegistration)
        } else {
            if message.hwnd == 0 {
                return self.complete_return(registers, return_to.0, return_to.1,
                    return_to.2, 0, Win16ReturnKind::Dword);
            }
            if let Some((address, instance)) = self.native_subclass_procedure(message.hwnd) {
                (address, WindowCallbackContinuation::GuestDispatch, Some(instance),
                    WindowClassRoot::NoRegistration)
            } else if let Some((address, instance)) = self.dialog_procedures.get(&message.hwnd).copied() {
                self.initialize_dialog_window_data(message.hwnd, instance)?;
                self.reset_dialog_message_result(message.hwnd);
                (address, WindowCallbackContinuation::GuestDialogDispatch {
                    window: message.hwnd,
                }, Some(instance), self.window_class_root(message.hwnd))
            } else if let Some(procedure) = self.window_procedures.get(&message.hwnd).copied() {
                (procedure.address, WindowCallbackContinuation::GuestDispatch,
                    Some(procedure.instance), WindowClassRoot::Class(procedure.class))
            } else {
                return self.complete_return(registers, return_to.0, return_to.1,
                    return_to.2, 0, Win16ReturnKind::Dword);
            }
        };
        self.check_window_callback(registers, procedure, memory)?;
        let callback_payload = GuestWindowPayload {
            message: message.message,
            w_param: message.w_param,
            l_param: if timer { message.time } else { message.l_param },
            allocation: None,
            output: None,
            callback_dc: None,
            command_control: None,
            command_parent: None,
            common_dialog_request: None,
        };
        self.write_window_callback_stack(registers, message.hwnd, &callback_payload, memory)?;
        self.push_window_operation(registers.clone(), return_to,
            if timer { WindowReturn::GuestTimerDispatch } else { WindowReturn::GuestDispatch })?;
        let callback_id = self.reserve_window_callback_frame()?;
        self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "guest USER dispatch operation disappeared before callback binding",
        ))?.guest_callback_id = Some(callback_id);
        self.publish_window_callback_frame(WindowCallbackFrame::guest(
            callback_id,
            registers.clone(),
            callback_payload,
            None,
            procedure,
            class_root,
            None,
            None,
            continuation,
        ))?;
        registers.set_sp(registers.sp() - WNDPROC_STACK_BYTES);
        registers.cs = (procedure >> 16) as u16;
        registers.set_ip(procedure as u16);
        if let Some(instance) = instance { registers.set_ax(instance); }
        registers.ds = registers.ss;
        registers.es = registers.ss;
        Ok(None)
    }

    /// Invoke a checked Win16 FARPROC using the same reentrant USER frame as
    /// a WndProc call. No instance is placed in AX for CallWindowProc.
    pub(super) fn begin_call_window_proc(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        procedure: u32,
        window: u16,
        message: u16,
        w_param: u16,
        l_param: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if let Some(native) = self.native_procedure_for_address(procedure) {
            return self.begin_native_window_proc(registers, memory, host,
                native, window, message, w_param, l_param, return_to);
        }
        self.check_window_callback(registers, procedure, memory)?;
        // Carry the suspended native callback only when this FAR call forwards
        // the exact active guest WndProc message. New SendMessage operations do
        // not capture or inherit this capability.
        let forwarded = self.active_window_message(window, message, w_param, l_param);
        let payload = GuestWindowPayload {
            message,
            w_param,
            l_param,
            allocation: None,
            output: None,
            callback_dc: None,
            command_control: None,
            command_parent: None,
            common_dialog_request: None,
        };
        self.write_window_callback_stack(registers, window, &payload, memory)?;
        self.push_window_operation(registers.clone(), return_to,
            WindowReturn::GuestProcedureCall { return_kind: Win16ReturnKind::Dword })?;
        let callback_id = self.reserve_window_callback_frame()?;
        self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "guest CallWindowProc operation disappeared before callback binding",
        ))?.guest_callback_id = Some(callback_id);
        self.publish_window_callback_frame(WindowCallbackFrame::guest(
            callback_id,
            registers.clone(),
            payload,
            forwarded.and_then(|message| message.guest_notification),
            procedure,
            forwarded.map_or(WindowClassRoot::NoRegistration, |source| source.class_root),
            None,
            None,
            WindowCallbackContinuation::GuestProcedureCall { forwarded },
        ))?;
        registers.set_sp(registers.sp() - WNDPROC_STACK_BYTES);
        registers.cs = (procedure >> 16) as u16;
        registers.set_ip(procedure as u16);
        registers.ds = registers.ss;
        registers.es = registers.ss;
        Ok(None)
    }
}

fn guest_code_reference(selector: u16, offset: u16) -> u32 {
    (u32::from(selector) << 16) | u32::from(offset)
}
