//! Synchronous Win16 USER operations backed by a dedicated native UI thread.
//!
//! The worker owns every HWND and registered class. Only numeric tokens and
//! owned Win16 message data cross this client boundary.

#[path = "win16_common_controls_bitmap_pins.rs"]
pub(super) mod win16_common_controls_bitmap_pins;
#[path = "win16_common_controls_dc_retention.rs"]
mod win16_common_controls_dc_retention;
#[path = "win16_common_controls_drag_list.rs"]
mod win16_common_controls_drag_list;
#[path = "win16_control_outputs.rs"]
mod win16_control_outputs;
#[path = "win16_cursor_clip.rs"]
mod win16_cursor_clip;
#[path = "win16_deferred_native_messages.rs"]
mod win16_deferred_native_messages;
#[path = "win16_dialog_icon_controls.rs"]
mod win16_dialog_icon_controls;
#[path = "win16_dialog_callbacks.rs"]
mod win16_dialog_callbacks;
#[path = "win16_gdi_bitmap_lease.rs"]
pub(super) mod win16_gdi_bitmap_lease;
#[path = "win16_guest_notifications.rs"]
mod win16_guest_notifications;
#[path = "win16_ime_profiles.rs"]
mod win16_ime_profiles;
#[path = "win16_mdi_pending_creation.rs"]
mod win16_mdi_pending_creation;
#[path = "win16_native_procedures.rs"]
mod win16_native_procedures;
#[path = "win16_window_instances.rs"]
mod win16_window_instances;
#[path = "win16_character_messages.rs"]
mod win16_character_messages;
#[path = "win16_subclass_send.rs"]
mod win16_subclass_send;
#[path = "win16_owner_draw_callbacks.rs"]
mod win16_owner_draw_callbacks;
#[path = "win16_shell_execution.rs"]
mod win16_shell_execution;
#[path = "win16_standard_controls.rs"]
mod win16_standard_controls;
#[path = "win16_static_controls.rs"]
mod win16_static_controls;
#[path = "win16_system_classes.rs"]
mod win16_system_classes;
#[path = "win16_window_callbacks.rs"]
mod win16_window_callbacks;
#[path = "win16_window_control_color.rs"]
mod win16_window_control_color;
#[path = "win16_window_creation_hook.rs"]
mod win16_window_creation_hook;
#[path = "win16_window_default.rs"]
mod win16_window_default;
#[path = "win16_window_dialog_creation.rs"]
mod win16_window_dialog_creation;
#[path = "win16_window_identity.rs"]
mod win16_window_identity;
#[path = "win16_dialog_root_identity.rs"]
mod win16_dialog_root_identity;
#[path = "win16_window_input.rs"]
mod win16_window_input;
#[path = "win16_ctl3d_worker.rs"]
mod win16_ctl3d_worker;
#[path = "win16_window_worker.rs"]
mod win16_window_worker;
pub(super) use win16_window_worker::{
    ModalWakeDispatcher, current_operation_id, worker_context, yield_pending_modal_guest_work,
};
#[path = "win16_windows_class_queue.rs"]
mod class_queue;
#[path = "win16_windows_classic_dde.rs"]
mod classic_dde;
#[path = "win16_windows_com.rs"]
mod com_api;
#[path = "win16_windows_operation_inputs.rs"]
mod operation_inputs;
#[path = "win16_windows_terminal_sources.rs"]
mod terminal_sources;
#[path = "win16_windows_user_completion.rs"]
mod user_completion;
#[path = "win16_common_controls_worker.rs"]
mod win16_common_controls_worker;
#[path = "win16_common_dialog_callbacks.rs"]
mod win16_common_dialog_callbacks;
#[path = "win16_common_dialog_worker.rs"]
mod win16_common_dialog_worker;
#[path = "win16_menu_attachment.rs"]
mod win16_menu_attachment;
#[path = "win16_menu_worker.rs"]
mod win16_menu_worker;
#[path = "win16_message_calls.rs"]
mod win16_message_calls;
#[path = "win16_message_loop.rs"]
mod win16_message_loop;
#[path = "win16_user_cursor_accelerator.rs"]
pub(super) mod win16_user_cursor_accelerator;
#[path = "win16_user_services_clipboard.rs"]
mod win16_user_services_clipboard;
#[path = "win16_user_services_controls.rs"]
mod win16_user_services_controls;
#[path = "win16_user_services_dialog.rs"]
mod win16_user_services_dialog;
#[path = "win16_user_services_scroll_bar.rs"]
mod win16_user_services_scroll_bar;
#[path = "win16_user_services_system_parameters.rs"]
mod win16_user_services_system_parameters;
#[path = "win16_user_services_update_region.rs"]
mod win16_user_services_update_region;
#[path = "win16_user_services_window_dc.rs"]
mod win16_user_services_window_dc;
#[path = "win16_window_data.rs"]
mod win16_window_data;
#[path = "win16_window_enumeration.rs"]
mod win16_window_enumeration;
#[path = "win16_window_geometry.rs"]
mod win16_window_geometry;
#[path = "win16_window_sizing.rs"]
mod win16_window_sizing;
#[path = "win16_frame_geometry.rs"]
mod win16_frame_geometry;
pub(super) use win16_frame_geometry::caption_height;
#[path = "win16_window_ops.rs"]
mod win16_window_ops;
#[path = "win16_window_caret.rs"]
mod win16_window_caret;
#[path = "win16_window_position.rs"]
mod win16_window_position;
#[path = "win16_window_properties.rs"]
mod win16_window_properties;
#[path = "win16_window_text.rs"]
mod win16_window_text;
#[path = "win16_window_text_context.rs"]
mod win16_window_text_context;
#[path = "win16_windows_dde.rs"]
mod win16_windows_dde;

use operation_inputs::{
    native_bitmap_tokens, toolbar_bitmap_tokens, transferred_dc_region,
    update_region_output, update_region_tokens,
};
#[path = "win16_gray_string.rs"]
mod win16_gray_string;
#[path = "win16_metafile_enumeration.rs"]
pub(in crate::windows) mod metafile_enumeration;
#[path = "win16_windows_graphics.rs"]
mod graphics;

#[path = "win16_control_color_return.rs"]
mod control_color_return;
use control_color_return::{
    ControlColorReturnSlot, HostNativeBrushResult, operation_control_color_message,
};

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{self, Receiver};

use super::win16_dde::Win16DdeHost;
use super::{
    win16_gdi::Win16Dcs,
    win16_gdi_objects::{Win16Objects, Win16RegionLease},
    win16_images::Win16Images,
};
use runtime::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, Win16HostCallback, Win16HostDdeCallbackStep,
    Win16HostDdeResume, Win16HostDdeStep, Win16HostDropRetirementReceipt, Win16HostGdiObject,
    Win16HostWindow, Win16HostWindowLiveness, Win16HostWindowOperationId, Win16MessageCall,
    Win16NativeCallbackCancellation, Win16NativeModalGuestWorkRetirement,
    Win16NativeWindowOperationKind, Win16NativeWindowOperationProof,
    Win16NativeWindowOperationState, Win16WindowAbortReceipt, Win16WindowOperation,
    Win16WindowOperationStartedFailure, Win16WindowReply, Win16WindowSourceRetiredProof,
    Win16WindowStep, Win16WindowTerminalAck, Win16WindowTerminalSourceTop,
};
use win16_window_worker::{
    NativeClassResource, NativeDropRetirementQueue, NativeDropRetirementQueueHandle,
    WindowWorker, WorkerCommand,
};
pub(super) use win16_windows_dde::allocate_shared_identity;
use win16_windows_dde::{DdeSourceLedger, PendingSource};

struct PendingOperation {
    id: u64,
    kind: Win16NativeWindowOperationKind,
    worker_generation: u64,
    response: Receiver<Result<Win16WindowStep, RuntimeError>>,
    awaiting: Option<Win16HostCallback>,
    awaiting_source: Option<Win16NativeCallbackCancellation>,
    response_error: Option<Arc<RuntimeError>>,
    /// Exact native source phase, recorded before runtime projection or guest
    /// memory writeback can fail after a worker response has returned.
    native_state: Win16NativeWindowOperationState,
    terminal_started_failure: Option<Arc<Win16WindowOperationStartedFailure>>,
    /// Index of this operation's exact modal cancellation in the immutable
    /// cached abort receipt. It carries terminal identity without cloning or
    /// reconstructing the native response.
    terminal_modal_receipt_index: Option<usize>,
    modal_work_history: Vec<Win16NativeModalGuestWorkRetirement>,
    /// Exact modal guest-work identity whose resume command was accepted and
    /// whose next worker response has not yet been journaled.
    resumed_modal_work: Option<Win16NativeModalGuestWorkRetirement>,
    /// A real USER `Complete` step remains owned here until its caller-thread
    /// output and source-retirement phases finish. The response receiver is
    /// never read again while this slot is populated.
    completion: Option<PendingUserCompletion>,
    region_output: Option<(Win16HostGdiObject, Win16RegionLease)>,
    transferred_dc_region: Option<Win16HostGdiObject>,
    graphics: Option<graphics::DrawingLease>,
    metafile: Option<Arc<metafile_enumeration::MetafileSession>>,
    control_color_return: Option<ControlColorReturnSlot>,
    wait_kind: Option<PendingWaitKind>,
    pending_guest_work: Option<PendingGuestWorkContinuation>,
    pending_modal_guest_work: Option<PendingModalGuestWorkContinuation>,
    last_guest_work_generation: u64,
    last_modal_guest_work_generation: u64,
}

pub(super) struct PendingUserCompletion {
    pub(super) step: Win16WindowStep,
    pub(super) phase: PendingUserCompletionPhase,
    pub(super) source_proof: Option<Arc<Win16WindowSourceRetiredProof>>,
    /// A modal marker may retire only after the matching USER result is
    /// cached. Keep that exact identity until the completion journal commits it.
    pub(super) modal_work_retirement: Option<Win16NativeModalGuestWorkRetirement>,
    /// Preserve the first failure even when a later exact retry succeeds.
    pub(super) first_cause: Option<Arc<RuntimeError>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PendingUserCompletionPhase {
    ResultReceived,
    ModalWorkRetired,
    OutputCommitted,
    SourceProofPrepared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingWaitKind {
    GetMessage,
    WaitMessage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingGuestWorkContinuation {
    operation_id: Win16HostWindowOperationId,
    generation: u64,
    kind: PendingWaitKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingModalGuestWorkContinuation {
    operation_id: Win16HostWindowOperationId,
    scope_id: u64,
    generation: u64,
    marker_id: Option<u64>,
    wake_generation: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalShutdownRetirementProof {
    worker_generation: u64,
    source_request_id: u64,
    shutdown_request_id: u64,
}

/// Owns the command client and the guest-facing continuation stack. The
/// native state itself never leaves the worker thread.
pub(super) struct Win16Windows {
    worker: Option<WindowWorker>,
    dcs: Win16Dcs,
    worker_start_error: Option<Arc<RuntimeError>>,
    pending: Vec<PendingOperation>,
    dde_sources: DdeSourceLedger,
    identity_source: Arc<AtomicU64>,
    dde: Option<Win16DdeHost>,
    dde_start_error: Option<Arc<RuntimeError>>,
    aborted: bool,
    terminal_abort: Option<Win16WindowAbortReceipt>,
    terminal_shutdown_retirement: Option<TerminalShutdownRetirementProof>,
    terminal_acknowledgements: Vec<Win16WindowTerminalAck>,
    /// Exact normal-return source tombstones retained until the runtime has
    /// projected the corresponding result and releases the same proof.
    source_retirements: Vec<Arc<Win16WindowSourceRetiredProof>>,
    /// Independent classic WM_DDE operation stack. It remains separate from
    /// both the DDEML ledger and normal USER GetMessage/WaitMessage sources.
    classic_dde_sources: Vec<classic_dde::PendingClassicDdeOperation>,
    native_drop_retirements: NativeDropRetirementQueueHandle,
}

impl Win16Windows {
    pub(super) fn new(
        dcs: Win16Dcs,
        images: Win16Images,
        identity_source: Arc<AtomicU64>,
        oem_text_codec: super::guest_text::GuestTextCodec,
    ) -> Self {
        let guest_ansi_codec = dcs.text_codec();
        let (dde, dde_start_error) =
            match Win16DdeHost::new(Arc::clone(&identity_source), guest_ansi_codec) {
                Ok(dde) => (Some(dde), None),
                Err(error) => (None, Some(Arc::new(error))),
            };
        let native_drop_retirements = NativeDropRetirementQueue::shared();
        let worker = WindowWorker::spawn(
            dcs.clone(),
            images,
            Arc::clone(&identity_source),
            oem_text_codec,
            Arc::clone(&native_drop_retirements),
        );
        match worker {
            Ok(worker) => Self {
                worker: Some(worker),
                dcs,
                worker_start_error: None,
                pending: Vec::new(),
                dde_sources: DdeSourceLedger::default(),
                identity_source,
                dde,
                dde_start_error,
                aborted: false,
                terminal_abort: None,
                terminal_shutdown_retirement: None,
                terminal_acknowledgements: Vec::new(),
                source_retirements: Vec::new(),
                classic_dde_sources: Vec::new(),
                native_drop_retirements,
            },
            Err(error) => Self {
                worker: None,
                dcs,
                worker_start_error: Some(Arc::new(error)),
                pending: Vec::new(),
                dde_sources: DdeSourceLedger::default(),
                identity_source,
                dde,
                dde_start_error,
                aborted: false,
                terminal_abort: None,
                terminal_shutdown_retirement: None,
                terminal_acknowledgements: Vec::new(),
                source_retirements: Vec::new(),
                classic_dde_sources: Vec::new(),
                native_drop_retirements,
            },
        }
    }

    pub(super) fn take_native_drop_retirement(&self) -> Option<Win16HostDropRetirementReceipt> {
        NativeDropRetirementQueue::peek(&self.native_drop_retirements)
    }

    pub(super) fn acknowledge_native_drop_retirement(
        &mut self,
        receipt: Win16HostDropRetirementReceipt,
    ) -> Result<(), RuntimeError> {
        NativeDropRetirementQueue::acknowledge(&self.native_drop_retirements, receipt)
    }

    /// Read the next USER response without acknowledging a callback,
    /// operation, or guest-work source. This is used only after runtime has
    /// consumed and separately acknowledged a native-drop retirement receipt.
    pub(super) fn receive_pending(
        &mut self,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let pending = self.pending.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "native-drop receipt has no pending USER operation to continue reading",
            )
        })?;
        if pending.awaiting.is_some()
            || pending.awaiting_source.is_some()
            || pending.pending_guest_work.is_some()
            || pending.pending_modal_guest_work.is_some()
            || pending.completion.is_some()
            || pending.response_error.is_some()
            || pending.native_state != runtime::Win16NativeWindowOperationState::Active
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native-drop receipt polling attempted to cross a suspended USER source",
            ));
        }
        let (id, kind, worker_generation, resumed_modal_work) = (
            pending.id,
            pending.kind,
            pending.worker_generation,
            pending.resumed_modal_work,
        );
        let step = self.receive_step_inner(objects)?;
        if let Some(retirement) = resumed_modal_work {
            self.account_resumed_modal_response(id, kind, worker_generation, retirement, &step)?;
        }
        Ok(step)
    }

    fn account_resumed_modal_response(
        &mut self,
        id: u64,
        kind: Win16NativeWindowOperationKind,
        worker_generation: u64,
        retirement: Win16NativeModalGuestWorkRetirement,
        step: &Win16WindowStep,
    ) -> Result<(), RuntimeError> {
        if let Win16WindowStep::SourceRetired { proof, .. } = step {
            if proof.operation.operation_id != Win16HostWindowOperationId(id)
                || proof.operation.kind != kind
                || proof.worker_generation != worker_generation
                || proof.state != Win16NativeWindowOperationState::Returned
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "modal completion returned a USER source proof for another owner",
                ));
            }
            return Ok(());
        }
        let index = self.pending.len().checked_sub(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "resumed modal response has no exact pending USER operation",
            )
        })?;
        let pending = &self.pending[index];
        if pending.id != id
            || pending.kind != kind
            || pending.worker_generation != worker_generation
            || pending.resumed_modal_work != Some(retirement)
            || pending
                .modal_work_history
                .iter()
                .filter(|item| **item == retirement)
                .count()
                != 1
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "resumed modal response changed its exact USER source identity",
            ));
        }
        if matches!(step, Win16WindowStep::NativeDropRetired(_)) {
            // This transport receipt does not complete the accepted modal
            // resume. Keep its marker history until receive_pending obtains
            // the actual USER response from this same operation.
            return Ok(());
        }
        let pending = self
            .pending
            .get_mut(index)
            .filter(|pending| pending.id == id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "resumed modal response lost its exact pending operation",
                )
            })?;
        let source_index = pending
            .modal_work_history
            .iter()
            .position(|item| *item == retirement)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "resumed modal response lost its exact source identity",
                )
            })?;
        pending.modal_work_history.remove(source_index);
        pending.resumed_modal_work = None;
        Ok(())
    }

    pub(super) fn multimedia_wake_sender(
        &self,
    ) -> Result<super::multimedia_wake::MultimediaWakeSender, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 USER worker has been aborted; multimedia wake is unavailable",
            ));
        }
        self.worker().map(WindowWorker::multimedia_wake_sender)
    }

    pub(super) fn ime_profile(
        &self,
        call: runtime::Win16HostImeProfileCall,
    ) -> Result<runtime::Win16HostImeProfileResult, RuntimeError> {
        self.worker()?.ime_profile(call)
    }

    /// Start a native operation. A callback step leaves its operation and
    /// response channel on the client stack until `resume` receives Complete.
    pub(super) fn begin(
        &mut self,
        operation: Win16WindowOperation,
        objects: &mut Win16Objects,
        win_exec: Option<Result<super::win16_program_launch::PreparedLaunch, u16>>,
    ) -> Result<Win16WindowStep, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 native window/DDE host has been aborted",
            ));
        }
        let operation = match operation {
            Win16WindowOperation::Dde(call) => return self.begin_dde_inner(call),
            operation => operation,
        };
        self.refresh_pending_graphics(objects)?;
        let graphics = match &operation {
            Win16WindowOperation::EnumMetafile { dc, .. } | Win16WindowOperation::GrayString { dc, .. } =>
                Some(graphics::DrawingLease::capture(&self.dcs, objects, *dc)?),
            _ => None,
        };
        let control_color_return =
            operation_control_color_message(&operation).then(ControlColorReturnSlot::new);
        let kind = operation.native_operation_kind();
        let wait_kind = match &operation {
            Win16WindowOperation::GetMessage { .. } => Some(PendingWaitKind::GetMessage),
            Win16WindowOperation::MessageCall(Win16MessageCall::WaitMessage) => {
                Some(PendingWaitKind::WaitMessage)
            }
            _ => None,
        };
        let worker = match self.worker.as_ref() {
            Some(worker) => worker,
            None => return Err(self.worker_start_failure()),
        };
        let worker_generation = worker.worker_generation();
        let id = allocate_shared_identity(&self.identity_source)?;
        let (reply, response) = mpsc::channel();
        let metafile = metafile_enumeration::prepare(&operation, id)?;
        let native_font = match &operation {
            Win16WindowOperation::Default { message, .. }
            | Win16WindowOperation::DefFrameProc { message, .. }
            | Win16WindowOperation::DefaultMdiChild { message, .. }
            | Win16WindowOperation::Send { message, .. }
            | Win16WindowOperation::CallProcedure { message, .. } => match message {
                runtime::Win16HostMessage::SetFont {
                    font: Some(token), ..
                } => objects
                    .native_font(*token)
                    .map(|font| (*token, font as usize)),
                _ => None,
            },
            _ => None,
        };
        let native_bitmaps = native_bitmap_tokens(&operation)
            .into_iter()
            .map(|token| {
                (
                    token,
                    objects.native_bitmap(token).map(|bitmap| bitmap as usize),
                )
            })
            .collect();
        let native_regions: std::collections::BTreeMap<_, _> = update_region_tokens(&operation)
            .into_iter()
            .map(|token| objects.lease_region(token).map(|lease| (token, lease)))
            .collect::<Result<_, _>>()?;
        let region_output = update_region_output(&operation).and_then(|token| {
            native_regions
                .get(&token)?
                .as_ref()
                .map(|region| (token, region.clone()))
        });
        let transferred_dc_region = transferred_dc_region(&operation);
        self.pending.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 USER pending operation",
                error,
            )
        })?;
        self.dde_sources.pending.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 USER/DDE pending source",
                error,
            )
        })?;

        let toolbar_tokens = toolbar_bitmap_tokens(&operation);
        worker.reserve_toolbar_bitmap_leases(toolbar_tokens.len())?;
        let mut toolbar_bitmap_leases = std::collections::BTreeMap::new();
        for token in &toolbar_tokens {
            toolbar_bitmap_leases.insert(*token, None);
        }
        // All fallible bookkeeping and capacity checks precede CopyImage. The
        // map already owns every key, so filling its slots does not allocate.
        for (token, slot) in &mut toolbar_bitmap_leases {
            *slot = objects.native_bitmap(*token).and_then(|bitmap| {
                win16_gdi_bitmap_lease::Win16BitmapLease::snapshot(*token, bitmap)
            });
        }
        let gray_string_brush = match &operation {
            Win16WindowOperation::GrayString { brush: Some(brush), .. } =>
                win16_gray_string::BrushLease::capture(objects, *brush),
            _ => None,
        };
        super::win16_gdi::flush_thread_batch();
        let command = WorkerCommand::Begin {
            id,
            operation,
            win_exec,
            control_color_return: control_color_return.clone(),
            native_bitmaps,
            native_font,
            toolbar_bitmap_leases,
            native_regions,
            gray_string_brush,
            metafile: metafile.clone(),
            response: reply,
        };
        if let Err(command) = worker.send_begin(command) {
            let primary = worker_stopped("send Begin to Win16 native window worker");
            return match command {
                WorkerCommand::Begin {
                    toolbar_bitmap_leases,
                    ..
                } => {
                    let cleanup =
                        worker.release_unconsumed_toolbar_bitmap_leases(id, toolbar_bitmap_leases);
                    Err(combine_begin_cleanup(primary, cleanup))
                }
                _ => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed USER Begin send returned a different command",
                )),
            };
        }
        self.pending.push(PendingOperation {
            id,
            kind,
            worker_generation,
            response,
            awaiting: None,
            awaiting_source: None,
            response_error: None,
            native_state: Win16NativeWindowOperationState::Active,
            terminal_started_failure: None,
            terminal_modal_receipt_index: None,
            modal_work_history: Vec::new(),
            resumed_modal_work: None,
            completion: None,
            region_output,
            transferred_dc_region,
            graphics,
            metafile,
            control_color_return,
            wait_kind,
            pending_guest_work: None,
            pending_modal_guest_work: None,
            last_guest_work_generation: 0,
            last_modal_guest_work_generation: 0,
        });
        self.dde_sources.pending.push(PendingSource::User { id });
        let step = match self.receive_step_inner(objects) {
            Ok(step) => step,
            Err(error) => {
                return self.started_failure(id, error);
            }
        };
        Ok(Win16WindowStep::Started {
            operation_id: Win16HostWindowOperationId(id),
            worker_generation,
            kind,
            step: Box::new(step),
        })
    }

    /// Terminal cleanup path. This deliberately suppresses guest callbacks;
    /// ordinary DestroyWindow calls use `Win16WindowOperation::Destroy`.
    pub(super) fn destroy_window(&mut self, window: Win16HostWindow) -> bool {
        let Ok(worker) = self.worker() else {
            return false;
        };
        let (reply, response) = mpsc::channel();
        if worker
            .send(WorkerCommand::DestroyQuiet {
                window,
                response: reply,
            })
            .is_err()
        {
            return false;
        }
        response.recv().unwrap_or(false)
    }

    pub(super) fn host_window_liveness(
        &self,
        window: Win16HostWindow,
    ) -> Result<Win16HostWindowLiveness, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "exact Win16 window liveness is unavailable after USER worker abort",
            ));
        }
        self.worker()?.query_window_liveness(window)
    }

    pub(super) fn host_window_parent(
        &self,
        window: Win16HostWindow,
    ) -> Result<runtime::Win16HostWindowParentObservation, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "exact Win16 window parent is unavailable after USER worker abort",
            ));
        }
        self.worker()?.query_window_parent(window)
    }

    pub(super) fn resume(
        &mut self,
        reply: Option<Win16WindowReply>,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let operation_id = match self.dde_sources.pending.last().copied() {
            Some(PendingSource::User { id }) => id,
            _ => return self.resume_inner(reply, objects),
        };
        match self.resume_inner(reply, objects) {
            Ok(step) => Ok(step),
            Err(error) => self.started_failure(operation_id, error),
        }
    }

    /// Retry only the completion already received for this exact USER owner.
    /// This path never sends a worker command or reads the response receiver;
    /// it resumes the cached result/output/source-retirement journal in place.
    pub(super) fn retry_cached_completion(
        &mut self,
        operation: Win16NativeWindowOperationProof,
        worker_generation: u64,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let id = operation.operation_id.0;
        let index = self.pending.len().checked_sub(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::HostFailure,
                "cached USER completion retry has no pending operation owner",
            )
        })?;
        let pending = &self.pending[index];
        let failure = pending.terminal_started_failure.as_ref().ok_or_else(|| {
            RuntimeError::new(
                Kind::HostFailure,
                "cached USER completion retry has no retained first failure",
            )
        })?;
        if id == 0
            || worker_generation == 0
            || pending.id != id
            || pending.kind != operation.kind
            || pending.worker_generation != worker_generation
            || pending.native_state != Win16NativeWindowOperationState::Returned
            || pending.completion.is_none()
            || pending.response_error.is_some()
            || pending.awaiting.is_some()
            || pending.awaiting_source.is_some()
            || pending.pending_guest_work.is_some()
            || pending.pending_modal_guest_work.is_some()
            || failure.operation != operation
            || failure.worker_generation != worker_generation
            || failure.state != Win16NativeWindowOperationState::Returned
            || self
                .pending
                .iter()
                .filter(|candidate| candidate.id == id)
                .count()
                != 1
            || self.pending.last().map(|candidate| candidate.id) != Some(id)
            || self.dde_sources.pending.last() != Some(&PendingSource::User { id })
            || self
                .dde_sources
                .pending
                .iter()
                .filter(|source| **source == (PendingSource::User { id }))
                .count()
                != 1
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "cached USER completion retry does not match the exact returned top owner",
            ));
        }
        self.receive_step_inner(objects)
    }

    pub(super) fn resume_modal_guest_work(
        &mut self,
        operation_id: Win16HostWindowOperationId,
        scope_id: u64,
        generation: u64,
        marker_id: Option<u64>,
        wake_generation: Option<u64>,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let index = self.pending.len().checked_sub(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "modal guest-work resume has no pending USER operation",
            )
        })?;
        let expected = self.pending[index].pending_modal_guest_work;
        if expected
            != Some(PendingModalGuestWorkContinuation {
                operation_id,
                scope_id,
                generation,
                marker_id,
                wake_generation,
            })
            || operation_id != Win16HostWindowOperationId(self.pending[index].id)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "modal guest-work resume does not match the exact pending host tuple",
            ));
        }
        let expected = expected.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "modal guest-work source disappeared before resume",
            )
        })?;
        let (worker_generation, operation_kind, existing_resume) = {
            let pending = &self.pending[index];
            (
                pending.worker_generation,
                pending.kind,
                pending.resumed_modal_work,
            )
        };
        if worker_generation == 0 || existing_resume.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "modal guest-work resume has a zero worker identity or an uncommitted prior resume",
            ));
        }
        let retirement = match (expected.marker_id, expected.wake_generation) {
            (Some(marker_id), Some(wake_generation)) => Some(Win16NativeModalGuestWorkRetirement {
                operation_id,
                scope_id: expected.scope_id,
                generation: expected.generation,
                marker_id,
                wake_generation,
            }),
            (None, None) => None,
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "modal guest-work resume lost one half of its marker identity",
                ));
            }
        };
        if retirement.is_some_and(|retirement| {
            self.pending[index]
                .modal_work_history
                .iter()
                .filter(|item| **item == retirement)
                .count()
                != 1
        }) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "modal guest-work resume does not match one retained exact history item",
            ));
        }
        if let Err(error) = self.worker()?.resume_modal_guest_work(
            operation_id,
            scope_id,
            generation,
            marker_id,
            wake_generation,
        ) {
            return self.started_failure(operation_id.0, error);
        }
        self.pending[index].pending_modal_guest_work = None;
        self.pending[index].resumed_modal_work = retirement;
        match self.receive_step_inner(objects) {
            Ok(step) => {
                if let Some(retirement) = retirement {
                    self.account_resumed_modal_response(
                        operation_id.0,
                        operation_kind,
                        worker_generation,
                        retirement,
                        &step,
                    )?;
                }
                Ok(step)
            }
            Err(error) => {
                // The resume command may already have been accepted. Keep the
                // exact submitted identity/history in the owner so teardown
                // can account for it; never enqueue the same modal resume a
                // second time from this retry path.
                self.started_failure(operation_id.0, error)
            }
        }
    }

    fn started_failure(
        &mut self,
        id: u64,
        cause: RuntimeError,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let index = self
            .pending
            .iter()
            .position(|pending| pending.id == id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed USER operation lost its reserved host identity before terminal proof",
                )
            })?;
        if let Some(failure) = self.pending[index].terminal_started_failure.as_ref() {
            let expected_state = self.pending[index].native_state;
            if failure.operation.operation_id != Win16HostWindowOperationId(id)
                || failure.operation.kind != self.pending[index].kind
                || failure.worker_generation != self.pending[index].worker_generation
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "cached USER StartedFailure changed its real operation identity",
                ));
            }
            if failure.state != expected_state {
                if failure.state != Win16NativeWindowOperationState::Active
                    || expected_state != Win16NativeWindowOperationState::Returned
                    || (self.pending[index].response_error.is_none()
                        && self.pending[index].completion.is_none())
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "cached USER StartedFailure changed state without a real returned response",
                    ));
                }
                let returned = Arc::new(Win16WindowOperationStartedFailure {
                    operation: failure.operation,
                    worker_generation: failure.worker_generation,
                    state: Win16NativeWindowOperationState::Returned,
                    cause: Arc::clone(&failure.cause),
                });
                self.pending[index].terminal_started_failure = Some(Arc::clone(&returned));
                return Ok(Win16WindowStep::StartedFailure(returned));
            }
            return Ok(Win16WindowStep::StartedFailure(Arc::clone(failure)));
        }
        let pending = &self.pending[index];
        let shared_cause = pending
            .response_error
            .as_ref()
            .or_else(|| {
                pending
                    .completion
                    .as_ref()
                    .and_then(|completion| completion.first_cause.as_ref())
            })
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::new(cause));
        let failure = Arc::new(Win16WindowOperationStartedFailure {
            operation: Win16NativeWindowOperationProof {
                operation_id: Win16HostWindowOperationId(id),
                kind: pending.kind,
            },
            worker_generation: pending.worker_generation,
            state: pending.native_state,
            cause: shared_cause,
        });
        self.pending[index].terminal_started_failure = Some(Arc::clone(&failure));
        Ok(Win16WindowStep::StartedFailure(failure))
    }

    pub(super) fn poll_dde_callback(
        &mut self,
    ) -> Result<Option<Arc<Win16HostDdeCallbackStep>>, RuntimeError> {
        self.poll_dde_callback_inner()
    }

    pub(super) fn dde_callback_reply(
        &mut self,
        resume: Win16HostDdeResume,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        self.dde_callback_reply_inner(resume)
    }

    pub(super) fn take_dde_diagnostics(&mut self) -> Vec<Diagnostic> {
        self.take_dde_diagnostics_inner()
    }

    pub(super) fn shutdown(&mut self) -> Result<(), RuntimeError> {
        self.shutdown_inner()
    }

    pub(super) fn abort(&mut self) -> Result<runtime::Win16WindowAbortReceipt, RuntimeError> {
        self.abort_inner()
    }

    /// Bind each real terminal modal response to its already-retained USER
    /// operation. The cached abort receipt owns the response bytes; the
    /// pending operation stores only its exact vector index, so retries do
    /// not clone or synthesize modal identities.
    fn worker(&self) -> Result<&WindowWorker, RuntimeError> {
        self.worker
            .as_ref()
            .ok_or_else(|| self.worker_start_failure())
    }

    pub(super) fn worker_start_failure(&self) -> RuntimeError {
        self.worker_start_error.as_ref().map_or_else(
            || {
                RuntimeError::new(
                    Kind::HostFailure,
                    "Win16 native window worker is unavailable",
                )
            },
            |failure| {
                RuntimeError::with_source(
                    failure.kind(),
                    "Win16 native window worker failed to start",
                    Arc::clone(failure),
                )
            },
        )
    }

    fn send(&self, command: WorkerCommand) -> Result<(), RuntimeError> {
        self.worker()?
            .send(command)
            .map_err(|_| worker_stopped("send command to Win16 native window worker"))
    }
}

/// Modal hooks and unwind scopes are siblings of this USER adapter. Keep the
/// private carrier table encapsulated here while exposing only these typed
/// operations inside the `windows` module.
pub(in crate::windows) fn route_modal_guest_notification(
    message: &mut windows_sys::Win32::UI::WindowsAndMessaging::MSG,
) -> Result<bool, RuntimeError> {
    match win16_window_worker::worker_context() {
        Some(worker) => win16_guest_notifications::handle_modal_message(&worker, message),
        None => win16_guest_notifications::defer_modal_message(message),
    }
}

pub(in crate::windows) fn is_guest_notification_remove_retrieval() -> bool {
    win16_guest_notifications::is_guest_remove_retrieval()
}

pub(in crate::windows) fn requeue_deferred_guest_notifications() -> Result<(), RuntimeError> {
    win16_guest_notifications::requeue_deferred()
}

#[cfg(test)]
#[path = "win16_ctl3d_reentrancy_tests.rs"]
mod win16_ctl3d_reentrancy_tests;

impl Drop for Win16Windows {
    fn drop(&mut self) {
        let _ = self.abort();
    }
}

fn worker_stopped(operation: &str) -> RuntimeError {
    RuntimeError::new(
        Kind::HostFailure,
        format!("{operation}: Win16 native window worker stopped"),
    )
}

fn combine_begin_cleanup(primary: RuntimeError, cleanup: Result<(), RuntimeError>) -> RuntimeError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => primary.with_cleanup(
            "Win16 USER Begin send and bitmap cleanup both failed",
            cleanup,
        ),
    }
}
