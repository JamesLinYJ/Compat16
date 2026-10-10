//! Publish exact callback owners before entering fallible guest setup.

use std::sync::Arc;

use super::*;

impl Win16State {
    pub(super) fn reserve_window_callback_frame(
        &mut self,
    ) -> Result<CallbackFrameId, RuntimeError> {
        self.window_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain exact Win16 USER callback owner",
                error,
            )
        })?;
        self.reserve_callback_frame_id()
    }

    pub(super) fn publish_window_callback_frame(
        &mut self,
        frame: WindowCallbackFrame,
    ) -> Result<(), RuntimeError> {
        // The ID comes from the same monotonic allocator as Font/ACM and the
        // callback stack has capacity before this binding is published.
        self.push_callback_kind(CallbackKind::Window, frame.callback_id)?;
        self.window_callbacks.push(frame);
        Ok(())
    }

    pub(in crate::win16_runtime) fn begin_host_window_callback(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        operation_id: crate::Win16HostWindowOperationId,
        callback: Win16HostCallback,
        native_window: Win16HostWindow,
        window: u16,
        procedure: WindowProcedure,
        message: Win16HostMessage,
        creation: Option<&WindowCreateRequest>,
        source: crate::Win16NativeCallbackSource,
        destroyed: bool,
    ) -> Result<(), RuntimeError> {
        let guest_notification = match &message {
            Win16HostMessage::GuestNotification(notification) => Some(*notification),
            _ => None,
        };
        let mdi_child_creation = match &message {
            Win16HostMessage::MdiChildCreation { data, .. } => Some(data.clone()),
            _ => None,
        };
        let callback_id = self.reserve_window_callback_frame()?;
        let expected_root = WindowClassRoot::Class(procedure.class);
        let class_root = if WindowClassRoot::from_native_message(source, native_window) == expected_root {
            expected_root
        } else {
            WindowClassRoot::Unresolved
        };
        let frame = WindowCallbackFrame {
            callback_id,
            saved: registers.clone(),
            payload: GuestWindowPayload {
                message: 0,
                w_param: 0,
                l_param: 0,
                allocation: None,
                output: None,
                callback_dc: None,
                command_control: None,
                command_parent: None,
                common_dialog_request: None,
            },
            payload_allocation_locked: false,
            guest_drop_global: None,
            guest_drop_generation: None,
            payload_selector: None,
            guest_return_value: None,
            payload_result: None,
            payload_error: None,
            payload_cleanup_error: None,
            payload_retained: None,
            payload_cleaned: false,
            window_tree_retired: false,
            clipboard_retired: false,
            trace_observed: false,
            native_resume_error: None,
            setup_error: None,
            entry_phase: WindowCallbackEntryPhase::Preparing,
            setup: WindowCallbackSetupJournal::preparing(),
            guest_notification,
            mdi_child_creation,
            callback_address: procedure.address,
            class_root,
            host_operation: Some(operation_id),
            native_source: Some(source),
            continuation: WindowCallbackContinuation::Host {
                callback,
                native_window,
                window,
                destroyed,
            },
        };
        self.publish_window_callback_frame(frame)?;

        let setup = (|| {
            self.refresh_pending_window_parents(host)?;
            if class_root == WindowClassRoot::Unresolved {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native WndProc source differs from its exact selected class registration"));
            }
            self.record_window_class_root(window, native_window, class_root)?;
            self.check_window_callback(registers, procedure.address, memory)?;
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::ProcedureValidated,
            );
            let payload = self.prepare_window_payload(
                message, Some(window), creation, memory, host,
            )?;
            let callback_message = payload.message;
            // Save any command-parent validation failure until the owned
            // payload is installed in its already-published callback frame.
            let command_parent = self.record_native_command_parent(&payload);
            let retained = self.window_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "pre-entry WndProc frame disappeared during payload retention",
            ))?;
            debug_assert_eq!(retained.callback_id, callback_id);
            retained.payload_allocation_locked = payload.allocation.is_some();
            retained.payload = payload;
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::PayloadPrepared,
            );
            command_parent?;
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::CommandParentResolved,
            );
            let retained_payload = &self.window_callbacks.last()
                .expect("pre-entry WndProc payload retained").payload;
            self.write_window_callback_stack(registers, window, retained_payload, memory)?;
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::CallbackStackWritten,
            );
            Ok(callback_message)
        })();
        let callback_message = match setup {
            Ok(message) => message,
            Err(error) => {
                return Err(self.fail_preparing_window_callback(callback_id, error));
            }
        };
        let frame = self.window_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "pre-entry WndProc frame disappeared before guest entry",
        ))?;
        debug_assert_eq!(frame.callback_id, callback_id);
        frame.entry_phase = WindowCallbackEntryPhase::GuestCallback;
        // The callback now owns the HGLOBAL through its WM_DROPFILES wParam;
        // teardown must not free a handle the guest may retain or finish.
        frame.guest_drop_global = None;
        registers.set_sp(registers.sp() - WNDPROC_STACK_BYTES);
        registers.cs = (procedure.address >> 16) as u16;
        registers.set_ip(procedure.address as u16);
        registers.set_ax(procedure.instance);
        registers.ds = registers.ss;
        registers.es = registers.ss;
        frame.setup.last_completed = WindowCallbackSetupPhase::GuestEntryCommitted;
        if host.win16_service_trace_enabled() {
            host.observe_win16_io(&crate::Win16IoEvent::WindowCallback {
                callback: callback.0,
                window,
                procedure: crate::Win16WindowCallbackProcedure::WindowProcedure,
                phase: crate::Win16WindowCallbackPhase::GuestEntry,
                message: callback_message,
                return_value: None,
                dialog_message_result: None,
            });
        }
        Ok(())
    }

    /// A null DLGPROC still has a real suspended native callback. Retain a
    /// payload-free owner while querying pending parent changes and retiring
    /// its tree; errors must not discard the only cancellable source identity.
    pub(super) fn retain_default_dialog_parent_callback(
        &mut self,
        registers: &Registers,
        operation_id: crate::Win16HostWindowOperationId,
        callback: Win16HostCallback,
        native_window: Win16HostWindow,
        window: u16,
        class_root: WindowClassRoot,
        source: crate::Win16NativeCallbackSource,
        destroyed: bool,
    ) -> Result<CallbackFrameId, RuntimeError> {
        let callback_id = self.reserve_window_callback_frame()?;
        self.publish_window_callback_frame(WindowCallbackFrame {
            callback_id,
            saved: registers.clone(),
            payload: GuestWindowPayload {
                message: 0,
                w_param: 0,
                l_param: 0,
                allocation: None,
                output: None,
                callback_dc: None,
                command_control: None,
                command_parent: None,
                common_dialog_request: None,
            },
            payload_allocation_locked: false,
            guest_drop_global: None,
            guest_drop_generation: None,
            payload_selector: None,
            guest_return_value: None,
            payload_result: None,
            payload_error: None,
            payload_cleanup_error: None,
            payload_retained: None,
            payload_cleaned: false,
            window_tree_retired: false,
            clipboard_retired: false,
            trace_observed: false,
            native_resume_error: None,
            setup_error: None,
            entry_phase: WindowCallbackEntryPhase::Preparing,
            setup: WindowCallbackSetupJournal::preparing(),
            guest_notification: None,
            mdi_child_creation: None,
            callback_address: 0,
            class_root,
            host_operation: Some(operation_id),
            native_source: Some(source),
            continuation: WindowCallbackContinuation::HostDialog {
                callback,
                native_window,
                window,
                destroyed,
            },
        })?;
        Ok(callback_id)
    }

    pub(in crate::win16_runtime) fn preparing_window_callback_id(
        &self,
    ) -> Option<CallbackFrameId> {
        let frame = self.window_callbacks.last()?;
        (frame.entry_phase == WindowCallbackEntryPhase::Preparing).then_some(frame.callback_id)
    }

    pub(in crate::win16_runtime) fn retain_preparing_window_payload_allocation(
        &mut self,
        callback_id: CallbackFrameId,
        allocation: win16_abi::GlobalHandle,
        locked: bool,
        selector: Option<win16_abi::SelectorRef>,
    ) {
        let frame = self.window_callbacks.last_mut()
            .expect("pre-entry USER callback frame retained during payload allocation");
        debug_assert_eq!(frame.callback_id, callback_id);
        debug_assert_eq!(frame.entry_phase, WindowCallbackEntryPhase::Preparing);
        frame.payload.allocation = Some(allocation);
        frame.payload_allocation_locked = locked;
        frame.payload_selector = selector;
        frame.setup.last_completed = if locked {
            WindowCallbackSetupPhase::PayloadLocked
        } else {
            WindowCallbackSetupPhase::PayloadAllocated
        };
    }

    pub(in crate::win16_runtime) fn record_preparing_window_callback_phase(
        &mut self,
        callback_id: CallbackFrameId,
        phase: WindowCallbackSetupPhase,
    ) {
        let frame = self.window_callbacks.last_mut()
            .expect("pre-entry USER callback frame retained during setup");
        debug_assert_eq!(frame.callback_id, callback_id);
        debug_assert_eq!(frame.entry_phase, WindowCallbackEntryPhase::Preparing);
        frame.setup.last_completed = phase;
    }

    pub(in crate::win16_runtime) fn record_preparing_window_callback_focus_link(
        &mut self,
        callback_id: CallbackFrameId,
    ) {
        let frame = self.window_callbacks.last_mut()
            .expect("pre-entry DLGPROC frame retained during focus linking");
        debug_assert_eq!(frame.callback_id, callback_id);
        debug_assert_eq!(frame.entry_phase, WindowCallbackEntryPhase::Preparing);
        frame.setup.focus_links_completed += 1;
        frame.setup.last_completed = WindowCallbackSetupPhase::FocusAncestorLinked;
    }

    pub(in crate::win16_runtime) fn retain_preparing_window_callback_error(
        &mut self,
        callback_id: CallbackFrameId,
        error: RuntimeError,
    ) -> RuntimeError {
        let frame = self.window_callbacks.last_mut()
            .expect("pre-entry USER callback frame retained after payload setup error");
        debug_assert_eq!(frame.callback_id, callback_id);
        debug_assert_eq!(frame.entry_phase, WindowCallbackEntryPhase::Preparing);
        let kind = error.kind();
        let error = Arc::new(error);
        if frame.setup_error.is_none() {
            frame.setup_error = Some(Arc::clone(&error));
        }
        RuntimeError::with_source(kind, "Win16 USER callback setup failed", error)
    }

    pub(in crate::win16_runtime) fn fail_preparing_window_callback(
        &mut self,
        callback_id: CallbackFrameId,
        error: RuntimeError,
    ) -> RuntimeError {
        let frame = self.window_callbacks.last_mut()
            .expect("pre-entry USER callback frame retained after setup failure");
        debug_assert_eq!(frame.callback_id, callback_id);
        debug_assert_eq!(frame.entry_phase, WindowCallbackEntryPhase::Preparing);
        let kind = error.kind();
        let error = Arc::new(error);
        if frame.setup_error.is_none() {
            frame.setup_error = Some(Arc::clone(&error));
        }
        frame.entry_phase = WindowCallbackEntryPhase::SetupFailed;
        RuntimeError::with_source(kind, "Win16 USER callback setup failed", error)
    }
}
