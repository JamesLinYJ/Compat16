//! Checked guest DLGPROC entry setup for native dialog callbacks.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn begin_dialog_callback(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        operation_id: crate::Win16HostWindowOperationId,
        callback: Win16HostCallback,
        native_window: Win16HostWindow,
        message: Win16HostDialogMessage,
        source: crate::Win16NativeCallbackSource,
    ) -> Result<bool, RuntimeError> {
        let is_init = matches!(&message, Win16HostDialogMessage::Init { .. });
        let focus_native = match &message {
            Win16HostDialogMessage::Init { focus, .. } => *focus,
            _ => None,
        };
        let focus_ancestry = match &message {
            Win16HostDialogMessage::Init { focus_ancestry, .. } => focus_ancestry.clone(),
            _ => Vec::new(),
        };
        let notification_alias = match &message {
            Win16HostDialogMessage::Message(
                crate::Win16HostMessage::GuestNotification(notification),
            ) => match notification.target {
                crate::Win16GuestNotificationTarget::Window { window, guest_hwnd }
                    if window == native_window
                        && self.window_handles.get(&guest_hwnd) == Some(&window) =>
                            Some(guest_hwnd),
                _ => return Ok(false),
            },
            _ => None,
        };
        let mapped_window = notification_alias.or_else(|| self.window_handles.iter()
            .find_map(|(guest, native)| (*native == native_window).then_some(*guest)));
        let pending_route = if is_init || mapped_window.is_none() {
            self.pending_dialog_procedure_for(native_window)
        } else {
            None
        };
        let pending_procedure = pending_route.and_then(|(procedure, _, _)| procedure);
        let window = match (mapped_window, pending_route) {
            (Some(window), _) => window,
            (None, Some(_)) => self.map_window_handle(native_window, false)?,
            (None, None) => {
                if matches!(
                    &message,
                    Win16HostDialogMessage::Message(Win16HostMessage::Scalar {
                        kind: Win16ScalarMessage::NcDestroy,
                        ..
                    })
                ) {
                    self.mark_pending_dialog_destroyed(native_window);
                }
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "native dialog callback has no guest HWND mapping; dialog default handling was used",
                ));
                return Ok(false);
            }
        };
        let is_destroy = matches!(
            &message,
            Win16HostDialogMessage::Message(Win16HostMessage::Scalar {
                kind: Win16ScalarMessage::NcDestroy,
                ..
            })
        );
        let procedure = if is_init {
            pending_procedure.or_else(|| self.dialog_procedures.get(&window).copied())
        } else {
            self.dialog_procedures
                .get(&window)
                .copied()
                .or(pending_procedure)
        };
        let known_null_procedure = pending_route.is_some_and(|(procedure, _, _)| procedure.is_none())
            || self.dialog_procedures.get(&window)
                .is_some_and(|(procedure, _)| *procedure == 0);
        let dialog_instance = pending_route.map(|(_, instance, _)| instance)
            .or_else(|| self.dialog_procedures.get(&window).map(|(_, instance)| *instance));
        let source_root = WindowClassRoot::from_native_message(source, native_window);
        let existing_root = self.window_class_root(window);
        let pending_root = pending_route.map_or(WindowClassRoot::Unresolved, |(_, _, root)| root);
        let valid_root = source_root != WindowClassRoot::Unresolved
            && [existing_root, pending_root].into_iter().all(|root|
                root == WindowClassRoot::Unresolved || root == source_root);
        let class_root = if valid_root { source_root } else { WindowClassRoot::Unresolved };
        let Some((address, instance)) = procedure.filter(|(address, _)| *address != 0) else {
            let owner = if self.has_pending_window_parent_mutation() {
                Some(self.retain_default_dialog_parent_callback(
                    registers, operation_id, callback, native_window, window,
                    class_root, source, is_destroy,
                )?)
            } else { None };
            let setup = (|| {
                if !valid_root {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native DLGPROC source differs from its exact dialog class provenance"));
                }
                if let Some(instance) = dialog_instance {
                    self.initialize_dialog_window_data(window, instance)?;
                    self.record_window_class_root(window, native_window, class_root)?;
                    if is_init {
                        self.dialog_procedures.insert(window, (0, instance));
                    }
                }
                self.refresh_pending_window_parents(host)?;
                if is_destroy {
                    self.mark_pending_dialog_destroyed(native_window);
                    self.retire_window_tree(window)?;
                }
                if !known_null_procedure {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "native dialog procedure has no active checked Win16 DLGPROC; dialog default handling was used",
                    ));
                }
                // Windows 3.1 SDK DEFPROCS/DEFDLG.C:16-20 calls a DLGPROC only
                // when lpfnDlg is non-NULL; false returns fall through to
                // DefDlgProc. Keep this trampoline false and preserve MSGRESULT.
                Ok(())
            })();
            if let Err(error) = setup {
                return Err(match owner {
                    Some(callback_id) => self.fail_preparing_window_callback(callback_id, error),
                    None => error,
                });
            }
            if owner.is_some() {
                let frame = self.window_callbacks.last_mut().expect("default dialog owner retained");
                frame.payload_cleaned = true;
                frame.window_tree_retired = is_destroy;
            }
            return Ok(false);
        };

        let callback_id = self.reserve_window_callback_frame()?;
        let guest_notification = match &message {
            Win16HostDialogMessage::Message(
                crate::Win16HostMessage::GuestNotification(notification),
            ) => Some(*notification),
            _ => None,
        };
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
            guest_notification,
            mdi_child_creation: None,
            callback_address: address,
            class_root,
            host_operation: Some(operation_id),
            native_source: Some(source),
            continuation: WindowCallbackContinuation::HostDialog {
                callback,
                native_window,
                window,
                destroyed: is_destroy,
            },
        })?;

        let setup = (|| {
            self.refresh_pending_window_parents(host)?;
            if !valid_root {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native DLGPROC source differs from its exact dialog class provenance"));
            }
            if is_destroy {
                self.mark_pending_dialog_destroyed(native_window);
                self.record_preparing_window_callback_phase(
                    callback_id,
                    WindowCallbackSetupPhase::DestroyMarked,
                );
            }
            self.initialize_dialog_window_data(window, instance)?;
            self.record_window_class_root(window, native_window, class_root)?;
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::DialogDataInitialized,
            );
            self.reset_dialog_message_result(window);
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::DialogResultReset,
            );
            self.check_window_callback(registers, address, memory)?;
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::ProcedureValidated,
            );
            let payload = self.prepare_dialog_callback_payload(message, memory, host)?;
            let callback_message = payload.message;
            // Keep any command-parent error pending until the payload and its
            // temporary allocation have an exact frame owner.
            let command_parent = if is_init {
                Ok(())
            } else {
                self.record_native_command_parent(&payload)
            };
            {
                let frame = self.window_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "pre-entry DLGPROC frame disappeared during payload preparation",
                ))?;
                debug_assert_eq!(frame.callback_id, callback_id);
                frame.payload_allocation_locked = payload.allocation.is_some();
                frame.payload = payload;
            }
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::PayloadPrepared,
            );
            command_parent?;
            let link_result: Result<(), RuntimeError> = (|| {
                if is_init {
                    if let Some(native_focus) = focus_native {
                        self.map_window_handle(native_focus, false)?;
                        self.record_preparing_window_callback_phase(
                            callback_id,
                            WindowCallbackSetupPhase::FocusMapped,
                        );
                    }
                    for (native_child, native_parent) in &focus_ancestry {
                        let child = self.map_window_handle(*native_child, false)?;
                        self.record_preparing_window_callback_phase(
                            callback_id,
                            WindowCallbackSetupPhase::FocusAncestorChildMapped,
                        );
                        let parent = self.map_window_handle(*native_parent, false)?;
                        self.record_preparing_window_callback_phase(
                            callback_id,
                            WindowCallbackSetupPhase::FocusAncestorParentMapped,
                        );
                        self.set_window_parent_from_host(child, parent)?;
                        self.record_preparing_window_callback_focus_link(callback_id);
                    }
                    Ok(())
                } else {
                    self.record_preparing_window_callback_phase(
                        callback_id,
                        WindowCallbackSetupPhase::CommandParentResolved,
                    );
                    Ok(())
                }
            })();
            link_result?;
            let retained_payload = &self.window_callbacks.last()
                .expect("pre-entry DLGPROC payload retained").payload;
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
        if is_init {
            self.dialog_procedures.insert(window, (address, instance));
            self.record_preparing_window_callback_phase(
                callback_id,
                WindowCallbackSetupPhase::DialogProcedureCommitted,
            );
        }
        let frame = self.window_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "pre-entry DLGPROC frame disappeared before guest entry",
        ))?;
        debug_assert_eq!(frame.callback_id, callback_id);
        frame.entry_phase = WindowCallbackEntryPhase::GuestCallback;
        frame.guest_drop_global = None;
        registers.set_sp(registers.sp() - WNDPROC_STACK_BYTES);
        registers.cs = (address >> 16) as u16;
        registers.set_ip(address as u16);
        registers.set_ax(instance);
        registers.ds = registers.ss;
        registers.es = registers.ss;
        frame.setup.last_completed = WindowCallbackSetupPhase::GuestEntryCommitted;
        if host.win16_service_trace_enabled() {
            host.observe_win16_io(&crate::Win16IoEvent::WindowCallback {
                callback: callback.0,
                window,
                procedure: crate::Win16WindowCallbackProcedure::DialogProcedure,
                phase: crate::Win16WindowCallbackPhase::GuestEntry,
                message: callback_message,
                return_value: None,
                dialog_message_result: None,
            });
        }
        Ok(true)
    }
}
