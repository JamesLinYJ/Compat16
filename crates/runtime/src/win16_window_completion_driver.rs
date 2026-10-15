//! Frame-owned projection and source retirement for native USER returns.

use super::*;

impl Win16State {
    pub(super) fn project_window_completion(
        &mut self,
        frame_id: u64,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(u32, Win16ReturnKind), RuntimeError> {
        if let Err(error) = super::super::window_drop_completion::prepare_queued_drop_delivery(
            self, frame_id, memory, host,
        ) {
            return self.retain_window_completion_failure(frame_id, error);
        }
        if self.window_completion_needs_state_projection(frame_id)? {
            return self.project_state_owned_window_completion(frame_id, memory, host);
        }
        let is_create = self
            .window_operations
            .last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .is_some_and(|completion| {
                matches!(
                    (&completion.continuation, &completion.result),
                    (WindowReturn::Create { .. }, Win16WindowResult::Created(_)),
                )
            });
        if is_create {
            let projected = self.project_create_window_completion(frame_id);
            return match projected {
                Ok((value, return_kind)) => {
                    let completion = self
                        .window_operations
                        .last_mut()
                        .filter(|frame| frame.id == frame_id)
                        .and_then(|frame| frame.completion.as_mut())
                        .ok_or_else(|| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "CreateWindow result disappeared after projection",
                            )
                        })?;
                    completion.journal.phase =
                        WindowOperationCompletionPhase::GuestProjected { value, return_kind };
                    Ok((value, return_kind))
                }
                Err(error) => self.retain_window_completion_failure(frame_id, error),
            };
        }
        let is_query_procedure = self
            .window_operations
            .last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .is_some_and(|completion| {
                matches!(
                    (&completion.continuation, &completion.result),
                    (
                        WindowReturn::QueryProcedure { .. }
                            | WindowReturn::PrepareNativeSubclass { .. }
                            | WindowReturn::NativeSubclass(_),
                        Win16WindowResult::Procedure(_) | Win16WindowResult::SubclassProcedure { .. }
                    ),
                )
            });
        if is_query_procedure {
            let projected = self.project_query_procedure_completion(frame_id, memory);
            return match projected {
                Ok((value, return_kind)) => {
                    let completion = self
                        .window_operations
                        .last_mut()
                        .filter(|frame| frame.id == frame_id)
                        .and_then(|frame| frame.completion.as_mut())
                        .ok_or_else(|| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "QueryWindowProcedure result disappeared after projection",
                            )
                        })?;
                    completion.journal.phase =
                        WindowOperationCompletionPhase::GuestProjected { value, return_kind };
                    Ok((value, return_kind))
                }
                Err(error) => self.retain_window_completion_failure(frame_id, error),
            };
        }
        let is_explicit_destroy = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .is_some_and(|completion| matches!(
                (&completion.continuation, &completion.result),
                (WindowReturn::WindowCall(call),
                    Win16WindowResult::WindowCall(crate::Win16WindowCallResult::Destroyed { .. }))
                    if call.destroyed_guest_window.is_some(),
            ));
        if is_explicit_destroy {
            return self.project_explicit_destroy_completion(frame_id);
        }
        let projection_result = {
            let Self {
                window_operations,
                selectors,
                guest_gdi,
                guest_menus,
                guest_images,
                guest_accelerators,
                window_classes,
                timers,
                clipboard_state,
                window_handles,
                window_parents,
                window_parent_observations,
                window_procedures,
                window_system_classes,
                mdi_children,
                dialog_procedures,
                tasks,
                task_handles,
                user_task_queue,
                owned_window_handles,
                next_window_handle,
                pending_kernel_diagnostic_effects,
                ..
            } = self;
            let (frame, prior_operations) =
                window_operations.split_last_mut().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "exact USER completion frame disappeared before projection",
                    )
                })?;
            if frame.id != frame_id {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "exact USER completion frame changed before projection",
                ));
            }
            let mut access = WindowProjectionAccess {
                selectors,
                guest_gdi,
                guest_menus,
                timers,
                clipboard_state,
                window_handles,
                window_parents,
                window_parent_observations,
                prior_operations,
                owned_window_handles,
                next_window_handle,
                window_system_classes,
                mdi_children,
                guest_images,
                guest_accelerators,
                window_classes,
                window_procedures,
                dialog_procedures,
                user_task_queue: *user_task_queue,
                current_task_owner: tasks.current(),
                task_handles,
                kernel_diagnostic_effects: pending_kernel_diagnostic_effects,
            };
            let completion = frame.completion.as_mut().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "USER completion result disappeared before projection",
                )
            })?;
            if !completion.journal.owns_return(&completion.continuation) {
                Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "USER completion journal does not own its exact continuation",
                ))
            } else if completion.journal.phase != WindowOperationCompletionPhase::Received {
                Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "USER completion projection was invoked in the wrong phase",
                ))
            } else {
                let projected = if let (
                    WindowReturn::KernelDiagnostics(continuation),
                    result,
                    WindowProjectionJournal::Api(WindowApiProjectionJournal::KernelDiagnostics(
                        phase,
                    )),
                ) = (
                    &completion.continuation,
                    &completion.result,
                    &mut completion.journal.projection,
                ) {
                    super::completion_native_api::finish_kernel_diagnostic(
                        continuation,
                        result,
                        phase,
                        &mut completion.journal.kernel_effect,
                        &mut access,
                    )
                } else {
                    match (
                        &mut completion.continuation,
                        &completion.result,
                        &mut completion.journal.projection,
                    ) {
                        (
                            WindowReturn::Menu(call),
                            Win16WindowResult::Menu(result),
                            WindowProjectionJournal::Menu { phase, value },
                        ) => super::completion_native_api::finish_menu_call(
                            call,
                            result,
                            phase,
                            value,
                            &mut access,
                            memory,
                        ),
                        (
                            WindowReturn::MessageCall(call),
                            Win16WindowResult::MessageCall(result),
                            WindowProjectionJournal::MessageCall { phase, value },
                        ) => super::completion_api::finish_message_call(
                            call,
                            result,
                            phase,
                            value,
                            &mut access,
                            memory,
                        ),
                        (
                            WindowReturn::UpdateRegion(call),
                            Win16WindowResult::UpdateRegion(result),
                            WindowProjectionJournal::UpdateRegion { phase, value },
                        ) => super::completion_native_api::finish_update_region(
                            call, result, phase, value, &access, memory,
                        ),
                        (
                            WindowReturn::ScrollBar(call),
                            Win16WindowResult::ScrollBar(result),
                            WindowProjectionJournal::ScrollBar { phase, value },
                        ) => super::completion_native_api::finish_scroll_bar(
                            call, result, phase, value, &access, memory,
                        ),
                        (
                            WindowReturn::SetWindowText,
                            Win16WindowResult::WindowTextSet(succeeded),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::SetWindowText(phase),
                            ),
                        ) => {
                            if *phase == super::operation_frame::WindowTextSetProjectionPhase::Ready
                            {
                                *phase = super::operation_frame::WindowTextSetProjectionPhase::ReturnReady;
                            }
                            *phase = super::operation_frame::WindowTextSetProjectionPhase::Complete;
                            // Native success remains in the retained host result; the
                            // Win16 API has no guest-visible return value.
                            Ok((u32::from(*succeeded), Win16ReturnKind::Void))
                        }
                        (
                            WindowReturn::GetWindowTextLength,
                            Win16WindowResult::WindowTextLength(value),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::GetWindowTextLength(phase),
                            ),
                        ) => {
                            if *phase
                                == super::operation_frame::WindowTextLengthProjectionPhase::Ready
                            {
                                *phase = super::operation_frame::WindowTextLengthProjectionPhase::ReturnReady;
                            }
                            *phase =
                                super::operation_frame::WindowTextLengthProjectionPhase::Complete;
                            let length = u32::try_from(*value).map_err(|_| {
                                RuntimeError::new(
                                    Kind::HostFailure,
                                    "native window text length returned a negative value",
                                )
                            })?;
                            Ok((length, Win16ReturnKind::Word))
                        }
                        (
                            WindowReturn::Icon { .. },
                            Win16WindowResult::StaticIcon(crate::Win16HostStaticIconResult::Icon(
                                icon,
                            )),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::Icon(owner)),
                        ) => {
                            use super::operation_frame::IconProjectionPhase as Phase;
                            if owner.phase == Phase::Ready {
                                let guest = match *icon {
                                    Some(icon) => guest_images
                                        .allocate_icon(icon)
                                        .map(|(handle, _)| handle)
                                        .ok_or_else(|| {
                                            RuntimeError::new(
                                                Kind::ResourceExhausted,
                                                "Win16 icon handle table is full",
                                            )
                                        }),
                                    None => Ok(0),
                                };
                                match guest {
                                    Ok(handle) => {
                                        owner.value = Some(handle);
                                        owner.phase = Phase::Complete;
                                        Ok((u32::from(handle), Win16ReturnKind::Dword))
                                    }
                                    Err(error) => Err(error),
                                }
                            } else {
                                owner
                                    .value
                                    .map(|handle| {
                                        owner.phase = Phase::Complete;
                                        (u32::from(handle), Win16ReturnKind::Dword)
                                    })
                                    .ok_or_else(|| {
                                        RuntimeError::new(
                                            Kind::InternalInvariant,
                                            "static-icon projection lost its cached guest handle",
                                        )
                                    })
                            }
                        }
                        (
                            WindowReturn::Icon { window, message },
                            Win16WindowResult::StaticIcon(
                                crate::Win16HostStaticIconResult::Untranslated,
                            ),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::Icon(owner)),
                        ) => {
                            let _ = owner;
                            Err(RuntimeError::new(
                                Kind::CompatibilityGap,
                                format!(
                                    "Win16 control message 0x{message:04X} for guest HWND 0x{window:04X} has no exact parameter conversion owner"
                                ),
                            ))
                        }
                        (
                            WindowReturn::GetWindowText {
                                output,
                                output_range,
                            },
                            Win16WindowResult::WindowText { value, buffer },
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::GetWindowText(owner),
                            ),
                        ) => {
                            if buffer.len() > usize::from(output.capacity)
                                || buffer.len() > output_range.length()
                            {
                                Err(RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "native window text exceeded its retained guest output range",
                                ))
                            } else {
                                use super::operation_frame::GuestTextProjectionPhase as Phase;
                                let write = if owner.phase == Phase::Ready {
                                    match super::super::guest_ranges::commit_guest_output_with_selectors(
                                    access.selectors,
                                    memory,
                                    output_range,
                                    buffer,
                                ) {
                                    Ok(()) => {
                                        owner.phase = Phase::OutputCommitted;
                                        Ok(())
                                    }
                                    Err(error) => Err(error),
                                }
                                } else {
                                    Ok(())
                                };
                                match write {
                                    Err(error) => Err(error),
                                    Ok(()) => {
                                        if owner.value.is_none() {
                                            owner.value = Some(*value as u32);
                                            owner.phase = Phase::ValueCaptured;
                                        }
                                        owner.phase = Phase::Complete;
                                        owner.value.map(|value| (value, Win16ReturnKind::Word))
                                        .ok_or_else(|| RuntimeError::new(
                                            Kind::InternalInvariant,
                                            "window-text completion lost its cached return value",
                                        ))
                                    }
                                }
                            }
                        }
                        (
                            WindowReturn::GetMessage { output },
                            Win16WindowResult::QueuedMessage(message),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::GetMessage(
                                owner,
                            )),
                        ) => super::completion_api::finish_queued_message(
                            output,
                            super::super::window_drop_completion::queued_delivery_message(message)?,
                            true,
                            owner,
                            &mut access,
                            memory,
                        ),
                        (
                            WindowReturn::PeekMessage { output },
                            Win16WindowResult::QueuedMessage(message),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::PeekMessage(
                                owner,
                            )),
                        ) => super::completion_api::finish_queued_message(
                            output,
                            super::super::window_drop_completion::queued_delivery_message(message)?,
                            false,
                            owner,
                            &mut access,
                            memory,
                        ),
                        (
                            WindowReturn::GetMessage { .. },
                            Win16WindowResult::MessageError,
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::GetMessage(
                                owner,
                            )),
                        ) => cache_queued_message_return(owner, u32::from(u16::MAX)),
                        (
                            WindowReturn::PeekMessage { .. },
                            Win16WindowResult::MessageError,
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::PeekMessage(
                                owner,
                            )),
                        ) => cache_queued_message_return(owner, 0),
                        (
                            WindowReturn::TranslateMessage,
                            Win16WindowResult::Translated(value),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::TranslateMessage(phase),
                            ),
                        ) => cache_simple_return(phase, u32::from(*value), Win16ReturnKind::Word),
                        (
                            WindowReturn::DispatchMessage { mdi_output: None },
                            Win16WindowResult::Dispatched(value),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::DispatchMessage(phase),
                            ),
                        )
                        | (
                            WindowReturn::GuestDispatch,
                            Win16WindowResult::Dispatched(value),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::GuestDispatch(phase),
                            ),
                        )
                        | (
                            WindowReturn::GuestTimerDispatch,
                            Win16WindowResult::Dispatched(value),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::GuestTimerDispatch(phase),
                            ),
                        ) => cache_simple_return(phase, *value as u32, Win16ReturnKind::Dword),
                        (
                            WindowReturn::GuestNotificationPost,
                            Win16WindowResult::NotificationPosted(posted),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::GuestNotificationPost(phase),
                            ),
                        ) => cache_simple_return(phase, u32::from(*posted), Win16ReturnKind::Word),
                        (
                            WindowReturn::PostQuitMessage,
                            Win16WindowResult::QuitPosted,
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::PostQuitMessage(phase),
                            ),
                        ) => cache_simple_return(phase, 0, Win16ReturnKind::Void),
                        (
                            WindowReturn::Show,
                            Win16WindowResult::Visibility(previous),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::Show(phase)),
                        ) => cache_visibility_return(phase, u32::from(previous.unwrap_or(false))),
                        (
                            WindowReturn::WindowProperties(pending),
                            Win16WindowResult::WindowCall(result),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::WindowProperties(owner),
                            ),
                        ) => {
                            super::completion_api::finish_window_properties(pending, result, owner)
                        }
                        (
                            WindowReturn::UserCursorAccelerator(continuation),
                            Win16WindowResult::UserCursorAccelerator(result),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::UserCursorAccelerator(owner),
                            ),
                        ) => super::completion_api::finish_cursor_accelerator(
                            continuation,
                            result,
                            owner,
                            &mut access,
                        ),
                        (
                            WindowReturn::Paint {
                                guest_dc_reserved,
                                output,
                                ..
                            },
                            Win16WindowResult::Paint { acquired },
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::Paint(owner)),
                        ) => super::completion_gdi::finish_paint(
                            output,
                            *guest_dc_reserved,
                            *acquired,
                            owner,
                            &mut access,
                            memory,
                        ),
                        (
                            WindowReturn::AcquireWindowDc {
                                guest_dc_reserved, consumed_region, ..
                            },
                            Win16WindowResult::WindowDc(acquired),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::AcquireWindowDc(owner),
                            ),
                        ) => super::completion_gdi::finish_acquire_dc(
                            *guest_dc_reserved,
                            *acquired,
                            *consumed_region,
                            owner,
                            &mut access,
                        ),
                        (
                            WindowReturn::EndPaint {
                                guest_dc,
                                native_dc,
                            },
                            Win16WindowResult::PaintEnded(succeeded),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::EndPaint(
                                owner,
                            )),
                        ) => super::completion_gdi::finish_dc_retirement(
                            *guest_dc,
                            *native_dc,
                            *succeeded,
                            Win16ReturnKind::Void,
                            owner,
                            &mut access,
                        ),
                        (
                            WindowReturn::ReleaseWindowDc {
                                guest_dc,
                                native_dc,
                            },
                            Win16WindowResult::DcReleased(succeeded),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::ReleaseWindowDc(owner),
                            ),
                        ) => super::completion_gdi::finish_dc_retirement(
                            *guest_dc,
                            *native_dc,
                            *succeeded,
                            Win16ReturnKind::Word,
                            owner,
                            &mut access,
                        ),
                        (
                            WindowReturn::CleanupPaint {
                                guest_dc_reserved, ..
                            },
                            Win16WindowResult::PaintEnded(succeeded),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::CleanupPaint(
                                owner,
                            )),
                        ) => super::completion_gdi::finish_dc_compensation(
                            *guest_dc_reserved,
                            *succeeded,
                            owner,
                            &mut access,
                        )
                        .map(|()| (0, Win16ReturnKind::Word)),
                        (
                            WindowReturn::CleanupWindowDc {
                                guest_dc_reserved, ..
                            },
                            Win16WindowResult::DcReleased(succeeded),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::CleanupWindowDc(owner),
                            ),
                        ) => super::completion_gdi::finish_dc_compensation(
                            *guest_dc_reserved,
                            *succeeded,
                            owner,
                            &mut access,
                        )
                        .map(|()| (0, Win16ReturnKind::Word)),
                        (
                            WindowReturn::WindowCall(call),
                            Win16WindowResult::WindowCall(result),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::WindowCall(
                                owner,
                            )),
                        ) => super::completion_api::finish_window_call(
                            call,
                            result,
                            owner,
                            &mut access,
                            memory,
                            host,
                        ),
                        (
                            WindowReturn::WindowData(continuation),
                            Win16WindowResult::WindowCall(
                                crate::Win16WindowCallResult::WindowData(result),
                            ),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::WindowData(
                                owner,
                            )),
                        ) => super::completion_api::finish_window_data(
                            continuation,
                            result,
                            owner,
                            &mut access,
                            host,
                        ),
                        (
                            WindowReturn::Message { output },
                            Win16WindowResult::Message(result),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::Message(
                                owner,
                            )),
                        ) => super::completion_api::finish_window_message(
                            output,
                            result.as_ref(),
                            owner,
                            &mut access,
                            memory,
                        ),
                        (
                            WindowReturn::UserMessageBox,
                            Win16WindowResult::UserService(
                                crate::Win16HostUserServiceResult::Dialog(
                                    crate::Win16HostDialogResult::MessageBox(value),
                                ),
                            ),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::UserMessageBox(phase),
                            ),
                        ) => cache_simple_return(phase, u32::from(*value), Win16ReturnKind::Word),
                        (
                            WindowReturn::GrayString { .. },
                            Win16WindowResult::GrayString(value),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::GrayString(phase)),
                        ) => cache_simple_return(phase, u32::from(*value), Win16ReturnKind::Word),
                        (
                            WindowReturn::DialogItemMessage { .. },
                            Win16WindowResult::UserService(
                                crate::Win16HostUserServiceResult::DialogControl(
                                    crate::Win16HostDialogControlResult::Item(None),
                                ),
                            ),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::DialogItemMessage(phase),
                            ),
                        ) => super::completion_api::finish_dialog_item_miss(phase),
                        (
                            WindowReturn::DialogItemMessage { .. },
                            Win16WindowResult::UserService(
                                crate::Win16HostUserServiceResult::DialogControl(
                                    crate::Win16HostDialogControlResult::Item(Some(_)),
                                ),
                            ),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::DialogItemMessage(_),
                            ),
                        ) => Err(RuntimeError::new(
                            Kind::CompatibilityGap,
                            "SendDlgItemMessage child lookup needs an exact same-frame SendMessage stage owner",
                        )),
                        (
                            WindowReturn::CommonControls(continuation),
                            Win16WindowResult::CommonControls(result),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::CommonControls { phase, value },
                            ),
                        ) => super::completion_native_api::finish_common_controls_simple(
                            continuation,
                            result,
                            phase,
                            value,
                            &mut access,
                            memory,
                        ),
                        (
                            WindowReturn::UserFamily(continuation),
                            Win16WindowResult::UserService(result),
                            WindowProjectionJournal::Api(WindowApiProjectionJournal::UserFamily(
                                owner,
                            )),
                        ) => super::completion_native_api::finish_user_family_simple(
                            continuation,
                            result,
                            owner,
                            &mut access,
                            memory,
                        ),
                        (
                            WindowReturn::GuestProcedureCall { return_kind },
                            Win16WindowResult::Dispatched(value),
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::GuestProcedureCall(phase),
                            ),
                        ) => cache_simple_return(phase, *value as u32, *return_kind),
                        (WindowReturn::Dde(_), _, _) => Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "DDE result must use its DDE-owned source-retired completion carrier",
                        )),
                        (_, Win16WindowResult::NativeModalCancelled(_), _) => {
                            Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "terminal modal cancellation cannot be projected as a normal USER result",
                            ))
                        }
                        _ => Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "native USER result variant does not match the exact retained continuation",
                        )),
                    }
                };
                match projected {
                    Ok((value, return_kind)) => {
                        completion.journal.phase =
                            WindowOperationCompletionPhase::GuestProjected { value, return_kind };
                        Ok((value, return_kind))
                    }
                    Err(error)
                        if matches!(
                            (&completion.continuation, &completion.result),
                            (
                                WindowReturn::Paint { .. },
                                Win16WindowResult::Paint { acquired: Some(_) }
                            ) | (
                                WindowReturn::AcquireWindowDc { .. },
                                Win16WindowResult::WindowDc(Some(_))
                            ),
                        ) =>
                    {
                        let error_kind = error.kind();
                        let cause = match &completion.journal.first_cause {
                            Some(cause) => std::sync::Arc::clone(cause),
                            None => std::sync::Arc::new(error),
                        };
                        if completion.journal.first_cause.is_none() {
                            completion.journal.first_cause = Some(std::sync::Arc::clone(&cause));
                        }
                        if let Some(cleanup) =
                            super::completion_gdi::compensation_return_after_projection_failure(
                                &completion.continuation,
                                &completion.result,
                                std::sync::Arc::clone(&cause),
                            )
                        {
                            completion.continuation = cleanup;
                            completion.journal.projection = WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::for_return(&completion.continuation),
                            );
                            completion.journal.phase = WindowOperationCompletionPhase::Received;
                            Err(RuntimeError::with_source(
                                error_kind,
                                "Win16 GDI result projection retained an exact HDC compensation owner",
                                std::sync::Arc::clone(&cause),
                            ))
                        } else {
                            Err(RuntimeError::with_source(
                                Kind::InternalInvariant,
                                "Win16 GDI projection failure lost its exact acquired HDC",
                                std::sync::Arc::clone(&cause),
                            ))
                        }
                    }
                    Err(error) => Err(error),
                }
            }
        };
        match projection_result {
            Ok(value) => Ok(value),
            Err(error) => self.retain_window_completion_failure(frame_id, error),
        }
    }

    fn project_explicit_destroy_completion(
        &mut self,
        frame_id: u64,
    ) -> Result<(u32, Win16ReturnKind), RuntimeError> {
        use super::operation_frame::WindowCallProjectionPhase as Phase;
        let frame = self.window_operations.last_mut()
            .filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DestroyWindow projection lost its exact source frame"))?;
        let mut completion = frame.completion.take().ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "DestroyWindow projection lost its cached result")
        })?;
        // Temporarily borrow the carrier, as for state-owned message output.
        // Always restore it, including after partial cleanup failure. Retrying
        // consumes the same receipts and never repeats native DestroyWindow.
        let result = (|| {
            let (
                WindowReturn::WindowCall(call),
                Win16WindowResult::WindowCall(crate::Win16WindowCallResult::Destroyed {
                    succeeded, retirements,
                }),
                WindowProjectionJournal::Api(WindowApiProjectionJournal::WindowCall(owner)),
            ) = (&completion.continuation, &completion.result, &mut completion.journal.projection)
            else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DestroyWindow result has no matching completion owner"));
            };
            if call.destroyed_guest_window.is_none()
                || !matches!(call.output, crate::Win16WindowCallOutput::None)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DestroyWindow result conflicts with its captured output contract"));
            }
            if owner.phase == Phase::Ready {
                self.retire_exact_window_retirement_batch(retirements)?;
                owner.value = Some(u32::from(*succeeded));
                owner.phase = Phase::Complete;
            }
            if owner.phase != Phase::Complete {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DestroyWindow projection has an unexpected retirement phase"));
            }
            owner.value.map(|value| (value, call.return_kind)).ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant,
                    "DestroyWindow projection lost its cached BOOL result")
            })
        })();
        self.window_operations.last_mut().expect("projection cannot pop its source frame")
            .completion = Some(completion);
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.retain_window_completion_failure(frame_id, error),
        }
    }
}

pub(super) fn cache_simple_return(
    phase: &mut super::operation_frame::SimpleReturnProjectionPhase,
    value: u32,
    return_kind: Win16ReturnKind,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::operation_frame::SimpleReturnProjectionPhase as Phase;
    match phase {
        Phase::Ready => *phase = Phase::ValueCaptured,
        Phase::ValueCaptured | Phase::ReturnInstalled | Phase::Complete => {}
    }
    if *phase == Phase::ValueCaptured {
        *phase = Phase::ReturnInstalled;
    }
    *phase = Phase::Complete;
    Ok((value, return_kind))
}

fn cache_visibility_return(
    phase: &mut super::operation_frame::VisibilityProjectionPhase,
    value: u32,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::operation_frame::VisibilityProjectionPhase as Phase;
    match phase {
        Phase::Ready => *phase = Phase::ValueCaptured,
        Phase::ValueCaptured | Phase::ReturnReady | Phase::Complete => {}
    }
    if *phase == Phase::ValueCaptured {
        *phase = Phase::ReturnReady;
    }
    *phase = Phase::Complete;
    Ok((value, Win16ReturnKind::Word))
}

fn cache_queued_message_return(
    owner: &mut super::operation_frame::QueuedMessageProjection,
    value: u32,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::operation_frame::QueuedMessageProjectionPhase as Phase;
    if let Some(cached) = owner.value {
        if cached != value {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "queued-message API error changed its retained Win16 result",
            ));
        }
    } else {
        owner.value = Some(value);
    }
    match owner.phase {
        Phase::Ready
        | Phase::QueueOwnerValidated
        | Phase::GuestHandlesMapped
        | Phase::OutputCommitted => owner.phase = Phase::ReturnReady,
        Phase::ReturnReady | Phase::Complete => {}
    }
    owner.phase = Phase::Complete;
    Ok((value, Win16ReturnKind::Word))
}
