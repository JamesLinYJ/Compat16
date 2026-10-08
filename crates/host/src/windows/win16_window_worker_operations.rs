//! Dispatch USER worker operations and complete their response channels.

use super::super::super::win16_modal::NativeModalOperationOutcome;
use super::*;

fn get_message_with_pending_guest_work(
    state: &Rc<RefCell<WorkerState>>,
    id: u64,
    filter: runtime::Win16MessageFilter,
    response: &Sender<Result<Win16WindowStep, RuntimeError>>,
) -> Result<Win16WindowResult, RuntimeError> {
    super::begin_user_wait(state, id, super::UserWaitKind::GetMessage)?;
    let outcome = (|| loop {
        // Internal DDE endpoints are not guest HWNDs and therefore are not
        // returned by the guest's native MSG filter. Pump their private
        // messages on this same USER thread before checking the wake cursor.
        super::pump_classic_dde_messages(state)?;
        match super::super::win16_message_loop::get_message(state, filter)? {
            super::super::win16_message_loop::MessagePoll::Message(message) => {
                return Ok(Win16WindowResult::QueuedMessage(message));
            }
            super::super::win16_message_loop::MessagePoll::Error => {
                return Ok(Win16WindowResult::MessageError);
            }
            super::super::win16_message_loop::MessagePoll::Empty => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native GetMessage completed without a message or API error",
                ));
            }
            super::super::win16_message_loop::MessagePoll::PendingGuestWork { generation } => {
                super::yield_pending_guest_work(
                    state,
                    id,
                    generation,
                    super::UserWaitKind::GetMessage,
                    response,
                )?;
            }
        }
    })();
    let retired = super::end_user_wait(state, id, super::UserWaitKind::GetMessage);
    match (outcome, retired) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(RuntimeError::with_source(
            primary.kind().with_cleanup(cleanup.kind()),
            "Win16 GetMessage failed while retiring classic-DDE wait ownership",
            WaitAndRetirementFailure { primary, cleanup },
        )),
    }
}

#[derive(Debug)]
struct WaitAndRetirementFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for WaitAndRetirementFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; wait cleanup failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for WaitAndRetirementFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

pub(super) fn run_operation(
    state: &Rc<RefCell<WorkerState>>,
    id: u64,
    operation: Win16WindowOperation,
    control_color_return: Option<ControlColorReturnSlot>,
    native_bitmaps: BTreeMap<Win16HostGdiObject, Option<usize>>,
    native_font: Option<(Win16HostGdiObject, usize)>,
    mut toolbar_bitmap_leases: BTreeMap<
        Win16HostGdiObject,
        Option<super::super::win16_gdi_bitmap_lease::Win16BitmapLease>,
    >,
    native_regions: BTreeMap<Win16HostGdiObject, Option<Win16RegionLease>>,
    response: Sender<Result<Win16WindowStep, RuntimeError>>,
) {
    if state.borrow().aborted {
        let primary = RuntimeError::new(
            Kind::HostFailure,
            "Win16 native window operation was canceled",
        );
        let _ = response.send(Err(combine_operation_cleanup(
            primary,
            release_toolbar_bitmap_leases(state, id, toolbar_bitmap_leases),
        )));
        return;
    }
    let preflight = {
        let mut worker = state.borrow_mut();
        let depth = worker
            .active_operations
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 USER operation nesting depth is exhausted",
                )
            });
        depth.and_then(|depth| {
            let failure_capacity = depth.checked_add(4).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 terminal failure ledger capacity is exhausted",
                )
            })?;
            worker.active_operations.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 USER active-operation tracking",
                    error,
                )
            })?;
            worker
                .cancelled_modals
                .try_reserve(depth)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve Win16 modal cancellation receipt tracking",
                        error,
                    )
                })?;
            worker
                .terminal_failures
                .try_reserve(failure_capacity)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve Win16 terminal failure tracking",
                        error,
                    )
                })?;
            worker.active_operations.push(ActiveOperation {
                id,
                native_font,
                kind: operation.native_operation_kind(),
                response: response.clone(),
                native_queue_dispatch: matches!(
                    &operation,
                    Win16WindowOperation::DispatchMessage { message }
                        if message.source == runtime::Win16MessageSource::NativeQueue
                ),
                native_dialog_pump: matches!(
                    &operation,
                    Win16WindowOperation::CommonDialog(_)
                        | Win16WindowOperation::UserService(
                            runtime::Win16HostUserServiceOperation::Dialog(
                                runtime::Win16HostDialogOperation::MessageBox { .. }
                                    | runtime::Win16HostDialogOperation::Create { modal: true, .. }
                            )
                        )
                ),
            });
            Ok(())
        })
    };
    if let Err(error) = preflight {
        let response_error = {
            let mut worker = state.borrow_mut();
            if worker.aborted || worker.modal_control.terminal_requested() {
                let failure = Arc::new(error);
                // The current active-operation ancestors reserved room for
                // one rejected nested call, their own unwind failures, and
                // terminal cleanup before any native entry was attempted.
                worker.terminal_failures.push(Arc::clone(&failure));
                RuntimeError::with_source(
                    failure.kind(),
                    "Win16 USER operation capacity preflight failed during terminal unwind",
                    Arc::clone(&failure),
                )
            } else {
                error
            }
        };
        let response_error = combine_operation_cleanup(
            response_error,
            release_toolbar_bitmap_leases(state, id, toolbar_bitmap_leases),
        );
        let _ = response.send(Err(response_error));
        return;
    }
    let result = match operation {
        Win16WindowOperation::UserService(operation) => {
            user_services::execute(state, id, operation, control_color_return.as_ref())
        }
        Win16WindowOperation::ShellExecution(operation) => {
            super::super::win16_shell_execution::execute(state, id, operation)
        }
        operation => {
            let result = match operation {
                Win16WindowOperation::Dde(_) => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE operation reached the USER worker",
                )),
                Win16WindowOperation::Thunk(_) => Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "Win16 thunk execution requires a separate legacy 32-bit DLL execution boundary",
                )),
                Win16WindowOperation::Create { creation, data } => {
                    create_window(state, creation, data).map(Win16WindowResult::Created)
                }
                Win16WindowOperation::Default {
                    window,
                    callback,
                    message,
                } => win16_window_callbacks::default_message(
                    state,
                    window,
                    callback,
                    message,
                    control_color_return.as_ref(),
                )
                .map(Win16WindowResult::Message),
                Win16WindowOperation::DefFrameProc {
                    frame,
                    mdi_client,
                    callback,
                    message,
                } => super::super::win16_window_default::frame_default_message(
                    state,
                    frame,
                    mdi_client,
                    callback,
                    message,
                    control_color_return.as_ref(),
                )
                .map(Win16WindowResult::Message),
                Win16WindowOperation::DefaultMdiChild {
                    window,
                    callback,
                    message,
                } => super::super::win16_window_default::mdi_child_default_message(
                    state,
                    window,
                    callback,
                    message,
                    control_color_return.as_ref(),
                )
                .map(Win16WindowResult::Message),
                Win16WindowOperation::TranslateMDISysAccel {
                    mdi_client,
                    message,
                } => super::super::win16_message_loop::translate_mdi_accelerator(
                    state, mdi_client, message,
                )
                .map(Win16WindowResult::Translated),
                Win16WindowOperation::Send { window, message } => {
                    super::super::win16_window_default::send_message(
                        state,
                        window,
                        message,
                        control_color_return.as_ref(),
                    )
                    .map(Win16WindowResult::Message)
                }
                Win16WindowOperation::StaticIcon {
                    window,
                    procedure,
                    operation,
                } => match procedure {
                    Some(procedure) => super::super::win16_native_procedures::call_static_icon(
                        state, procedure, window, operation,
                    ),
                    None => {
                        super::super::win16_static_controls::icon(state, window, None, operation)
                    }
                }
                .map(Win16WindowResult::StaticIcon),
                Win16WindowOperation::QueryProcedure { window } => {
                    super::super::win16_native_procedures::query(state, window)
                        .map(Win16WindowResult::Procedure)
                }
                Win16WindowOperation::CallProcedure {
                    procedure,
                    window,
                    callback,
                    message,
                } => super::super::win16_native_procedures::call(
                    state,
                    procedure,
                    window,
                    callback,
                    message,
                    control_color_return.as_ref(),
                )
                .map(Win16WindowResult::Message),
                Win16WindowOperation::Show { window, command } => Ok(
                    Win16WindowResult::Visibility(show_window(state, window, command)),
                ),
                Win16WindowOperation::Destroy { window } => {
                    let (succeeded, invalidated_menus) = destroy_window_operation(state, window);
                    Ok(Win16WindowResult::Destroyed {
                        succeeded,
                        invalidated_menus,
                    })
                }
                Win16WindowOperation::Menu(operation) => {
                    super::super::win16_menu_worker::execute(state, operation, &native_bitmaps)
                        .map(Win16WindowResult::Menu)
                }
                Win16WindowOperation::WindowCall(call) => {
                    super::super::win16_window_ops::execute(state, call)
                        .map(Win16WindowResult::WindowCall)
                }
                Win16WindowOperation::MessageCall(call) => {
                    super::super::win16_message_calls::execute(state, id, call, &response)
                        .map(Win16WindowResult::MessageCall)
                }
                Win16WindowOperation::UserService(_) => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 USER service escaped its native-modal outcome adapter",
                )),
                Win16WindowOperation::ShellExecution(_) => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 Shell operation escaped its native-modal outcome adapter",
                )),
                Win16WindowOperation::CommonControls(operation) => {
                    super::super::win16_common_controls_worker::execute(
                        state,
                        operation,
                        &mut toolbar_bitmap_leases,
                    )
                    .map(Win16WindowResult::CommonControls)
                }
                Win16WindowOperation::CommonDialog(operation) => {
                    super::super::win16_common_dialog_worker::execute(state, operation)
                        .map(Win16WindowResult::CommonDialog)
                }
                Win16WindowOperation::UpdateRegion(operation) => {
                    super::super::win16_user_services_update_region::execute(
                        state,
                        operation,
                        &native_regions,
                    )
                    .map(Win16WindowResult::UpdateRegion)
                }
                Win16WindowOperation::ScrollBar(operation) => {
                    super::super::win16_user_services_scroll_bar::execute(state, operation)
                        .map(Win16WindowResult::ScrollBar)
                }
                Win16WindowOperation::UserCursorAccelerator(operation) => {
                    super::super::win16_user_cursor_accelerator::execute(state, operation)
                        .map(Win16WindowResult::UserCursorAccelerator)
                }
                Win16WindowOperation::BeginPaint { window } => {
                    super::super::win16_user_services_window_dc::begin_paint(state, window)
                        .map(|acquired| Win16WindowResult::Paint { acquired })
                }
                Win16WindowOperation::EndPaint { window, dc, info } => {
                    super::super::win16_user_services_window_dc::end_paint(state, window, dc, info)
                        .map(Win16WindowResult::PaintEnded)
                }
                Win16WindowOperation::AcquireWindowDc {
                    window: Some(window),
                    whole_window,
                } => super::super::win16_user_services_window_dc::acquire_window_dc(
                    state,
                    window,
                    whole_window,
                )
                .map(Win16WindowResult::WindowDc),
                Win16WindowOperation::AcquireWindowDc { window: None, .. } => {
                    Ok(Win16WindowResult::WindowDc(None))
                }
                Win16WindowOperation::ReleaseWindowDc {
                    window: Some(window),
                    dc,
                } => super::super::win16_user_services_window_dc::release_window_dc(
                    state, window, dc,
                )
                .map(Win16WindowResult::DcReleased),
                Win16WindowOperation::ReleaseWindowDc { window: None, .. } => {
                    Ok(Win16WindowResult::DcReleased(false))
                }
                Win16WindowOperation::SetWindowText { window, text } => {
                    super::super::win16_window_text::set_text(state, window, text)
                }
                Win16WindowOperation::GetWindowText { window, buffer } => {
                    super::super::win16_window_text::get_text(state, window, buffer)
                }
                Win16WindowOperation::GetWindowTextLength { window } => {
                    super::super::win16_window_text::text_length(state, window)
                }
                Win16WindowOperation::GetMessage { filter } => {
                    get_message_with_pending_guest_work(state, id, filter, &response)
                }
                Win16WindowOperation::PeekMessage { filter, flags } => {
                    super::super::win16_message_loop::peek_message(state, filter, flags).and_then(
                        |poll| match poll {
                            super::super::win16_message_loop::MessagePoll::Message(message) => {
                                Ok(Win16WindowResult::QueuedMessage(message))
                            }
                            super::super::win16_message_loop::MessagePoll::Empty => {
                                Ok(Win16WindowResult::QueuedMessage(
                                    runtime::Win16HostQueuedDelivery::empty(),
                                ))
                            }
                            super::super::win16_message_loop::MessagePoll::Error => {
                                Ok(Win16WindowResult::MessageError)
                            }
                            super::super::win16_message_loop::MessagePoll::PendingGuestWork {
                                ..
                            } => Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "nonblocking PeekMessage produced a pending-work wait",
                            )),
                        },
                    )
                }
                Win16WindowOperation::PostGuestNotification(notification) => {
                    super::super::win16_guest_notifications::post(state, notification)
                        .map(Win16WindowResult::NotificationPosted)
                }
                Win16WindowOperation::TranslateMessage { message } => {
                    super::super::win16_message_loop::translate_message(state, message)
                        .map(Win16WindowResult::Translated)
                }
                Win16WindowOperation::DispatchMessage { message } => {
                    super::super::win16_message_loop::dispatch_message(state, message)
                }
                Win16WindowOperation::PostQuitMessage { exit_code } => {
                    super::super::win16_message_loop::post_quit_message(exit_code);
                    Ok(Win16WindowResult::QuitPosted)
                }
            };
            result.map(NativeModalOperationOutcome::Returned)
        }
    };
    let result = finish_toolbar_bitmap_leases(state, id, result, toolbar_bitmap_leases);
    // Retire native input leases before publishing completion. Otherwise a
    // fast guest DeleteObject after Complete could observe a finished call as
    // still borrowing its region. Suspended callbacks retain this local map.
    drop(native_regions);
    let (balanced, stranded) = {
        let mut state = state.borrow_mut();
        if state
            .active_operations
            .last()
            .is_some_and(|active| active.id == id)
        {
            state.active_operations.pop();
            (true, Vec::new())
        } else {
            state.callbacks_enabled = false;
            state.aborted = true;
            state.live_callbacks.clear();
            state.terminal_failures.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 native operation stack was not balanced",
            )));
            let stranded = state
                .active_operations
                .iter()
                .map(|active| active.response.clone())
                .collect::<Vec<_>>();
            state.active_operations.clear();
            (false, stranded)
        }
    };
    if !balanced {
        // Stack damage already forces a negative terminal result. Preserve the
        // completed operation's real cause and cancellation receipt as well.
        {
            let mut state = state.borrow_mut();
            match result {
                Ok(NativeModalOperationOutcome::Cancelled {
                    receipt,
                    cleanup_error,
                }) => {
                    state.cancelled_modals.push(receipt);
                    if let Some(error) = cleanup_error {
                        state.terminal_failures.push(Arc::new(error));
                    }
                }
                Ok(NativeModalOperationOutcome::Returned(
                    Win16WindowResult::NativeModalCancelled(receipt),
                )) => {
                    state.cancelled_modals.push(receipt);
                    state.terminal_failures.push(Arc::new(RuntimeError::new(
                        Kind::InternalInvariant,
                        "native modal cancellation bypassed the worker cancellation outcome",
                    )));
                }
                Err(error) => state.terminal_failures.push(Arc::new(error)),
                Ok(NativeModalOperationOutcome::Returned(_)) => {}
            }
        }
        for channel in stranded {
            let _ = channel.send(Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 native operation stack was not balanced",
            )));
        }
        return;
    }
    let terminal_in_progress = {
        let state = state.borrow();
        state.aborted || state.modal_control.terminal_requested()
    };
    match result {
        Ok(NativeModalOperationOutcome::Cancelled {
            receipt,
            cleanup_error,
        }) => {
            if terminal_in_progress {
                let mut state = state.borrow_mut();
                state.cancelled_modals.push(receipt);
                if let Some(error) = cleanup_error {
                    state.terminal_failures.push(Arc::new(error));
                }
            } else {
                let error = RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "Win16 native modal cancellation arrived without a terminal worker request",
                    WorkerOperationFailures {
                        cleanup: cleanup_error,
                        receipt: Some(receipt),
                    },
                );
                let _ = response.send(Err(error));
            }
        }
        Ok(NativeModalOperationOutcome::Returned(Win16WindowResult::NativeModalCancelled(
            receipt,
        ))) => {
            if terminal_in_progress {
                let error = RuntimeError::new(
                    Kind::InternalInvariant,
                    "native modal cancellation bypassed the worker cancellation outcome",
                );
                let mut state = state.borrow_mut();
                state.cancelled_modals.push(receipt);
                state.terminal_failures.push(Arc::new(error));
            } else {
                let error = RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "native modal cancellation bypassed the worker cancellation outcome",
                    WorkerOperationFailures {
                        cleanup: None,
                        receipt: Some(receipt),
                    },
                );
                let _ = response.send(Err(error));
            }
        }
        Err(error) if terminal_in_progress => {
            state.borrow_mut().terminal_failures.push(Arc::new(error));
        }
        Ok(NativeModalOperationOutcome::Returned(_)) if terminal_in_progress => {}
        Ok(NativeModalOperationOutcome::Returned(result)) => {
            let _ = response.send(Ok(Win16WindowStep::Complete(result)));
        }
        Err(error) => {
            let _ = response.send(Err(error));
        }
    }
}

fn release_toolbar_bitmap_leases(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
    leases: BTreeMap<
        Win16HostGdiObject,
        Option<super::super::win16_gdi_bitmap_lease::Win16BitmapLease>,
    >,
) -> Result<(), RuntimeError> {
    let (worker_id, retention) = {
        match state.try_borrow() {
            Ok(worker) => (
                worker.worker_retirement_id,
                Arc::clone(&worker.toolbar_bitmap_retention),
            ),
            Err(_) => {
                return Err(RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "cannot inspect USER state; unconsumed bitmap leases remain owned by this error",
                    UnavailableBitmapRetention { leases },
                ));
            }
        }
    };
    super::super::win16_common_controls_bitmap_pins::release_unconsumed_leases(
        worker_id, operation, &retention, leases,
    )
}

#[derive(Debug)]
struct UnavailableBitmapRetention {
    leases: BTreeMap<
        Win16HostGdiObject,
        Option<super::super::win16_gdi_bitmap_lease::Win16BitmapLease>,
    >,
}

impl std::fmt::Display for UnavailableBitmapRetention {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} unconsumed toolbar bitmap leases remain owned",
            self.leases.len()
        )
    }
}

impl std::error::Error for UnavailableBitmapRetention {}

fn finish_toolbar_bitmap_leases(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
    result: Result<NativeModalOperationOutcome, RuntimeError>,
    leases: BTreeMap<
        Win16HostGdiObject,
        Option<super::super::win16_gdi_bitmap_lease::Win16BitmapLease>,
    >,
) -> Result<NativeModalOperationOutcome, RuntimeError> {
    let lease_cleanup = release_toolbar_bitmap_leases(state, operation, leases);
    let destruction_cleanup =
        super::super::win16_common_controls_bitmap_pins::retire_destroyed_windows(state);
    let cleanup = combine_bitmap_cleanups(lease_cleanup, destruction_cleanup);
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Err(primary), Err(cleanup)) => Err(primary.with_cleanup(
            "Win16 USER operation and unconsumed toolbar bitmap cleanup both failed",
            cleanup,
        )),
        (Ok(NativeModalOperationOutcome::Returned(_)), Err(cleanup)) => Err(cleanup),
        (
            Ok(NativeModalOperationOutcome::Cancelled {
                receipt,
                cleanup_error,
            }),
            Err(error),
        ) => {
            let cleanup_error = Some(match cleanup_error {
                None => error,
                Some(primary) => primary.with_cleanup(
                    "native modal cleanup and unconsumed toolbar bitmap cleanup both failed",
                    error,
                ),
            });
            Ok(NativeModalOperationOutcome::Cancelled {
                receipt,
                cleanup_error,
            })
        }
    }
}

fn combine_bitmap_cleanups(
    first: Result<(), RuntimeError>,
    second: Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => {
            Err(primary.with_cleanup("toolbar bitmap cleanup steps both failed", cleanup))
        }
    }
}

fn combine_operation_cleanup(
    primary: RuntimeError,
    cleanup: Result<(), RuntimeError>,
) -> RuntimeError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => primary.with_cleanup(
            "Win16 USER preflight and toolbar bitmap cleanup both failed",
            cleanup,
        ),
    }
}

#[derive(Debug)]
struct WorkerOperationFailures {
    cleanup: Option<RuntimeError>,
    receipt: Option<runtime::Win16NativeModalCancellation>,
}

impl std::fmt::Display for WorkerOperationFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("unexpected modal cancellation during an ordinary USER operation")?;
        if let Some(cleanup) = &self.cleanup {
            write!(formatter, "; modal cleanup also failed: {cleanup}")?;
        }
        if self.receipt.is_some() {
            formatter.write_str("; the cancellation receipt remains attached to this error")?;
        }
        Ok(())
    }
}

impl std::error::Error for WorkerOperationFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cleanup
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}
