//! Native Windows host adapters for USER worker and console-window operations.

use super::*;

fn drain_win16_dde_diagnostics(host: &mut WindowsHost) {
    for diagnostic in host.win16_windows.take_dde_diagnostics() {
        RuntimeHost::report_diagnostic(host, &diagnostic);
    }
}

pub(super) fn win16_initialize_user_queue(host: &mut WindowsHost) -> Result<(), RuntimeError> {
    host.win16_windows.initialize_user_queue()
}

pub(super) fn win16_bind_task_queue(
    host: &mut WindowsHost,
    owner: guest_core::OwnerId,
    guest_htask: u16,
    task_selector_generation: u64,
) -> Result<Option<runtime::Win16HostTaskQueue>, RuntimeError> {
    host.win16_windows.bind_task_queue(owner, guest_htask, task_selector_generation)
}

pub(super) fn win16_retire_task_queue(
    host: &mut WindowsHost,
    owner: guest_core::OwnerId,
    guest_htask: u16,
    task_selector_generation: u64,
    queue: runtime::Win16HostTaskQueue,
) -> Result<bool, RuntimeError> {
    host.win16_windows.retire_task_queue(owner, guest_htask,
        task_selector_generation, queue)
}

pub(super) fn win16_register_window_class(
    host: &mut WindowsHost,
    spec: Win16HostClassSpec,
) -> Result<Option<Win16RegisteredClass>, RuntimeError> {
    host.win16_windows
        .register_class(spec, &host.win16_images, &host.win16_objects)
}

pub(super) fn win16_unregister_window_class(
    host: &mut WindowsHost,
    class: Win16HostClass,
) -> Result<bool, RuntimeError> {
    Ok(host.win16_windows.unregister_class(class))
}

pub(super) fn win16_window_begin(
    host: &mut WindowsHost,
    operation: Win16WindowOperation,
) -> Result<Win16WindowStep, RuntimeError> {
    let result = host.win16_windows.begin(operation, &mut host.win16_objects);
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_window_resume(
    host: &mut WindowsHost,
    reply: Option<Win16WindowReply>,
) -> Result<Win16WindowStep, RuntimeError> {
    let result = host.win16_windows.resume(reply, &mut host.win16_objects);
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_take_native_drop_retirement(
    host: &mut WindowsHost,
) -> Result<Option<runtime::Win16HostDropRetirementReceipt>, RuntimeError> {
    Ok(host.win16_windows.take_native_drop_retirement())
}

pub(super) fn win16_ack_native_drop_retirement(
    host: &mut WindowsHost,
    receipt: runtime::Win16HostDropRetirementReceipt,
) -> Result<(), RuntimeError> {
    host.win16_windows.acknowledge_native_drop_retirement(receipt)
}

pub(super) fn win16_window_receive_pending(
    host: &mut WindowsHost,
) -> Result<Win16WindowStep, RuntimeError> {
    let result = host.win16_windows.receive_pending(&mut host.win16_objects);
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_window_resume_modal_guest_work(
    host: &mut WindowsHost,
    operation_id: runtime::Win16HostWindowOperationId,
    scope_id: u64,
    generation: u64,
    marker_id: Option<u64>,
    wake_generation: Option<u64>,
) -> Result<Win16WindowStep, RuntimeError> {
    let result = host.win16_windows.resume_modal_guest_work(
        operation_id,
        scope_id,
        generation,
        marker_id,
        wake_generation,
        &mut host.win16_objects,
    );
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_window_terminal_ack(
    host: &mut WindowsHost,
    ack: runtime::Win16WindowTerminalAck,
) -> Result<(), RuntimeError> {
    host.win16_windows.terminal_ack(ack)
}

pub(super) fn win16_window_terminal_acknowledged(
    host: &WindowsHost,
    receipt: &runtime::Win16WindowAbortReceipt,
    ack: &runtime::Win16WindowTerminalAck,
) -> Result<bool, RuntimeError> {
    host.win16_windows.terminal_acknowledged(receipt, ack)
}

pub(super) fn win16_window_terminal_source_top(
    host: &mut WindowsHost,
    receipt: &runtime::Win16WindowAbortReceipt,
) -> Result<Option<runtime::Win16WindowTerminalSourceTop>, RuntimeError> {
    host.win16_windows.terminal_source_top(receipt)
}

pub(super) fn win16_window_source_retirement(
    host: &mut WindowsHost,
    operation: runtime::Win16NativeWindowOperationProof,
    worker_generation: u64,
) -> Result<Option<std::sync::Arc<runtime::Win16WindowSourceRetiredProof>>, RuntimeError> {
    host.win16_windows.source_retirement(operation, worker_generation)
}

pub(super) fn win16_window_retry_cached_completion(
    host: &mut WindowsHost,
    operation: runtime::Win16NativeWindowOperationProof,
    worker_generation: u64,
) -> Result<runtime::Win16WindowStep, RuntimeError> {
    host.win16_windows.retry_cached_completion(
        operation,
        worker_generation,
        &mut host.win16_objects,
    )
}

pub(super) fn win16_window_source_retirement_consumed(
    host: &mut WindowsHost,
    proof: &runtime::Win16WindowSourceRetiredProof,
) -> Result<(), RuntimeError> {
    host.win16_windows.source_retirement_consumed(proof)
}

pub(super) fn win16_dde_poll_callback(
    host: &mut WindowsHost,
) -> Result<Option<std::sync::Arc<runtime::Win16HostDdeCallbackStep>>, RuntimeError> {
    let result = host.win16_windows.poll_dde_callback();
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_dde_callback_published(
    host: &mut WindowsHost,
    step: &runtime::Win16HostDdeCallbackStep,
) -> Result<(), RuntimeError> {
    let result = host.win16_windows.dde_callback_published(step);
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_dde_callback_reply(
    host: &mut WindowsHost,
    resume: runtime::Win16HostDdeResume,
) -> Result<runtime::Win16HostDdeStep, RuntimeError> {
    let result = host.win16_windows.dde_callback_reply(resume);
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_dde_retire_completed_source(
    host: &mut WindowsHost,
    operation: runtime::Win16HostDdeOperation,
    result: &runtime::Win16HostDdeResult,
) -> Result<runtime::Win16HostDdeStep, RuntimeError> {
    let result = host.win16_windows.dde_retire_completed_source(operation, result);
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_dde_callback_retirement_is_pending(
    host: &mut WindowsHost,
    frame: runtime::Win16HostDdeCallbackFrame,
    parent: Option<runtime::Win16HostDdeOperation>,
    instance: runtime::Win16HostDdeInstance,
    owner: runtime::Win16HostDdeOwner,
    worker_generation: u64,
) -> Result<bool, RuntimeError> {
    let result = host.win16_windows.dde_callback_retirement_is_pending(
        frame, parent, instance, owner, worker_generation,
    );
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_dde_callback_retired(
    host: &mut WindowsHost,
    frame: runtime::Win16HostDdeCallbackFrame,
    parent: Option<runtime::Win16HostDdeOperation>,
    instance: runtime::Win16HostDdeInstance,
    owner: runtime::Win16HostDdeOwner,
    worker_generation: u64,
) -> Result<(), RuntimeError> {
    let result = host.win16_windows.dde_callback_retired(
        frame, parent, instance, owner, worker_generation,
    );
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_dde_operation_retired(
    host: &mut WindowsHost,
    proof: &runtime::Win16DdeOperationRetirementProof,
    receipt: &runtime::Win16DdeAbortReceipt,
) -> Result<(), RuntimeError> {
    let result = host.win16_windows.dde_operation_retired(proof, receipt);
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_dde_source_retirement(
    host: &mut WindowsHost,
    proof: &runtime::Win16DdeSourceRetiredProof,
) -> Result<bool, RuntimeError> {
    host.win16_windows.dde_source_retirement(proof)
}

pub(super) fn win16_dde_source_retirement_consumed(
    host: &mut WindowsHost,
    proof: &runtime::Win16DdeSourceRetiredProof,
) -> Result<(), RuntimeError> {
    host.win16_windows.dde_source_retirement_consumed(proof)
}

pub(super) fn win16_dde_runtime_resources_retired(
    host: &mut WindowsHost,
    receipt: &runtime::Win16DdeAbortReceipt,
) -> Result<(), RuntimeError> {
    let result = host.win16_windows.dde_runtime_resources_retired(receipt);
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_dde_abort(host: &mut WindowsHost) -> runtime::Win16DdeAbortReceipt {
    let result = host.win16_windows.abort_dde_receipt();
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_window_abort(
    host: &mut WindowsHost,
) -> Result<runtime::Win16WindowAbortReceipt, RuntimeError> {
    let result = host.win16_windows.abort();
    drain_win16_dde_diagnostics(host);
    result
}

pub(super) fn win16_destroy_window(
    host: &mut WindowsHost,
    window: Win16HostWindow,
) -> Result<bool, RuntimeError> {
    Ok(host.win16_windows.destroy_window(window))
}

pub(super) fn win16_host_window_liveness(
    host: &WindowsHost,
    window: Win16HostWindow,
) -> Result<runtime::Win16HostWindowLiveness, RuntimeError> {
    host.win16_windows.host_window_liveness(window)
}

pub(super) fn win16_host_window_parent(
    host: &WindowsHost,
    window: Win16HostWindow,
) -> Result<runtime::Win16HostWindowParentObservation, RuntimeError> {
    host.win16_windows.host_window_parent(window)
}

pub(super) fn render_graphics(
    host: &mut WindowsHost,
    frame: &devices::vga::VgaFrame,
) -> Result<(), RuntimeError> {
    let keys = host.vga_window.render(frame).map_err(vga_runtime_error)?;
    // Text-mode mouse samples cannot be interpreted against a graphics
    // frame; discard pending samples and allow the first resumed text
    // sample to be observed even if it matches the last pre-graphics one.
    host.mouse_inputs.clear();
    host.last_mouse_input = None;
    host.queue_vga_keys(keys)
}

pub(super) fn render_text(
    host: &mut WindowsHost,
    screen: &ConsoleSnapshot,
) -> Result<(), RuntimeError> {
    let expected = usize::from(screen.columns) * usize::from(screen.rows);
    if screen.columns == 0 || screen.rows == 0 || screen.cells.len() != expected {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "invalid text snapshot dimensions",
        ));
    }
    host.vga_window.hide().map_err(vga_runtime_error)?;
    host.mouse_mapper
        .set_text_size(u16::from(screen.columns), u16::from(screen.rows));
    let mut cells = Vec::with_capacity(expected);
    let page = CodePage::try_from(host.code_page).map_err(|e| {
        RuntimeError::with_source(Kind::InternalInvariant, "configured console code page", e)
    })?;
    for row in screen.cells.chunks(usize::from(screen.columns)) {
        let bytes: Vec<u8> = row.iter().map(|cell| cell.character).collect();
        let decoded = decode_text_row(&bytes, page)
            .map_err(|e| RuntimeError::with_source(Kind::GuestFault, "text row", e))?;
        for (cell, decoded) in row.iter().zip(decoded) {
            let mut utf16 = [0; 2];
            let character = decoded.character.unwrap_or(' ');
            let encoded = character.encode_utf16(&mut utf16);
            if encoded.len() != 1 {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "text cell requires more than one UTF-16 unit",
                ));
            }
            let dbcs = match decoded.role {
                CellRole::Single => 0,
                CellRole::Lead => COMMON_LVB_LEADING_BYTE,
                CellRole::Trail => COMMON_LVB_TRAILING_BYTE,
            };
            cells.push(CHAR_INFO {
                Char: CHAR_INFO_0 {
                    UnicodeChar: encoded[0],
                },
                Attributes: u16::from(cell.attribute) | dbcs,
            });
        }
    }
    let size = COORD {
        X: i16::from(screen.columns),
        Y: i16::from(screen.rows),
    };
    let mut region = SMALL_RECT {
        Left: 0,
        Top: 0,
        Right: size.X - 1,
        Bottom: size.Y - 1,
    };
    // SAFETY: Standard output is obtained from the OS; buffer contains columns*rows CHAR_INFO values.
    let output = unsafe { GetStdHandle((-11i32) as u32) };
    // SAFETY: FFI structs use documented C layouts and the source buffer matches size.
    if unsafe {
        WriteConsoleOutputW(
            output,
            cells.as_ptr(),
            size,
            COORD { X: 0, Y: 0 },
            &mut region,
        )
    } == 0
    {
        return Err(RuntimeError::with_source(
            Kind::HostFailure,
            "console render",
            io::Error::last_os_error(),
        ));
    }
    if region.Right != size.X - 1 || region.Bottom != size.Y - 1 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "console is smaller than the guest text screen",
        ));
    }
    // SAFETY: Cursor coordinates originate from the checked text-device model.
    if unsafe {
        SetConsoleCursorPosition(
            output,
            COORD {
                X: i16::from(screen.cursor_column),
                Y: i16::from(screen.cursor_row),
            },
        )
    } == 0
    {
        return Err(RuntimeError::with_source(
            Kind::HostFailure,
            "console cursor",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}
