//! Native worker ownership and terminal projection for asynchronous Win16 NetBIOS NCBs.

use super::*;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::time::Duration;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

const NRC_PENDING: u8 = 0xff;
const NRC_GOODRET: u8 = 0x00;
const NRC_INVDDID: u8 = 0x3b;
const NRC_CANOCCR: u8 = 0x24;
const NCBCANCEL: u8 = 0x35;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[path = "win16_netbios_worker_dispatch.rs"]
mod dispatch;
#[path = "win16_netbios_worker_quarantine.rs"]
mod quarantine;
use dispatch::{
    finish_accepted_async_request, publish_inline_terminal, report_wait_failure,
    service_native_owner_after_wait_failure,
};

pub(super) fn native_worker(
    call: runtime::Win16HostNetbiosCall,
    commands: Receiver<WorkerCommand>,
    completions: Sender<WorkerCompletion>,
    start: SyncSender<Result<WorkerStart, RuntimeError>>,
    multimedia_wake: MultimediaWakeSender,
    wake_status: super::SharedWakeStatus,
) {
    let mut owner =
        match NativeNcbOwner::new(call, start.clone(), std::sync::Arc::clone(&wake_status)) {
            Ok(owner) => Box::new(owner),
            Err(error) => {
                let _ = start.send(Err(error));
                return;
            }
        };
    // SAFETY: this worker owns the NCB and aligned buffer. A zero return may
    // still leave Windows writing them asynchronously, so no field is read
    // until the request event proves terminal completion.
    let function_return = unsafe { Netbios(owner.ncb.get()) };
    owner.in_flight = function_return == NRC_GOODRET;
    owner.terminal = !owner.in_flight;
    if function_return == NRC_INVDDID {
        mark_native_terminal(&wake_status);
        let result = runtime::Win16HostNetbiosResult::status(NRC_INVDDID);
        if (crate::windows::win32_safe::close_handle(owner.event)) == 0 {
            let error = last_error("close rejected asynchronous NetBIOS event");
            let _ = send_worker_start(&mut owner, Err(error));
            return;
        }
        owner.event = std::ptr::null_mut();
        owner
            .wake_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .event_closed = true;
        let _ = send_worker_start(&mut owner, Ok(WorkerStart::Immediate(result)));
        return;
    }
    if function_return != NRC_GOODRET {
        // Netbios' documented nonzero return is a synchronous terminal result
        // with the event signaled. NRC_INVDDID above is the special
        // function-only result and never permits an NCB or buffer read.
        mark_native_terminal(&wake_status);
        publish_inline_terminal(
            &mut owner,
            function_return,
            &commands,
            &completions,
            &multimedia_wake,
            &wake_status,
        );
        return;
    }

    // Zero means accepted, not completed. Mark the owner potentially in
    // flight before polling; the event is the only proof that permits an NCB
    // or native buffer read.
    // SAFETY: WaitForSingleObject waits on a handle this process owns.
    match unsafe { WaitForSingleObject(owner.event, 0) } {
        WAIT_OBJECT_0 => {
            owner.terminal = true;
            owner.in_flight = false;
            mark_native_terminal(&wake_status);
            publish_inline_terminal(
                &mut owner,
                function_return,
                &commands,
                &completions,
                &multimedia_wake,
                &wake_status,
            );
        }
        WAIT_TIMEOUT => {
            let accepted_status = pending_status(&owner.call);
            if !send_worker_start(&mut owner, Ok(WorkerStart::Accepted(accepted_status))) {
                abandon_until_terminal(&mut owner);
                return;
            }
            finish_accepted_async_request(
                &mut owner,
                &commands,
                &completions,
                &multimedia_wake,
                &wake_status,
            );
        }
        _ => {
            let accepted_status = pending_status(&owner.call);
            if !send_worker_start(&mut owner, Ok(WorkerStart::Accepted(accepted_status))) {
                abandon_until_terminal(&mut owner);
                return;
            }
            let error = last_error("poll accepted asynchronous NetBIOS event");
            if !report_wait_failure(error, &completions, &multimedia_wake, &wake_status, true) {
                abandon_until_terminal(&mut owner);
                return;
            }
            service_native_owner_after_wait_failure(
                &mut owner,
                &commands,
                &completions,
                &multimedia_wake,
                &wake_status,
            );
            return;
        }
    }
}

fn send_worker_start(
    owner: &mut NativeNcbOwner,
    receipt: Result<WorkerStart, RuntimeError>,
) -> bool {
    if owner.start_reported {
        return true;
    }
    owner.start_reported = true;
    let sent = owner.start.send(receipt).is_ok();
    if !sent {
        let mut status = owner
            .wake_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        super::mark_no_consumer(
            &mut status,
            RuntimeError::new(
                Kind::HostFailure,
                "NetBIOS startup receiver disappeared before the source receipt was accepted",
            ),
        );
    }
    sent
}

fn publish_terminal_projection(
    owner: &mut NativeNcbOwner,
    commands: &Receiver<WorkerCommand>,
    completions: &Sender<WorkerCompletion>,
    multimedia_wake: &MultimediaWakeSender,
    wake_status: &super::SharedWakeStatus,
    first_error: Option<RuntimeError>,
) {
    let mut projection_error_reported = false;
    if let Some(error) = first_error {
        if !publish_projection_failure(completions, wake_status, error) {
            close_after_terminal(owner);
            return;
        }
        if owner.teardown_reason.is_none() {
            super::request_wake(wake_status, false);
            let _ = super::publish_pending_wake(multimedia_wake, wake_status);
        }
        projection_error_reported = true;
    }
    loop {
        // A failed signal leaves the exact source, queued result, and typed
        // cause retained. Retry here while still servicing Cancel and ACK.
        if owner.teardown_reason.is_none() {
            let _ = super::publish_pending_wake(multimedia_wake, wake_status);
        }
        match snapshot(owner, 0) {
            Ok(completion) => {
                if completions
                    .send(WorkerCompletion::Completed(completion))
                    .is_err()
                {
                    close_after_terminal(owner);
                    return;
                }
                if owner.teardown_reason.is_none() {
                    super::request_wake(wake_status, true);
                    let _ = super::publish_pending_wake(multimedia_wake, wake_status);
                }
                break;
            }
            Err(error) => {
                if !projection_error_reported {
                    if !publish_projection_failure(completions, wake_status, error) {
                        close_after_terminal(owner);
                        return;
                    }
                    if owner.teardown_reason.is_none() {
                        super::request_wake(wake_status, false);
                        let _ = super::publish_pending_wake(multimedia_wake, wake_status);
                    }
                    projection_error_reported = true;
                }
            }
        }
        match commands.recv_timeout(POLL_INTERVAL) {
            Ok(WorkerCommand::Cancel(reply)) => {
                let _ = reply.send(Ok(runtime::Win16HostNetbiosResult::status(NRC_CANOCCR)));
            }
            Ok(WorkerCommand::ProbeTerminal) => clear_native_probe_pending(wake_status),
            Ok(WorkerCommand::Ack { reply, .. }) => {
                // A terminal source cannot be retired until its exact output
                // projection has reached the runtime and guest commit succeeds.
                let _ = reply.send(Ok(false));
            }
            Ok(WorkerCommand::Teardown {
                reason,
                issue_cancel,
            }) => {
                clear_native_probe_pending(wake_status);
                owner.teardown_reason = Some(reason);
                mark_teardown_requested(wake_status, reason);
                if issue_cancel && !owner.cancel_requested {
                    let _ = cancel_native(owner);
                }
                finish_native_teardown(owner, commands, wake_status);
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                close_after_terminal(owner);
                return;
            }
        }
    }
    if owner.teardown_reason.is_some() {
        finish_native_teardown(owner, commands, wake_status);
    } else {
        await_exact_ack(
            owner,
            commands,
            Some((multimedia_wake, wake_status)),
            wake_status,
        );
    }
}

fn publish_projection_failure(
    completions: &Sender<WorkerCompletion>,
    wake_status: &super::SharedWakeStatus,
    error: RuntimeError,
) -> bool {
    let cause = std::sync::Arc::new(error);
    // Record once before send so a vanished consumer still leaves the native
    // receipt with the actual projection cause and its bounded phase tally.
    super::record_projection_failure(wake_status, std::sync::Arc::clone(&cause));
    completions
        .send(WorkerCompletion::ProjectionFailure(cause))
        .is_ok()
}

fn raw_snapshot(owner: &NativeNcbOwner, function_return: u8) -> runtime::Win16HostNetbiosResult {
    // SAFETY: callers use this only after inline return or terminal event.
    let native = unsafe { &*owner.ncb.get() };
    let projected_function_return =
        if function_return == NRC_GOODRET && native.ncb_retcode != NRC_GOODRET {
            native.ncb_retcode
        } else {
            function_return
        };
    runtime::Win16HostNetbiosResult {
        function_return: projected_function_return,
        retcode: native.ncb_retcode,
        lsn: native.ncb_lsn,
        num: native.ncb_num,
        length: if owner.call.native_length != owner.call.length {
            owner.call.length
        } else {
            native.ncb_length
        },
        cmd_cplt: native.ncb_cmd_cplt,
        call_name: None,
        payload: runtime::Win16HostNetbiosOutput::None,
    }
}

struct NativeNcbOwner {
    call: runtime::Win16HostNetbiosCall,
    ncb: std::cell::UnsafeCell<NCB>,
    buffer: Option<std::cell::UnsafeCell<NativeBuffer>>,
    event: HANDLE,
    in_flight: bool,
    terminal: bool,
    cancel_requested: bool,
    teardown_reason: Option<runtime::Win16HostNetbiosTeardownReason>,
    wake_status: super::SharedWakeStatus,
    start: SyncSender<Result<WorkerStart, RuntimeError>>,
    start_reported: bool,
}

impl NativeNcbOwner {
    fn new(
        call: runtime::Win16HostNetbiosCall,
        start: SyncSender<Result<WorkerStart, RuntimeError>>,
        wake_status: super::SharedWakeStatus,
    ) -> Result<Self, RuntimeError> {
        let mut buffer = make_native_buffer(&call)?;
        // SAFETY: CreateEventW reads an optional caller-owned name and returns a new event handle.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(last_error(
                "create manual-reset event for asynchronous NetBIOS",
            ));
        }
        let buffer_pointer = buffer
            .as_mut()
            .map_or(std::ptr::null_mut(), NativeBuffer::as_mut_ptr);
        let mut ncb = NCB::default();
        ncb.ncb_command = call.command | ASYNCH;
        ncb.ncb_retcode = NRC_PENDING;
        ncb.ncb_lsn = call.lsn;
        ncb.ncb_num = call.num;
        ncb.ncb_buffer = buffer_pointer;
        ncb.ncb_length = call.native_length;
        ncb.ncb_callname = call.call_name;
        ncb.ncb_name = call.name;
        ncb.ncb_rto = call.receive_timeout;
        ncb.ncb_sto = call.send_timeout;
        // Win16 ncb_post is a guest callback, never a Windows function pointer.
        ncb.ncb_post = 0;
        ncb.ncb_lana_num = call.lana_num;
        ncb.ncb_cmd_cplt = NRC_PENDING;
        ncb.ncb_event = event;
        wake_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .native_owner_created = true;
        Ok(Self {
            call,
            ncb: std::cell::UnsafeCell::new(ncb),
            buffer: buffer.map(std::cell::UnsafeCell::new),
            event,
            in_flight: false,
            terminal: false,
            cancel_requested: false,
            teardown_reason: None,
            wake_status,
            start,
            start_reported: false,
        })
    }
}

fn make_native_buffer(
    call: &runtime::Win16HostNetbiosCall,
) -> Result<Option<NativeBuffer>, RuntimeError> {
    match &call.payload {
        runtime::Win16HostNetbiosPayload::None => Ok(None),
        runtime::Win16HostNetbiosPayload::Bytes { bytes, access } => {
            if bytes.len() != usize::from(call.native_length)
                || !payload_access_matches_command(call.command, *access)
            {
                return Err(payload_command_mismatch());
            }
            NativeBuffer::from_bytes(bytes).map(Some)
        }
        runtime::Win16HostNetbiosPayload::AdapterStatus { capacity }
        | runtime::Win16HostNetbiosPayload::SessionStatus { capacity }
        | runtime::Win16HostNetbiosPayload::FindName { capacity }
        | runtime::Win16HostNetbiosPayload::LanaEnum { capacity } => {
            require_capacity_matches_ncb_length(usize::from(*capacity), call.native_length)?;
            NativeBuffer::zeroed(usize::from(*capacity)).map(Some)
        }
    }
}

fn wait_for_terminal(
    owner: &mut NativeNcbOwner,
    commands: &Receiver<WorkerCommand>,
    completions: &Sender<WorkerCompletion>,
    multimedia_wake: &MultimediaWakeSender,
    wake_status: &super::SharedWakeStatus,
) -> bool {
    loop {
        if owner.teardown_reason.is_none() {
            let _ = super::publish_pending_wake(multimedia_wake, wake_status);
        }
        // SAFETY: WaitForSingleObject waits on a handle this process owns.
        match unsafe { WaitForSingleObject(owner.event, POLL_INTERVAL.as_millis() as u32) } {
            WAIT_OBJECT_0 => {
                owner.terminal = true;
                owner.in_flight = false;
                mark_native_terminal(wake_status);
                return true;
            }
            WAIT_TIMEOUT => {}
            _ => {
                let error = last_error("wait for asynchronous Windows NetBIOS completion");
                if !report_wait_failure(
                    error,
                    completions,
                    multimedia_wake,
                    wake_status,
                    owner.teardown_reason.is_none(),
                ) {
                    abandon_until_terminal(owner);
                    return false;
                }
                // Retain the native owner, but stop retrying a failed event
                // handle. Host completion and typed teardown remain serviceable.
                return false;
            }
        }
        match commands.try_recv() {
            Ok(WorkerCommand::Cancel(reply)) => {
                let _ = reply.send(Ok(cancel_native(owner)));
            }
            Ok(WorkerCommand::ProbeTerminal) => clear_native_probe_pending(wake_status),
            Ok(WorkerCommand::Ack { reply, .. }) => {
                let _ = reply.send(Ok(false));
            }
            Ok(WorkerCommand::Teardown {
                reason,
                issue_cancel,
            }) => {
                clear_native_probe_pending(wake_status);
                owner.teardown_reason = Some(reason);
                mark_teardown_requested(wake_status, reason);
                if issue_cancel && !owner.cancel_requested {
                    let _ = cancel_native(owner);
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                abandon_until_terminal(owner);
                return false;
            }
        }
    }
}

fn await_exact_ack(
    owner: &mut NativeNcbOwner,
    commands: &Receiver<WorkerCommand>,
    wake: Option<(&MultimediaWakeSender, &super::SharedWakeStatus)>,
    wake_status: &super::SharedWakeStatus,
) {
    loop {
        if let Some((multimedia_wake, wake_status)) = wake {
            let _ = super::publish_pending_wake(multimedia_wake, wake_status);
        }
        match commands.recv_timeout(POLL_INTERVAL) {
            Ok(WorkerCommand::Cancel(reply)) => {
                let _ = reply.send(Ok(runtime::Win16HostNetbiosResult::status(NRC_CANOCCR)));
            }
            Ok(WorkerCommand::ProbeTerminal) => clear_native_probe_pending(wake_status),
            Ok(WorkerCommand::Ack {
                allow_release,
                reply,
            }) => {
                let expected = if wake.is_some() {
                    runtime::Win16HostNetbiosCompletionPublication::SharedWake
                } else {
                    runtime::Win16HostNetbiosCompletionPublication::InlineReturn
                };
                let exact_publication = super::completion_publication_is(wake_status, expected);
                if !allow_release || !exact_publication {
                    let _ = reply.send(Ok(false));
                    continue;
                }
                if (crate::windows::win32_safe::close_handle(owner.event)) == 0 {
                    let error =
                        std::sync::Arc::new(last_error("close exact completed NetBIOS event"));
                    {
                        let mut shared = wake_status.lock().unwrap_or_else(PoisonError::into_inner);
                        super::remember_native_event_close_error(
                            &mut shared,
                            std::sync::Arc::clone(&error),
                            "normal NetBIOS ACK could not close its event",
                        );
                    }
                    let _ = reply.send(Err(super::retained_runtime_error(
                        error,
                        "close exact completed NetBIOS event",
                    )));
                    continue;
                }
                owner.event = std::ptr::null_mut();
                wake_status
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .event_closed = true;
                let _ = reply.send(Ok(true));
                return;
            }
            Ok(WorkerCommand::Teardown {
                reason,
                issue_cancel,
            }) => {
                clear_native_probe_pending(wake_status);
                owner.teardown_reason = Some(reason);
                mark_teardown_requested(wake_status, reason);
                if issue_cancel && !owner.cancel_requested && !owner.terminal {
                    let _ = cancel_native(owner);
                }
                finish_native_teardown(owner, commands, wake_status);
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                close_after_terminal(owner);
                return;
            }
        }
    }
}

fn cancel_native(owner: &mut NativeNcbOwner) -> runtime::Win16HostNetbiosResult {
    let mut cancel = NCB::default();
    cancel.ncb_command = NCBCANCEL;
    cancel.ncb_buffer = owner.ncb.get().cast::<u8>();
    cancel.ncb_lana_num = owner.call.lana_num;
    // SAFETY: cancellation names only the retained native NCB; no guest FAR
    // address or guest-resident structure is passed to the Windows API.
    let function_return = unsafe { Netbios(&mut cancel) };
    owner.cancel_requested = true;
    runtime::Win16HostNetbiosResult {
        function_return,
        retcode: cancel.ncb_retcode,
        lsn: cancel.ncb_lsn,
        num: cancel.ncb_num,
        length: cancel.ncb_length,
        cmd_cplt: cancel.ncb_cmd_cplt,
        call_name: None,
        payload: runtime::Win16HostNetbiosOutput::None,
    }
}

fn mark_native_terminal(status: &super::SharedWakeStatus) {
    let mut status = status.lock().unwrap_or_else(PoisonError::into_inner);
    status.native_terminal = true;
    status.native_probe_pending = false;
}

fn mark_native_wait_failed(
    status: &super::SharedWakeStatus,
    cause: Option<std::sync::Arc<RuntimeError>>,
) {
    let mut status = status.lock().unwrap_or_else(PoisonError::into_inner);
    status.native_wait_failed = true;
    if let Some(error) = cause.as_ref() {
        status
            .failure_diagnostics
            .native_wait
            .record(std::sync::Arc::clone(error));
    }
    if status.native_wait_error.is_none() {
        status.native_wait_error = cause;
    }
}

fn clear_native_probe_pending(status: &super::SharedWakeStatus) {
    status
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .native_probe_pending = false;
}

fn mark_teardown_requested(
    status: &super::SharedWakeStatus,
    reason: runtime::Win16HostNetbiosTeardownReason,
) {
    let mut status = status.lock().unwrap_or_else(PoisonError::into_inner);
    status.teardown_reason = Some(reason);
    status.teardown_requested = true;
}

fn finish_native_teardown(
    owner: &mut NativeNcbOwner,
    commands: &Receiver<WorkerCommand>,
    status: &super::SharedWakeStatus,
) {
    if !owner.terminal {
        return;
    }
    loop {
        if owner.event.is_null() || { crate::windows::win32_safe::close_handle(owner.event) } != 0 {
            owner.event = std::ptr::null_mut();
            status
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .event_closed = true;
            return;
        }
        let error = std::sync::Arc::new(last_error(
            "close exact terminal NetBIOS event during teardown",
        ));
        {
            let mut shared = status.lock().unwrap_or_else(PoisonError::into_inner);
            super::remember_native_event_close_error(
                &mut shared,
                std::sync::Arc::clone(&error),
                "close exact terminal NetBIOS event during teardown",
            );
        }
        loop {
            match commands.recv_timeout(POLL_INTERVAL) {
                Ok(WorkerCommand::Cancel(reply)) => {
                    let _ = reply.send(Ok(runtime::Win16HostNetbiosResult::status(NRC_CANOCCR)));
                }
                Ok(WorkerCommand::ProbeTerminal) => clear_native_probe_pending(status),
                Ok(WorkerCommand::Ack { reply, .. }) => {
                    let _ = reply.send(Ok(false));
                }
                Ok(WorkerCommand::Teardown { reason, .. })
                    if owner.teardown_reason == Some(reason) =>
                {
                    clear_native_probe_pending(status);
                    break;
                }
                Ok(WorkerCommand::Teardown { .. }) => {}
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

fn abandon_until_terminal(owner: &mut NativeNcbOwner) {
    quarantine::abandon_until_terminal(owner);
}

fn close_after_terminal(owner: &mut NativeNcbOwner) {
    quarantine::close_after_terminal(owner);
}

fn snapshot(
    owner: &NativeNcbOwner,
    initial_function_return: u8,
) -> Result<runtime::Win16HostNetbiosResult, RuntimeError> {
    // SAFETY: this is called only after the completion event or an immediate
    // synchronous rejection proves the provider has stopped writing the NCB.
    let native = unsafe { &*owner.ncb.get() };
    let function_return = if initial_function_return == 0 && native.ncb_retcode != NRC_GOODRET {
        native.ncb_retcode
    } else {
        initial_function_return
    };
    let outcome = NativeCallResult {
        command: owner.call.command,
        function_return,
        retcode: native.ncb_retcode,
        cmd_cplt: native.ncb_cmd_cplt,
        lsn: native.ncb_lsn,
        num: native.ncb_num,
        length: if owner.call.native_length != owner.call.length {
            owner.call.length
        } else {
            native.ncb_length
        },
        call_name: native.ncb_callname,
    };
    let buffer = owner.buffer.as_ref().map(|buffer| {
        // SAFETY: native completion has been observed before buffer projection.
        unsafe { &*buffer.get() }
    });
    let payload = match (&owner.call.payload, buffer) {
        (runtime::Win16HostNetbiosPayload::None, _) => runtime::Win16HostNetbiosOutput::None,
        (runtime::Win16HostNetbiosPayload::Bytes { access, .. }, Some(buffer)) => {
            buffer.check_overrun()?;
            if matches!(access, runtime::Win16HostNetbiosBufferAccess::Read)
                || !super::has_buffer_completion(outcome)
            {
                runtime::Win16HostNetbiosOutput::None
            } else {
                let length = usize::from(outcome.length);
                if length > usize::from(owner.call.length) || length > buffer.as_bytes().len() {
                    return Err(super::native_buffer_overrun());
                }
                let mut bytes = super::output_buffer(
                    length,
                    "unable to retain asynchronous Windows NetBIOS output",
                )?;
                bytes.extend_from_slice(&buffer.as_bytes()[..length]);
                runtime::Win16HostNetbiosOutput::Bytes { bytes }
            }
        }
        (runtime::Win16HostNetbiosPayload::FindName { capacity }, Some(buffer)) => {
            buffer.check_overrun()?;
            if super::has_successful_completion(outcome) {
                super::require_find_name_layout()?;
                let native_bytes = buffer.as_bytes();
                if native_bytes.len() < std::mem::size_of::<FIND_NAME_HEADER>() {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "asynchronous NCBFINDNAME success omitted its header",
                    ));
                }
                let node_count = usize::from(super::read_u16(native_bytes, 0)?);
                let extent = node_count
                    .checked_mul(std::mem::size_of::<FIND_NAME_BUFFER>())
                    .and_then(|length| length.checked_add(std::mem::size_of::<FIND_NAME_HEADER>()))
                    .ok_or_else(super::native_buffer_overrun)?;
                if extent > usize::from(*capacity) || extent > native_bytes.len() {
                    return Err(super::native_buffer_overrun());
                }
                let mut bytes = super::output_buffer(
                    extent,
                    "unable to retain asynchronous NCBFINDNAME results",
                )?;
                bytes.extend_from_slice(&native_bytes[..extent]);
                runtime::Win16HostNetbiosOutput::FindName { bytes }
            } else {
                runtime::Win16HostNetbiosOutput::None
            }
        }
        (runtime::Win16HostNetbiosPayload::LanaEnum { capacity }, Some(buffer)) => {
            buffer.check_overrun()?;
            if super::has_successful_completion(outcome) {
                super::require_lana_enum_layout()?;
                let extent = std::mem::size_of::<LANA_ENUM>();
                if usize::from(*capacity) < extent || buffer.as_bytes().len() < extent {
                    return Err(super::native_buffer_overrun());
                }
                let mut bytes =
                    super::output_buffer(extent, "unable to retain asynchronous LANA_ENUM output")?;
                bytes.extend_from_slice(&buffer.as_bytes()[..extent]);
                runtime::Win16HostNetbiosOutput::LanaEnum { bytes }
            } else {
                runtime::Win16HostNetbiosOutput::None
            }
        }
        (runtime::Win16HostNetbiosPayload::AdapterStatus { capacity }, Some(buffer)) => {
            buffer.check_overrun()?;
            if super::has_successful_completion(outcome) {
                super::require_adapter_layout()?;
                let output = super::output_buffer(
                    usize::from(*capacity),
                    "unable to retain asynchronous adapter status",
                )?;
                runtime::Win16HostNetbiosOutput::AdapterStatus {
                    bytes: super::project_adapter_status(buffer.as_bytes(), output)?,
                }
            } else {
                runtime::Win16HostNetbiosOutput::None
            }
        }
        (runtime::Win16HostNetbiosPayload::SessionStatus { capacity }, Some(buffer)) => {
            super::require_session_layout()?;
            buffer.check_overrun()?;
            if super::has_successful_completion(outcome) {
                let output = super::output_buffer(
                    usize::from(*capacity),
                    "unable to retain asynchronous session status",
                )?;
                runtime::Win16HostNetbiosOutput::SessionStatus {
                    bytes: super::project_session_status(
                        buffer.as_bytes(),
                        output,
                        usize::from(outcome.length),
                        false,
                    )?,
                }
            } else if outcome.function_return == 0x06
                && outcome.retcode == 0x06
                && outcome.cmd_cplt == 0x06
                && outcome.length >= 4
            {
                let output = super::output_buffer(
                    usize::from(*capacity),
                    "unable to retain partial asynchronous session status",
                )?;
                runtime::Win16HostNetbiosOutput::SessionStatus {
                    bytes: super::project_session_status(
                        buffer.as_bytes(),
                        output,
                        usize::from(outcome.length),
                        true,
                    )?,
                }
            } else {
                runtime::Win16HostNetbiosOutput::None
            }
        }
        _ => return Err(payload_command_mismatch()),
    };
    Ok(outcome.into_guest_result(payload))
}

fn pending_status(call: &runtime::Win16HostNetbiosCall) -> runtime::Win16HostNetbiosResult {
    runtime::Win16HostNetbiosResult {
        function_return: NRC_GOODRET,
        retcode: NRC_PENDING,
        lsn: call.lsn,
        num: call.num,
        length: call.length,
        cmd_cplt: NRC_PENDING,
        call_name: None,
        payload: runtime::Win16HostNetbiosOutput::None,
    }
}

fn last_error(operation: &'static str) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        operation,
        Win16NetbiosWindowsError(crate::windows::win32_safe::last_error()),
    )
}

#[derive(Debug)]
struct Win16NetbiosWindowsError(u32);

impl std::fmt::Display for Win16NetbiosWindowsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Windows error {}", self.0)
    }
}

impl std::error::Error for Win16NetbiosWindowsError {}
