//! Native DDEML callback trampolines and typed callback replies.

use super::*;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

#[path = "win16_dde_native_callback_completion.rs"]
mod completion;
use completion::CallbackFrameCompletion;

#[path = "win16_dde_native_callback_projection.rs"]
mod projection;
use projection::{CallbackProjection, callback_call};

#[path = "win16_dde_native_callback_slots.rs"]
mod slots;
pub(super) use slots::CALLBACKS;

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
pub(super) unsafe extern "system" fn callback_trampoline<const SLOT: u16>(
    transaction_type: u32,
    format: u32,
    conversation: HCONV,
    string_1: HSZ,
    string_2: HSZ,
    data: HDDEDATA,
    data_1: usize,
    data_2: usize,
) -> HDDEDATA {
    dde_callback(
        SLOT,
        transaction_type,
        format,
        conversation,
        string_1,
        string_2,
        data,
        data_1,
        data_2,
    )
}

fn dde_callback(
    callback_slot: u16,
    transaction_type: u32,
    format: u32,
    conversation: HCONV,
    string_1: HSZ,
    string_2: HSZ,
    data: HDDEDATA,
    data_1: usize,
    data_2: usize,
) -> HDDEDATA {
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        worker::with_current_worker(|context| {
            run_callback(
                context,
                callback_slot,
                transaction_type,
                format,
                conversation,
                string_1,
                string_2,
                data,
                data_1,
                data_2,
            )
        })
    }));
    match caught {
        Ok(Some(Ok(native))) => native,
        Ok(Some(Err(error))) => {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker::with_current_worker(|context| {
                    worker::latch_callback_failure(context, error)
                });
            }));
            ptr::null_mut()
        }
        Ok(None) => ptr::null_mut(),
        Err(_) => {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker::with_current_worker(|context| {
                    worker::latch_callback_failure(
                        context,
                        RuntimeError::new(
                            Kind::HostFailure,
                            "panic occurred while projecting a native DDE callback",
                        ),
                    )
                });
            }));
            ptr::null_mut()
        }
    }
}

fn run_callback(
    context: &WorkerContext,
    callback_slot: u16,
    transaction_type: u32,
    format: u32,
    conversation: HCONV,
    string_1: HSZ,
    string_2: HSZ,
    data: HDDEDATA,
    data_1: usize,
    data_2: usize,
) -> Result<HDDEDATA, RuntimeError> {
    let call = match callback_call(
        context,
        callback_slot,
        transaction_type,
        format,
        conversation,
        string_1,
        string_2,
        data,
        data_1,
        data_2,
    )? {
        CallbackProjection::Guest(call) => call,
        CallbackProjection::Reject(value) => return Ok(value),
    };
    let delivery = match worker::publish_callback(context, call.clone()) {
        Ok(Some(delivery)) => delivery,
        Ok(None) => {
            cleanup_callback_frame(context, &call, None, None)?;
            return Ok(ptr::null_mut());
        }
        Err(error) => {
            let cleanup = cleanup_callback_frame(context, &call, None, None);
            return combine_callback_result(Err(error), cleanup.map(|()| ptr::null_mut()));
        }
    };
    let mut completion =
        CallbackFrameCompletion::new(context, &call, delivery.frame, delivery.parent);
    let response = match worker::wait_for_callback_reply(context, delivery.reply) {
        Ok(Some(reply)) => callback_reply(context, &call, delivery.frame, delivery.parent, reply),
        Ok(None) => Err(RuntimeError::new(
            Kind::HostFailure,
            "native DDE callback was cancelled before its guest reply",
        )),
        Err(error) => Err(error),
    };
    let result = match response {
        Err(error) => {
            let cleanup = completion.cleanup(None, None);
            combine_callback_result(Err(error), cleanup.map(|()| ptr::null_mut()))
        }
        Ok(reply) => {
            completion.remember(&reply);
            let cleanup = completion.cleanup(reply.returned_token, reply.wildconnect_source);
            if let Err(error) = cleanup {
                Err(error)
            } else {
                Ok(reply.native)
            }
        }
    };
    completion.finish(result)
}

#[derive(Default)]
struct NativeCallbackReply {
    native: HDDEDATA,
    native_instance: Option<u32>,
    returned_token: Option<Win16HostDdeData>,
    wildconnect_source: Option<Win16HostDdeData>,
    owns_reply: bool,
}

#[derive(Debug)]
struct DdeNativeApiFailure {
    operation: &'static str,
    native_instance: u32,
    dde_error: u16,
}

impl fmt::Display for DdeNativeApiFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} failed for DDEML instance {:#010x} (DMLERR={:#06x})",
            self.operation, self.native_instance, self.dde_error,
        )
    }
}

impl Error for DdeNativeApiFailure {}

fn callback_native_api_failure(operation: &'static str, native_instance: u32) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        operation,
        DdeNativeApiFailure {
            operation,
            native_instance,
            dde_error: native_error(native_instance),
        },
    )
}

impl NativeCallbackReply {
    fn no_data() -> Self {
        Self {
            native: ptr::null_mut(),
            ..Self::default()
        }
    }
}

fn callback_reply(
    context: &WorkerContext,
    call: &runtime::Win16DdeCallbackCall,
    frame: runtime::Win16HostDdeCallbackFrame,
    parent: Option<runtime::Win16HostDdeOperation>,
    reply: Win16DdeCallbackReply,
) -> Result<NativeCallbackReply, RuntimeError> {
    match reply {
        Win16DdeCallbackReply::NoData => Ok(NativeCallbackReply::no_data()),
        Win16DdeCallbackReply::CancelledByOwnerShutdown => Ok(NativeCallbackReply::no_data()),
        Win16DdeCallbackReply::Scalar(value) => {
            let class = callback_class::from_transaction_type(call.transaction_type)
                .ok_or_else(|| protocol_error("DDE callback transaction has no return class"))?;
            if class == callback_class::DATA && value != 0 && value != callback_class::BLOCK {
                return Err(protocol_error(
                    "DDE DATA-class callback returned a non-data scalar",
                ));
            }
            let raw = if value == callback_class::BLOCK {
                usize::MAX
            } else {
                value as usize
            };
            Ok(NativeCallbackReply {
                native: raw as HDDEDATA,
                ..NativeCallbackReply::default()
            })
        }
        Win16DdeCallbackReply::Data(token) => {
            if callback_class::from_transaction_type(call.transaction_type)
                != Some(callback_class::DATA)
            {
                return Err(protocol_error(
                    "non-DATA DDE callback returned an HDDEDATA token",
                ));
            }
            let (record, native_instance, native_item) = {
                let state = context.state.borrow();
                let record = state
                    .data
                    .get(&token)
                    .copied()
                    .filter(|record| record.instance == call.host_instance && record.available)
                    .ok_or_else(|| protocol_error("DDE callback returned an unknown data token"))?;
                ensure_byte_payload_format(record.format)?;
                (
                    record,
                    state.native_instance(call.host_instance)?,
                    state.native_optional_string(call.host_instance, record.item)?,
                )
            };
            match record.origin {
                DataOrigin::Created { .. } => Ok(NativeCallbackReply {
                    native: record.native,
                    returned_token: Some(token),
                    ..NativeCallbackReply::default()
                }),
                DataOrigin::CallbackBorrowed | DataOrigin::ClientResult => {
                    worker::reserve_callback_reply_cleanup_slot(context)?;
                    let creation = data::copy_transaction_data(
                        native_instance,
                        record.native,
                        native_item,
                        record.format,
                    );
                    match creation {
                        Ok(transaction::DataCopyCreation::Created(native)) => {
                            Ok(NativeCallbackReply {
                                native,
                                native_instance: Some(native_instance),
                                owns_reply: true,
                                ..NativeCallbackReply::default()
                            })
                        }
                        Ok(transaction::DataCopyCreation::Failed(error)) => {
                            let failure = RuntimeError::new(
                                Kind::HostFailure,
                                format!("DDE callback data copy failed with DMLERR {error:#06x}"),
                            );
                            match worker::release_callback_reply_cleanup_slot(context) {
                                Ok(()) => Err(failure),
                                Err(cleanup) => Err(super::super::errors::combine_cleanup_errors(
                                    failure,
                                    cleanup,
                                    "DDE callback data copy and owner-slot release both failed",
                                )),
                            }
                        }
                        Err(failure) => {
                            match worker::release_callback_reply_cleanup_slot(context) {
                                Ok(()) => Err(failure),
                                Err(cleanup) => Err(super::super::errors::combine_cleanup_errors(
                                    failure,
                                    cleanup,
                                    "DDE callback data copy and owner-slot release both failed",
                                )),
                            }
                        }
                    }
                }
            }
        }
        Win16DdeCallbackReply::WildConnect { source, pairs } => {
            if transaction_type::base(call.transaction_type)
                != transaction_type::base(XTYP_WILDCONNECT)
                || callback_class::from_transaction_type(call.transaction_type)
                    != Some(callback_class::DATA)
            {
                return Err(protocol_error(
                    "non-WILDCONNECT callback returned HSZPAIR data",
                ));
            }
            let (native_instance, source_record, native_pairs) = {
                let state = context.state.borrow();
                let source_record = state
                    .data
                    .get(&source)
                    .copied()
                    .filter(|record| record.instance == call.host_instance && record.available)
                    .ok_or_else(|| protocol_error("DDE WILDCONNECT source token is unavailable"))?;
                ensure_byte_payload_format(source_record.format)?;
                let native_instance = state.native_instance(call.host_instance)?;
                let capacity = pairs.len().checked_add(1).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "DDE WILDCONNECT pair count overflowed",
                    )
                })?;
                let mut native_pairs = Vec::new();
                native_pairs.try_reserve_exact(capacity).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "allocate native DDE WILDCONNECT pairs",
                        error,
                    )
                })?;
                for pair in pairs {
                    let (Some(service), Some(topic)) = (pair.service, pair.topic) else {
                        return Err(protocol_error("DDE WILDCONNECT pair contains a null HSZ"));
                    };
                    native_pairs.push(HSZPAIR {
                        hszSvc: state.native_string(call.host_instance, service)?,
                        hszTopic: state.native_string(call.host_instance, topic)?,
                    });
                }
                native_pairs.push(HSZPAIR::default());
                (native_instance, source_record, native_pairs)
            };
            let byte_count = native_pairs
                .len()
                .checked_mul(size_of::<HSZPAIR>())
                .and_then(|count| u32::try_from(count).ok())
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "DDE WILDCONNECT pair array exceeds DWORD size",
                    )
                })?;
            worker::reserve_callback_reply_cleanup_slot(context)?;
            // SAFETY: DdeCreateDataHandle reads a caller-owned byte span.
            let native = unsafe {
                DdeCreateDataHandle(
                    native_instance,
                    native_pairs.as_ptr().cast::<u8>(),
                    byte_count,
                    0,
                    ptr::null_mut(),
                    0,
                    0,
                )
            };
            if native.is_null() {
                let failure = callback_native_api_failure(
                    "DdeCreateDataHandle for WILDCONNECT reply",
                    native_instance,
                );
                return match worker::release_callback_reply_cleanup_slot(context) {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(super::super::errors::combine_cleanup_errors(
                        failure,
                        cleanup,
                        "WILDCONNECT creation and owner-slot release both failed",
                    )),
                };
            }
            if matches!(
                source_record.origin,
                DataOrigin::Created {
                    retain_after_transfer: false
                } // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
            ) && unsafe { DdeFreeDataHandle(source_record.native) } == 0
            {
                let source_failure = callback_native_api_failure(
                    "DdeFreeDataHandle for WILDCONNECT source",
                    native_instance,
                );
                // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
                if unsafe { DdeFreeDataHandle(native) } == 0 {
                    let reply_error = Arc::new(callback_native_api_failure(
                        "DdeFreeDataHandle for untransferred WILDCONNECT reply",
                        native_instance,
                    ));
                    let reply_failure = RuntimeError::with_source(
                        reply_error.kind(),
                        "DDEML could not release the prepared WILDCONNECT result",
                        Arc::clone(&reply_error),
                    );
                    let retained = worker::retain_failed_callback_reply(
                        context,
                        worker::FailedCallbackReplyIdentity {
                            frame,
                            operation: parent,
                            instance: call.host_instance,
                            role: runtime::Win16DdeCallbackReplyRole::WildConnectReply,
                        },
                        Some(native_instance),
                        native as usize,
                        RuntimeError::with_source(
                            reply_error.kind(),
                            "retain the WILDCONNECT reply after native release failed",
                            Arc::clone(&reply_error),
                        ),
                    );
                    let mut failure = super::super::errors::combine_cleanup_errors(
                        source_failure,
                        reply_failure,
                        "WILDCONNECT source consumption and prepared-result release both failed",
                    );
                    if let Err(retention) = retained {
                        failure = super::super::errors::combine_cleanup_errors(
                            failure,
                            retention,
                            "WILDCONNECT failure and reply-owner retention both failed",
                        );
                    }
                    return Err(failure);
                }
                return match worker::release_callback_reply_cleanup_slot(context) {
                    Ok(()) => Err(source_failure),
                    Err(cleanup) => Err(super::super::errors::combine_cleanup_errors(
                        source_failure,
                        cleanup,
                        "WILDCONNECT source release and owner-slot release both failed",
                    )),
                };
            }
            Ok(NativeCallbackReply {
                native,
                native_instance: Some(native_instance),
                wildconnect_source: Some(source),
                owns_reply: true,
                ..NativeCallbackReply::default()
            })
        }
    }
}

fn cleanup_callback_frame(
    context: &WorkerContext,
    call: &runtime::Win16DdeCallbackCall,
    returned_token: Option<Win16HostDdeData>,
    wildconnect_source: Option<Win16HostDdeData>,
) -> Result<(), RuntimeError> {
    let mut state = context.state.borrow_mut();
    if let Some(token) = returned_token {
        let record = state
            .data
            .get(&token)
            .copied()
            .filter(|record| record.instance == call.host_instance)
            .ok_or_else(|| protocol_error("DDE callback result disappeared before transfer"))?;
        match record.origin {
            DataOrigin::Created {
                retain_after_transfer: true,
            } => {
                state
                    .data
                    .get_mut(&token)
                    .ok_or_else(|| {
                        protocol_error("DDE callback result disappeared during transfer")
                    })?
                    .transferred = true;
            }
            DataOrigin::Created {
                retain_after_transfer: false,
            } => {
                let native_key = record.native as usize;
                {
                    let record = state.data.get_mut(&token).ok_or_else(|| {
                        protocol_error("DDE callback result disappeared during transfer")
                    })?;
                    record.transferred = true;
                    record.available = false;
                }
                if state.data_by_native.get(&native_key) == Some(&token) {
                    state.data_by_native.remove(&native_key);
                }
            }
            DataOrigin::CallbackBorrowed | DataOrigin::ClientResult => {
                return Err(protocol_error(
                    "callback copy source was incorrectly scheduled as a transferred result",
                ));
            }
        }
    }
    if let Some(token) = wildconnect_source {
        let record = state
            .data
            .get(&token)
            .copied()
            .filter(|record| record.instance == call.host_instance)
            .ok_or_else(|| {
                protocol_error("DDE WILDCONNECT source disappeared before retirement")
            })?;
        match record.origin {
            DataOrigin::Created {
                retain_after_transfer: true,
            } => {
                if let Some(record) = state.data.get_mut(&token) {
                    record.transferred = true;
                }
            }
            DataOrigin::Created {
                retain_after_transfer: false,
            } => {
                if let Some(record) = state.data.get_mut(&token) {
                    record.transferred = true;
                    record.available = false;
                }
                if state.data_by_native.get(&(record.native as usize)) == Some(&token) {
                    state.data_by_native.remove(&(record.native as usize));
                }
                state.collect_consumed_data(token)?;
            }
            DataOrigin::CallbackBorrowed | DataOrigin::ClientResult => {}
        }
    }
    if let Win16HostDdeCallbackData::Borrowed { handle, .. } = &call.data {
        let handle = *handle;
        let record = state
            .data
            .get(&handle)
            .filter(|record| record.instance == call.host_instance)
            .ok_or_else(|| {
                protocol_error("DDE callback input lost its pinned native data identity")
            })?;
        if record.callback_references == 0 {
            return Err(protocol_error("DDE callback input pin count underflow"));
        }
        state.unpin_callback_data(handle)?;
    }
    let strings: BTreeSet<_> = [call.host_string_1, call.host_string_2]
        .into_iter()
        .flatten()
        .collect();
    for token in strings {
        state.unpin_callback_string(token)?;
    }
    if transaction_type::base(call.transaction_type) == transaction_type::base(XTYP_DISCONNECT)
        && let Some(conversation) = call.host_conversation
    {
        state.remove_conversation(conversation);
    }
    Ok(())
}

fn split_callback_result<T>(
    result: Result<T, RuntimeError>,
) -> (Result<T, RuntimeError>, Result<(), RuntimeError>) {
    match result {
        Ok(value) => (Ok(value), Ok(())),
        Err(error) => {
            let kind = error.kind();
            let message = error.to_string();
            let shared = Arc::new(error);
            (
                Err(RuntimeError::with_source(
                    kind,
                    message.clone(),
                    Arc::clone(&shared),
                )),
                Err(RuntimeError::with_source(kind, message, shared)),
            )
        }
    }
}

fn combine_cleanup_errors(
    first: Result<(), RuntimeError>,
    second: Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    match (first, second) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(primary), Err(cleanup)) => Err(super::super::errors::combine_cleanup_errors(
            primary,
            cleanup,
            "DDE callback cleanup and reply release both failed",
        )),
    }
}

fn combine_callback_result<T>(
    first: Result<T, RuntimeError>,
    cleanup: Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    match (first, cleanup) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(super::super::errors::combine_cleanup_errors(
            error,
            cleanup,
            "DDE callback projection and cleanup both failed",
        )),
    }
}
