//! Native DDEML transaction and data-handle ownership operations.

use super::data::copy_transaction_data;
use super::*;
use crate::windows::guest_text::GuestTextCodec;
use windows_sys::Win32::Foundation::ERROR_NO_UNICODE_TRANSLATION;

pub(super) enum DataCopyCreation {
    Created(HDDEDATA),
    Failed(u16),
}

pub(super) fn client_transaction(
    context: &WorkerContext,
    expected_instance: Win16HostDdeInstance,
    data: Win16HostDdeTransactionData,
    conversation: Win16HostDdeConversation,
    item: Option<Win16HostDdeString>,
    format: u16,
    transaction_type: u16,
    timeout: u32,
    return_result: bool,
    copyback: Option<Vec<u8>>,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let transaction_base = transaction_type::base(u32::from(transaction_type));
    let is_execute = transaction_base == transaction_type::base(XTYP_EXECUTE);
    let is_poke = transaction_base == transaction_type::base(XTYP_POKE);
    let transaction_uses_input_data = is_execute || is_poke;
    // DDEML consumes lpvData only for POKE and EXECUTE. The guest decoder
    // normalizes ignored fields to None; reject a direct opaque handle here
    // before native entry so its receipt remains NotPassed.
    if !transaction_uses_input_data {
        if let Win16HostDdeTransactionData::Data(token) = &data {
            return Ok(client_transaction_not_passed(
                Some(*token),
                compat_services::win16_dde::error::INVALIDPARAMETER,
            ));
        }
    }
    let (instance, native_conversation, native_item, input_data) = {
        let state = context.state.borrow();
        let instance = state.owner_for_conversation(conversation)?;
        if instance != expected_instance {
            return Err(protocol_error(
                "DDE ClientTransaction instance differs from its conversation owner",
            ));
        }
        let native_conversation = state.native_conversation(conversation)?;
        let native_item = if is_execute {
            ptr::null_mut()
        } else {
            state.native_optional_string(instance, item)?
        };
        let input_data = match (&data, transaction_uses_input_data) {
            (Win16HostDdeTransactionData::Data(token), true) => {
                let record = state.data.get(token)
                    .filter(|record| record.instance == instance && record.available)
                    .ok_or_else(|| protocol_error(
                        "DDE transaction data belongs to another instance or is no longer available"))?;
                Some((
                    *token,
                    record.native,
                    record.origin,
                    record.format,
                    record.item,
                    state.native_optional_string(instance, record.item)?,
                ))
            }
            _ => None,
        };
        (instance, native_conversation, native_item, input_data)
    };
    let native_instance = context.state.borrow().native_instance(instance)?;
    let has_input_payload =
        transaction_uses_input_data && !matches!(data, Win16HostDdeTransactionData::None);

    if is_poke {
        if let Some((token, _, _, source_format, _, source_item)) = input_data {
            let item_matches = match (source_item.is_null(), native_item.is_null()) {
                (true, true) => true,
                // SAFETY: `DdeCmpStringHandles` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                (false, false) => (unsafe { DdeCmpStringHandles(source_item, native_item) }) == 0,
                _ => false,
            };
            if source_format != format || !item_matches {
                return Ok(client_transaction_not_passed(
                    Some(token),
                    compat_services::win16_dde::error::INVALIDPARAMETER,
                ));
            }
        }
    }

    let unsupported_format = (!is_execute
        && format_requires_native_translation(format)
        && (has_input_payload || transaction_base == transaction_type::base(XTYP_REQUEST)))
        || input_data.is_some_and(|(_, _, _, source_format, _, _)| {
            format_requires_native_translation(source_format)
        });
    if unsupported_format {
        return Ok(client_transaction_not_passed(
            input_data.map(|(token, ..)| token),
            compat_services::win16_dde::error::NOTPROCESSED,
        ));
    }

    let transfer_operation_id = if input_data.is_some() {
        Some(worker::current_operation(context).ok_or_else(|| {
            protocol_error("DDE ClientTransaction has no owner operation identity")
        })?)
    } else {
        None
    };

    if let Some(bytes) = copyback.as_ref() {
        let Some((token, _, origin, _, _, _)) = input_data else {
            return Err(protocol_error(
                "DDE transaction copyback has no DataHandle source",
            ));
        };
        let state = context.state.borrow_mut();
        let record = state
            .data
            .get(&token)
            .filter(|record| {
                record.available
                    && record.origin == origin
                    && matches!(record.origin, DataOrigin::Created { .. })
                    && !record.transferred
            })
            .ok_or_else(|| {
                protocol_error("DDE transaction copyback source is no longer writable")
            })?;
        let lease = state.latest_access_lease(token)?;
        if state.access_count(token) == 0
            || usize::try_from(lease.byte_length).ok() != Some(bytes.len())
        {
            return Err(protocol_error(
                "DDE transaction copyback does not match its active AccessData lease",
            ));
        }
        // SAFETY: this is the live native pointer retained for the guest's
        // successful AccessData lease and both snapshots have the same length.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), lease.pointer, bytes.len());
        }
        let _ = record;
    } else if matches!(data, Win16HostDdeTransactionData::Data(_)) {
        // No copyback is required for a token without an active writable guest
        // AccessData snapshot.
    }

    let execute_payload = if is_execute {
        let source = match (&data, input_data) {
            (Win16HostDdeTransactionData::None, _) => None,
            (Win16HostDdeTransactionData::Bytes(bytes), _) => Some(bytes.clone()),
            (Win16HostDdeTransactionData::Data(_), Some((_, native, ..))) => {
                Some(super::data::snapshot_transaction_data(native)?)
            }
            (Win16HostDdeTransactionData::Data(_), None) => {
                return Err(protocol_error(
                    "DDE execute data handle has no validated native source",
                ));
            }
        };
        match source {
            Some(source) => match guest_execute_payload(context.guest_ansi_codec, &source) {
                Ok(payload) => Some(payload),
                Err(error) if is_guest_text_error(&error) => {
                    return Ok(client_transaction_not_passed(
                        input_data.map(|(token, ..)| token),
                        compat_services::win16_dde::error::INVALIDPARAMETER,
                    ));
                }
                Err(error) => return Err(error),
            },
            None => None,
        }
    } else {
        None
    };
    let execute_payload_length = execute_payload
        .as_ref()
        .map(|bytes| {
            u32::try_from(bytes.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "DDE UTF-16 execute payload exceeds DWORD size",
                    error,
                )
            })
        })
        .transpose()?
        .unwrap_or(0);

    let (native_data, mut owned_native_copy) = if is_execute {
        (None, None)
    } else {
        match input_data {
            Some((
                _,
                native,
                DataOrigin::CallbackBorrowed | DataOrigin::ClientResult,
                source_format,
                _,
                source_item,
            )) => match copy_transaction_data(native_instance, native, source_item, source_format)?
            {
                DataCopyCreation::Created(copy) => (Some(copy), Some(copy)),
                DataCopyCreation::Failed(error) => {
                    return Ok(client_transaction_not_passed(
                        input_data.map(|(token, ..)| token),
                        error,
                    ));
                }
            },
            Some((_, native, _, _, _, _)) => (Some(native), None),
            None => (None, None),
        }
    };
    let native_data_pointer = if !is_execute && matches!(data, Win16HostDdeTransactionData::Data(_))
    {
        match native_data {
            Some(native) => native as *const u8,
            None => {
                let error = protocol_error("DDE transaction native data token is missing");
                return match release_prepared_copy(native_instance, &mut owned_native_copy) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(super::super::errors::combine_cleanup_errors(
                        error,
                        cleanup,
                        "missing transaction data and prepared-copy cleanup both failed",
                    )),
                };
            }
        }
    } else {
        ptr::null()
    };

    let transfer_operation = match (input_data, transfer_operation_id) {
        (Some((token, native, origin, source_format, _, _)), Some(operation)) => {
            let guard_result = {
                let mut state = context.state.borrow_mut();
                state
                    .register_data_transfer_guard(
                        operation,
                        token,
                        instance,
                        native,
                        origin,
                        source_format,
                    )
                    .and_then(|()| {
                        match state.begin_data_transfer(
                            operation,
                            token,
                            instance,
                            native,
                            origin,
                            source_format,
                            is_execute
                                && matches!(
                                    origin,
                                    DataOrigin::Created {
                                        retain_after_transfer: false
                                    }
                                ),
                        ) {
                            Ok(()) => Ok(()),
                            Err(error) => match state.cancel_unbegun_data_transfer_guard(
                                operation,
                                token,
                                instance,
                                native,
                                origin,
                                source_format,
                            ) {
                                Ok(()) => Err(error),
                                Err(cleanup) => Err(super::super::errors::combine_cleanup_errors(
                                    error,
                                    cleanup,
                                    "DDE transfer guard entry and rollback both failed",
                                )),
                            },
                        }
                    })
            };
            if let Err(error) = guard_result {
                return match release_prepared_copy(native_instance, &mut owned_native_copy) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(super::super::errors::combine_cleanup_errors(
                        error,
                        cleanup,
                        "DDE transfer guard and prepared-copy cleanup both failed",
                    )),
                };
            }
            Some((operation, token, native, origin, source_format))
        }
        (None, None) => None,
        _ => {
            let error =
                protocol_error("DDE transaction source and operation guard identity disagree");
            return match release_prepared_copy(native_instance, &mut owned_native_copy) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(super::super::errors::combine_cleanup_errors(
                    error,
                    cleanup,
                    "DDE transfer identity and prepared-copy cleanup both failed",
                )),
            };
        }
    };

    let mut result_code = 0u32;
    let result_pointer = if return_result {
        &mut result_code
    } else {
        ptr::null_mut()
    };
    let native_format = if is_execute { 0 } else { u32::from(format) };
    let native_result = if is_execute {
        let payload = execute_payload.as_deref();
        let pointer = payload.map_or(ptr::null(), |bytes| {
            if bytes.is_empty() {
                ptr::null()
            } else {
                bytes.as_ptr()
            }
        });
        // SAFETY: DdeClientTransaction reads a caller-owned data span.
        unsafe {
            DdeClientTransaction(
                pointer,
                execute_payload_length,
                native_conversation,
                ptr::null_mut(),
                native_format,
                u32::from(transaction_type),
                timeout,
                result_pointer,
            )
        }
    } else if !transaction_uses_input_data {
        // SAFETY: DdeClientTransaction reads a caller-owned data span.
        unsafe {
            DdeClientTransaction(
                ptr::null(),
                0,
                native_conversation,
                native_item,
                native_format,
                u32::from(transaction_type),
                timeout,
                result_pointer,
            )
        }
    } else {
        match &data {
            // SAFETY: DdeClientTransaction reads a caller-owned data span.
            Win16HostDdeTransactionData::None => unsafe {
                DdeClientTransaction(
                    ptr::null(),
                    0,
                    native_conversation,
                    native_item,
                    native_format,
                    u32::from(transaction_type),
                    timeout,
                    result_pointer,
                )
            },
            Win16HostDdeTransactionData::Bytes(bytes) => {
                let length = u32::try_from(bytes.len()).map_err(|_| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "DDE transaction data exceeds DWORD size",
                    )
                })?;
                let pointer = if bytes.is_empty() {
                    ptr::null()
                } else {
                    bytes.as_ptr()
                };
                // SAFETY: DdeClientTransaction reads a caller-owned data span.
                unsafe {
                    DdeClientTransaction(
                        pointer,
                        length,
                        native_conversation,
                        native_item,
                        native_format,
                        u32::from(transaction_type),
                        timeout,
                        result_pointer,
                    )
                }
            }
            Win16HostDdeTransactionData::Data(_) => {
                // SAFETY: DdeClientTransaction reads a caller-owned data span.
                let result = unsafe {
                    DdeClientTransaction(
                        native_data_pointer,
                        u32::MAX,
                        native_conversation,
                        native_item,
                        native_format,
                        u32::from(transaction_type),
                        timeout,
                        result_pointer,
                    )
                };
                // DDEML receives ownership at entry for this fresh unowned copy,
                // regardless of the transaction's eventual success value.
                result
            }
        }
    };
    let succeeded = !native_result.is_null();
    let error = if succeeded {
        0
    } else {
        native_error(native_instance)
    };
    let returned_data = if succeeded
        && timeout != TIMEOUT_ASYNC
        && transaction_base == transaction_type::base(XTYP_REQUEST)
    {
        match context.state.borrow_mut().intern_data(
            instance,
            native_result,
            format,
            DataOrigin::ClientResult,
            item,
        ) {
            Ok(data) => data,
            Err(error) => {
                // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
                if unsafe { DdeFreeDataHandle(native_result) } == 0 {
                    return Err(RuntimeError::with_source(
                        Kind::HostFailure,
                        "DDE request data could not be indexed or released",
                        error,
                    ));
                }
                return Err(error);
            }
        }
    } else {
        None
    };

    let mut data_transfer = None;
    if let Some((operation, token, native, origin, source_format)) = transfer_operation {
        {
            let mut state = context.state.borrow_mut();
            let (guest_free_seen, instance_retired) = state.finish_data_transfer_guard(
                operation,
                token,
                instance,
                native,
                origin,
                source_format,
            )?;
            if matches!(
                origin,
                DataOrigin::Created {
                    retain_after_transfer: false
                }
            ) && state.data.contains_key(&token)
            {
                state.consume_data_transfer(token)?;
            }
            let source_remains = state.data.get(&token).is_some_and(|record| {
                record.instance == instance
                    && record.native == native
                    && record.origin == origin
                    && record.format == source_format
            });
            if matches!(
                origin,
                DataOrigin::Created {
                    retain_after_transfer: true
                }
            ) && !source_remains
                && !guest_free_seen
                && !instance_retired
            {
                return Err(protocol_error(
                    "APPOWNED DDE source disappeared without successful guest FreeData evidence",
                ));
            }
        }
        let outcome = match origin {
            DataOrigin::Created {
                retain_after_transfer: true,
            } => Win16HostDdeDataTransferOutcome::RetainedReadOnly,
            DataOrigin::Created {
                retain_after_transfer: false,
            } => Win16HostDdeDataTransferOutcome::Consumed,
            DataOrigin::CallbackBorrowed | DataOrigin::ClientResult => {
                Win16HostDdeDataTransferOutcome::CopiedInputRetained
            }
        };
        data_transfer = Some(Win16HostDdeDataTransfer { token, outcome });
    }

    if succeeded
        && returned_data.is_none()
        && timeout != TIMEOUT_ASYNC
        && transaction_base == transaction_type::base(XTYP_REQUEST)
        // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
        && unsafe { DdeFreeDataHandle(native_result) } == 0
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "unpublished DDE request result could not be released",
        ));
    }
    Ok(Win16HostDdeResult {
        value: Win16HostDdeValue::ClientTransaction {
            data: returned_data,
            succeeded,
            entered_native: true,
        },
        dde_error: error,
        transaction_result: return_result.then_some(result_code),
        data_transfer,
    })
}

fn guest_execute_payload(codec: GuestTextCodec, bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    // XTYP_EXECUTE is a null-terminated command string. Bytes after its first
    // guest NUL are outside that string and are not sent to the W conversation.
    let command = &bytes[..bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())];
    let wide = codec.to_wide(command)?;
    let units = wide.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "DDE UTF-16 execute unit count overflowed",
        )
    })?;
    let byte_length = units.checked_mul(2).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "DDE UTF-16 execute byte length overflowed",
        )
    })?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(byte_length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate UTF-16 DDE execute payload",
            error,
        )
    })?;
    for unit in wide {
        payload.extend_from_slice(&unit.to_le_bytes());
    }
    payload.extend_from_slice(&0_u16.to_le_bytes());
    Ok(payload)
}

fn is_guest_text_error(error: &RuntimeError) -> bool {
    error.kind() == Kind::InvalidInput
        || (error.kind() == Kind::HostFailure
            && (crate::windows::win32_safe::last_error()) == ERROR_NO_UNICODE_TRANSLATION)
}

fn client_transaction_not_passed(
    token: Option<Win16HostDdeData>,
    error: u16,
) -> Win16HostDdeResult {
    Win16HostDdeResult {
        value: Win16HostDdeValue::ClientTransaction {
            data: None,
            succeeded: false,
            entered_native: false,
        },
        dde_error: error,
        transaction_result: None,
        data_transfer: token.map(|token| Win16HostDdeDataTransfer {
            token,
            outcome: Win16HostDdeDataTransferOutcome::NotPassed,
        }),
    }
}

fn release_prepared_copy(
    native_instance: u32,
    prepared: &mut Option<HDDEDATA>,
) -> Result<(), RuntimeError> {
    let Some(native) = *prepared else {
        return Ok(());
    };
    // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
    if unsafe { DdeFreeDataHandle(native) } == 0 {
        let error = (crate::windows::win32_safe::dde_last_error(native_instance)) as u16;
        return Err(RuntimeError::new(
            Kind::HostFailure,
            format!(
                "DDEML could not release a prepared transaction copy before native entry (DMLERR {error:#06x})"
            ),
        ));
    }
    *prepared = None;
    Ok(())
}
