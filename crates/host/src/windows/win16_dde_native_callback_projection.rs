//! Native DDEML callback argument projection and host-handle staging.

use super::*;
use windows_sys::Win32::Foundation::ERROR_NO_UNICODE_TRANSLATION;
use windows_sys::Win32::System::DataExchange::{XCLASS_NOTIFICATION, XTYPF_NOBLOCK};

// windows-sys omits XTYP_ERROR although the target SDK defines it as
// XCLASS_NOTIFICATION | XTYPF_NOBLOCK. Compose the missing transaction type
// from windows-sys's exported SDK constants instead of duplicating its value.
const XTYP_ERROR: u32 = XCLASS_NOTIFICATION | XTYPF_NOBLOCK;

pub(super) fn callback_call(
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
) -> Result<CallbackProjection, RuntimeError> {
    let (host_instance, callback_route) = {
        let state = context.state.borrow();
        let registration = state
            .callbacks_by_slot
            .get(&callback_slot)
            .ok_or_else(|| protocol_error("native DDE callback used an unknown trampoline slot"))?;
        (registration.instance, registration.route)
    };
    publish_initializing_instance(context, host_instance)?;
    let callback_format = word_value(format, "DDE callback format")?;
    let base = transaction_type::base(transaction_type);
    let is_context_transaction = transaction_type::base(transaction_type)
        == transaction_type::base(XTYP_CONNECT)
        || base == transaction_type::base(XTYP_WILDCONNECT);
    let conversation_context = if is_context_transaction && data_1 != 0 {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let native_context = unsafe { &*(data_1 as *const CONVCONTEXT) };
        Some(from_native_context(native_context)?)
    } else {
        None
    };
    // Only transaction types whose contract uses these ULONG_PTR fields are
    // projected. Other callback variants receive zeroed reserved fields so a
    // 64-bit HWND/HANDLE value can never be mistaken for a guest DWORD.
    let (data_1, data_2) = if is_context_transaction {
        (
            Some(0),
            Some(u32::try_from(data_2).map_err(|_| {
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "DDE callback scalar does not fit the Win16 DWORD field",
                )
            })?),
        )
    } else if base == transaction_type::base(XTYP_CONNECT_CONFIRM)
        || base == transaction_type::base(XTYP_DISCONNECT)
    {
        // For these notifications lParam1 is reserved and lParam2 carries
        // fSameInstance, per DDEML.H and the Windows 3.1 reference.
        (
            Some(0),
            Some(u32::try_from(data_2).map_err(|_| {
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "DDE same-instance flag does not fit the Win16 BOOL field",
                )
            })?),
        )
    } else if base == transaction_type::base(XTYP_ADVREQ) {
        // XTYP_ADVREQ defines LOWORD(dwData1) as the requested advise count;
        // CADV_LATEACK is the valid sentinel 0xffff.
        (Some(u32::from(data_1 as u16)), Some(0))
    } else if base == transaction_type::base(XTYP_ERROR) {
        // XTYP_ERROR defines LOWORD(dwData1) as the DMLERR value.
        (Some(u32::from(data_1 as u16)), Some(0))
    } else if base == transaction_type::base(XTYP_XACT_COMPLETE) {
        (
            Some(u32::try_from(data_1).map_err(|_| {
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "DDE transaction identifier does not fit the Win16 DWORD field",
                )
            })?),
            Some(u32::try_from(data_2).map_err(|_| {
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "DDE transaction result does not fit the Win16 DWORD field",
                )
            })?),
        )
    } else {
        (Some(0), Some(0))
    };
    let success_without_data =
        !data.is_null() && base == transaction_type::base(XTYP_XACT_COMPLETE) && data as usize == 1;
    let data_is_used = matches!(base,
        value if value == transaction_type::base(XTYP_ADVDATA)
            || value == transaction_type::base(XTYP_EXECUTE)
            || value == transaction_type::base(XTYP_POKE)
            || value == transaction_type::base(XTYP_XACT_COMPLETE));
    let data_uses_item = base == transaction_type::base(XTYP_ADVDATA)
        || base == transaction_type::base(XTYP_POKE)
        || base == transaction_type::base(XTYP_XACT_COMPLETE);
    let borrowed_native_data = if !data_is_used || data.is_null() || success_without_data {
        None
    } else if format_requires_native_translation(callback_format) {
        worker::report_diagnostic_once(
            context,
            "dde-known-handle-callback-payload",
            runtime::Diagnostic::warning(
                Kind::CompatibilityGap,
                "DDE callback payload uses a Win16 bitmap, palette, or metafile handle format that has no safe host-resource translator",
            ),
        )?;
        if base != transaction_type::base(XTYP_XACT_COMPLETE) {
            // For POKE, EXECUTE, and ADVDATA the SDK defines zero as
            // DDE_FNOTPROCESSED. Do not publish native resource bytes to the
            // guest or pretend the guest callback handled them.
            return Ok(CallbackProjection::Reject(ptr::null_mut()));
        }
        // Preserve the transaction-complete notification while withholding
        // its unsafe data payload from the Win16 callback.
        None
    } else if base == transaction_type::base(XTYP_EXECUTE) {
        match translated_execute_data(context, host_instance, data)? {
            Some(native) => Some((native, callback_format, true)),
            None => return Ok(CallbackProjection::Reject(ptr::null_mut())),
        }
    } else {
        Some((data, callback_format, false))
    };
    let (host_conversation, host_string_1, host_string_2, host_data) = {
        let mut state = context.state.borrow_mut();
        intern_callback_handles(
            &mut state,
            host_instance,
            conversation,
            string_1,
            string_2,
            borrowed_native_data,
            data_uses_item,
        )?
    };
    let callback_data = if success_without_data {
        Win16HostDdeCallbackData::SuccessNoData
    } else if let Some(handle) = host_data {
        Win16HostDdeCallbackData::Borrowed {
            handle,
            snapshot: None,
        }
    } else {
        Win16HostDdeCallbackData::Null
    };
    Ok(CallbackProjection::Guest(runtime::Win16DdeCallbackCall {
        host_instance,
        callback_route,
        transaction_type,
        format: callback_format,
        host_conversation,
        host_string_1,
        host_string_2,
        data: callback_data,
        conversation_context,
        data_1,
        data_2,
    }))
}

pub(super) enum CallbackProjection {
    Guest(runtime::Win16DdeCallbackCall),
    Reject(HDDEDATA),
}

fn publish_initializing_instance(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
) -> Result<(), RuntimeError> {
    let Some(pointer) = worker::initializing_instance_output(context, instance)? else {
        return Ok(());
    };
    if pointer.is_null() {
        return Err(protocol_error(
            "DDE initialization callback lost its native instance output slot",
        ));
    }
    // SAFETY: initialize stores this pointer only around the synchronous
    // DdeInitializeW call, on the same DDE owner thread that invokes us.
    let native = unsafe { *pointer };
    if native == 0 {
        return Err(protocol_error(
            "DDEML invoked its callback before publishing the native instance ID",
        ));
    }
    let mut state = context.state.borrow_mut();
    if let Some(owner) = state.instances_by_native.get(&native) {
        if *owner != instance {
            return Err(protocol_error(
                "provisional DDE instance ID aliases another live instance",
            ));
        }
    }
    let record = state.instances.get_mut(&instance).ok_or_else(|| {
        protocol_error("provisional DDE instance disappeared during its callback")
    })?;
    if record.native != 0 && record.native != native {
        return Err(protocol_error(
            "DDE initialization changed its native instance ID",
        ));
    }
    record.native = native;
    state.instances_by_native.insert(native, instance);
    Ok(())
}

fn intern_callback_handles(
    state: &mut NativeState,
    instance: Win16HostDdeInstance,
    conversation: HCONV,
    string_1: HSZ,
    string_2: HSZ,
    data: Option<(HDDEDATA, u16, bool)>,
    data_uses_item: bool,
) -> Result<
    (
        Option<Win16HostDdeConversation>,
        Option<Win16HostDdeString>,
        Option<Win16HostDdeString>,
        Option<Win16HostDdeData>,
    ),
    RuntimeError,
> {
    let conversation_was_known = conversation.is_null()
        || state
            .conversations_by_native
            .contains_key(&(conversation as usize));
    let string_1_was_known = string_1.is_null()
        || state
            .strings_by_native
            .contains_key(&(instance, string_1 as usize));
    let string_2_was_known = string_2.is_null()
        || state
            .strings_by_native
            .contains_key(&(instance, string_2 as usize));
    let data_was_known = data.map_or(true, |(native, _, _)| {
        state.data_by_native.contains_key(&(native as usize))
    });
    let result = (|| {
        let host_conversation = state.intern_conversation(instance, conversation)?;
        let host_string_1 = state.intern_string(instance, string_1)?;
        let host_string_2 = state.intern_string(instance, string_2)?;
        let data_item = if data_uses_item { host_string_2 } else { None };
        let host_data = data
            .map(|(native, format, native_owned)| {
                state
                    .intern_data(
                        instance,
                        native,
                        format,
                        DataOrigin::CallbackBorrowed,
                        data_item,
                    )
                    .and_then(|token| {
                        token.ok_or_else(|| {
                            protocol_error(
                                "non-null DDE callback data did not produce a host token",
                            )
                        })
                    })
                    .and_then(|token| {
                        if native_owned {
                            state.mark_native_data_owned(token)?;
                        }
                        Ok(token)
                    })
            })
            .transpose()?;
        let callback_strings: BTreeSet<_> = [host_string_1, host_string_2]
            .into_iter()
            .flatten()
            .collect();
        for token in &callback_strings {
            let record = state.strings.get(token).ok_or_else(|| {
                protocol_error("DDE callback string token disappeared before it was pinned")
            })?;
            record.callback_references.checked_add(1).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "DDE callback string pin count is exhausted",
                )
            })?;
        }
        if let Some(token) = host_data {
            let record = state.data.get(&token).ok_or_else(|| {
                protocol_error("DDE callback data token disappeared before it was pinned")
            })?;
            record.callback_references.checked_add(1).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "DDE callback data pin count is exhausted",
                )
            })?;
        }
        if let Some(token) = host_data {
            if let Some(record) = state.data.get_mut(&token) {
                record.callback_references += 1;
            }
        }
        for token in callback_strings {
            if let Some(record) = state.strings.get_mut(&token) {
                record.callback_references += 1;
            }
        }
        Ok((host_conversation, host_string_1, host_string_2, host_data))
    })();
    match result {
        Err(primary) => {
            let mut failure = primary;
            if !data_was_known {
                if let Some((native, _, native_owned)) = data {
                    if let Some(token) = state.data_by_native.get(&(native as usize)).copied() {
                        if let Err(cleanup) = state.remove_data(token) {
                            failure = super::super::super::errors::combine_cleanup_errors(
                                failure,
                                cleanup,
                                "DDE callback projection and data rollback both failed",
                            );
                        }
                    // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
                    } else if native_owned && unsafe { DdeFreeDataHandle(native) } == 0 {
                        failure = super::super::super::errors::combine_cleanup_errors(
                            failure,
                            RuntimeError::new(
                                Kind::HostFailure,
                                "release an unindexed translated DDE execute payload",
                            ),
                            "DDE callback projection and unindexed data rollback both failed",
                        );
                    }
                }
            }
            if !string_2_was_known {
                if let Some(token) = state
                    .strings_by_native
                    .get(&(instance, string_2 as usize))
                    .copied()
                {
                    state.discard_unreferenced_string(token);
                }
            }
            if !string_1_was_known {
                if let Some(token) = state
                    .strings_by_native
                    .get(&(instance, string_1 as usize))
                    .copied()
                {
                    state.discard_unreferenced_string(token);
                }
            }
            if !conversation_was_known {
                if let Some(token) = state
                    .conversations_by_native
                    .get(&(conversation as usize))
                    .copied()
                {
                    state.remove_conversation(token);
                }
            }
            Err(failure)
        }
        Ok(value) => Ok(value),
    }
}

/// Project the Unicode command supplied to a W DDE callback into a temporary
/// guest-ANSI DDE object. The original execute handle remains DDEML-owned.
fn translated_execute_data(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    source: HDDEDATA,
) -> Result<Option<HDDEDATA>, RuntimeError> {
    let bytes = super::data::snapshot_transaction_data(source)?;
    let Some(terminator) = bytes.chunks_exact(2).position(|unit| unit == [0, 0]) else {
        return Ok(None);
    };
    if bytes.len() % 2 != 0 {
        return Ok(None);
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(terminator).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate UTF-16 DDE execute snapshot",
            error,
        )
    })?;
    wide.extend(
        bytes[..terminator * 2]
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]])),
    );
    let encoded = match context.guest_ansi_codec.from_wide(&wide) {
        Ok(encoded) => encoded,
        Err(error) if is_guest_text_error(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    if encoded.used_default_char == Some(true) {
        return Ok(None);
    }
    let length = encoded.bytes.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "guest DDE execute payload length overflowed",
        )
    })?;
    let count = u32::try_from(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "guest DDE execute payload exceeds DWORD size",
            error,
        )
    })?;
    let mut guest_bytes = encoded.bytes;
    guest_bytes.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "terminate guest DDE execute payload",
            error,
        )
    })?;
    guest_bytes.push(0);
    let native_instance = context.state.borrow().native_instance(instance)?;
    // SAFETY: DdeCreateDataHandle reads a caller-owned byte span.
    let native = unsafe {
        DdeCreateDataHandle(
            native_instance,
            guest_bytes.as_ptr(),
            count,
            0,
            ptr::null_mut(),
            0,
            u32::from(compat_services::win16_dde::data_flag::HDATA_APPOWNED),
        )
    };
    if !native.is_null() {
        return Ok(Some(native));
    }
    let error = native_error(native_instance);
    if error == compat_services::win16_dde::error::MEMORY_ERROR {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "DDEML could not allocate translated execute data",
        ));
    }
    Err(RuntimeError::new(
        Kind::HostFailure,
        format!("DDEML could not allocate translated execute data (DMLERR {error:#06x})"),
    ))
}

fn is_guest_text_error(error: &RuntimeError) -> bool {
    error.kind() == Kind::InvalidInput
        || (error.kind() == Kind::HostFailure
            && (crate::windows::win32_safe::last_error()) == ERROR_NO_UNICODE_TRANSLATION)
}
