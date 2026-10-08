//! Typed DDEML cleanup, error, and wire-conversion helpers.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::mem::size_of;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeAbortPhase, Win16DdeCleanupFailure,
    Win16DdeCleanupStatus, Win16DdeNativeInstanceReceipt, Win16HostDdeContext,
    Win16HostDdeConversation, Win16HostDdeData, Win16HostDdeInstance,
    Win16HostDdeResult, Win16HostDdeValue,
};
use windows_sys::Win32::System::DataExchange::{
    DdeDisconnect, DdeGetLastError, DdeUnaccessData, DdeUninitialize,
};

use super::{NativeState, WorkerContext};

pub(in super::super) fn release_all_data_accesses(
    state: &mut NativeState,
    token: Win16HostDdeData,
) -> Result<(), RuntimeError> {
    loop {
        if state.access_count(token) == 0 {
            return Ok(());
        }
        let record = state.data.get(&token).copied().ok_or_else(|| {
            protocol_error("DDE access lease lost its native data record during cleanup")
        })?;
        let native_instance = state.native_instance(record.instance)?;
        if unsafe { DdeUnaccessData(record.native) } == 0 {
            let error = unsafe { DdeGetLastError(native_instance) };
            return Err(RuntimeError::new(
                Kind::HostFailure,
                format!(
                    "DDEML refused to release a retained AccessData lease (error {error:#06x})"
                ),
            ));
        }
        state.note_unaccess(token)?;
        state.collect_consumed_data(token)?;
    }
}

pub(in super::super) fn cancel_active_conversations(
    context: &WorkerContext,
) -> Result<(), RuntimeError> {
    let conversations: Vec<_> = context
        .state
        .borrow()
        .conversations
        .iter()
        .map(|(token, record)| (*token, record.instance, record.native))
        .collect();
    let mut first_error = None;
    for (token, instance, native) in conversations {
        if !conversation_identity_is_live(context, token, instance, native) {
            continue;
        }
        let disconnected = unsafe { DdeDisconnect(native) } != 0;
        if disconnected {
            if conversation_identity_is_live(context, token, instance, native) {
                context.state.borrow_mut().remove_conversation(token);
            }
        } else if conversation_identity_is_live(context, token, instance, native) {
            let native_instance = match context.state.borrow().native_instance(instance) {
                Ok(native_instance) => native_instance,
                Err(error) => {
                    remember_cleanup_failure(
                        &mut first_error,
                        error,
                        "DDE conversation shutdown cleanup had multiple failures",
                    );
                    continue;
                }
            };
            let error = unsafe { DdeGetLastError(native_instance) };
            remember_cleanup_failure(
                &mut first_error,
                RuntimeError::new(
                    Kind::HostFailure,
                    format!(
                        "DDEML could not disconnect an active conversation for shutdown (error {error:#06x})"
                    ),
                ),
                "DDE conversation shutdown cleanup had multiple failures",
            );
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn conversation_identity_is_live(
    context: &WorkerContext,
    token: Win16HostDdeConversation,
    instance: Win16HostDdeInstance,
    native: windows_sys::Win32::System::DataExchange::HCONV,
) -> bool {
    let state = context.state.borrow();
    state.instances.contains_key(&instance)
        && state
            .conversations
            .get(&token)
            .is_some_and(|record| record.instance == instance && record.native == native)
}

pub(in super::super) struct NativeInstanceShutdownReport {
    pub(in super::super) instances: Vec<Win16DdeNativeInstanceReceipt>,
    pub(in super::super) transfer_guards:
        Vec<runtime::Win16DdeNativeTransferGuardReceipt>,
    pub(in super::super) failures: Vec<Win16DdeCleanupFailure>,
    pub(in super::super) all_uninitialized: bool,
    pub(in super::super) all_transfer_guards_retired: bool,
}

pub(in super::super) fn uninitialize_all(context: &WorkerContext) -> NativeInstanceShutdownReport {
    let mut first_errors = BTreeMap::new();
    let mut access_failures = BTreeMap::new();
    let mut receipts = BTreeMap::new();
    loop {
        let access_tokens: Vec<_> = context
            .state
            .borrow()
            .access_pointers
            .keys()
            .copied()
            .collect();
        for token in access_tokens {
            let instance = context
                .state
                .borrow()
                .data
                .get(&token)
                .map(|record| record.instance);
            let release_result = {
                let mut state = context.state.borrow_mut();
                release_all_data_accesses(&mut state, token)
            };
            if let Err(error) = release_result {
                let cause = Arc::new(RuntimeError::with_source(
                    error.kind(),
                    format!("release retained DDE AccessData leases for {token:?} during shutdown"),
                    error,
                ));
                access_failures.entry(token).or_insert((instance, cause));
            }
        }
        let instances: Vec<(Win16HostDdeInstance, u32)> = context
            .state
            .borrow()
            .instances
            .iter()
            .map(|(token, record)| (*token, record.native))
            .collect();
        if instances.is_empty() {
            break;
        }

        let mut retry_needed = false;
        for (token, native) in instances {
            if unsafe { DdeUninitialize(native) } != 0 {
                context.state.borrow_mut().remove_instance(token);
                let failure = first_errors.get(&token).cloned();
                receipts.insert(token, Win16DdeNativeInstanceReceipt {
                    instance: token,
                    status: if failure.is_some() {
                        Win16DdeCleanupStatus::RetriedAndReleased
                    } else {
                        Win16DdeCleanupStatus::Released
                    },
                    failure,
                });
                continue;
            }

            retry_needed = true;
            let native_error = unsafe { DdeGetLastError(native) };
            first_errors.entry(token).or_insert_with(|| {
                Arc::new(RuntimeError::with_source(
                    Kind::HostFailure,
                    "DDEML refused to release an owned instance during shutdown",
                    DdeUninitializeFailure { token, native_error },
                ))
            });
        }
        if retry_needed {
            thread::sleep(Duration::from_millis(50));
        }
    }

    let mut failures: Vec<_> = first_errors
        .into_iter()
        .map(|(instance, cause)| Win16DdeCleanupFailure {
            phase: Win16DdeAbortPhase::UninitializeInstance,
            frame: None,
            operation: None,
            instance: Some(instance),
            status: Win16DdeCleanupStatus::RetriedAndReleased,
            cause,
        })
        .collect();
    failures.extend(access_failures.into_iter().map(|(_token, (instance, cause))| {
        Win16DdeCleanupFailure {
            phase: Win16DdeAbortPhase::UninitializeInstance,
            frame: None,
            operation: None,
            instance,
            status: if instance.is_some_and(|instance| receipts.contains_key(&instance)) {
                Win16DdeCleanupStatus::RetriedAndReleased
            } else {
                Win16DdeCleanupStatus::Retained
            },
            cause,
        }
    }));
    let instances: Vec<_> = receipts.into_values().collect();
    let (transfer_guards, all_transfer_guards_retired) = match context
        .state
        .borrow_mut()
        .retire_shutdown_transfer_guards(&instances)
    {
        Ok(receipts) => receipts,
        Err(error) => {
            failures.push(Win16DdeCleanupFailure {
                phase: Win16DdeAbortPhase::UninitializeInstance,
                frame: None,
                operation: None,
                instance: None,
                status: Win16DdeCleanupStatus::Retained,
                cause: Arc::new(error),
            });
            (Vec::new(), false)
        }
    };
    NativeInstanceShutdownReport {
        instances,
        transfer_guards,
        failures,
        all_uninitialized: context.state.borrow().instances.is_empty(),
        all_transfer_guards_retired,
    }
}

#[derive(Debug)]
struct DdeUninitializeFailure {
    token: Win16HostDdeInstance,
    native_error: u32,
}

impl fmt::Display for DdeUninitializeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "DDEML could not uninitialize instance {:#06x} (error {:#06x})",
            self.token.0, self.native_error
        )
    }
}

impl Error for DdeUninitializeFailure {}

fn remember_cleanup_failure(
    failures: &mut Option<RuntimeError>,
    error: RuntimeError,
    context: &'static str,
) {
    *failures = Some(match failures.take() {
        Some(primary) => primary.with_cleanup(context, error),
        None => error,
    });
}

pub(super) fn to_native_context(
    value: Win16HostDdeContext,
) -> windows_sys::Win32::System::DataExchange::CONVCONTEXT {
    use windows_sys::Win32::System::DataExchange::CONVCONTEXT;
    let mut native = CONVCONTEXT::default();
    native.cb = u32::try_from(size_of::<CONVCONTEXT>()).expect("CONVCONTEXT size fits DWORD");
    native.wFlags = u32::from(value.flags);
    native.wCountryID = u32::from(value.country_id);
    native.iCodePage = i32::from(value.code_page);
    native.dwLangID = value.language_id;
    native.dwSecurity = value.security;
    native
}

pub(super) fn from_native_context(
    value: &windows_sys::Win32::System::DataExchange::CONVCONTEXT,
) -> Result<Win16HostDdeContext, RuntimeError> {
    Ok(Win16HostDdeContext {
        flags: word_value(value.wFlags, "DDE context flags")?,
        country_id: word_value(value.wCountryID, "DDE context country")?,
        code_page: i16::try_from(value.iCodePage).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "DDE context code page does not fit the Win16 INT16 field",
            )
        })?,
        language_id: value.dwLangID,
        security: value.dwSecurity,
    })
}

pub(super) fn word_value(value: u32, name: &'static str) -> Result<u16, RuntimeError> {
    u16::try_from(value).map_err(|_| {
        RuntimeError::new(
            Kind::CompatibilityGap,
            format!("{name} does not fit the Win16 WORD field"),
        )
    })
}

/// Windows 3.1's DDEDATA/DDEPOKE layouts explicitly define these formats as
/// native object handles or structures (SDK Programmer's Reference Vol. 3,
/// printed pp. 272–273). Other clipboard formats remain opaque owned bytes.
pub(super) fn ensure_byte_payload_format(format: u16) -> Result<(), RuntimeError> {
    if format_requires_native_translation(format) {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            format!("DDE clipboard format {format} requires a native handle/structure translator"),
        ));
    }
    Ok(())
}

pub(super) fn format_requires_native_translation(format: u16) -> bool {
    matches!(format, 2 | 3 | 9)
}

pub(super) fn merge_data_origin(
    current: super::DataOrigin,
    observed: super::DataOrigin,
) -> super::DataOrigin {
    match current {
        super::DataOrigin::Created { .. } | super::DataOrigin::ClientResult => current,
        super::DataOrigin::CallbackBorrowed => observed,
    }
}

pub(super) fn native_error(instance: u32) -> u16 {
    unsafe { DdeGetLastError(instance) as u16 }
}

pub(super) fn result(value: Win16HostDdeValue, dde_error: u16) -> Win16HostDdeResult {
    Win16HostDdeResult {
        value,
        dde_error,
        transaction_result: None,
        data_transfer: None,
    }
}

pub(super) fn protocol_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
