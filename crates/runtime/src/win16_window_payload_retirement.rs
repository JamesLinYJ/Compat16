//! Exact USER callback buffers retained after output projection.

use std::sync::Arc;

use win16_abi::{GlobalHandle, SelectorRef};

use super::{CallbackFrameId, Win16State};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::win16_runtime) enum WindowCallbackPayloadCleanup {
    Released,
    RetainedTransferred,
    RetainedInFrame,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::win16_runtime) struct RetainedWindowPayloadCounts {
    pub(in crate::win16_runtime) selector_aliases: u16,
    pub(in crate::win16_runtime) page_locks: u16,
    pub(in crate::win16_runtime) internal_pins: u16,
}

pub(in crate::win16_runtime) struct RetiredWindowPayloadOwner {
    pub(in crate::win16_runtime) callback_id: CallbackFrameId,
    pub(in crate::win16_runtime) allocation: GlobalHandle,
    pub(in crate::win16_runtime) selector: SelectorRef,
    pub(in crate::win16_runtime) first_cause: Option<Arc<crate::RuntimeError>>,
    pub(in crate::win16_runtime) last_retained: Option<RetainedWindowPayloadCounts>,
    pub(in crate::win16_runtime) last_error: Option<Arc<crate::RuntimeError>>,
}

impl Win16State {
    pub(in crate::win16_runtime) fn retained_window_payload_error(
        &self,
    ) -> Option<Arc<crate::RuntimeError>> {
        self.window_callbacks
            .iter()
            .rev()
            .find_map(|frame| {
                frame
                    .setup_error
                    .as_ref()
                    .or(frame.payload_error.as_ref())
                    .or(frame.payload_cleanup_error.as_ref())
                    .map(Arc::clone)
            })
            .or_else(|| {
                let owner = self.retired_window_payloads.first()?;
                let retained = owner.last_retained.map_or_else(
                    || "unavailable".to_owned(),
                    |counts| {
                        format!(
                            "selector_aliases={}, page_locks={}, internal_pins={}",
                            counts.selector_aliases,
                            counts.page_locks,
                            counts.internal_pins,
                        )
                    },
                );
                let message = format!(
                    "retired Win16 callback payload remains owned after retry: callback_id={} allocation=0x{:04x} allocation_generation={} selector=0x{:04x} selector_generation={} last_retained=[{}]",
                    owner.callback_id.0,
                    owner.allocation.raw().0,
                    owner.allocation.generation(),
                    owner.selector.raw().0,
                    owner.selector.generation(),
                    retained,
                );
                match owner.first_cause.as_ref().or(owner.last_error.as_ref()) {
                    Some(cause) => Some(Arc::new(crate::RuntimeError::with_source(
                        cause.kind(),
                        message,
                        Arc::clone(cause),
                    ))),
                    None => Some(Arc::new(crate::RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        message,
                    ))),
                }
            })
    }
}

pub(super) fn retire_active_window_callback_payload(
    state: &mut Win16State,
) -> Result<WindowCallbackPayloadCleanup, crate::RuntimeError> {
    retire_window_callback_payload(state, None)
}

/// The terminal caller has validated USER quiescence and the exact native
/// cancellation receipt (or the exact guest operation owner). The sealed
/// execution-ended proof permits ownership transfer without inventing a
/// normal callback result. CPU selector leases remain live until the existing
/// operation retirement releases them, then deferred payload cleanup retries.
pub(super) fn retire_terminal_window_callback_payload(
    state: &mut Win16State,
    ended: &super::super::execute::Win16TaskExecutionEnded,
) -> Result<WindowCallbackPayloadCleanup, crate::RuntimeError> {
    retire_window_callback_payload(state, Some(ended))
}

fn retire_window_callback_payload(
    state: &mut Win16State,
    ended: Option<&super::super::execute::Win16TaskExecutionEnded>,
) -> Result<WindowCallbackPayloadCleanup, crate::RuntimeError> {
    use super::super::global_memory::GlobalTeardownResult;
    use super::super::global_teardown::GlobalMemoryTeardownAccess;
    use super::WindowCallbackContinuation;
    use crate::DiagnosticKind as Kind;

    let Win16State {
        heap,
        selectors,
        selector_backing_leases,
        modules,
        global_handles,
        global_selectors,
        discarded_handles,
        allocated_selector_aliases,
        api_allocated_selectors,
        mapls_selectors,
        mapls_bases,
        module_reap_pending,
        guest_gdi,
        window_callbacks,
        retired_window_payloads,
        ..
    } = state;
    let frame = window_callbacks.last_mut().ok_or_else(|| crate::RuntimeError::new(
        Kind::InternalInvariant,
        "Win16 callback payload retirement has no retained frame",
    ))?;
    if frame.payload_cleaned {
        return Ok(WindowCallbackPayloadCleanup::Released);
    }
    let callback_id = frame.callback_id;
    let transfer_is_safe = ended.is_some() || (frame.entry_phase == super::WindowCallbackEntryPhase::GuestCallback
        && frame.setup_error.is_none()
        && frame.payload_error.is_none()
        && match frame.continuation {
            WindowCallbackContinuation::Host { .. }
            | WindowCallbackContinuation::HostDialog { .. } => frame.payload_result.is_some(),
            WindowCallbackContinuation::HostTimer { .. }
            | WindowCallbackContinuation::GuestDispatch
            | WindowCallbackContinuation::GuestDialogDispatch { .. }
            | WindowCallbackContinuation::GuestTimer
            | WindowCallbackContinuation::GuestProcedureCall { .. } => true,
        });
    if transfer_is_safe && frame.payload.allocation.is_some() {
        retired_window_payloads.try_reserve(1).map_err(|error| {
            crate::RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve an exact owner for a retained Win16 callback payload",
                error,
            )
        })?;
    }
    let mut memory = GlobalMemoryTeardownAccess::from_parts(
        heap,
        selectors,
        selector_backing_leases,
        &mut modules.records,
        global_handles,
        global_selectors,
        discarded_handles,
        allocated_selector_aliases,
        api_allocated_selectors,
        mapls_selectors,
        mapls_bases,
        module_reap_pending,
    );
    let cleanup = super::super::Win16State::discard_callback_window_payload_resources(
        &mut memory,
        guest_gdi,
        &mut frame.payload,
        &mut frame.guest_drop_global,
        &mut frame.payload_allocation_locked,
    );
    match cleanup {
        Ok(GlobalTeardownResult::Freed) => {
            frame.payload_retained = None;
            frame.payload_cleaned = true;
            Ok(WindowCallbackPayloadCleanup::Released)
        }
        Ok(GlobalTeardownResult::Retained {
            selector_aliases,
            page_locks,
            internal_pins,
        }) => {
            let counts = RetainedWindowPayloadCounts {
                selector_aliases,
                page_locks,
                internal_pins,
            };
            frame.payload_retained = Some(counts);
            if frame.guest_drop_global.is_some() {
                // This HGLOBAL is only owned by a pre-entry callback frame;
                // keep its exact generation there for retry instead of
                // handing it to the payload-only retirement queue below.
                return Ok(WindowCallbackPayloadCleanup::RetainedInFrame);
            }
            if !transfer_is_safe {
                return Ok(WindowCallbackPayloadCleanup::RetainedInFrame);
            }
            let Some(allocation) = frame.payload.allocation else {
                return Err(crate::RuntimeError::new(
                    Kind::InternalInvariant,
                    "retained Win16 payload has no exact GlobalHandle owner",
                ));
            };
            let Some(selector) = frame.payload_selector else {
                return Ok(WindowCallbackPayloadCleanup::RetainedInFrame);
            };
            if frame.payload_allocation_locked {
                return Err(crate::RuntimeError::new(
                    Kind::InternalInvariant,
                    "locked Win16 payload cannot transfer to a deferred GlobalFree owner",
                ));
            }
            let first_cause = frame.payload_cleanup_error.as_ref()
                .or(frame.payload_error.as_ref())
                .or(frame.setup_error.as_ref())
                .map(Arc::clone);
            retired_window_payloads.push(RetiredWindowPayloadOwner {
                callback_id,
                allocation,
                selector,
                first_cause,
                last_retained: Some(counts),
                last_error: None,
            });
            frame.payload.allocation = None;
            frame.payload_selector = None;
            frame.payload_retained = None;
            frame.payload_cleaned = true;
            Ok(WindowCallbackPayloadCleanup::RetainedTransferred)
        }
        Err(error) => {
            let error = Arc::new(error);
            if frame.payload_cleanup_error.is_none() {
                frame.payload_cleanup_error = Some(Arc::clone(&error));
            }
            Err(crate::RuntimeError::with_source(
                error.kind(),
                "Win16 callback payload cleanup failed",
                error,
            ))
        }
    }
}

impl Win16State {
    pub(in crate::win16_runtime) fn retry_retired_window_payloads(
        &mut self,
    ) -> Result<bool, crate::RuntimeError> {
        use super::super::global_memory::GlobalTeardownResult;
        use super::super::global_teardown::GlobalMemoryTeardownAccess;

        let Win16State {
            heap,
            selectors,
            selector_backing_leases,
            modules,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
            retired_window_payloads,
            ..
        } = self;
        let mut memory = GlobalMemoryTeardownAccess::from_parts(
            heap,
            selectors,
            selector_backing_leases,
            &mut modules.records,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
        );
        let mut first_error: Option<crate::RuntimeError> = None;
        let mut index = 0;
        while index < retired_window_payloads.len() {
            let owner = &mut retired_window_payloads[index];
            match memory.free_runtime_global_on_teardown(owner.allocation) {
                Ok(GlobalTeardownResult::Freed) => {
                    retired_window_payloads.remove(index);
                }
                Ok(GlobalTeardownResult::Retained {
                    selector_aliases,
                    page_locks,
                    internal_pins,
                }) => {
                    owner.last_retained = Some(RetainedWindowPayloadCounts {
                        selector_aliases,
                        page_locks,
                        internal_pins,
                    });
                    owner.last_error = None;
                    index += 1;
                }
                Err(error) => {
                    let error = Arc::new(error);
                    owner.last_error = Some(Arc::clone(&error));
                    let error = crate::RuntimeError::with_source(
                        error.kind(),
                        "retrying retained Win16 callback payload cleanup",
                        error,
                    );
                    first_error = Some(match first_error.take() {
                        Some(primary) => primary.with_cleanup(
                            "retry several retained Win16 callback payloads",
                            error,
                        ),
                        None => error,
                    });
                    index += 1;
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(retired_window_payloads.is_empty()),
        }
    }
}
