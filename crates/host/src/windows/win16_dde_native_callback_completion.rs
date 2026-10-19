//! Callback-frame ownership, cleanup, and acknowledgement completion.

use super::super::super::errors::combine_cleanup_errors as combine_runtime_error_pair;
use super::*;
use runtime::Win16HostDdeCallbackFrame;
use std::sync::Arc;

pub(super) struct CallbackFrameCompletion<'a> {
    context: &'a WorkerContext,
    call: &'a runtime::Win16DdeCallbackCall,
    frame: Win16HostDdeCallbackFrame,
    parent: Option<Win16HostDdeOperation>,
    returned_token: Option<Win16HostDdeData>,
    wildconnect_source: Option<Win16HostDdeData>,
    owned_reply: Option<HDDEDATA>,
    owned_reply_native_instance: Option<u32>,
    owned_reply_failure: Option<Arc<RuntimeError>>,
    reply_slot_reserved: bool,
    cleanup_attempted: bool,
    acknowledgement_attempted: bool,
    completed: bool,
}

impl<'a> CallbackFrameCompletion<'a> {
    pub(super) fn new(
        context: &'a WorkerContext,
        call: &'a runtime::Win16DdeCallbackCall,
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
    ) -> Self {
        Self {
            context,
            call,
            frame,
            parent,
            returned_token: None,
            wildconnect_source: None,
            owned_reply: None,
            owned_reply_native_instance: None,
            owned_reply_failure: None,
            reply_slot_reserved: false,
            cleanup_attempted: false,
            acknowledgement_attempted: false,
            completed: false,
        }
    }

    pub(super) fn remember(&mut self, reply: &NativeCallbackReply) {
        self.returned_token = reply.returned_token;
        self.wildconnect_source = reply.wildconnect_source;
        if reply.owns_reply && !reply.native.is_null() {
            self.owned_reply = Some(reply.native);
            self.owned_reply_native_instance = reply.native_instance;
            self.reply_slot_reserved = true;
        }
    }

    pub(super) fn cleanup(
        &mut self,
        returned_token: Option<Win16HostDdeData>,
        wildconnect_source: Option<Win16HostDdeData>,
    ) -> Result<(), RuntimeError> {
        self.cleanup_attempted = true;
        cleanup_callback_frame(self.context, self.call, returned_token, wildconnect_source)
    }

    pub(super) fn finish(
        mut self,
        result: Result<HDDEDATA, RuntimeError>,
    ) -> Result<HDDEDATA, RuntimeError> {
        let result = match result {
            Err(error) if self.owned_reply.is_some() => match self.release_owned_reply() {
                Ok(()) => Err(error),
                Err(release) => Err(combine_runtime_error_pair(
                    error,
                    release,
                    "DDE callback result and prepared reply release both failed",
                )),
            },
            result => result,
        };
        let (result, acknowledgement) = split_callback_result(result);
        let acknowledgement =
            worker::complete_callback_frame(self.context, self.frame, self.parent, acknowledgement);
        self.acknowledgement_attempted = true;
        if acknowledgement.is_ok() {
            self.completed = true;
            if result.is_ok() {
                // Successful ACK transfers HDDEDATA ownership to DDEML. Keep
                // the handle, but release the independent preallocation slot.
                self.owned_reply = None;
                self.owned_reply_native_instance = None;
                if self.reply_slot_reserved {
                    let released = worker::release_callback_reply_cleanup_slot(self.context);
                    self.reply_slot_reserved = false;
                    if let Err(error) = released {
                        return Err(error.with_context(
                            "DDE callback reply transferred but its cleanup reservation could not be retired",
                        ));
                    }
                }
            }
        }
        match (result, acknowledgement) {
            (result, Ok(())) => result,
            (Ok(_), Err(error)) => Err(error),
            (Err(callback_error), Err(error)) => Err(combine_runtime_error_pair(
                callback_error,
                error,
                "DDE callback result and native frame acknowledgement both failed",
            )),
        }
    }
}

impl Drop for CallbackFrameCompletion<'_> {
    fn drop(&mut self) {
        if self.completed {
            self.release_owned_reply_after_ack();
            return;
        }
        let cleanup = if self.cleanup_attempted {
            Ok(())
        } else {
            self.cleanup_attempted = true;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                cleanup_callback_frame(
                    self.context,
                    self.call,
                    self.returned_token,
                    self.wildconnect_source,
                )
            })) {
                Ok(result) => result,
                Err(_) => Err(RuntimeError::new(
                    Kind::HostFailure,
                    "panic occurred while cleaning a native DDE callback frame",
                )),
            }
        };
        let release = self.release_owned_reply();
        let mut failure = combine_cleanup_errors(cleanup, release);
        if failure.is_err() && self.owned_reply.is_some() {
            if let Err(retention) = self.retain_owned_reply_after_failure() {
                failure = combine_cleanup_errors(failure, Err(retention));
            }
        }
        let failure = failure.err().unwrap_or_else(|| {
            RuntimeError::new(
                Kind::HostFailure,
                "native DDE callback unwound before frame completion",
            )
        });
        if !self.acknowledgement_attempted {
            self.acknowledgement_attempted = true;
            let kind = failure.kind();
            let shared = Arc::new(failure);
            let acknowledgement_error = RuntimeError::with_source(
                kind,
                "native DDE callback cleanup failed before frame acknowledgement",
                Arc::clone(&shared),
            );
            let latch_error = RuntimeError::with_source(
                kind,
                "native DDE callback cleanup acknowledgement could not be delivered",
                shared,
            );
            let acknowledgement = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker::complete_callback_frame(
                    self.context,
                    self.frame,
                    self.parent,
                    Err(acknowledgement_error),
                )
            }));
            let acknowledgement_failure = match acknowledgement {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(combine_runtime_error_pair(
                    latch_error,
                    error,
                    "DDE callback cleanup and frame acknowledgement both failed",
                )),
                Err(_) => Some(combine_runtime_error_pair(
                    latch_error,
                    RuntimeError::new(
                        Kind::HostFailure,
                        "panic occurred while publishing DDE callback cleanup acknowledgement",
                    ),
                    "DDE callback cleanup and acknowledgement panic both failed",
                )),
            };
            if let Some(error) = acknowledgement_failure {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker::latch_callback_failure(self.context, error)
                }));
            }
        } else {
            // The failed frame-ACK attempt is returned through the enclosing
            // extern callback and latched there; do not publish a second ACK.
            let _ = failure;
        }
        self.completed = true;
    }
}

impl CallbackFrameCompletion<'_> {
    fn release_owned_reply(&mut self) -> Result<(), RuntimeError> {
        let Some(reply) = self.owned_reply else {
            return Ok(());
        };
        // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
        if unsafe { DdeFreeDataHandle(reply) } == 0 {
            let additional = Arc::new(match self.owned_reply_native_instance {
                Some(native_instance) => callback_native_api_failure(
                    "DdeFreeDataHandle for an owned callback reply",
                    native_instance,
                ),
                None => RuntimeError::new(
                    Kind::InternalInvariant,
                    "owned DDE callback reply lost its native instance identity",
                ),
            });
            let failure = match self.owned_reply_failure.take() {
                Some(previous) => Arc::new(combine_runtime_error_pair(
                    RuntimeError::with_source(
                        previous.kind(),
                        "earlier DdeFreeDataHandle failure for an owned DDE callback reply",
                        Arc::clone(&previous),
                    ),
                    RuntimeError::with_source(
                        additional.kind(),
                        "additional DdeFreeDataHandle failure for an owned DDE callback reply",
                        Arc::clone(&additional),
                    ),
                    "repeated DDE callback reply releases failed",
                )),
                None => additional,
            };
            let kind = failure.kind();
            self.owned_reply_failure = Some(Arc::clone(&failure));
            return Err(RuntimeError::with_source(
                kind,
                "DdeFreeDataHandle failed for an owned DDE callback reply",
                failure,
            ));
        }
        self.owned_reply = None;
        self.owned_reply_native_instance = None;
        if self.reply_slot_reserved {
            let released = worker::release_callback_reply_cleanup_slot(self.context);
            self.reply_slot_reserved = false;
            released
        } else {
            Ok(())
        }
    }

    fn retain_owned_reply_after_failure(&mut self) -> Result<(), RuntimeError> {
        let Some(reply) = self.owned_reply else {
            return Ok(());
        };
        let failure = self.owned_reply_failure.clone().unwrap_or_else(|| {
            Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "failed DDE callback reply release had no typed native failure",
            ))
        });
        let retention = worker::retain_failed_callback_reply(
            self.context,
            worker::FailedCallbackReplyIdentity {
                frame: self.frame,
                operation: self.parent,
                instance: self.call.host_instance,
                role: callback_reply_role(self.call.transaction_type),
            },
            self.owned_reply_native_instance,
            reply as usize,
            RuntimeError::with_source(
                failure.kind(),
                "retain owned DDE callback reply after native release failure",
                Arc::clone(&failure),
            ),
        );
        // The worker ledger now owns the exact native handle even when mutex
        // poisoning is separately reported by the insertion operation.
        self.owned_reply = None;
        self.owned_reply_native_instance = None;
        self.reply_slot_reserved = false;
        retention
    }

    fn release_owned_reply_after_ack(&mut self) {
        if let Err(error) = self.release_owned_reply() {
            let error = if self.owned_reply.is_some() {
                match self.retain_owned_reply_after_failure() {
                    Ok(()) => error,
                    Err(retention) => combine_runtime_error_pair(
                        error,
                        retention,
                        "DDE reply release and owner retention both failed",
                    ),
                }
            } else {
                error
            };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker::latch_callback_failure(self.context, error)
            }));
        }
    }
}

fn callback_reply_role(transaction: u32) -> runtime::Win16DdeCallbackReplyRole {
    if compat_services::win16_dde::transaction_type::base(transaction)
        == compat_services::win16_dde::transaction_type::base(
            compat_services::win16_dde::transaction_type::WILDCONNECT,
        )
    {
        runtime::Win16DdeCallbackReplyRole::WildConnectReply
    } else {
        runtime::Win16DdeCallbackReplyRole::ReturnedData
    }
}
