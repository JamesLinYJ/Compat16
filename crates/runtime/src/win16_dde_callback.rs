//! Checked guest execution for synchronous and unsolicited DDEML callbacks.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::{Access, GlobalHandle};
use x86_cpu::Cpu;

use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::{
    CallbackFrameId, CallbackKind, Win16DdeCallbackReadback, Win16DdeContinuation,
    Win16DdeFinish, Win16State, runtime_dde,
};
use crate::win16_dde::Win16DdeCallbackEventError;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DdeCallbackReply,
    Win16HostDdeCallbackStep, Win16HostDdeResume, Win16HostDdeStep,
};
use compat_services::win16_dde::DdeConvContext16;
use compat_services::win16_dde::{error as dde_error, transaction_type};

#[path = "win16_dde_callback_readback.rs"]
mod readback;
#[path = "win16_dde_callback_context.rs"]
mod context;
#[path = "win16_dde_callback_abort.rs"]
mod abort;
#[path = "win16_dde_callback_retirement.rs"]
mod retirement;
#[path = "win16_dde_callback_support.rs"]
mod support;
#[path = "win16_dde_callback_guest_finish.rs"]
mod guest_finish;
#[path = "win16_dde_callback_follow_up_driver.rs"]
mod follow_up_driver;
#[path = "win16_dde_callback_follow_up_cache.rs"]
mod follow_up_cache;
pub(super) use support::{
    callback_projection_fallback_for_type, clone_dde_callback_reply, combine_dde_errors,
    dde_callback_failure, invariant, validate_resumed_step,
};

/// Why a callback was dispatched. `WindowWait` identifies the exact runtime
/// window-operation wait (which may itself suspend USER or a foreground DDE
/// call). `GuestExecution` identifies the safe-point guest context captured by
/// the root scheduler; neither unsolicited path synthesizes a DDE completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16DdeCallbackOrigin {
    Foreground(crate::Win16HostDdeOperation),
    WindowWait {
        operation: u64,
    },
    GuestExecution {
        frame: crate::Win16HostDdeCallbackFrame,
    },
    /// A callback emitted while an exact DDE call is owned by a suspended
    /// callback frame. This is not a USER WindowOperationFrame and carries
    /// both callback-owner and submitted-operation identities.
    CallbackFollowUp {
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
    },
}

pub(in crate::win16_runtime) enum Win16DdeCallbackFollowUpDispatch {
    /// A nested callback was entered under the existing owner; its exact
    /// callback frame remains on the shared callback stack.
    GuestEntered,
    /// The callback-owned readback and exact callback retirement completed;
    /// the step resumes the stored origin of the original callback owner.
    Resume {
        origin: Win16DdeCallbackOrigin,
        step: Win16HostDdeStep,
    },
    StartedFailure {
        failure: std::sync::Arc<crate::Win16DdeOperationStartedFailure>,
    },
}

pub(in crate::win16_runtime) enum Win16DdeCallbackFinish {
    Resume {
        origin: Win16DdeCallbackOrigin,
        step: Win16HostDdeStep,
    },
    FollowUp {
        callback_id: super::CallbackFrameId,
    },
}

pub(super) struct Win16DdeCallbackFollowUp {
    pub(super) owner: super::runtime_dde::Win16DdeFollowUpOwner,
    pub(super) call: crate::Win16HostDdeCall,
    pub(super) continuation: Option<Box<Win16DdeContinuation>>,
    pub(super) phase: super::runtime_dde::Win16DdeFollowUpPhase,
    /// A reply-produced operation completion is retained here before any
    /// callback retirement or normal-source ACK can fail.
    pub(super) completed_step: Option<Win16HostDdeStep>,
    /// Reply input and returned step for the original callback are journaled
    /// independently from the internal GetData operation carrier.
    pub(super) callback_reply: Option<Win16DdeCallbackReply>,
    pub(super) callback_reply_step: Option<Win16HostDdeStep>,
    /// Exact child callback currently published under this follow-up call.
    pub(super) pending_child_callback:
        Option<std::sync::Arc<Win16HostDdeCallbackStep>>,
}

/// A guest callback continuation is distinct from its native callback frame
/// and from the foreground native operation suspended beneath it.
pub(super) struct Win16DdeCallbackFrame {
    pub(super) callback_id: super::CallbackFrameId,
    active_call: Option<Win16FarCallbackFrame>,
    host_frame: crate::Win16HostDdeCallbackFrame,
    source_step: std::sync::Arc<Win16HostDdeCallbackStep>,
    host_instance: crate::Win16HostDdeInstance,
    origin: Win16DdeCallbackOrigin,
    native_reply_source: Option<crate::Win16DdeCancellationSource>,
    native_source_retired: bool,
    guest_instance: u32,
    callback_route: u64,
    transaction_type: u32,
    guest_conversation: u32,
    guest_data: u32,
    callback_strings: Vec<u32>,
    borrowed_strings: Vec<u32>,
    context_allocation: Option<GlobalHandle>,
    context_allocation_locked: bool,
    pub(super) callback_kind_active: bool,
    runtime_published: bool,
    pub(super) guest_context_restored: bool,
    pub(super) guest_context_owner_released: bool,
    callback_resources_ended: bool,
    pending_access_block: Option<GlobalHandle>,
    pending_access_block_locked: bool,
    pending_returned_data: Option<u32>,
    pending_resumed_step: Option<Win16HostDdeStep>,
    /// The checked native response is owned before the reply API can fail.
    /// Retrying this frame therefore reuses the same response and never
    /// executes the already-returned guest callback again.
    pending_callback_reply: Option<Win16DdeCallbackReply>,
    pending_callback_error: Option<std::sync::Arc<RuntimeError>>,
    pending_follow_up: Option<Win16DdeCallbackFollowUp>,
}

impl Win16State {
    /// Start one native callback. `None` means guest code was entered;
    /// `Some` is a completed safe fallback reply whose returned step the root
    /// must route through the originating continuation.
    pub(in crate::win16_runtime) fn begin_dde_callback(
        &mut self,
        step: std::sync::Arc<Win16HostDdeCallbackStep>,
        origin: Win16DdeCallbackOrigin,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<(Win16DdeCallbackOrigin, Win16HostDdeStep)>, RuntimeError> {
        if !step.has_valid_identity() {
            return Err(invariant("DDE callback step has an invalid owner identity"));
        }
        if let Win16DdeCallbackOrigin::CallbackFollowUp {
            callback_id,
            host_frame,
            operation,
            owner,
            worker_generation,
        } = origin
        {
            self.validate_callback_follow_up_origin(
                callback_id,
                host_frame,
                operation,
                owner,
                worker_generation,
                &step,
            )?;
        }
        if let Some(existing_index) = self.dde_callbacks.iter().position(|frame| {
            frame.host_frame == step.frame
        }) {
            if existing_index + 1 != self.dde_callbacks.len() {
                return Err(invariant(
                    "replayed DDE callback is not the exact callback-family top",
                ));
            }
            let published = self.dde_callbacks[existing_index].runtime_published;
            if !std::sync::Arc::ptr_eq(
                &self.dde_callbacks[existing_index].source_step,
                &step,
            ) || self.dde_callbacks[existing_index].origin != origin {
                return Err(invariant(
                    "replayed DDE callback changed its exact source step or origin",
                ));
            }
            let (prior_error, pending_reply, pending_step, host_frame) = {
                let frame = &self.dde_callbacks[existing_index];
                (
                    frame.pending_callback_error.clone(),
                    frame.pending_callback_reply.clone(),
                    frame.pending_resumed_step.clone(),
                    frame.host_frame,
                )
            };
            if !published {
                match host.win16_dde_callback_published(&step) {
                    Ok(()) => {
                        self.dde_callbacks[existing_index].runtime_published = true;
                    }
                    Err(error) => {
                        let callback_id = self.dde_callbacks[existing_index].callback_id;
                        return Err(self.retain_dde_callback_entry_error(callback_id, error));
                    }
                }
            }
            if let Some(returned_step) = pending_step {
                validate_resumed_step(origin, host_frame, returned_step.clone())?;
                self.finish_dde_callback_frame(None, host)?;
                if let Some(error) = prior_error {
                    return Err(super::callback_lifo::shared_runtime_error(error));
                }
                return Ok(Some((origin, returned_step)));
            }
            if let Some(reply) = pending_reply {
                let returned_step = self.ack_unentered_dde_callback(
                    host_frame,
                    step.parent,
                    step.callback.host_instance,
                    origin,
                    reply,
                    host,
                )?;
                if let Some(error) = prior_error {
                    return Err(super::callback_lifo::shared_runtime_error(error));
                }
                return Ok(Some((origin, returned_step)));
            }
            return Err(prior_error.map_or_else(
                || invariant("published DDE callback retry cannot re-enter guest code"),
                |error| super::callback_lifo::shared_runtime_error(error),
            ));
        }
        match (origin, step.parent) {
            (Win16DdeCallbackOrigin::Foreground(expected), Some(actual)) if expected == actual => {}
            (Win16DdeCallbackOrigin::Foreground(_), _) => {
                return Err(invariant(
                    "foreground DDE callback parent does not match its operation",
                ));
            }
            (
                Win16DdeCallbackOrigin::CallbackFollowUp { operation, .. },
                Some(actual),
            ) if operation == actual => {}
            (Win16DdeCallbackOrigin::CallbackFollowUp { .. }, _) => {
                return Err(invariant(
                    "callback-owned DDE follow-up callback has no matching submitted operation",
                ));
            }
            (
                Win16DdeCallbackOrigin::WindowWait { .. }
                | Win16DdeCallbackOrigin::GuestExecution { .. },
                None,
            ) => {}
            (
                Win16DdeCallbackOrigin::WindowWait { .. }
                | Win16DdeCallbackOrigin::GuestExecution { .. },
                Some(_),
            ) => {
                return Err(invariant(
                    "unsolicited DDE callback unexpectedly has a native parent",
                ));
            }
        }
        if matches!(origin, Win16DdeCallbackOrigin::GuestExecution { frame } if frame != step.frame)
        {
            return Err(invariant(
                "guest-execution callback context does not match its native frame",
            ));
        }
        match origin {
            Win16DdeCallbackOrigin::Foreground(operation) => {
                self.reserve_dde_guest_return_transfer(operation)?;
            }
            Win16DdeCallbackOrigin::CallbackFollowUp {
                callback_id,
                host_frame,
                operation,
                owner,
                worker_generation,
            } => self.reserve_callback_owned_dde_return_transfer(
                callback_id,
                host_frame,
                operation,
                owner,
                worker_generation,
            )?,
            Win16DdeCallbackOrigin::WindowWait { .. }
            | Win16DdeCallbackOrigin::GuestExecution { .. } => {}
        }
        // The native callback is already suspended. Reserve its family slot,
        // central LIFO slot, and stable ID before projecting callback-owned
        // data or allocating a guest CONVCONTEXT16 block.
        self.dde_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain Win16 DDE callback-frame owner before projection",
                error,
            )
        })?;
        // The callback's sidecar projection can later need an access-block
        // retirement entry. Reserve that owner capacity before projection so
        // setup failure can always transfer an exact block into the retry set.
        self.reserve_dde_guest_block_retirement()?;
        // Argument-vector allocation is also completed before a guest context
        // block is acquired; the fixed eight arguments then push without a
        // further reservation failure.
        let mut arguments = Vec::new();
        arguments.try_reserve_exact(8).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 DDE callback argument frame",
                error,
            )
        })?;
        let callback_id = self.reserve_callback_frame_id()?;
        let transaction_type = step.callback.transaction_type;
        let route = step.callback.callback_route;
        let host_frame = step.frame;
        let parent_operation = step.parent;
        let host_instance = step.callback.host_instance;
        let guest_instance = self.dde.instance_for_route(route);
        // Publish the exact native frame and shared LIFO owner before callback
        // token projection or CONVCONTEXT allocation can mutate guest state.
        self.push_callback_kind(CallbackKind::Dde, callback_id)?;
        self.dde_callbacks.push(Win16DdeCallbackFrame {
            callback_id,
            active_call: None,
            host_frame,
            source_step: std::sync::Arc::clone(&step),
            host_instance,
            origin,
            native_reply_source: None,
            native_source_retired: false,
            guest_instance: guest_instance.unwrap_or(0),
            callback_route: route,
            transaction_type,
            guest_conversation: 0,
            guest_data: 0,
            callback_strings: Vec::new(),
            borrowed_strings: Vec::new(),
            context_allocation: None,
            context_allocation_locked: false,
            callback_kind_active: true,
            runtime_published: false,
            guest_context_restored: false,
            guest_context_owner_released: false,
            callback_resources_ended: true,
            pending_access_block: None,
            pending_access_block_locked: false,
            pending_returned_data: None,
            pending_resumed_step: None,
            pending_callback_reply: None,
            pending_callback_error: None,
            pending_follow_up: None,
        });
        if let Err(error) = host.win16_dde_callback_published(&step) {
            return Err(self.retain_dde_callback_entry_error(callback_id, error));
        }
        if let Some(frame) = self.dde_callbacks.last_mut() {
            frame.runtime_published = true;
        }
        let callback = match self.dde.callback_event(&step.callback) {
            Ok(callback) => callback,
            Err(classification) => {
                let fallback = callback_projection_fallback_for_type(transaction_type);
                let error = match classification {
                    Win16DdeCallbackEventError::StaleRoute => {
                        if let Some(instance) = guest_instance {
                            self.dde.set_last_error(instance, dde_error::NOTPROCESSED);
                        }
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            "Win16 DDE callback arrived for a retired route; returned its documented empty callback value"));
                        if fallback.is_some() {
                            None
                        } else {
                            Some(RuntimeError::new(
                                Kind::CompatibilityGap,
                                "stale Win16 DDE callback has no documented fallback for its return class",
                            ))
                        }
                    }
                    Win16DdeCallbackEventError::ResourceExhausted => {
                        host.report_diagnostic(&Diagnostic::warning(
                            Kind::ResourceExhausted,
                            "Win16 DDE callback token projection exhausted runtime resources",
                        ));
                        Some(RuntimeError::new(
                            Kind::ResourceExhausted,
                            "projecting native DDE callback handles into guest tokens",
                        ))
                    }
                    Win16DdeCallbackEventError::InvalidProjection => {
                        if let Some(instance) = guest_instance {
                            self.dde.set_last_error(instance, dde_error::NOTPROCESSED);
                        }
                        host.report_diagnostic(&Diagnostic::warning(
                            Kind::CompatibilityGap,
                            "native DDE callback values do not fit the Win16 callback projection",
                        ));
                        if fallback.is_some() {
                            None
                        } else {
                            Some(RuntimeError::new(
                                Kind::CompatibilityGap,
                                "native DDE callback projection has no defined Win16 fallback",
                            ))
                        }
                    }
                    Win16DdeCallbackEventError::InstanceMismatch => {
                        let error = invariant(
                            "native DDE callback instance does not match its captured route",
                        );
                        return Err(self.retain_dde_callback_entry_error(callback_id, error));
                    }
                    Win16DdeCallbackEventError::InvalidState => {
                        let error = invariant(
                            "native DDE callback contradicted staged runtime route state",
                        );
                        return Err(self.retain_dde_callback_entry_error(callback_id, error));
                    }
                };
                let Some(reply) = fallback else {
                    let error = error.unwrap_or_else(|| {
                        RuntimeError::new(
                            Kind::CompatibilityGap,
                            "native DDE callback has no documented Win16 fallback",
                        )
                    });
                    return Err(self.retain_dde_callback_entry_error(callback_id, error));
                };
                let next = self.ack_unentered_dde_callback(
                    host_frame,
                    parent_operation,
                    host_instance,
                    origin,
                    reply,
                    host,
                )?;
                return Ok(Some((origin, next)));
            }
        };
        let crate::win16_dde::Win16DdeGuestCallback {
            guest_instance,
            callback_route,
            arguments: projected_arguments,
            data_guest,
            borrowed_strings,
            callback_strings,
            conversation_context,
            ..
        } = callback;
        {
            let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                invariant("DDE callback projection lost its published frame owner")
            })?;
            if frame.callback_id != callback_id || frame.host_frame != host_frame {
                return Err(invariant(
                    "DDE callback projection changed its exact published frame owner",
                ));
            }
            frame.guest_instance = guest_instance;
            frame.callback_route = callback_route;
            frame.guest_data = data_guest;
            frame.callback_strings = callback_strings;
            frame.borrowed_strings = borrowed_strings;
            frame.callback_resources_ended = false;
        }
        let guest_conversation = match projected_arguments[2] {
            crate::win16_dde::Win16DdeCallbackArgument::Dword(value) => value,
            _ => {
                let error = invariant("DDE callback HCONV was not a DWORD");
                return Err(self.retain_dde_callback_entry_error(callback_id, error));
            }
        };
        if let Some(frame) = self.dde_callbacks.last_mut() {
            frame.guest_conversation = guest_conversation;
        }
        let procedure = match self.dde.callback_for_route(callback_route) {
            Some(procedure) => procedure,
            None => {
                let error = invariant(
                    "DDE callback route lost its checked guest procedure",
                );
                return Err(self.retain_dde_callback_entry_error(callback_id, error));
            }
        };

        let mut context_far = None;
        if let Some(context) = conversation_context {
            match self.allocate_dde_context(callback_id, memory, context) {
                Ok((_allocation, far)) => {
                    context_far = Some(far);
                }
                Err(error)
                    if error.kind() == Kind::ResourceExhausted
                        && self.dde_callbacks.last().is_some_and(|frame| {
                            frame.callback_id == callback_id
                                && frame.context_allocation.is_none()
                        }) =>
                {
                    let Some(fallback) = callback_projection_fallback_for_type(transaction_type) else {
                        let error = RuntimeError::new(
                            Kind::CompatibilityGap,
                            "DDE callback return class has no defined allocation-failure fallback",
                        );
                        return Err(self.retain_dde_callback_entry_error(callback_id, error));
                    };
                    if let Err(cleanup) = self.with_dde_completion_access(|access| {
                        access.retire_top_dde_callback_frame(None)
                    }) {
                        let error = error.with_cleanup(
                            "DDE callback context allocation and projected-owner cleanup both failed",
                            cleanup,
                        );
                        return Err(self.retain_dde_callback_entry_error(callback_id, error));
                    }
                    host.report_diagnostic(&Diagnostic::warning(Kind::ResourceExhausted,
                        "Win16 DDE callback CONVCONTEXT16 allocation failed; returned the documented empty callback value"));
                    let next = self.ack_unentered_dde_callback(
                        host_frame,
                        parent_operation,
                        host_instance,
                        origin,
                        fallback,
                        host,
                    )?;
                    return Ok(Some((origin, next)));
                }
                Err(error) => {
                    return Err(self.retain_dde_callback_entry_error(callback_id, error));
                }
            }
        }

        for (index, argument) in projected_arguments.iter().enumerate() {
            match *argument {
                crate::win16_dde::Win16DdeCallbackArgument::Word(value) => {
                    arguments.push(Win16FarCallbackArgument::Word(value));
                }
                crate::win16_dde::Win16DdeCallbackArgument::Dword(value) => {
                    if index == 6 {
                        if let Some(far) = context_far {
                            arguments.push(Win16FarCallbackArgument::GuestPointer {
                                far,
                                access: Access::Read,
                                bytes: DdeConvContext16::SIZE as u32,
                            });
                            continue;
                        }
                    }
                    arguments.push(Win16FarCallbackArgument::Dword(value));
                }
            }
        }

        let active = self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            procedure,
            &arguments,
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Dword,
        );
        let active = match active {
            Ok(active) => active,
            Err(error) => {
                return Err(self.retain_dde_callback_entry_error(callback_id, error));
            }
        };
        let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("DDE callback frame disappeared while entering its guest procedure")
        })?;
        if frame.callback_id != callback_id {
            return Err(invariant(
                "DDE callback entry changed its exact published frame owner",
            ));
        }
        frame.active_call = Some(active);
        frame.context_allocation_locked = context_far.is_some();
        Ok(None)
    }

    fn ack_unentered_dde_callback(
        &mut self,
        host_frame: crate::Win16HostDdeCallbackFrame,
        parent_operation: Option<crate::Win16HostDdeOperation>,
        host_instance: crate::Win16HostDdeInstance,
        origin: Win16DdeCallbackOrigin,
        reply: Win16DdeCallbackReply,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Dde)?;
        let frame = self.dde_callbacks.last().ok_or_else(|| {
            invariant("unentered DDE callback lost its published runtime owner")
        })?;
        let expected_parent = match origin {
            Win16DdeCallbackOrigin::Foreground(operation)
            | Win16DdeCallbackOrigin::CallbackFollowUp { operation, .. } => Some(operation),
            Win16DdeCallbackOrigin::WindowWait { .. }
            | Win16DdeCallbackOrigin::GuestExecution { .. } => None,
        };
        if frame.callback_id != callback_id
            || frame.host_frame != host_frame
            || frame.origin != origin
            || frame.host_instance != host_instance
            || frame.active_call.is_some()
            || !frame.callback_resources_ended
            || parent_operation != expected_parent
        {
            return Err(invariant(
                "unentered DDE callback fallback is not bound to its exact cleaned top frame",
            ));
        }
        {
            let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                invariant("unentered DDE callback owner disappeared before reply reservation")
            })?;
            match frame.pending_callback_reply.as_ref() {
                Some(existing) if existing == &reply => {}
                Some(_) => {
                    let error = invariant(
                        "unentered DDE callback retry changed its exact fallback reply",
                    );
                    if frame.pending_callback_error.is_none() {
                        let error = std::sync::Arc::new(error);
                        frame.pending_callback_error = Some(std::sync::Arc::clone(&error));
                        return Err(super::callback_lifo::shared_runtime_error(error));
                    }
                    return Err(error);
                }
                None => frame.pending_callback_reply = Some(reply),
            }
        }
        let copied_reply = self.dde_callbacks.last().and_then(|frame| {
            frame.pending_callback_reply.as_ref().map(clone_dde_callback_reply)
        }).ok_or_else(|| invariant("unentered DDE callback lost its cached reply"))?;
        let retry_reply = match copied_reply {
            Ok(reply) => reply,
            Err(error) => {
                return Err(self.retain_dde_callback_entry_error(callback_id, error));
            }
        };
        let next = match host.win16_dde_callback_reply(Win16HostDdeResume {
            frame: host_frame,
            reply: retry_reply,
        }) {
            Ok(step) => step,
            Err(error) => {
                return Err(self.retain_dde_callback_entry_error(callback_id, error));
            }
        };
        {
            let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                invariant("unentered DDE callback owner disappeared after its reply")
            })?;
            frame.pending_resumed_step = Some(next.clone());
            frame.native_reply_source = Some(crate::Win16DdeCancellationSource::GuestReply);
        }
        let validation = match validate_resumed_step(origin, host_frame, next.clone()) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.retain_dde_callback_entry_error(callback_id, error)),
        };
        if validation.is_ok() {
            let cached = match (origin, &next) {
                (Win16DdeCallbackOrigin::Foreground(operation), Win16HostDdeStep::Complete(result)) => {
                    self.cache_foreground_dde_completion(operation, result.clone())
                }
                (
                    Win16DdeCallbackOrigin::Foreground(operation),
                    Win16HostDdeStep::SourceRetired { proof, result },
                ) => self.cache_foreground_dde_source_retirement(
                    operation,
                    std::sync::Arc::clone(proof),
                    result.clone(),
                ),
                (
                    Win16DdeCallbackOrigin::CallbackFollowUp {
                        callback_id: parent_id,
                        host_frame: parent_frame,
                        operation,
                        owner,
                        worker_generation,
                    },
                    _,
                ) => self.cache_callback_follow_up_returned_step(
                    parent_id,
                    parent_frame,
                    operation,
                    owner,
                    worker_generation,
                    &next,
                ),
                _ => Ok(()),
            };
            if let Err(error) = cached {
                return Err(self.retain_dde_callback_entry_error(callback_id, error));
            }
        }
        if let Err(cleanup) = self.finish_dde_callback_frame(None, host) {
            return Err(match validation {
                Ok(()) => cleanup,
                Err(primary) => primary.with_cleanup(
                    "DDE callback fallback result validation and exact frame retirement both failed",
                    cleanup,
                ),
            });
        }
        validation?;
        Ok(next)
    }

    /// Read code roots for callback routes and every in-flight guest return
    /// frame so module unloading cannot invalidate a suspended DDE callback.
    pub(super) fn dde_code_references(&self) -> Vec<u32> {
        let mut references = Vec::with_capacity(self.dde_callbacks.len().saturating_mul(4));
        for frame in &self.dde_callbacks {
            if let Some(procedure) = self.dde.callback_for_route(frame.callback_route) {
                references.push(procedure);
            }
            if let Some(active) = &frame.active_call {
                references.extend(active.code_references());
            }
        }
        references
    }

}
