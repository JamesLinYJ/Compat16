//! WILDCONNECT guest-buffer readback and Win16-to-native HSZPAIR projection.

use super::runtime_dde::{DdeCompletionAccess, Win16DdeCompletionPurpose};
use super::*;
use win16_abi::Win16DdeRequest;

pub(super) enum CallbackOwnedReadbackProgress {
    Continue,
    Resume {
        origin: Win16DdeCallbackOrigin,
        step: Win16HostDdeStep,
        returned_data: Option<u32>,
        retained_failure: Option<std::sync::Arc<RuntimeError>>,
    },
}

/// Complete an internal GetData readback while its continuation remains in
/// the exact callback-frame owner. This path deliberately receives no borrow
/// of the callback vector, so the callback frame and its nested continuation
/// can be split into disjoint field borrows by the caller.
pub(super) fn finish_callback_owned_readback(
    frame: &mut Win16DdeCallbackFrame,
    dde: &mut crate::win16_dde::Win16DdeState,
    result: crate::Win16HostDdeResult,
    host: &mut impl RuntimeHost,
) -> Result<CallbackOwnedReadbackProgress, RuntimeError> {
    let attempt = finish_callback_owned_readback_inner(frame, dde, result, host);
    match attempt {
        Ok(progress) => Ok(progress),
        Err(error) => {
            let reported = if let Some(follow_up) = frame.pending_follow_up.as_mut()
                && let Some(continuation) = follow_up.continuation.as_deref_mut()
            {
                continuation.retain_finish_failure(error)
            } else {
                error
            };
            let reported = std::sync::Arc::new(reported);
            if frame.pending_callback_error.is_none() {
                frame.pending_callback_error = Some(std::sync::Arc::clone(&reported));
            }
            Err(super::super::callback_lifo::shared_runtime_error(reported))
        }
    }
}

impl Win16State {
    pub(super) fn finish_callback_owned_readback(
        &mut self,
        callback_id: super::CallbackFrameId,
        result: crate::Win16HostDdeResult,
        host: &mut impl RuntimeHost,
    ) -> Result<CallbackOwnedReadbackProgress, RuntimeError> {
        let (callbacks, dde) = (&mut self.dde_callbacks, &mut self.dde);
        let frame = callbacks
            .last_mut()
            .filter(|frame| frame.callback_id == callback_id)
            .ok_or_else(|| invariant(
                "DDE callback readback has no exact top callback-frame owner",
            ))?;
        super::readback::finish_callback_owned_readback(frame, dde, result, host)
    }
}

fn finish_callback_owned_readback_inner(
    frame: &mut Win16DdeCallbackFrame,
    dde: &mut crate::win16_dde::Win16DdeState,
    result: crate::Win16HostDdeResult,
    host: &mut impl RuntimeHost,
) -> Result<CallbackOwnedReadbackProgress, RuntimeError> {
    let follow_up = frame.pending_follow_up.as_mut().ok_or_else(|| {
        invariant("DDE callback source proof has no exact readback owner")
    })?;
    let super::runtime_dde::Win16DdeFollowUpOwner::Callback {
        callback_id,
        host_frame,
        owner,
        worker_generation,
        ..
    } = follow_up.owner
    else {
        return Err(invariant(
            "DDE callback readback changed to a window-operation owner",
        ));
    };
    if callback_id != frame.callback_id
        || host_frame != frame.host_frame
        || owner != frame.source_step.owner
        || worker_generation != frame.source_step.worker_generation
        || !frame.runtime_published
        || frame.callback_kind_active
        || frame.active_call.is_some()
    {
        return Err(invariant(
            "DDE callback readback no longer matches its exact retained callback owner",
        ));
    }
    let continuation = follow_up.continuation.as_deref_mut().ok_or_else(|| {
        invariant("DDE callback readback lost its nested continuation")
    })?;
    let operation = continuation.host_operation().ok_or_else(|| {
        invariant("DDE callback readback has no exact submitted operation")
    })?;
    if continuation.host_owner_identity() != Some((owner, worker_generation)) {
        return Err(invariant(
            "DDE callback readback changed its native owner generation",
        ));
    }
    let Win16DdeCompletionPurpose::WildConnectReadback(readback) = continuation.purpose()
    else {
        return Err(invariant(
            "non-callback DDE continuation entered callback-owned readback",
        ));
    };
    if frame.host_frame != readback.frame
        || frame.origin != readback.origin
        || frame.guest_instance != continuation.instance().unwrap_or(0)
    {
        return Err(invariant(
            "DDE callback readback changed its exact callback frame or instance",
        ));
    }
    match follow_up.completed_step.as_ref() {
        Some(Win16HostDdeStep::SourceRetired {
            proof,
            result: cached,
        }) if proof.has_valid_identity()
            && proof.operation == operation
            && proof.owner == owner
            && proof.worker_generation == worker_generation
            && cached == &result => {}
        Some(_) => {
            return Err(invariant(
                "DDE callback readback result changed its exact source-retirement proof",
            ));
        }
        None => {
            return Err(invariant(
                "DDE callback readback result arrived without its cached source-retirement proof",
            ));
        }
    }

    if let Some(step) = follow_up.callback_reply_step.as_ref() {
        if frame.pending_resumed_step.as_ref() != Some(step) {
            return Err(invariant(
                "cached DDE callback reply step is not retained on its callback frame",
            ));
        }
        super::runtime_dde::consume_source_retirements(continuation, host)?;
        return Ok(CallbackOwnedReadbackProgress::Resume {
            origin: readback.origin,
            step: step.clone(),
            returned_data: frame.pending_returned_data,
            retained_failure: frame.pending_callback_error.clone(),
        });
    }

    if follow_up.callback_reply.is_none() {
        continuation.require_cached_normal_source_result(&result)?;
        if result.transaction_result.is_some() {
            return Err(invariant(
                "internal DdeGetData readback returned an unexpected transaction result",
            ));
        }
        let reply = if result.dde_error != dde_error::NO_ERROR {
            if !(0x4000..=0x4011).contains(&result.dde_error)
                || !matches!(&result.value,
                    crate::Win16HostDdeValue::GetData { bytes, copied: 0 } if bytes.is_empty())
            {
                return Err(invariant(
                    "WILDCONNECT readback returned a malformed DDE error result",
                ));
            }
            dde.set_last_error(frame.guest_instance, result.dde_error);
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 WILDCONNECT result data could not be read; callback replied with no data",
            ));
            Win16DdeCallbackReply::NoData
        } else {
            let crate::Win16HostDdeValue::GetData { bytes, copied } = &result.value else {
                return Err(invariant(
                    "WILDCONNECT readback returned the wrong host result type",
                ));
            };
            if readback.expected_size.is_none() {
                if !bytes.is_empty() {
                    return Err(invariant(
                        "DdeGetData size query unexpectedly returned copied bytes",
                    ));
                }
                if *copied < 8 {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "Win16 WILDCONNECT callback returned a malformed HSZPAIR byte count; replied with no data",
                    ));
                    Win16DdeCallbackReply::NoData
                } else {
                    let next_readback = Win16DdeCallbackReadback {
                        expected_size: Some(*copied),
                        ..readback
                    };
                    let mut next = Win16DdeContinuation::wildconnect_readback(
                        continuation.instance(),
                        next_readback,
                    )?;
                    next.inherit_source_retirements_from(continuation)?;
                    let next_call = crate::Win16HostDdeCall::GetData {
                        data: readback.source_host,
                        capacity: Some(*copied),
                        offset: 0,
                    };
                    follow_up.call = next_call;
                    follow_up.continuation = Some(Box::new(next));
                    follow_up.phase = super::runtime_dde::Win16DdeFollowUpPhase::Prepared(
                        follow_up.owner,
                    );
                    follow_up.completed_step = None;
                    follow_up.callback_reply = None;
                    follow_up.callback_reply_step = None;
                    follow_up.pending_child_callback = None;
                    return Ok(CallbackOwnedReadbackProgress::Continue);
                }
            } else {
                let expected = readback.expected_size.ok_or_else(|| {
                    invariant("WILDCONNECT readback lost its expected buffer size")
                })?;
                let expected_length = usize::try_from(expected).map_err(|_| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "WILDCONNECT data exceeds host address width",
                    )
                })?;
                if *copied != expected || bytes.len() != expected_length {
                    return Err(invariant(
                        "DdeGetData returned an inconsistent WILDCONNECT byte count",
                    ));
                }
                match project_wildconnect_pairs(dde, frame.guest_instance, bytes)? {
                    Some(pairs) => {
                        mark_callback_returned_data(dde, readback.source_data)?;
                        frame.pending_returned_data = Some(readback.source_data);
                        Win16DdeCallbackReply::WildConnect {
                            source: readback.source_host,
                            pairs,
                        }
                    }
                    None => {
                        host.report_diagnostic(&Diagnostic::warning(
                            Kind::CompatibilityGap,
                            "Win16 WILDCONNECT callback returned invalid guest HSZPAIR tokens; replied with no data",
                        ));
                        Win16DdeCallbackReply::NoData
                    }
                }
            }
        };
        follow_up.callback_reply = Some(reply);
    }

    // The full guest projection and exact query result now live in the callback
    // owner. Retire its native source tombstones before sending the callback
    // reply; partial ACKs remain in the continuation and can be retried.
    super::runtime_dde::consume_source_retirements(continuation, host)?;
    let reply = follow_up.callback_reply.as_ref().ok_or_else(|| {
        invariant("DDE callback readback lost its cached native reply")
    })?;
    let step = match follow_up.callback_reply_step.as_ref() {
        Some(step) => step.clone(),
        None => {
            let retry_reply = super::clone_dde_callback_reply(reply)?;
            let step = host.win16_dde_callback_reply(crate::Win16HostDdeResume {
                frame: readback.frame,
                reply: retry_reply,
            })?;
            follow_up.callback_reply_step = Some(step.clone());
            step
        }
    };
    validate_resumed_step(readback.origin, readback.frame, step.clone())?;
    if let Some(existing) = frame.pending_resumed_step.as_ref() {
        if existing != &step {
            return Err(invariant(
                "DDE callback reply changed its cached returned step",
            ));
        }
    } else {
        frame.pending_resumed_step = Some(step.clone());
    }
    frame.native_reply_source = Some(crate::Win16DdeCancellationSource::GuestReply);
    Ok(CallbackOwnedReadbackProgress::Resume {
        origin: readback.origin,
        step,
        returned_data: frame.pending_returned_data,
        retained_failure: frame.pending_callback_error.clone(),
    })
}

fn mark_callback_returned_data(
    dde: &mut crate::win16_dde::Win16DdeState,
    guest_data: u32,
) -> Result<(), RuntimeError> {
    let origin = dde.data_origin(guest_data).ok_or_else(|| {
        invariant("DDE callback data token disappeared before native acknowledgement")
    })?;
    if matches!(origin, crate::win16_dde::Win16DdeDataOrigin::Created { .. }) {
        dde.mark_data_transferred(guest_data).ok_or_else(|| {
            invariant("created DDE callback data token disappeared before native acknowledgement")
        })?;
    }
    Ok(())
}

fn project_wildconnect_pairs(
    dde: &crate::win16_dde::Win16DdeState,
    instance: u32,
    bytes: &[u8],
) -> Result<Option<Vec<crate::Win16HostDdeStringPair>>, RuntimeError> {
    if bytes.len() < 8 {
        return Ok(None);
    }
    let mut pairs = Vec::new();
    pairs.try_reserve_exact(bytes.len() / 8).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve converted Win16 WILDCONNECT HSZPAIR records",
            error,
        )
    })?;
    let mut terminated = false;
    for record in bytes.chunks_exact(8) {
        let service = u32::from_le_bytes(record[0..4].try_into().map_err(|_| {
            invariant("Win16 WILDCONNECT service HSZ field was truncated")
        })?);
        let topic = u32::from_le_bytes(record[4..8].try_into().map_err(|_| {
            invariant("Win16 WILDCONNECT topic HSZ field was truncated")
        })?);
        if service == 0 && topic == 0 {
            terminated = true;
            break;
        }
        if service == 0 || topic == 0 {
            return Ok(None);
        }
        let Some(service) = project_wildconnect_string(dde, instance, service)? else {
            return Ok(None);
        };
        let Some(topic) = project_wildconnect_string(dde, instance, topic)? else {
            return Ok(None);
        };
        pairs.push(crate::Win16HostDdeStringPair { service, topic });
    }
    if !terminated {
        return Ok(None);
    }
    Ok(Some(pairs))
}

fn project_wildconnect_string(
    dde: &crate::win16_dde::Win16DdeState,
    instance: u32,
    guest_string: u32,
) -> Result<Option<Option<crate::Win16HostDdeString>>, RuntimeError> {
    if guest_string == 0 {
        return Ok(Some(None));
    }
    if dde.instance_for_string(guest_string) != Some(instance) {
        return Ok(None);
    }
    let host = dde
        .host_string(guest_string)
        .ok_or_else(|| invariant("WILDCONNECT HSZ token lost its native identity"))?;
    Ok(Some(Some(host)))
}

impl DdeCompletionAccess<'_> {
    /// Complete either stage of the private DdeGetData readback used to
    /// translate Win16's 8-byte WILDCONNECT HSZPAIR records into host tokens.
    pub(in crate::win16_runtime) fn finish_dde_callback_readback(
        &mut self,
        continuation: &mut Win16DdeContinuation,
        result: crate::Win16HostDdeResult,
        _memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16DdeFinish, RuntimeError> {
        let Win16DdeCompletionPurpose::WildConnectReadback(readback) = continuation.purpose()
        else {
            return Err(invariant(
                "non-callback DDE continuation entered WILDCONNECT readback",
            ));
        };
        let frame = self.dde_callbacks.last().ok_or_else(|| {
            invariant("WILDCONNECT native frame disappeared during data readback")
        })?;
        if frame.host_frame != readback.frame
            || frame.origin != readback.origin
            || frame.callback_kind_active
            || frame.active_call.is_some()
            || frame.guest_instance != continuation.instance().unwrap_or(0)
        {
            return Err(invariant(
                "WILDCONNECT readback no longer matches its suspended guest callback",
            ));
        }
        if !matches!(&continuation.request,
            Win16DdeRequest::GetData { data, output, offset: 0 }
                if *data == readback.source_data && output.far_pointer == 0)
        {
            return Err(invariant(
                "WILDCONNECT readback continuation changed its source request",
            ));
        }
        if result.transaction_result.is_some() {
            return Err(invariant(
                "internal DdeGetData readback returned an unexpected transaction result",
            ));
        }
        if result.dde_error != dde_error::NO_ERROR {
            if !(0x4000..=0x4011).contains(&result.dde_error)
                || !matches!(&result.value,
                    crate::Win16HostDdeValue::GetData { bytes, copied: 0 } if bytes.is_empty())
            {
                return Err(invariant(
                    "WILDCONNECT readback returned a malformed DDE error result",
                ));
            }
            self.dde
                .set_last_error(frame.guest_instance, result.dde_error);
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 WILDCONNECT result data could not be read; callback replied with no data",
            ));
            return self.ack_wildconnect_no_data(readback, continuation, host);
        }

        let crate::Win16HostDdeValue::GetData { bytes, copied } = result.value else {
            return Err(invariant(
                "WILDCONNECT readback returned the wrong host result type",
            ));
        };
        if readback.expected_size.is_none() {
            if !bytes.is_empty() {
                return Err(invariant(
                    "DdeGetData size query unexpectedly returned copied bytes",
                ));
            }
            if copied < 8 {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 WILDCONNECT callback returned a malformed HSZPAIR byte count; replied with no data"));
                return self.ack_wildconnect_no_data(readback, continuation, host);
            }
            let next = Win16DdeCallbackReadback {
                expected_size: Some(copied),
                ..readback
            };
            let mut next_continuation = Win16DdeContinuation::wildconnect_readback(
                continuation.instance(),
                next,
            )?;
            next_continuation.inherit_source_retirements_from(continuation)?;
            let follow_up_owner = super::runtime_dde::Win16DdeFollowUpOwner::Callback {
                callback_id: frame.callback_id,
                host_frame: frame.host_frame,
                parent: frame.source_step.parent,
                owner: frame.source_step.owner,
                worker_generation: frame.source_step.worker_generation,
                origin: frame.origin,
            };
            return Ok(Win16DdeFinish::FollowUp {
                call: crate::Win16HostDdeCall::GetData {
                    data: readback.source_host,
                    capacity: Some(copied),
                    offset: 0,
                },
                continuation: Some(Box::new(next_continuation)),
                phase: super::runtime_dde::Win16DdeFollowUpPhase::Prepared(follow_up_owner),
            });
        }

        let expected = readback
            .expected_size
            .ok_or_else(|| invariant("WILDCONNECT readback lost its expected buffer size"))?;
        let expected_length = usize::try_from(expected).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "WILDCONNECT data exceeds host address width",
            )
        })?;
        if copied != expected || bytes.len() != expected_length {
            return Err(invariant(
                "DdeGetData returned an inconsistent WILDCONNECT byte count",
            ));
        }
        let pairs = match self.project_wildconnect_pairs(frame.guest_instance, &bytes) {
            Ok(Some(pairs)) => pairs,
            Ok(None) => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 WILDCONNECT callback returned invalid guest HSZPAIR tokens; replied with no data"));
                return self.ack_wildconnect_no_data(readback, continuation, host);
            }
            Err(error) => return Err(error),
        };
        self.mark_callback_returned_data(readback.source_data)?;
        let step = host.win16_dde_callback_reply(Win16HostDdeResume {
            frame: readback.frame,
            reply: Win16DdeCallbackReply::WildConnect {
                source: readback.source_host,
                pairs,
            },
        })?;
        validate_resumed_step(readback.origin, readback.frame, step.clone())?;
        if let crate::Win16HostDdeStep::Complete(result) = &step {
            let Win16DdeCallbackOrigin::Foreground(operation) = readback.origin else {
                return Err(invariant(
                    "parentless DDE callback returned a foreground native result",
                ));
            };
            continuation.cache_native_completion(operation, result.clone())?;
        }
        self.mark_dde_callback_guest_reply(readback.frame)?;
        self.finish_dde_callback_frame_with_continuation(
            Some(readback.source_data), host, Some(continuation),
        )?;
        if matches!(step, crate::Win16HostDdeStep::Complete(_)) {
            let Win16DdeCallbackOrigin::Foreground(operation) = readback.origin else {
                return Err(invariant(
                    "parentless DDE callback completed a foreground operation",
                ));
            };
            continuation.mark_normal_source_retirement_pending(operation)?;
        }
        Ok(Win16DdeFinish::ResumeCallback {
            origin: readback.origin,
            step,
        })
    }

    fn ack_wildconnect_no_data(
        &mut self,
        readback: Win16DdeCallbackReadback,
        continuation: &mut Win16DdeContinuation,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16DdeFinish, RuntimeError> {
        let step = host.win16_dde_callback_reply(Win16HostDdeResume {
            frame: readback.frame,
            reply: Win16DdeCallbackReply::NoData,
        })?;
        validate_resumed_step(readback.origin, readback.frame, step.clone())?;
        if let crate::Win16HostDdeStep::Complete(result) = &step {
            let Win16DdeCallbackOrigin::Foreground(operation) = readback.origin else {
                return Err(invariant(
                    "parentless DDE callback returned a foreground native result",
                ));
            };
            continuation.cache_native_completion(operation, result.clone())?;
        }
        self.mark_dde_callback_guest_reply(readback.frame)?;
        self.finish_dde_callback_frame_with_continuation(None, host, Some(continuation))?;
        if matches!(step, crate::Win16HostDdeStep::Complete(_)) {
            let Win16DdeCallbackOrigin::Foreground(operation) = readback.origin else {
                return Err(invariant(
                    "parentless DDE callback completed a foreground operation",
                ));
            };
            continuation.mark_normal_source_retirement_pending(operation)?;
        }
        Ok(Win16DdeFinish::ResumeCallback {
            origin: readback.origin,
            step,
        })
    }

    fn project_wildconnect_pairs(
        &self,
        instance: u32,
        bytes: &[u8],
    ) -> Result<Option<Vec<crate::Win16HostDdeStringPair>>, RuntimeError> {
        if bytes.len() < 8 {
            return Ok(None);
        }
        let count = bytes.len() / 8;
        let mut pairs = Vec::new();
        pairs
            .try_reserve_exact(count.saturating_sub(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve converted Win16 WILDCONNECT HSZPAIR records",
                    error,
                )
            })?;
        let mut terminated = false;
        for record in bytes.chunks_exact(8) {
            let service = u32::from_le_bytes(
                record[0..4]
                    .try_into()
                    .map_err(|_| invariant("Win16 WILDCONNECT service HSZ field was truncated"))?,
            );
            let topic = u32::from_le_bytes(
                record[4..8]
                    .try_into()
                    .map_err(|_| invariant("Win16 WILDCONNECT topic HSZ field was truncated"))?,
            );
            if service == 0 && topic == 0 {
                terminated = true;
                break;
            }
            if service == 0 || topic == 0 {
                return Ok(None);
            }
            let service = match self.project_wildconnect_string(instance, service)? {
                Some(Some(value)) => value,
                None | Some(None) => return Ok(None),
            };
            let topic = match self.project_wildconnect_string(instance, topic)? {
                Some(Some(value)) => value,
                None | Some(None) => return Ok(None),
            };
            pairs.push(crate::Win16HostDdeStringPair {
                service: Some(service),
                topic: Some(topic),
            });
        }
        if !terminated {
            return Ok(None);
        }
        Ok(Some(pairs))
    }

    fn project_wildconnect_string(
        &self,
        instance: u32,
        guest_string: u32,
    ) -> Result<Option<Option<crate::Win16HostDdeString>>, RuntimeError> {
        if guest_string == 0 {
            return Ok(Some(None));
        }
        if self.dde.instance_for_string(guest_string) != Some(instance) {
            return Ok(None);
        }
        let host = self
            .dde
            .host_string(guest_string)
            .ok_or_else(|| invariant("WILDCONNECT HSZ token lost its native identity"))?;
        Ok(Some(Some(host)))
    }
}

impl DdeCompletionAccess<'_> {
    fn mark_dde_callback_guest_reply(
        &mut self,
        host_frame: crate::Win16HostDdeCallbackFrame,
    ) -> Result<(), RuntimeError> {
        let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("DDE callback frame disappeared after guest reply")
        })?;
        if frame.host_frame != host_frame {
            return Err(invariant("DDE guest reply changed its exact native frame"));
        }
        frame.native_reply_source = Some(crate::Win16DdeCancellationSource::GuestReply);
        Ok(())
    }
}
