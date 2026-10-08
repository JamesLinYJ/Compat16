//! Retryable completion of an already-returned classic-DDE guest callback.

use super::*;
use super::super::classic_dde_dispatch::ClassicDdeGuestCallbackFrame;

impl Win16State {
    pub(in crate::win16_runtime) fn finish_classic_dde_guest_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::ClassicDde)?;
        let mut frame = self.classic_dde.callbacks.pop().ok_or_else(|| {
            dde_invariant("classic DDE callback binding has no retained checked guest frame")
        })?;
        if frame.callback_id != callback_id || frame.binding_retired {
            self.classic_dde.callbacks.push(frame);
            return Err(dde_invariant("classic DDE callback frame identity changed"));
        }
        if frame.returned_value.is_none() {
            match self.finish_guest_far_callback_checked(cpu, dos, memory, &mut frame.guest_frame) {
                Ok(value) => frame.returned_value = Some(value),
                Err(error) => {
                    self.classic_dde.callbacks.push(frame);
                    return Err(error);
                }
            }
        }
        self.finish_retained_classic_dde_guest_callback(frame, cpu, dos, memory, host)
            .map(|_| ())
    }

    pub(super) fn retry_returned_classic_dde_guest_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let retained = self.classic_dde.callbacks.last().ok_or_else(|| {
            dde_invariant("classic DDE returned callback lost its retained finish phases")
        })?;
        if let Some(poll) = retained.cleanup_poll {
            if self.classic_dde.operations.iter().any(|operation| operation.identity == poll) {
                return self.service_classic_dde_operation(cpu, dos, memory, host);
            }
            self.classic_dde.callbacks.last_mut().expect("retained frame was checked")
                .cleanup_poll = None;
        }
        let prepared = self.classic_dde.callbacks.last().and_then(|frame| {
            if !frame.binding_retired || frame.server_finish.is_some() { return None; }
            match &frame.continuation.completion {
                super::super::win16_ole1_server_callback::Ole1ServerCallbackCompletion::DdeExecute {
                    prepared_document, ..
                } => *prepared_document,
                _ => None,
            }
        });
        if let Some(proof) = prepared
            && let Some(pending) = self.pending_ole1_release_for_endpoint(proof.owner, proof.endpoint)?
            && !pending.pending_events.is_empty()
        {
            if pending.worker_generation != proof.worker_generation
                || !matches!(pending.target,
                    super::super::win16_ole1_server_state::Ole1ReleaseTarget::Document {
                        handle, generation, endpoint, ..
                    } if handle == proof.document && generation == proof.document_generation
                        && endpoint == proof.endpoint)
            {
                return Err(dde_invariant("classic DDE callback cleanup changed its exact document release wait"));
            }
            self.retain_classic_dde_pending_endpoint_poll(
                proof.owner, proof.endpoint, &pending.pending_events,
            )?;
            let poll = self.begin_classic_dde_host_call(
                Win16HostClassicDdeCall::Poll { owner: proof.owner, endpoint: proof.endpoint },
                ClassicDdeOperationOwner::PollEndpoint {
                    owner: proof.owner, endpoint: proof.endpoint,
                    expected_event_ids: pending.pending_events,
                },
                None, host,
            )?;
            self.classic_dde.callbacks.last_mut().expect("returned frame remains retained")
                .cleanup_poll = Some(poll);
            return Ok(false);
        }
        let frame = self.classic_dde.callbacks.pop().ok_or_else(|| {
            dde_invariant("classic DDE returned callback lost its retained finish phases")
        })?;
        self.finish_retained_classic_dde_guest_callback(frame, cpu, dos, memory, host)
    }

    fn finish_retained_classic_dde_guest_callback(
        &mut self,
        mut frame: ClassicDdeGuestCallbackFrame,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let result = (|| {
            let value = frame.returned_value.ok_or_else(|| {
                dde_invariant("classic DDE callback finish has no checked guest return")
            })?;
            if !frame.binding_retired {
                if self.require_callback_top(CallbackKind::ClassicDde)? != frame.callback_id {
                    return Err(dde_invariant("classic DDE returned callback changed its binding"));
                }
                self.release_guest_far_callback_owner(&mut frame.guest_frame, dos, memory)?;
                self.retire_callback_binding(CallbackKind::ClassicDde, frame.callback_id)?;
                frame.binding_retired = true;
            }
            if frame.server_finish.is_none() {
                let continuation = &frame.continuation;
                let finish = if matches!(
                    &continuation.completion,
                    super::super::win16_ole1_server_callback::Ole1ServerCallbackCompletion::DdeRelease { .. }
                ) {
                    self.finish_ole1_server_release_callback(continuation, value, memory, host)?
                } else {
                    self.finish_ole1_server_guest_callback(continuation, value, memory, host)?
                };
                frame.server_finish = Some(finish);
            }
            self.apply_server_finish(
                frame.server_finish.as_ref().expect("finish action was retained").clone(),
                cpu, dos, memory, host,
            )
        })();
        if result.is_err() {
            // The Vec slot removed above is still available. Keeping this
            // frame preserves the actual guest result, continuation, released
            // binding phase and generated action without another allocation.
            self.classic_dde.callbacks.push(frame);
        }
        result
    }
}
