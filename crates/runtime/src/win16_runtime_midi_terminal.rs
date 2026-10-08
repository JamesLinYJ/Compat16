//! Exact USER terminal retirement for a failed MIDI notification POST.

use std::sync::Arc;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostMidiNotificationId,
    Win16NativeWindowOperationKind, Win16WindowAbortReceipt,
    Win16WindowOperationStartedFailure, Win16WindowTerminalSourceTop,
};

use super::{MidiCallbackRoute, Win16State};

impl Win16State {
    /// Complete one terminal cancellation for the exact MIDI function source
    /// carried by the central asynchronous callback retirement receipt.
    pub(in crate::win16_runtime) fn finish_midi_asynchronous_callback_retirement(
        &mut self,
        host: &mut impl RuntimeHost,
        retirement: super::super::callback_scheduler::AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        if !self.midi.producers_quiesced
            || self.window_abort_receipt.is_none()
            || !retirement.source_bound
            || retirement.midi_source.is_none()
            || !self.pending_asynchronous_source_retirements().contains(&retirement)
        {
            return Err(midi_invariant(
                "MIDI teardown has no retained central callback source receipt",
            ));
        }
        if retirement.source_acknowledged {
            // The native source ACK may precede a failed scheduler retirement.
            // Its dispatch row is already gone; retry only the retained frame.
            return self.complete_asynchronous_source_retirement(
                retirement.callback_id,
                retirement.callback_token,
            );
        }
        let identity = retirement.midi_source.ok_or_else(|| midi_invariant(
            "MIDI callback retirement omitted its native notification identity",
        ))?;
        let dispatch = self.midi.dispatching.as_ref().ok_or_else(|| midi_invariant(
            "MIDI callback retirement lost its exact runtime dispatch owner",
        ))?;
        if dispatch.identity != identity
            || !dispatch.function_started
            || dispatch.post_accepted
            || dispatch.post_failure.is_some()
            || dispatch.post_attempt.is_some()
            || dispatch.terminal_ack.is_some()
            || dispatch.terminal_acknowledged
            || !matches!(dispatch.callback_route,
                MidiCallbackRoute::Function(callback) if callback == retirement.callback_token)
            || identity.device.token == 0
            || identity.device.generation == 0
            || identity.sequence == 0
        {
            return Err(midi_invariant(
                "central callback cancellation does not match the retained MIDI source owner",
            ));
        }
        match (dispatch.host_header, dispatch.completion) {
            (Some(header), Some(completion)) => {
                let exact = self.midi.headers.iter().filter(|record| {
                    record.host_device == identity.device
                        && record.host_header == header
                        && record.guest_device == dispatch.guest_device
                }).count();
                let exact_record = self.midi.headers.iter().find(|record| {
                    record.host_device == identity.device
                        && record.host_header == header
                        && record.guest_device == dispatch.guest_device
                });
                if exact != 1
                    || exact_record.is_none_or(|record| {
                        record.completed_pending.is_some_and(|current| current != completion)
                            || record.submission == Some(completion)
                    })
                {
                    return Err(midi_invariant(
                        "MIDI callback retirement lost its exact completed header generation",
                    ));
                }
            }
            (None, None) => {}
            _ => return Err(midi_invariant(
                "MIDI callback retirement split its exact native header completion pair",
            )),
        }

        self.cancel_midi_notification_source(
            host,
            identity,
            crate::Win16HostMidiCancellationReason::OwnerTerminated,
        )?;
        self.mark_pending_asynchronous_source_acknowledged(retirement)?;
        self.complete_asynchronous_source_retirement(
            retirement.callback_id,
            retirement.callback_token,
        )
    }

    pub(super) fn retain_midi_post_failure(
        &mut self,
        identity: Win16HostMidiNotificationId,
        failure: Arc<Win16WindowOperationStartedFailure>,
    ) -> Result<(), RuntimeError> {
        let dispatch = self.midi.dispatching.as_mut().ok_or_else(|| midi_invariant(
            "MIDI failed POST lost its exact notification owner"))?;
        if dispatch.identity != identity
            || dispatch.post_accepted
            || dispatch.post_failure.is_some()
            || dispatch.terminal_ack.is_some()
            || dispatch.terminal_acknowledged
            || !matches!(dispatch.callback_route,
                MidiCallbackRoute::Window { .. } | MidiCallbackRoute::Task(_))
            || identity.device.token == 0
            || identity.device.generation == 0
            || identity.sequence == 0
            || failure.operation.operation_id.0 == 0
            || failure.worker_generation == 0
            || failure.operation.kind != Win16NativeWindowOperationKind::PostGuestNotification
        {
            return Err(midi_invariant(
                "MIDI failed POST changed its unique source owner or typed identity",
            ));
        }
        dispatch.post_failure = Some(failure);
        Ok(())
    }

    pub(in crate::win16_runtime) fn owns_terminal_midi_post_source(
        &self,
        top: &Win16WindowTerminalSourceTop,
    ) -> bool {
        if !self.midi.producers_quiesced {
            return false;
        }
        let Win16WindowTerminalSourceTop::User {
            operation,
            kind,
            state,
            worker_generation,
        } = top else {
            return false;
        };
        if *kind != Win16NativeWindowOperationKind::PostGuestNotification {
            return false;
        }
        self.midi.dispatching.as_ref().is_some_and(|dispatch| {
            dispatch.post_failure.as_ref().is_some_and(|failure| {
                failure.operation.operation_id == *operation
                    && failure.operation.kind == *kind
                    && failure.state == *state
                    && failure.worker_generation == *worker_generation
            })
        })
    }

    pub(in crate::win16_runtime) fn retire_midi_terminal_post_source(
        &mut self,
        receipt: &Win16WindowAbortReceipt,
        top: &Win16WindowTerminalSourceTop,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !self.owns_terminal_midi_post_source(top) {
            return Ok(false);
        }
        let Win16WindowTerminalSourceTop::User {
            operation,
            kind,
            state,
            worker_generation,
        } = top else {
            return Ok(false);
        };
        let failure = self
            .midi
            .dispatching
            .as_ref()
            .and_then(|dispatch| dispatch.post_failure.as_ref())
            .filter(|failure| {
                failure.operation.operation_id == *operation
                    && failure.operation.kind == *kind
                    && failure.state == *state
                    && failure.worker_generation == *worker_generation
            })
            .cloned()
            .ok_or_else(|| midi_invariant(
                "MIDI terminal POST owner disappeared after exact-top preflight"))?;
        if self.window_abort_receipt.as_ref() != Some(receipt)
            || failure.operation.operation_id != *operation
            || failure.operation.kind != *kind
            || failure.state != *state
            || failure.worker_generation != *worker_generation
        {
            return Err(midi_invariant(
                "MIDI terminal POST does not match its cached USER receipt and exact source top",
            ));
        }
        let ack = crate::Win16WindowTerminalAck {
            worker_generation: failure.worker_generation,
            operation: failure.operation,
            state: failure.state,
            callbacks: Vec::new(),
            modals: Vec::new(),
        };
        let already_acknowledged = {
            let dispatch = self.midi.dispatching.as_ref().ok_or_else(|| midi_invariant(
                "MIDI terminal POST source disappeared before ACK"))?;
            if dispatch.post_failure.as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &failure))
                || dispatch.terminal_ack.as_ref().is_some_and(|saved| saved != &ack)
            {
                return Err(midi_invariant(
                    "MIDI terminal POST ACK changed its exact retained owner",
                ));
            }
            dispatch.terminal_acknowledged
        };
        if already_acknowledged {
            if !host.win16_window_terminal_acknowledged(receipt, &ack)? {
                return Err(midi_invariant(
                    "MIDI cached USER terminal ACK lost its exact host tombstone",
                ));
            }
            return Ok(true);
        }
        {
            let dispatch = self.midi.dispatching.as_mut().ok_or_else(|| midi_invariant(
                "MIDI terminal POST source disappeared before ACK"))?;
            if dispatch.post_failure.as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &failure))
                || dispatch.terminal_ack.as_ref().is_some_and(|saved| saved != &ack)
            {
                return Err(midi_invariant(
                    "MIDI terminal POST ACK changed its exact retained owner",
                ));
            }
            if dispatch.terminal_ack.is_none() {
                dispatch.terminal_ack = Some(ack.clone());
            }
        }
        // USER retires its own failed POST first. MIDI keeps this event and
        // only later ACKs its separate host source after the exact USER
        // tombstone is readable.
        self.acknowledge_started_post_failure(&failure, host)?;
        if !host.win16_window_terminal_acknowledged(receipt, &ack)? {
            return Err(midi_invariant(
                "MIDI USER POST terminal helper returned without exact tombstone readback",
            ));
        }
        let dispatch = self.midi.dispatching.as_mut().ok_or_else(|| midi_invariant(
            "MIDI terminal POST source disappeared after host ACK"))?;
        if dispatch.post_failure.as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, &failure))
            || dispatch.terminal_ack.as_ref() != Some(&ack)
        {
            return Err(midi_invariant(
                "MIDI USER ACK receipt lost the exact native notification owner",
            ));
        }
        dispatch.terminal_acknowledged = true;
        Ok(true)
    }
}

fn midi_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
