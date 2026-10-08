//! Bind a consumed native reaper receipt to exact WAVE callback sources.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct WaveUserSourceRetirementReceipt {
    notification_id: u64,
    source: crate::Win16GuestNotificationSource,
    route: WaveCallbackRoute,
    device: Win16HostWaveDevice,
    device_generation: u64,
    close_event_sequence: u64,
    quiescence_event_sequence: u64,
    pending_source_count: usize,
    pending_source_max_sequence: u64,
    abort_request_id: u64,
    abort_worker_generation: u64,
    terminal_post_operation: Option<crate::Win16NativeWindowOperationProof>,
    terminal_post_state: Option<crate::Win16NativeWindowOperationState>,
    terminal_post_acknowledged: bool,
}

impl WaveUserSourceRetirementReceipt {
    pub(super) fn device(&self) -> Win16HostWaveDevice {
        self.device
    }
}

impl Win16State {
    pub(super) fn wave_user_target_is_retired(
        &self,
        pending: &PendingWaveCallback,
    ) -> bool {
        match pending.route {
            WaveCallbackRoute::Window {
                window,
                guest_hwnd,
                task,
                queue,
            } => {
                self.window_handles.get(&guest_hwnd) != Some(&window)
                    || !self.wave_task_identity_is_live(task)
                    || !self.wave_task_queue_is_current(task, queue)
            }
            WaveCallbackRoute::Task { task, queue } => {
                !self.wave_task_identity_is_live(task)
                    || !self.wave_task_queue_is_current(task, queue)
            }
            WaveCallbackRoute::Function { .. } => false,
        }
    }

    pub(super) fn wave_user_source_retirement_receipt(
        &self,
        pending: &PendingWaveCallback,
        abort: &crate::Win16WindowAbortReceipt,
    ) -> Result<Option<WaveUserSourceRetirementReceipt>, RuntimeError> {
        if self.window_teardown_state != super::super::WindowTeardownState::Closed
            || abort.request_id == 0
            || abort.worker_generation == 0
            || !self.window_abort_receipt.as_ref().is_some_and(|cached| {
                cached.request_id == abort.request_id
                    && cached.worker_generation == abort.worker_generation
            })
        {
            return Ok(None);
        }
        match pending.route {
            WaveCallbackRoute::Window { window, guest_hwnd, .. }
                if self.window_handles.get(&guest_hwnd) == Some(&window) => return Ok(None),
            WaveCallbackRoute::Task { task, queue }
                if self.tasks.current() != Some(task.owner)
                    || self.current_task_handle().ok() != Some(task.guest_htask)
                    || !self.wave_task_identity_is_live(task)
                    || !self.user_task_queue.is_some_and(|(owner, handle, generation, current)| {
                        owner == task.owner
                            && handle == task.guest_htask
                            && generation == task.task_selector_generation
                            && current == queue
                    }) => return Ok(None),
            WaveCallbackRoute::Function { .. } => return Ok(None),
            _ => {}
        }
        if pending.dispatch != WaveCallbackDispatchState::Available {
            return Ok(None);
        }
        if pending.post_attempt.is_some() {
            return Ok(None);
        }
        let (terminal_post_operation, terminal_post_state, terminal_post_acknowledged) =
            match &pending.post_failure {
                Some(failure) => {
                    let Some(ack) = pending.terminal_ack.as_ref() else {
                        return Ok(None);
                    };
                    if !pending.terminal_acknowledged
                        || failure.worker_generation != abort.worker_generation
                        || ack.worker_generation != failure.worker_generation
                        || ack.operation != failure.operation
                        || ack.state != failure.state
                        || !ack.callbacks.is_empty()
                        || !ack.modals.is_empty()
                    {
                        return Ok(None);
                    }
                    (Some(failure.operation), Some(failure.state), true)
                }
                None if pending.terminal_ack.is_none() && !pending.terminal_acknowledged => {
                    (None, None, false)
                }
                None => return Ok(None),
            };
        let Some(device) = self.wave_audio.devices.iter().find(|device| {
            device.host.0 == pending.source.id
                && device.generation == pending.source.generation
        }) else {
            return Ok(None);
        };
        let (Some(close_event_sequence), Some(quiescence_event_sequence)) =
            (device.close_event_sequence, device.producer_quiescence_sequence)
        else {
            return Ok(None);
        };
        if !device.closing
            || device.close_result != Some(0)
            || quiescence_event_sequence <= close_event_sequence
            || device.last_received_sequence != quiescence_event_sequence
            || pending.source.sequence > close_event_sequence
            || self.wave_audio.pending_host_events.iter()
                .any(|event| event.device == device.host)
        {
            return Ok(None);
        }
        if pending.header_far != 0
            && self.wave_audio.headers.iter().filter(|header| {
                header.host_device == device.host
                    && header.guest_handle == pending.guest_handle
                    && header.header_far == pending.header_far
            }).count() != 1
        {
            return Ok(None);
        }
        let mut pending_source_count = 0usize;
        let mut pending_source_max_sequence = 0u64;
        for source in self.wave_audio.pending_callbacks.iter().filter(|source| {
            source.source.id == pending.source.id
                && source.source.generation == pending.source.generation
        }) {
            if source.source.sequence > close_event_sequence {
                return Ok(None);
            }
            pending_source_count += 1;
            pending_source_max_sequence = pending_source_max_sequence.max(source.source.sequence);
        }
        Ok(Some(WaveUserSourceRetirementReceipt {
            notification_id: pending.notification_id,
            source: pending.source,
            route: pending.route,
            device: device.host,
            device_generation: device.generation,
            close_event_sequence,
            quiescence_event_sequence,
            pending_source_count,
            pending_source_max_sequence,
            abort_request_id: abort.request_id,
            abort_worker_generation: abort.worker_generation,
            terminal_post_operation,
            terminal_post_state,
            terminal_post_acknowledged,
        }))
    }

    pub(super) fn wave_user_source_retirement_matches(
        &self,
        pending: &PendingWaveCallback,
        proof: WaveUserSourceRetirementReceipt,
    ) -> bool {
        let Some(abort) = self.window_abort_receipt.as_ref() else {
            return false;
        };
        if pending.notification_id != proof.notification_id
            || pending.source != proof.source
            || pending.route != proof.route
            || pending.dispatch != WaveCallbackDispatchState::Available
            || pending.post_attempt.is_some()
            || self.window_teardown_state != super::super::WindowTeardownState::Closed
            || abort.request_id != proof.abort_request_id
            || abort.worker_generation != proof.abort_worker_generation
            || proof.abort_request_id == 0
            || proof.abort_worker_generation == 0
        {
            return false;
        }
        match (&pending.post_failure, proof.terminal_post_operation, proof.terminal_post_state) {
            (Some(failure), Some(operation), Some(state))
                if proof.terminal_post_acknowledged
                    && failure.operation == operation
                    && failure.state == state
                    && failure.worker_generation == proof.abort_worker_generation
                    && pending.terminal_acknowledged
                    && pending.terminal_ack.as_ref().is_some_and(|ack| {
                        ack.operation == operation
                            && ack.state == state
                            && ack.worker_generation == failure.worker_generation
                            && ack.callbacks.is_empty()
                            && ack.modals.is_empty()
                    }) => {}
            (None, None, None)
                if !proof.terminal_post_acknowledged
                    && pending.terminal_ack.is_none()
                    && !pending.terminal_acknowledged => {}
            _ => return false,
        }
        let Some(device) = self.wave_audio.devices.iter().find(|device| {
            device.host == proof.device
                && device.generation == proof.device_generation
        }) else {
            return false;
        };
        if pending.source.id != proof.device.0
            || pending.source.generation != proof.device_generation
            || pending.source.sequence > proof.close_event_sequence
            || !device.closing
            || device.close_result != Some(0)
            || device.close_event_sequence != Some(proof.close_event_sequence)
            || device.producer_quiescence_sequence != Some(proof.quiescence_event_sequence)
            || proof.quiescence_event_sequence <= proof.close_event_sequence
            || device.last_received_sequence != proof.quiescence_event_sequence
            || self.wave_audio.pending_host_events.iter()
                .any(|event| event.device == proof.device)
        {
            return false;
        }
        if pending.header_far != 0
            && self.wave_audio.headers.iter().filter(|header| {
                header.host_device == proof.device
                    && header.guest_handle == pending.guest_handle
                    && header.header_far == pending.header_far
            }).count() != 1
        {
            return false;
        }
        let mut pending_count = 0usize;
        let mut pending_max_sequence = 0u64;
        for source in self.wave_audio.pending_callbacks.iter().filter(|source| {
            source.source.id == proof.device.0
                && source.source.generation == proof.device_generation
        }) {
            if source.source.sequence > proof.close_event_sequence {
                return false;
            }
            pending_count += 1;
            pending_max_sequence = pending_max_sequence.max(source.source.sequence);
        }
        pending_count == proof.pending_source_count
            && pending_max_sequence == proof.pending_source_max_sequence
    }

    pub(in crate::win16_runtime) fn wave_callback_receipt_for_frame(
        &self,
        callback_id: super::super::CallbackFrameId,
        callback_token: crate::Win16GuestCallbackToken,
    ) -> Option<super::WaveCallbackReceipt> {
        let pending = self.wave_audio.pending_callbacks.front()?;
        if pending.dispatch != WaveCallbackDispatchState::CallbackRunning(callback_id) {
            return None;
        }
        let WaveCallbackRoute::Function { callback, task } = pending.route else {
            return None;
        };
        (callback == callback_token).then_some(super::WaveCallbackReceipt {
            notification_id: pending.notification_id,
            source: pending.source,
            callback,
            task,
        })
    }

    pub(in crate::win16_runtime) fn cancel_wave_callback_after_quiescence(
        &mut self,
        receipt: super::WaveCallbackReceipt,
        retirement: super::super::callback_scheduler::AsynchronousCallbackRetirement,
        proof: super::WaveProducerQuiescenceReceipt,
    ) -> Result<(), RuntimeError> {
        if proof.callback_id != Some(retirement.callback_id)
            || retirement.callback_token != receipt.callback
            || proof.callback != receipt
        {
            return Err(wave_invariant(
                "WAVE terminal receipt does not bind the exact callback source and frame",
            ));
        }
        self.cancel_pending_wave_notification(
            receipt.notification_id,
            WaveCallbackCancellationReason::CallbackAbortedAfterProducerQuiescence {
                proof,
                retirement,
            },
        )
    }

    /// Return proof only after consuming the exact host Quiescent event.
    /// The entered callback additionally requires the current local async top;
    /// all-family teardown binding remains a Root integration boundary.
    pub(in crate::win16_runtime) fn wave_producer_quiescence_receipt(
        &self,
        receipt: super::WaveCallbackReceipt,
        callback_id: Option<super::super::CallbackFrameId>,
    ) -> Result<Option<super::WaveProducerQuiescenceReceipt>, RuntimeError> {
        let Some(pending) = self.wave_audio.pending_callbacks.front() else {
            return Ok(None);
        };
        if pending.notification_id != receipt.notification_id
            || pending.source != receipt.source
            || !matches!(pending.route,
                WaveCallbackRoute::Function { callback, task }
                    if callback == receipt.callback && task == receipt.task)
        {
            return Ok(None);
        }
        match (callback_id, pending.dispatch) {
            (Some(id), WaveCallbackDispatchState::CallbackRunning(active_id)) if id == active_id => {
                self.require_asynchronous_callback_top(id, receipt.callback)?;
            }
            (None, WaveCallbackDispatchState::Available
                | WaveCallbackDispatchState::CallbackUnavailable
                | WaveCallbackDispatchState::CallbackRetired(_)) => {}
            _ => return Ok(None),
        }
        let Some(device) = self.wave_audio.devices.iter().find(|device| {
            device.host.0 == receipt.source.id && device.generation == receipt.source.generation
        }) else {
            return Ok(None);
        };
        let (Some(close_event_sequence), Some(quiescence_event_sequence)) =
            (device.close_event_sequence, device.producer_quiescence_sequence)
        else {
            return Ok(None);
        };
        let guest_header_count = self.wave_audio.headers.iter()
            .filter(|header| header.host_device == device.host).count();
        if pending.header_far != 0
            && self.wave_audio.headers.iter().filter(|header| {
                header.host_device == device.host
                    && header.guest_handle == pending.guest_handle
                    && header.header_far == pending.header_far
            }).count() != 1
        {
            return Ok(None);
        }
        let pending_host_event_count = self.wave_audio.pending_host_events.iter()
            .filter(|event| event.device == device.host).count();
        if !device.closing
            || device.close_result != Some(0)
            || quiescence_event_sequence <= close_event_sequence
            || device.last_received_sequence != quiescence_event_sequence
            || pending_host_event_count != 0
        {
            return Ok(None);
        }
        let mut pending_source_count = 0usize;
        let mut pending_source_max_sequence = 0u64;
        for source in self.wave_audio.pending_callbacks.iter().filter(|source| {
            source.source.id == receipt.source.id
                && source.source.generation == receipt.source.generation
        }) {
            if source.source.sequence > close_event_sequence {
                return Ok(None);
            }
            pending_source_count += 1;
            pending_source_max_sequence = pending_source_max_sequence.max(source.source.sequence);
        }
        Ok(Some(super::WaveProducerQuiescenceReceipt {
            callback: receipt,
            callback_id,
            device: device.host,
            device_generation: device.generation,
            close_event_sequence,
            quiescence_event_sequence,
            guest_header_count,
            pending_host_event_count,
            pending_source_count,
            pending_source_max_sequence,
        }))
    }

    pub(in crate::win16_runtime) fn retire_quiescent_wave_device_if_idle(
        &mut self,
        device: Win16HostWaveDevice,
    ) {
        let Some(record) = self.wave_audio.devices.iter().find(|record| record.host == device) else {
            return;
        };
        if record.close_result != Some(0)
            || record.producer_quiescence_sequence.is_none()
            || self.wave_audio.pending_host_events.iter().any(|event| event.device == device)
            || self.wave_audio.pending_callbacks.iter().any(|source| source.source.id == device.0
                && source.source.generation == record.generation)
        {
            return;
        }
        let callback = record.callback;
        // The reaper proves WinMM no longer owns these headers. Closed guest
        // devices cannot unprepare them, so discard only drained metadata.
        self.wave_audio.headers.retain(|header| header.host_device != device);
        self.wave_audio.retire_device(device);
        self.unregister_wave_callback(callback);
    }

    pub(super) fn wave_producer_quiescence_matches(
        &self,
        pending: &PendingWaveCallback,
        proof: super::WaveProducerQuiescenceReceipt,
    ) -> bool {
        let dispatch_matches = match proof.callback_id {
            Some(id) => pending.dispatch == WaveCallbackDispatchState::CallbackRunning(id),
            None => matches!(pending.dispatch,
                WaveCallbackDispatchState::Available
                    | WaveCallbackDispatchState::CallbackUnavailable
                    | WaveCallbackDispatchState::CallbackRetired(_)),
        };
        if pending.notification_id != proof.callback.notification_id
            || pending.source != proof.callback.source
            || !matches!(pending.route,
                WaveCallbackRoute::Function { callback, task }
                    if callback == proof.callback.callback && task == proof.callback.task)
            || !dispatch_matches
            || proof.device.0 != pending.source.id
            || proof.device_generation != pending.source.generation
            || pending.source.sequence > proof.close_event_sequence
            || proof.quiescence_event_sequence <= proof.close_event_sequence
        {
            return false;
        }
        let Some(device) = self
            .wave_audio
            .devices
            .iter()
            .find(|device| device.host == proof.device)
        else {
            return false;
        };
        if device.generation != proof.device_generation
            || !device.closing
            || device.close_result != Some(0)
            || device.close_event_sequence != Some(proof.close_event_sequence)
            || device.producer_quiescence_sequence != Some(proof.quiescence_event_sequence)
            || device.last_received_sequence != proof.quiescence_event_sequence
            || self.wave_audio.headers.iter()
                .filter(|header| header.host_device == proof.device).count()
                != proof.guest_header_count
            || self.wave_audio.pending_host_events.iter()
                .filter(|event| event.device == proof.device).count()
                != proof.pending_host_event_count
            || proof.pending_host_event_count != 0
        {
            return false;
        }
        let mut pending_count = 0usize;
        let mut pending_max_sequence = 0u64;
        for source in self
            .wave_audio
            .pending_callbacks
            .iter()
            .filter(|source| {
                source.source.id == proof.device.0
                    && source.source.generation == proof.device_generation
            })
        {
            if source.source.sequence > proof.close_event_sequence {
                return false;
            }
            pending_count += 1;
            pending_max_sequence = pending_max_sequence.max(source.source.sequence);
        }
        pending_count == proof.pending_source_count
            && pending_max_sequence == proof.pending_source_max_sequence
    }
}
