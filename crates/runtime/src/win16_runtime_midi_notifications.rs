//! MIDI callback projection and exact native-event retirement.

use guest_core::memory::Memory;

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16CallbackArgumentData, Win16GuestCallbackEvent, Win16GuestNotification,
    Win16GuestNotificationSource, Win16GuestNotificationTarget,
    Win16HostMidiCall as HostCall, Win16HostMidiCancellationReason,
    Win16HostMidiNotification,
    Win16HostMidiNotificationDisposition as Disposition, Win16HostMidiNotificationId,
};
use crate::Win16HostMidiResult as HostResult;
use super::super::window_post::{window_post_attempt_consumed, window_post_attempt_result};

use super::{MidiCallbackRoute, Win16MidiDispatch, Win16State, MHDR_INQUEUE, MHDR_PREPARED};

const MM_MIM_CLOSE: u32 = 0x03c2;
const MM_MOM_CLOSE: u32 = 0x03c8;
const MIDI_TASK_QUEUE_GAP: u16 = u16::MAX;

#[derive(Clone, Debug)]
pub(crate) enum Win16MidiNotificationTarget {
    /// Window/task notification. ACK only after PostGuestNotification returns true.
    Post {
        identity: Win16HostMidiNotificationId,
        notification: Win16GuestNotification,
    },
    /// Function callback. ACK only after the exact asynchronous CPU frame returns.
    Function {
        identity: Win16HostMidiNotificationId,
        event: Win16GuestCallbackEvent,
    },
}

impl Win16State {
    /// Read the native queue front, commit any completed MIDIHDR16 state, and
    /// return one exact guest continuation. The caller owns delivery and ACK.
    pub(crate) fn poll_midi_notification_target(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16MidiNotificationTarget>, RuntimeError> {
        if self.retry_midi_callback_start_cleanup()? {
            // The exact native queue front remains unACKed. Re-poll it at the
            // next scheduler boundary after its callback buffer owner retires.
            return Ok(None);
        }
        if self.midi.dispatching.is_some() {
            return Ok(None);
        }
        self.retry_pending_midi_close_projections(memory, host)?;
        self.retry_closed_midi_device_retirement(host)?;
        let Some(notification) = host.win16_midi_peek_notification()? else {
            return Ok(None);
        };
        let identity = Win16HostMidiNotificationId {
            device: notification.device,
            sequence: notification.sequence,
        };
        let Some(device) = self.midi.device_for_host(notification.device).copied() else {
            return Err(midi_invariant("MIDI callback referenced an unknown host device"));
        };
        if notification.callback_instance != device.instance {
            return Err(midi_invariant("MIDI callback instance changed after open"));
        }
        if self.midi.notification_is_dispatching(identity) {
            return Ok(None);
        }
        if let MidiCallbackRoute::Task(task) = device.callback
            && self.midi_task_identity_for(task.owner, task.handle) == Some(task)
            && self.tasks.current() != Some(task.owner)
        {
            return Ok(None);
        }

        let guest_parameter1 = self.commit_callback_header(&notification, memory)?;
        let parameter1 = guest_parameter1.unwrap_or(notification.parameter1);
        let message = u16::try_from(notification.message).map_err(|error| {
            RuntimeError::with_source(Kind::CompatibilityGap,
                "WinMM MIDI callback message does not fit the Win16 UINT", error)
        })?;
        let dispatch = Win16MidiDispatch {
            identity,
            message: notification.message,
            guest_device: device.guest,
            host_header: notification.header.as_ref().map(|header| header.header),
            completion: notification.header.as_ref().and_then(|header|
                header.completed_submission),
            callback_route: device.callback,
            function_started: false,
            post_attempt: None,
            post_accepted: false,
            post_failure: None,
            terminal_ack: None,
            terminal_acknowledged: false,
        };

        match device.callback {
            MidiCallbackRoute::None => {
                self.midi.dispatching = Some(dispatch);
                self.cancel_midi_notification_source(host, identity,
                    Win16HostMidiCancellationReason::NoCallbackRequested)?;
                Ok(None)
            }
            MidiCallbackRoute::Function(callback) => {
                let mut arguments = Vec::new();
                arguments.try_reserve_exact(5).map_err(|error| {
                    RuntimeError::with_source(Kind::ResourceExhausted,
                        "reserve Win16 MIDI callback arguments", error)
                })?;
                arguments.push(Win16CallbackArgumentData::Word(device.guest));
                arguments.push(Win16CallbackArgumentData::Word(message));
                arguments.push(Win16CallbackArgumentData::Dword(device.instance));
                arguments.push(Win16CallbackArgumentData::Dword(parameter1));
                arguments.push(Win16CallbackArgumentData::Dword(notification.parameter2));
                self.midi.dispatching = Some(dispatch);
                Ok(Some(Win16MidiNotificationTarget::Function {
                    identity,
                    event: Win16GuestCallbackEvent { callback, arguments },
                }))
            }
            MidiCallbackRoute::Window { host: native_window, guest: guest_hwnd } => {
                if self.window_handles.get(&guest_hwnd) != Some(&native_window) {
                    self.warn_midi_gap(host, MIDI_TASK_QUEUE_GAP,
                        "MIDI window callback target was retired before notification delivery");
                    self.midi.dispatching = Some(dispatch);
                    self.cancel_midi_notification_source(host, identity,
                        Win16HostMidiCancellationReason::WindowTargetRetired)?;
                    return Ok(None);
                }
                let notification = Win16GuestNotification {
                    target: Win16GuestNotificationTarget::Window {
                        window: native_window,
                        guest_hwnd,
                    },
                    source: Win16GuestNotificationSource {
                        id: identity.device.token,
                        generation: identity.device.generation,
                        sequence: identity.sequence,
                    },
                    message,
                    w_param: device.guest,
                    l_param: parameter1,
                };
                self.midi.dispatching = Some(dispatch);
                Ok(Some(Win16MidiNotificationTarget::Post { identity, notification }))
            }
            MidiCallbackRoute::Task(task) => {
                if self.midi_task_identity_for(task.owner, task.handle) != Some(task) {
                    self.warn_midi_gap(host, MIDI_TASK_QUEUE_GAP,
                        "MIDI task callback target is no longer the captured live Win16 task");
                    self.midi.dispatching = Some(dispatch);
                    self.cancel_midi_notification_source(host, identity,
                        Win16HostMidiCancellationReason::TaskTargetRetired)?;
                    return Ok(None);
                }
                if self.tasks.current() != Some(task.owner) {
                    // A live CALLBACK_TASK target is eligible only while its
                    // exact Win16 owner is current; the queued source stays unACKed.
                    return Ok(None);
                }
                host.win16_initialize_user_queue()?;
                let Some(queue) = host.win16_bind_task_queue(
                    task.owner, task.handle, task.selector_generation,
                )? else {
                    self.warn_midi_gap(host, MIDI_TASK_QUEUE_GAP,
                        "MIDI CALLBACK_TASK target has no bound native guest-task queue");
                    return Ok(None);
                };
                self.user_task_queue = Some((
                    task.owner, task.handle, task.selector_generation, queue,
                ));
                let notification = Win16GuestNotification {
                    target: Win16GuestNotificationTarget::Task {
                        owner: task.owner,
                        guest_htask: task.handle,
                        task_selector_generation: task.selector_generation,
                        queue,
                    },
                    source: Win16GuestNotificationSource {
                        id: identity.device.token,
                        generation: identity.device.generation,
                        sequence: identity.sequence,
                    },
                    message,
                    w_param: device.guest,
                    l_param: parameter1,
                };
                self.midi.dispatching = Some(dispatch);
                Ok(Some(Win16MidiNotificationTarget::Post { identity, notification }))
            }
        }
    }

    /// Complete the exact posted/function callback source. USER ACK requires
    /// the consumed normal POST proof retained on this dispatch owner.
    pub(crate) fn finish_midi_notification_target(
        &mut self,
        host: &mut impl RuntimeHost,
        identity: Win16HostMidiNotificationId,
    ) -> Result<(), RuntimeError> {
        let pending = self.midi.dispatching.clone().ok_or_else(|| midi_invariant(
            "MIDI notification completion has no runtime dispatch frame"))?;
        if pending.identity != identity || pending.post_failure.is_some() {
            return Err(midi_invariant("MIDI notification completion changed source identity"));
        }
        if matches!(pending.callback_route,
            MidiCallbackRoute::Window { .. } | MidiCallbackRoute::Task(_))
            && (!pending.post_accepted
                || pending.post_attempt.as_ref().is_none_or(|attempt| {
                    !window_post_attempt_consumed(attempt)
                        || window_post_attempt_result(attempt) != Some(true)
                }))
        {
            return Err(midi_invariant(
                "MIDI USER delivery ACK lacks its exact consumed normal POST proof",
            ));
        }
        self.retire_midi_notification(host, pending,
            Disposition::Delivered)?;
        Ok(())
    }

    /// Complete the exact callback-buffer rollback from a failed FUNCTION
    /// entry, then make the same native queue front eligible for retry. This
    /// releases runtime temporary storage; it does not ACK the MIDI source.
    pub(super) fn retry_midi_callback_start_cleanup(
        &mut self,
    ) -> Result<bool, RuntimeError> {
        let Some(callback_id) = self.midi.pending_callback_cleanup else {
            return Ok(false);
        };
        let dispatch = self.midi.dispatching.clone().ok_or_else(|| midi_invariant(
            "MIDI callback rollback lost its exact notification source"))?;
        let Some(retirement) = self.retry_asynchronous_pre_entry_cleanup(callback_id)? else {
            return Err(midi_invariant(
                "MIDI callback rollback has no retained asynchronous cleanup owner"));
        };
        if retirement.callback_id != callback_id || !retirement.source_bound
            || retirement.midi_source.is_some()
            || !matches!(dispatch.callback_route,
                MidiCallbackRoute::Function(callback) if callback == retirement.callback_token)
        {
            return Err(midi_invariant(
                "MIDI callback rollback receipt changed its callback or source owner"));
        }
        self.complete_asynchronous_pre_entry_source_release(
            callback_id, retirement.callback_token,
        )?;
        self.cancel_midi_notification_target(dispatch.identity)?;
        self.midi.pending_callback_cleanup = None;
        Ok(true)
    }

    pub(super) fn begin_midi_asynchronous_guest_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu, dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        identity: Win16HostMidiNotificationId,
        event: Win16GuestCallbackEvent,
    ) -> Result<bool, RuntimeError> {
        let callback = event.callback;
        self.validate_midi_function_start(identity, callback)?;
        self.mark_midi_function_started(identity)?;
        match self.begin_asynchronous_guest_callback_midi_source(
            cpu,
            dos, memory, event, identity,
        ) {
            Ok(Some(_callback_id)) => Ok(true),
            Ok(None) => {
                self.restore_midi_function_start(identity)?;
                self.cancel_midi_notification_source(host, identity,
                    Win16HostMidiCancellationReason::CallbackRegistrationRetired)?;
                Ok(false)
            }
            Err(super::super::callback_scheduler::AsynchronousCallbackBeginFailure::Rejected {
                error,
            }) => {
                if let Err(cleanup) = self.restore_midi_function_start(identity) {
                    return Err(error.with_cleanup(
                        "MIDI callback entry and header-state rollback both failed", cleanup));
                }
                self.cancel_midi_notification_target(identity)?;
                Err(error)
            }
            Err(super::super::callback_scheduler::AsynchronousCallbackBeginFailure::RollbackRetained {
                callback_id,
                callback_token,
                error,
            }) => {
                if let Err(cleanup) = self.restore_midi_function_start(identity) {
                    return Err(error.with_cleanup(
                        "MIDI callback entry and header-state rollback both failed", cleanup));
                }
                self.midi.pending_callback_cleanup = Some(callback_id);
                if callback_token != callback {
                    return Err(error.with_cleanup("MIDI callback rollback changed its token",
                        midi_invariant("retained callback token does not match MIDI source")));
                }
                Err(error.with_context(format!(
                    "MIDI callback source {}:{} retains pre-entry rollback frame {}",
                    identity.device.token, identity.device.generation, callback_id.0,
                )))
            }
        }
    }

    pub(crate) fn cancel_midi_notification_source(
        &mut self,
        host: &mut impl RuntimeHost,
        identity: Win16HostMidiNotificationId,
        reason: Win16HostMidiCancellationReason,
    ) -> Result<(), RuntimeError> {
        let pending = self.midi.dispatching.clone().ok_or_else(|| midi_invariant(
            "MIDI notification cancellation has no runtime dispatch frame"))?;
        if pending.identity != identity {
            return Err(midi_invariant("MIDI notification cancellation changed source identity"));
        }
        self.retire_midi_notification(host, pending, Disposition::Cancelled(reason))
    }

    fn retire_midi_notification(
        &mut self,
        host: &mut impl RuntimeHost,
        pending: Win16MidiDispatch,
        disposition: Disposition,
    ) -> Result<(), RuntimeError> {
        let identity = pending.identity;
        if let Some(attempt) = &pending.post_attempt {
            if pending.post_failure.is_some()
                || !window_post_attempt_consumed(attempt)
                || match window_post_attempt_result(attempt) {
                    Some(true) => {
                        !pending.post_accepted || disposition != Disposition::Delivered
                    }
                    Some(false) => {
                        pending.post_accepted
                            || disposition
                                != Disposition::Cancelled(
                                    Win16HostMidiCancellationReason::UserPostRejected,
                                )
                    }
                    None => true,
                }
            {
                return Err(midi_invariant(
                    "MIDI source ACK preceded its exact consumed USER POST result",
                ));
            }
        } else if pending.post_accepted {
            return Err(midi_invariant(
                "MIDI accepted USER post lost its exact source-retirement proof",
            ));
        }
        if let Some(failure) = &pending.post_failure {
            if pending.post_accepted
                || !pending.terminal_acknowledged
                || pending.terminal_ack.as_ref().is_none_or(|ack| {
                    ack.operation != failure.operation
                        || ack.state != failure.state
                        || ack.worker_generation != failure.worker_generation
                        || !ack.callbacks.is_empty()
                        || !ack.modals.is_empty()
                })
                || disposition
                    != Disposition::Cancelled(Win16HostMidiCancellationReason::OwnerTerminated)
            {
                return Err(midi_invariant(
                    "MIDI source ACK preceded its exact USER terminal POST receipt",
                ));
            }
        }
        let completion_header = match (pending.host_header, pending.completion) {
            (Some(header), Some(completion)) => {
                let exact_count = self.midi.headers.iter().filter(|record|
                    record.host_device == identity.device
                        && record.host_header == header
                        && record.guest_device == pending.guest_device
                ).count();
                if exact_count != 1 {
                    return Err(midi_invariant(
                        "MIDI source ACK lost its exact guest/header generation",
                    ));
                }
                let index = self.midi.headers.iter().position(|record|
                    record.host_device == identity.device
                        && record.host_header == header
                        && record.guest_device == pending.guest_device
                ).ok_or_else(|| midi_invariant(
                    "MIDI source ACK exact header disappeared"))?;
                let record = &self.midi.headers[index];
                let entered_function = matches!(pending.callback_route,
                    MidiCallbackRoute::Function(_)) && pending.function_started;
                if entered_function {
                    if record.completed_pending.is_some_and(|current| current != completion)
                        || record.submission == Some(completion)
                    {
                        return Err(midi_invariant(
                            "MIDI FUNCTION ACK changed the exact returned header generation",
                        ));
                    }
                } else if record.completed_pending != Some(completion)
                    || record.submission.is_some()
                {
                    return Err(midi_invariant(
                        "MIDI source ACK lost its exact unentered completed header generation",
                    ));
                }
                Some((index, completion))
            }
            (None, None) => None,
            _ => return Err(midi_invariant(
                "MIDI source ACK split its exact native header completion identity")),
        };
        let close_device_index = if matches!(pending.message, MM_MOM_CLOSE | MM_MIM_CLOSE) {
            Some(self.midi.devices.iter().position(|record|
                record.guest == pending.guest_device && record.host == identity.device
            ).ok_or_else(|| midi_invariant(
                "MIDI close callback lost its exact guest owner before ACK"))?)
        } else {
            None
        };
        host.win16_midi_ack_notification(identity.device, identity.sequence, disposition)?;
        self.midi.notification_progress = self.midi.notification_progress.wrapping_add(1);
        self.midi.dispatching = None;
        if let Some((index, completion)) = completion_header {
            if self.midi.headers[index].completed_pending == Some(completion) {
                self.midi.headers[index].completed_pending = None;
            }
        }
        if let Some(index) = close_device_index {
            self.midi.devices[index].closing = true;
            self.midi.devices[index].close_seen = true;
        }
        // Header release is a separate exact host receipt. Keep the runtime
        // mapping after source ACK; the next MIDI safe point retries release
        // only after native callback/context quiescence is observable.
        Ok(())
    }

    /// Retry idle unprepare releases after a source ACK or a guest publication
    /// retry. An unrelated callback may have kept the device trampoline in
    /// flight; the host's exact header check remains final.
    pub(super) fn release_quiescent_close_headers(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut index = 0;
        while index < self.midi.headers.len() {
            let record = self.midi.headers[index].clone();
            if !record.retired
                || record.pending_close_projection.is_some()
                    && !record.close_projection_committed
                || record.pending_unprepare_projection.is_some()
                || record.submission.is_some() || record.completed_pending.is_some()
                || self.has_runtime_header_callback(&record)
                || self.midi.devices.iter().any(|device|
                    device.host == record.host_device && device.closing)
            {
                index += 1;
                continue;
            }
            match host.win16_midi(HostCall::ReleaseRetiredHeader {
                device: record.host_device,
                header: record.host_header,
            })? {
                HostResult::RetiredHeaderReleased { header, released }
                    if header == record.host_header && released =>
                {
                    self.midi.headers.remove(index);
                }
                HostResult::RetiredHeaderReleased { header, released: false }
                    if header == record.host_header => index += 1,
                _ => return Err(midi_invariant(
                    "retired MIDI callback owner could not prove exact host release")),
            }
        }
        Ok(())
    }

    /// Retire a device only after both the guest-visible terminal event and
    /// the host callback-context quiescence receipt have been observed.
    pub(super) fn try_retire_closed_midi_device(
        &mut self,
        host: &mut impl RuntimeHost,
        guest_device: u16,
        host_device: crate::Win16HostMidiDevice,
    ) -> Result<bool, RuntimeError> {
        let Some(device) = self.midi.devices.iter().find(|record|
            record.guest == guest_device && record.host == host_device).copied()
        else {
            return Err(midi_invariant("MIDI retirement lost its exact guest device mapping"));
        };
        if !device.closing || !device.close_seen {
            return Err(midi_invariant("MIDI owner retirement preceded its CLOSE receipt"));
        }
        if self.midi.headers.iter().any(|header| header.host_device == host_device
            && (header.submission.is_some() || header.completed_pending.is_some()
                || header.pending_close_projection.is_some()
                    && !header.close_projection_committed))
        {
            return Ok(false);
        }
        if !host.win16_midi_finalize_closed_device(host_device)? {
            return Ok(false);
        }
        self.retire_midi_device(guest_device, host_device);
        Ok(true)
    }

    fn retry_closed_midi_device_retirement(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut index = 0;
        while index < self.midi.devices.len() {
            let device = self.midi.devices[index];
            if device.closing && device.close_seen
                && self.try_retire_closed_midi_device(host, device.guest, device.host)?
            {
                continue;
            }
            index += 1;
        }
        Ok(())
    }

    /// A function continuation starts only after its callback code and FAR
    /// arguments have been checked. Clearing this guard lets guest callback
    /// code resubmit the just-completed MIDIHDR while host ACK remains pending.
    pub(crate) fn validate_midi_function_start(
        &self,
        identity: Win16HostMidiNotificationId,
        callback: crate::Win16GuestCallbackToken,
    ) -> Result<(), RuntimeError> {
        let pending = self.midi.dispatching.clone().ok_or_else(|| midi_invariant(
            "MIDI function callback validation has no pending source"))?;
        if pending.identity != identity
            || pending.callback_route != MidiCallbackRoute::Function(callback)
        {
            return Err(midi_invariant(
                "MIDI function callback validation changed its source route"));
        }
        if let (Some(header), Some(completion)) = (pending.host_header, pending.completion) {
            let record = self.midi.headers.iter().find(|record|
                record.host_header == header && record.host_device == identity.device
            ).ok_or_else(|| midi_invariant(
                "MIDI function callback header retired before entry validation"))?;
            if record.completed_pending != Some(completion) || record.submission.is_some() {
                return Err(midi_invariant(
                    "MIDI function callback completion changed before entry validation"));
            }
        }
        Ok(())
    }

    pub(crate) fn mark_midi_function_started(
        &mut self,
        identity: Win16HostMidiNotificationId,
    ) -> Result<(), RuntimeError> {
        let pending = self.midi.dispatching.clone().ok_or_else(|| midi_invariant(
            "MIDI function callback start has no pending source"))?;
        if pending.identity != identity
            || pending.function_started
            || !matches!(pending.callback_route, MidiCallbackRoute::Function(_))
        {
            return Err(midi_invariant(
                "MIDI function callback start changed its exact source or phase",
            ));
        }
        if let (Some(header), Some(completion)) = (pending.host_header, pending.completion) {
            let exact = self.midi.headers.iter().filter(|record|
                record.host_device == identity.device
                    && record.host_header == header
                    && record.guest_device == pending.guest_device
            ).count();
            if exact != 1 {
                return Err(midi_invariant(
                    "MIDI function callback lost its exact guest/header identity",
                ));
            }
            let record = self.midi.headers.iter_mut().find(|record|
                record.host_device == identity.device
                    && record.host_header == header
                    && record.guest_device == pending.guest_device
            ).ok_or_else(|| midi_invariant(
                "MIDI function callback header disappeared before entry"))?;
            if record.completed_pending != Some(completion) || record.submission.is_some() {
                return Err(midi_invariant(
                    "MIDI function callback lost its exact completed submission before entry",
                ));
            }
            record.completed_pending = None;
        }
        self.midi.dispatching.as_mut().ok_or_else(|| midi_invariant(
            "MIDI function callback start lost its source owner"))?.function_started = true;
        Ok(())
    }

    /// Roll back the start marker when FAR-frame entry fails before guest code
    /// executes. This preserves the same completion for a later safe-point try.
    pub(crate) fn restore_midi_function_start(
        &mut self,
        identity: Win16HostMidiNotificationId,
    ) -> Result<(), RuntimeError> {
        let pending = self.midi.dispatching.clone().ok_or_else(|| midi_invariant(
            "MIDI callback entry rollback has no pending source"))?;
        if pending.identity != identity
            || !pending.function_started
            || !matches!(pending.callback_route, MidiCallbackRoute::Function(_))
        {
            return Err(midi_invariant(
                "MIDI callback entry rollback changed its exact source or phase"));
        }
        if let (Some(header), Some(completion)) = (pending.host_header, pending.completion) {
            let exact = self.midi.headers.iter().filter(|record|
                record.host_device == identity.device
                    && record.host_header == header
                    && record.guest_device == pending.guest_device
            ).count();
            if exact != 1 {
                return Err(midi_invariant(
                    "MIDI callback entry rollback lost its exact guest/header identity",
                ));
            }
            let record = self.midi.headers.iter_mut().find(|record|
                record.host_device == identity.device
                    && record.host_header == header
                    && record.guest_device == pending.guest_device
            ).ok_or_else(|| midi_invariant(
                "MIDI callback entry rollback lost its exact header"))?;
            if record.submission.is_some()
                || record.completed_pending.is_some_and(|current| current != completion)
            {
                return Err(midi_invariant(
                    "MIDI callback entry rollback found a different header submission"));
            }
            record.completed_pending = Some(completion);
        }
        self.midi.dispatching.as_mut().ok_or_else(|| midi_invariant(
            "MIDI callback entry rollback lost its source owner"))?.function_started = false;
        Ok(())
    }

    /// Release a local dispatch reservation only when no USER post result was
    /// enqueued or cached. The native notification remains at the queue front.
    pub(crate) fn cancel_midi_notification_target(
        &mut self,
        identity: Win16HostMidiNotificationId,
    ) -> Result<(), RuntimeError> {
        let pending = self.midi.dispatching.as_ref().ok_or_else(|| midi_invariant(
            "MIDI notification cancel has no runtime dispatch frame"))?;
        if pending.identity != identity
            || pending.post_failure.is_some()
            || pending.post_attempt.is_some()
            || pending.post_accepted
            || pending.function_started
        {
            return Err(midi_invariant("MIDI notification cancel changed source identity"));
        }
        self.midi.dispatching = None;
        Ok(())
    }

    fn commit_callback_header(
        &mut self,
        notification: &Win16HostMidiNotification,
        memory: &mut Memory,
    ) -> Result<Option<u32>, RuntimeError> {
        let Some(state) = notification.header.as_ref() else { return Ok(None); };
        let Some(index) = self.midi.headers.iter().position(|record|
            record.host_device == notification.device && record.host_header == state.header)
        else {
            return Err(midi_invariant("MIDI callback names an unknown guest MIDIHDR"));
        };
        let record = self.midi.headers[index].clone();
        let completion = state.completed_submission;
        let retrying = completion.is_some() && record.completed_pending == completion
            && record.submission.is_none();
        if completion.is_none()
            || (!retrying && completion != record.submission)
            || (retrying && state.submission.is_some())
            || state.submission.is_some()
            || state.callback_pending
            || state.bytes_recorded > record.capacity
        {
            return Err(midi_invariant("MIDI completion did not match the exact active submission"));
        }
        let input_bytes = match (record.direction, state.input_data.as_deref()) {
            (crate::Win16HostMidiDirection::Input, Some(bytes))
                if bytes.len() == state.bytes_recorded as usize => Some(bytes),
            (crate::Win16HostMidiDirection::Output, None) => None,
            _ => return Err(midi_invariant("MIDI completion data did not match device direction")),
        };
        // A cached completion snapshot may predate a successful native
        // Unprepare. Preserve its DONE/data projection while honoring the
        // current exact owner's retired state instead of restoring old flags.
        let mut committed_state = state.clone();
        if !record.prepared || record.retired {
            committed_state.flags &= !(MHDR_PREPARED | MHDR_INQUEUE);
        }
        self.commit_midi_header_state(&record, &committed_state, input_bytes, memory)?;
        let Some(live) = self.midi.headers.iter_mut().find(|entry|
            entry.host_device == notification.device && entry.host_header == state.header)
        else { return Err(midi_invariant("MIDI guest header retired during completion commit")); };
        live.submission = None;
        live.completed_pending = completion;
        live.guest_flags = committed_state.flags;
        Ok(Some(record.header_far))
    }

    pub(super) fn retire_midi_device(
        &mut self,
        guest_device: u16,
        host_device: crate::Win16HostMidiDevice,
    ) {
        if let Some(index) = self.midi.devices.iter().position(|record|
            record.guest == guest_device && record.host == host_device)
        {
            let record = self.midi.devices.remove(index);
            if let MidiCallbackRoute::Function(callback) = record.callback {
                self.unregister_guest_callback(callback);
            }
            self.midi.headers.retain(|header| header.host_device != host_device);
        }
    }
}

fn midi_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
