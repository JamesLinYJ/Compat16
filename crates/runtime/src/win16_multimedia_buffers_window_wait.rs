//! Dispatch exact WAVE source receipts at ordinary or parked USER safe points.

use super::*;
use super::super::callback_scheduler::{
    AsynchronousCallbackBeginFailure,
    Win16AsynchronousCallbackArgument as CallbackArgument,
    Win16AsynchronousCallbackRequest as CallbackRequest,
};
use super::super::CallbackFrameId;
use super::super::window_post::started_failure_error;

impl Win16State {
    /// Post WINDOW/TASK sidecars or reserve one FUNCTION callback for the
    /// common callback scheduler. The source row remains until POST handoff or
    /// the exact callback-return ACK.
    pub(in crate::win16_runtime) fn dispatch_one_pending_wave_notification(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<(WaveCallbackReceipt, CallbackRequest)>, RuntimeError> {
        let pending_count = self.wave_audio.pending_callbacks.len();
        for _ in 0..pending_count {
            let Some(pending) = self.wave_audio.pending_callbacks.front().cloned() else {
                return Ok(None);
            };
            if pending.dispatch != WaveCallbackDispatchState::Available {
                return Ok(None);
            }
            if let Some(failure) = &pending.post_failure {
                return Err(started_failure_error(
                    failure,
                    "WAVE source retains its original failed USER POST",
                ));
            }
            if pending.post_attempt.is_some() {
                match pending.route {
                    WaveCallbackRoute::Window { task, queue, .. }
                    | WaveCallbackRoute::Task { task, queue } => {
                        self.dispatch_pending_wave_user_notification(
                            host,
                            &pending,
                            task,
                            queue,
                        )?;
                        continue;
                    }
                    WaveCallbackRoute::Function { .. } => {
                        return Err(wave_invariant(
                            "WAVE FUNCTION source unexpectedly owns a USER POST proof",
                        ));
                    }
                }
            }
            let task = match pending.route {
                WaveCallbackRoute::Function { task, .. }
                | WaveCallbackRoute::Window { task, .. }
                | WaveCallbackRoute::Task { task, .. } => task,
            };
            if !self.wave_task_identity_is_live(task) {
                if matches!(pending.route, WaveCallbackRoute::Function { .. }) {
                    if let Some(row) = self.wave_audio.pending_callbacks.front_mut() {
                        row.dispatch = WaveCallbackDispatchState::CallbackUnavailable;
                    }
                    self.rotate_pending_wave_notification(pending.notification_id)?;
                } else {
                    self.cancel_pending_wave_notification(
                        pending.notification_id,
                        WaveCallbackCancellationReason::TargetRetired,
                    )?;
                }
                continue;
            }
            if self.tasks.current() != Some(task.owner)
                || self.current_task_handle().ok() != Some(task.guest_htask)
            {
                if let Some(pending) = self.wave_audio.pending_callbacks.pop_front() {
                    self.wave_audio.pending_callbacks.push_back(pending);
                }
                continue;
            }

            match pending.route {
                WaveCallbackRoute::Function { callback, .. } => {
                    let mut arguments = Vec::new();
                    arguments.try_reserve_exact(5).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve Win16 WAVE callback arguments",
                            error,
                        )
                    })?;
                    arguments.push(CallbackArgument::Word(pending.guest_handle));
                    arguments.push(CallbackArgument::Word(pending.message));
                    arguments.push(CallbackArgument::Dword(pending.instance));
                    arguments.push(CallbackArgument::GuestFarPointer {
                        far: pending.header_far,
                        access: win16_abi::Access::Read,
                        bytes: WAVEHDR16_SIZE as u32,
                        selector_generation: pending.header_selector_generation,
                        allow_null: true,
                    });
                    arguments.push(CallbackArgument::Dword(0));
                    let receipt = WaveCallbackReceipt {
                        notification_id: pending.notification_id,
                        source: pending.source,
                        callback,
                        task,
                    };
                    let pending =
                        self.wave_audio
                            .pending_callbacks
                            .front_mut()
                            .ok_or_else(|| {
                                wave_invariant("WAVE callback disappeared before dispatch")
                            })?;
                    if pending.notification_id != receipt.notification_id {
                        return Err(wave_invariant(
                            "WAVE callback order changed before dispatch",
                        ));
                    }
                    pending.dispatch = WaveCallbackDispatchState::Reserved;
                    return Ok(Some((
                        receipt,
                        CallbackRequest {
                            callback,
                            arguments,
                            event: crate::Win16GuestCallbackEvent {
                                callback,
                                arguments: Vec::new(),
                            },
                        },
                    )));
                }
                WaveCallbackRoute::Window {
                    window,
                    guest_hwnd,
                    task,
                    queue,
                } => {
                    if self.window_handles.get(&guest_hwnd) != Some(&window) {
                        self.cancel_pending_wave_notification(
                            pending.notification_id,
                            WaveCallbackCancellationReason::TargetRetired,
                        )?;
                        continue;
                    }
                    self.dispatch_pending_wave_user_notification(
                        host,
                        &pending,
                        task,
                        queue,
                    )?;
                }
                WaveCallbackRoute::Task { task, queue } => {
                    self.dispatch_pending_wave_user_notification(
                        host,
                        &pending,
                        task,
                        queue,
                    )?;
                }
            }
        }
        Ok(None)
    }

    /// Enter one reserved FUNCTION notification at a checked guest boundary.
    /// The typed begin result decides whether a failed pre-entry attempt may
    /// release this exact reservation or must retain it for rollback cleanup.
    pub(in crate::win16_runtime) fn dispatch_pending_wave_function_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu, dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if let Some(pending) = self.wave_audio.pending_callbacks.front() {
            if let WaveCallbackDispatchState::RollbackRetained(callback_id)
            | WaveCallbackDispatchState::SourceReleasePending(callback_id) = pending.dispatch
            {
                if !self.retry_wave_pre_entry_cleanup(callback_id)? {
                    return Err(wave_invariant(
                        "WAVE rollback row has no exact asynchronous cleanup receipt",
                    ));
                }
            }
        }
        // A stale callback registration may cancel one source while another
        // completion from the same native wake is already queued. Retry only
        // within the queue length captured here; one wake can never spin.
        let dispatch_budget = self.wave_audio.pending_callbacks.len();
        for _ in 0..=dispatch_budget {
            let Some((receipt, request)) = self.dispatch_one_pending_wave_notification(host)? else {
                return Ok(false);
            };
            match self.begin_asynchronous_guest_callback_request_source(
                cpu,
                dos, memory, request, true,
            ) {
                Ok(Some(callback_id)) => {
                    self.bind_pending_wave_callback_frame(receipt, callback_id)?;
                    return Ok(true);
                }
                Ok(None) => {
                    self.retain_unavailable_wave_callback(receipt)?;
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "WAVE callback registration retired while its source receipt remained queued",
                    ));
                }
                Err(AsynchronousCallbackBeginFailure::Rejected { error }) => {
                    if let Err(cleanup) = self.release_pending_wave_notification_dispatch(receipt) {
                        return Err(error.with_cleanup(
                            "WAVE callback entry and exact reservation release both failed",
                            cleanup,
                        ));
                    }
                    return Err(error.with_context(format!(
                        "WAVE callback source {}:{}:{} rejected before guest entry",
                        receipt.source.id, receipt.source.generation, receipt.source.sequence,
                    )));
                }
                Err(AsynchronousCallbackBeginFailure::RollbackRetained {
                    callback_id,
                    callback_token,
                    error,
                }) => {
                    if callback_token != receipt.callback {
                        return Err(error.with_cleanup(
                            "WAVE rollback receipt changed its callback token",
                            wave_invariant("retained callback token does not match WAVE source"),
                        ));
                    }
                    self.retain_pending_wave_rollback(receipt, callback_id)?;
                    return Err(error.with_context(format!(
                        "WAVE callback source {}:{}:{} retains pre-entry rollback frame {}",
                        receipt.source.id,
                        receipt.source.generation,
                        receipt.source.sequence,
                        callback_id.0,
                    )));
                }
            }
        }
        Err(wave_invariant("WAVE callback dispatch exceeded its source-count budget"))
    }

    pub(in crate::win16_runtime) fn owns_terminal_wave_post_source(
        &self,
        top: &crate::Win16WindowTerminalSourceTop,
    ) -> Result<bool, RuntimeError> {
        let crate::Win16WindowTerminalSourceTop::User {
            operation,
            kind,
            state,
            worker_generation,
        } = top else {
            return Ok(false);
        };
        if *kind != crate::Win16NativeWindowOperationKind::PostGuestNotification {
            return Ok(false);
        }
        let mut owner = None;
        for (index, pending) in self.wave_audio.pending_callbacks.iter().enumerate() {
            let Some(failure) = pending.post_failure.as_ref() else {
                continue;
            };
            if failure.operation.operation_id == *operation
                && failure.operation.kind == *kind
                && failure.state == *state
                && failure.worker_generation == *worker_generation
            {
                if owner.replace(index).is_some() {
                    return Err(wave_invariant(
                        "one USER POST operation is retained by multiple WAVE source rows",
                    ));
                }
            }
        }
        Ok(owner.is_some())
    }

    pub(in crate::win16_runtime) fn retire_wave_terminal_post_source(
        &mut self,
        receipt: &crate::Win16WindowAbortReceipt,
        top: &crate::Win16WindowTerminalSourceTop,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !self.owns_terminal_wave_post_source(top)? {
            return Ok(false);
        }
        let crate::Win16WindowTerminalSourceTop::User {
            operation,
            kind,
            state,
            worker_generation,
        } = top else {
            return Ok(false);
        };
        let mut owner = None;
        for (index, pending) in self.wave_audio.pending_callbacks.iter().enumerate() {
            let Some(failure) = pending.post_failure.as_ref() else {
                continue;
            };
            if failure.operation.operation_id == *operation
                && failure.operation.kind == *kind
                && failure.state == *state
                && failure.worker_generation == *worker_generation
            {
                if owner.replace((index, pending.notification_id, pending.source, failure.clone())).is_some() {
                    return Err(wave_invariant(
                        "one USER POST operation is retained by multiple WAVE source rows",
                    ));
                }
            }
        }
        let (index, notification_id, source, failure) = owner.ok_or_else(|| {
            wave_invariant("WAVE terminal POST owner disappeared after exact-top preflight")
        })?;
        let ack = self.terminal_ack_for_post_failure(&failure, receipt, top)?;
        {
            let pending = self
                .wave_audio
                .pending_callbacks
                .get_mut(index)
                .ok_or_else(|| wave_invariant("WAVE terminal POST row disappeared"))?;
            if pending.notification_id != notification_id
                || pending.source != source
                || !pending
                    .post_failure
                    .as_ref()
                    .is_some_and(|current| std::sync::Arc::ptr_eq(current, &failure))
                || pending.terminal_ack.as_ref().is_some_and(|saved| saved != &ack)
            {
                return Err(wave_invariant(
                    "WAVE terminal POST ACK changed its exact retained owner",
                ));
            }
            if pending.terminal_acknowledged {
                return Err(wave_invariant(
                    "WAVE terminal POST ACK was already successful while still source-top",
                ));
            }
            if pending.terminal_ack.is_none() {
                pending.terminal_ack = Some(ack.clone());
            }
        }
        host.win16_window_terminal_ack(ack.clone())
            .map_err(|error| error.with_context("retire exact failed WAVE USER POST"))?;
        let pending = self
            .wave_audio
            .pending_callbacks
            .get_mut(index)
            .ok_or_else(|| wave_invariant("WAVE terminal POST row disappeared after ACK"))?;
        if pending.notification_id != notification_id
            || pending.source != source
            || !pending
                .post_failure
                .as_ref()
                .is_some_and(|current| std::sync::Arc::ptr_eq(current, &failure))
            || pending.terminal_ack.as_ref() != Some(&ack)
        {
            return Err(wave_invariant(
                "WAVE USER ACK receipt lost the exact source row after host ACK",
            ));
        }
        pending.terminal_acknowledged = true;
        Ok(true)
    }

    /// Complete only the exact FUNCTION receipt after guest return and the
    /// shared callback scheduler's context/resource cleanup have succeeded.
    fn finish_pending_wave_notification(
        &mut self,
        receipt: WaveCallbackReceipt,
        retirement: super::super::callback_scheduler::AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        if !retirement.source_bound
            || retirement.callback_token != receipt.callback
        {
            return Err(wave_invariant(
                "WAVE callback ACK lacks its exact source-bound scheduler retirement",
            ));
        }
        let callback_id = retirement.callback_id;
        let pending = self.wave_audio.pending_callbacks.front().ok_or_else(|| {
            wave_invariant("WAVE callback completion has no pending notification")
        })?;
        if pending.notification_id != receipt.notification_id
            || pending.source != receipt.source
            || !matches!(pending.route,
                WaveCallbackRoute::Function { callback, task }
                    if callback == receipt.callback && task == receipt.task)
            || pending.dispatch != WaveCallbackDispatchState::CallbackRunning(callback_id)
        {
            return Err(wave_invariant(
                "WAVE callback completion does not match the pending notification",
            ));
        }
        let pending = self.wave_audio.pending_callbacks.front_mut().ok_or_else(|| {
            wave_invariant("WAVE callback disappeared during completion")
        })?;
        pending.dispatch = WaveCallbackDispatchState::CallbackRetired(callback_id);
        let pending = self.wave_audio.pending_callbacks.pop_front().ok_or_else(|| {
            wave_invariant("WAVE callback disappeared during exact source ACK")
        })?;
        if let Some(device) = self.wave_audio.devices.iter().find(|device| {
            device.host.0 == pending.source.id
                && device.generation == pending.source.generation
        }).map(|device| device.host) {
            self.retire_unprepared_wave_header_if_idle(
                device,
                pending.source.generation,
                pending.guest_handle,
                pending.header_far,
            );
        }
        if let Some(device) = pending.closed_device {
            self.retire_quiescent_wave_device_if_idle(device);
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn finish_pending_wave_callback_retirement(
        &mut self,
        retirement: super::super::callback_scheduler::AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        if !retirement.source_bound {
            return Err(wave_invariant(
                "unbound asynchronous callback cannot acknowledge a WAVE source",
            ));
        }
        let receipt = {
            let pending = self.wave_audio.pending_callbacks.front().ok_or_else(|| {
                wave_invariant("retired WAVE callback has no exact source row")
            })?;
            let WaveCallbackRoute::Function { callback, task } = pending.route else {
                return Err(wave_invariant("retired WAVE callback source changed route"));
            };
            if pending.dispatch != WaveCallbackDispatchState::CallbackRunning(retirement.callback_id)
                || callback != retirement.callback_token
            {
                return Err(wave_invariant(
                    "retired callback identity does not match the reserved WAVE source row",
                ));
            }
            WaveCallbackReceipt {
                notification_id: pending.notification_id,
                source: pending.source,
                callback,
                task,
            }
        };
        self.finish_pending_wave_notification(
            receipt,
            retirement,
        )
    }

    pub(in crate::win16_runtime) fn prepare_wave_callback_terminal_retirement(
        &mut self,
        callback_id: CallbackFrameId,
        callback_token: crate::Win16GuestCallbackToken,
    ) -> Result<(), RuntimeError> {
        let Some(receipt) = self.wave_callback_receipt_for_frame(callback_id, callback_token)
        else {
            let Some(pending) = self.wave_audio.pending_callbacks.front() else {
                return Ok(());
            };
            if pending.dispatch == WaveCallbackDispatchState::CallbackRunning(callback_id) {
                return Err(wave_invariant(
                    "terminal WAVE frame does not match its exact function source",
                ));
            }
            return Ok(());
        };
        let proof = self
            .wave_producer_quiescence_receipt(receipt, Some(callback_id))?
            .ok_or_else(|| {
                wave_invariant(
                    "terminal WAVE callback lacks real producer-quiescence proof",
                )
            })?;
        let pending = self.wave_audio.pending_callbacks.front_mut().ok_or_else(|| {
            wave_invariant("WAVE source disappeared while caching terminal proof")
        })?;
        if pending.terminal_producer_proof.is_some_and(|cached| cached != proof) {
            return Err(wave_invariant(
                "terminal WAVE source already retains a different quiescence proof",
            ));
        }
        pending.terminal_producer_proof = Some(proof);
        Ok(())
    }

    pub(in crate::win16_runtime) fn finish_terminal_wave_callback_retirement(
        &mut self,
        retirement: super::super::callback_scheduler::AsynchronousCallbackRetirement,
    ) -> Result<bool, RuntimeError> {
        let Some(pending) = self.wave_audio.pending_callbacks.front() else {
            return Ok(false);
        };
        if pending.dispatch != WaveCallbackDispatchState::CallbackRunning(retirement.callback_id) {
            return Ok(false);
        }
        let WaveCallbackRoute::Function { callback, task } = pending.route else {
            return Err(wave_invariant(
                "terminal WAVE frame source changed away from function route",
            ));
        };
        if callback != retirement.callback_token {
            return Err(wave_invariant(
                "terminal WAVE frame callback token differs from its exact source",
            ));
        }
        if !retirement.source_bound {
            return Err(wave_invariant(
                "unbound terminal callback cannot retire a WAVE source",
            ));
        }
        let receipt = WaveCallbackReceipt {
            notification_id: pending.notification_id,
            source: pending.source,
            callback,
            task,
        };
        let proof = pending.terminal_producer_proof.ok_or_else(|| {
            wave_invariant(
                "terminal WAVE source reached retirement without cached quiescence proof",
            )
        })?;
        self.cancel_wave_callback_after_quiescence(receipt, retirement, proof)?;
        Ok(true)
    }

    fn bind_pending_wave_callback_frame(
        &mut self,
        receipt: WaveCallbackReceipt,
        callback_id: CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.wave_audio.pending_callbacks.front_mut().ok_or_else(|| {
            wave_invariant("WAVE source disappeared before callback frame binding")
        })?;
        if pending.notification_id != receipt.notification_id
            || pending.source != receipt.source
            || pending.dispatch != WaveCallbackDispatchState::Reserved
        {
            return Err(wave_invariant(
                "WAVE callback frame binding changed the exact source reservation",
            ));
        }
        pending.dispatch = WaveCallbackDispatchState::CallbackRunning(callback_id);
        Ok(())
    }

    fn retain_pending_wave_rollback(
        &mut self,
        receipt: WaveCallbackReceipt,
        callback_id: CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.wave_audio.pending_callbacks.front_mut().ok_or_else(|| {
            wave_invariant("WAVE source disappeared before pre-entry rollback retention")
        })?;
        if pending.notification_id != receipt.notification_id
            || pending.source != receipt.source
            || pending.dispatch != WaveCallbackDispatchState::Reserved
        {
            return Err(wave_invariant(
                "WAVE rollback does not match the exact reserved source row",
            ));
        }
        pending.dispatch = WaveCallbackDispatchState::RollbackRetained(callback_id);
        Ok(())
    }

    fn retain_unavailable_wave_callback(
        &mut self,
        receipt: WaveCallbackReceipt,
    ) -> Result<(), RuntimeError> {
        let pending = self.wave_audio.pending_callbacks.front_mut().ok_or_else(|| {
            wave_invariant("unavailable WAVE callback has no source row")
        })?;
        if pending.notification_id != receipt.notification_id
            || pending.source != receipt.source
            || pending.dispatch != WaveCallbackDispatchState::Reserved
        {
            return Err(wave_invariant(
                "unavailable WAVE callback does not match the exact reservation",
            ));
        }
        pending.dispatch = WaveCallbackDispatchState::CallbackUnavailable;
        Ok(())
    }

    fn rotate_pending_wave_notification(
        &mut self,
        notification_id: u64,
    ) -> Result<(), RuntimeError> {
        let pending = self.wave_audio.pending_callbacks.pop_front().ok_or_else(|| {
            wave_invariant("WAVE notification disappeared during queue rotation")
        })?;
        if pending.notification_id != notification_id {
            self.wave_audio.pending_callbacks.push_front(pending);
            return Err(wave_invariant("WAVE queue rotation changed its exact source row"));
        }
        self.wave_audio.pending_callbacks.push_back(pending);
        Ok(())
    }

    pub(in crate::win16_runtime) fn retry_wave_pre_entry_cleanup(
        &mut self,
        callback_id: CallbackFrameId,
    ) -> Result<bool, RuntimeError> {
        let Some(retirement) = self.retry_asynchronous_pre_entry_cleanup(callback_id)? else {
            return Ok(false);
        };
        if retirement.callback_id != callback_id || !retirement.source_bound {
            return Err(wave_invariant(
                "WAVE pre-entry cleanup returned an unbound or different callback identity",
            ));
        }
        let pending = self.wave_audio.pending_callbacks.front_mut().ok_or_else(|| {
            wave_invariant("pre-entry rollback lost its bound WAVE source row")
        })?;
        if !matches!(pending.route,
            WaveCallbackRoute::Function { callback, .. }
                if callback == retirement.callback_token)
        {
            return Err(wave_invariant(
                "pre-entry rollback receipt does not bind the exact WAVE source row",
            ));
        }
        match pending.dispatch {
            WaveCallbackDispatchState::RollbackRetained(id) if id == callback_id => {
                pending.dispatch = WaveCallbackDispatchState::SourceReleasePending(callback_id);
            }
            WaveCallbackDispatchState::SourceReleasePending(id) if id == callback_id => {}
            _ => return Err(wave_invariant(
                "pre-entry rollback no longer owns its exact WAVE source reservation",
            )),
        }
        self.complete_asynchronous_pre_entry_source_release(
            callback_id,
            retirement.callback_token,
        )?;
        let pending = self.wave_audio.pending_callbacks.front_mut().ok_or_else(|| {
            wave_invariant("WAVE source disappeared after exact rollback release")
        })?;
        if pending.dispatch != WaveCallbackDispatchState::SourceReleasePending(callback_id) {
            return Err(wave_invariant("WAVE rollback source-release state changed"));
        }
        pending.dispatch = WaveCallbackDispatchState::Available;
        Ok(true)
    }

    /// Release a reservation only if the callback scheduler failed before it
    /// entered guest code. The source receipt then remains queued for retry.
    pub(in crate::win16_runtime) fn release_pending_wave_notification_dispatch(
        &mut self,
        receipt: WaveCallbackReceipt,
    ) -> Result<(), RuntimeError> {
        let pending = self
            .wave_audio
            .pending_callbacks
            .front_mut()
            .ok_or_else(|| wave_invariant("WAVE callback cancellation has no pending item"))?;
        if pending.notification_id != receipt.notification_id
            || pending.source != receipt.source
            || !matches!(pending.route,
                WaveCallbackRoute::Function { callback, task }
                    if callback == receipt.callback && task == receipt.task)
            || pending.dispatch != WaveCallbackDispatchState::Reserved
        {
            return Err(wave_invariant(
                "WAVE callback cancellation does not match the active dispatch",
            ));
        }
        pending.dispatch = WaveCallbackDispatchState::Available;
        Ok(())
    }

}
