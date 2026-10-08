//! Notification delivery and task-level MCI retirement.

use super::{Win16MciFinishPhase, Win16MciState, Win16State};
#[path = "win16_mci_lifecycle_receipts.rs"]
mod receipts;
use receipts::{
    all_requested_owners_confirmed, apply_confirmed_mci_retirements, missing_owners,
    owners_in_request, quiescence_failure, retained_receipt, try_clone_request,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMciActiveYield,
    Win16HostMciQuiesceRequest, Win16HostMciQuiescenceEvidence,
    Win16HostMciQuiescenceStatus,
    Win16HostMciYieldRegistration,
};

impl Win16MciState {
    pub(in crate::win16_runtime) fn callback_producers_stopped(&self) -> bool {
        self.producer_quiescence_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.producers_stopped())
    }

    pub(in crate::win16_runtime) fn native_sources_quiescent(&self) -> bool {
        self.devices.values().all(|device| device.closed)
            && self.active.is_empty() && self.orphan_devices.is_empty()
            && self.pending_cleanup.is_empty() && self.yield_procedures.is_empty()
            && self.driver_data.is_empty() && self.reserved_guest_ids.is_empty()
            && self.pending_begin.is_none() && self.pending_notification.is_none()
            && self.completed_yields.is_empty() && self.completed_operations.is_empty()
            && self.retired_yield_sources.is_empty() && self.quiescence_causes.is_empty()
            && self.producer_quiescence_receipt.as_ref().is_none_or(|receipt| receipt.producers_stopped())
    }
}

impl Win16State {
    pub(in crate::win16_runtime) fn mci_code_references(
        &self,
    ) -> Result<Vec<u32>, RuntimeError> {
        let callback_refs = self
            .mci
            .active
            .iter()
            .filter(|frame| frame.active_call.is_some())
            .count()
            .saturating_add(
                self.mci
                    .pending_cleanup
                    .iter()
                    .filter(|pending| pending.continuation.active_call.is_some())
                    .count(),
            )
            .saturating_mul(2);
        let base_refs = self
            .mci
            .yield_procedures
            .len()
            .saturating_add(self.mci.active.len().saturating_mul(2))
            .saturating_add(self.mci.pending_cleanup.len().saturating_mul(2))
            .saturating_add(usize::from(self.mci.pending_begin.is_some()).saturating_mul(2));
        let capacity = base_refs.saturating_add(callback_refs);
        let mut references = Vec::new();
        references.try_reserve_exact(capacity).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MCI guest-code roots before module retirement",
                error,
            )
        })?;
        references.extend(
            self.mci
                .yield_procedures
                .values()
                .map(|entry| entry.procedure),
        );
        for frame in &self.mci.active {
            references.push(frame.caller_code);
            references.push((u32::from(frame.return_to.0) << 16) | u32::from(frame.return_to.1));
            if let Some(active_call) = &frame.active_call {
                references.extend(active_call.code_references());
            }
        }
        for pending in &self.mci.pending_cleanup {
            references.push(pending.continuation.caller_code);
            references.push(
                (u32::from(pending.continuation.return_to.0) << 16)
                    | u32::from(pending.continuation.return_to.1),
            );
            if let Some(active_call) = &pending.continuation.active_call {
                references.extend(active_call.code_references());
            }
        }
        if let Some(pending) = &self.mci.pending_begin {
            references.push(pending.caller_code);
            references.push(
                (u32::from(pending.return_to.0) << 16) | u32::from(pending.return_to.1),
            );
        }
        Ok(references)
    }

    pub(in crate::win16_runtime) fn close_mci_runtime(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.quiesce_mci_producers(host)?;
        if self.window_abort_receipt.is_some() {
            if !self.retire_mci_notifications_after_windows_abort(host)? {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "MCI notification still awaits its exact USER terminal source ACK",
                ));
            }
            if self.mci.pending_notification.is_some()
                || host.win16_mci_peek_notification()?.is_some()
            {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "MCI notification retains its exact event/source owner until the target retires",
                ));
            }
        } else {
            loop {
                if self.mci.pending_notification.is_none()
                    && host.win16_mci_peek_notification()?.is_none()
                {
                    break;
                }
                self.poll_mci_notification(host)?;
                if self.mci.pending_notification.is_some() {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "MCI notification still owns its exact USER/MCI source chain; native quiescence is deferred",
                    ));
                }
            }
        }
        let request = self.mci_quiesce_request()?;
        let cause_capacity = request
            .devices
            .len()
            .saturating_add(request.registrations.len())
            .saturating_add(request.active_yields.len())
            .saturating_add(request.active_yields.len())
            .saturating_add(request.returned_yields.len())
            .saturating_add(request.completed_operations.len())
            .max(1);
        self.mci.quiescence_causes.try_reserve(cause_capacity).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve cumulative MCI quiescence causes before native retirement",
                error,
            )
        })?;
        self.mci
            .retired_yield_sources
            .try_reserve(request.registrations.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact retired yield-source history before host quiescence",
                    error,
                )
            })?;
        self.mci
            .resolved_finish_causes
            .try_reserve(
                request
                    .resolved_causes
                    .len()
                    .saturating_add(request.registrations.len())
                    .saturating_add(self.mci.quiescence_causes.len()),
            )
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve resolved MCI phase evidence before native quiescence",
                    error,
                )
            })?;
        let host_request = try_clone_request(&request)?;
        let mut receipt = match host.win16_mci_quiesce_owned(host_request) {
            Ok(receipt) => receipt,
            Err(error) => {
                let receipt = retained_receipt(request, error)?;
                self.mci.quiescence_causes.extend(receipt.causes.iter().cloned());
                return Err(quiescence_failure(receipt));
            }
        };
        let exact_request = receipt.request == request;
        if !exact_request {
            let mismatch = RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI quiescence receipt changed the requested exact owner identities",
            );
            receipt.causes.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact-request mismatch cause in native MCI receipt",
                    error,
                )
            })?;
            receipt.causes.push(std::sync::Arc::new(mismatch));
            receipt.status = Win16HostMciQuiescenceStatus::Retained;
            receipt.request = try_clone_request(&request)?;
            receipt.confirmed.clear();
            receipt.retained = owners_in_request(&request)?;
        }
        self.mci.quiescence_causes.try_reserve(receipt.causes.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI receipt history before applying retirements",
                error,
            )
        })?;

        if exact_request {
            apply_confirmed_mci_retirements(self, &receipt);
            for cause in &receipt.resolved_causes {
                if !self
                    .mci
                    .resolved_finish_causes
                    .iter()
                    .any(|existing| std::sync::Arc::ptr_eq(existing, cause))
                {
                    self.mci.resolved_finish_causes.push(std::sync::Arc::clone(cause));
                }
            }
        }
        let request_is_empty = request.devices.is_empty()
            && request.registrations.is_empty()
            && request.pending_begins.is_empty()
            && request.active_yields.is_empty()
            && request.returned_yields.is_empty()
            && request.completed_operations.is_empty();
        if exact_request
            && request_is_empty
            && receipt.status == Win16HostMciQuiescenceStatus::NotStarted
            && receipt.confirmed.is_empty()
            && receipt.retained.is_empty()
            && receipt.causes.is_empty()
        {
            for cause in &receipt.resolved_causes {
                if !self
                    .mci
                    .resolved_finish_causes
                    .iter()
                    .any(|existing| std::sync::Arc::ptr_eq(existing, cause))
                {
                    self.mci.resolved_finish_causes.push(std::sync::Arc::clone(cause));
                }
            }
            self.mci.reserved_guest_ids.clear();
            self.mci.producer_quiescence_request = None;
            self.mci.producer_quiescence_receipt = None;
            return Ok(());
        }
        if receipt.status == Win16HostMciQuiescenceStatus::Quiesced
            && receipt.causes.is_empty()
            && receipt.retained.is_empty()
            && all_requested_owners_confirmed(&receipt)
        {
            self.mci.orphan_devices.retain(|device| {
                !receipt.confirmed.iter().any(|evidence| {
                    matches!(evidence, Win16HostMciQuiescenceEvidence::DeviceClosed { device: closed, native_result: 0 } if closed == device)
                })
            });
            for cause in &self.mci.quiescence_causes {
                if !self
                    .mci
                    .resolved_finish_causes
                    .iter()
                    .any(|existing| std::sync::Arc::ptr_eq(existing, cause))
                {
                    self.mci.resolved_finish_causes.push(std::sync::Arc::clone(cause));
                }
            }
            self.mci.quiescence_causes.clear();
            self.mci.reserved_guest_ids.clear();
            self.mci.producer_quiescence_request = None;
            self.mci.producer_quiescence_receipt = None;
            return Ok(());
        }

        if receipt.status == Win16HostMciQuiescenceStatus::NotStarted {
            receipt.status = Win16HostMciQuiescenceStatus::Retained;
            if receipt.retained.is_empty() {
                receipt.retained = owners_in_request(&request)?;
            }
            receipt.causes.try_reserve(1).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve missing-started MCI receipt cause",
                error,
            ))?;
            receipt.causes.push(std::sync::Arc::new(RuntimeError::new(
                Kind::CompatibilityGap,
                "native MCI owner returned NotStarted for an active resource request",
            )));
        }
        if receipt.status == Win16HostMciQuiescenceStatus::Quiesced {
            receipt.status = Win16HostMciQuiescenceStatus::Retained;
            if receipt.retained.is_empty() {
                receipt.retained = missing_owners(&receipt)?;
            }
            if receipt.retained.is_empty() {
                receipt.retained = owners_in_request(&request)?;
            }
            receipt.causes.try_reserve(1).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve incomplete-quiescence MCI receipt cause",
                error,
            ))?;
            receipt.causes.push(std::sync::Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI owner claimed quiescence without exact terminal evidence for every request",
            )));
        }
        if receipt.status == Win16HostMciQuiescenceStatus::Retained && receipt.retained.is_empty() {
            receipt.retained = missing_owners(&receipt)?;
            if receipt.retained.is_empty() {
                receipt.retained = owners_in_request(&request)?;
            }
        }
        self.mci.quiescence_causes.extend(receipt.causes.iter().cloned());
        Err(quiescence_failure(receipt))
    }

    pub(super) fn mci_quiesce_request(&self) -> Result<Win16HostMciQuiesceRequest, RuntimeError> {
        let mut request = Win16HostMciQuiesceRequest::default();
        request.devices.try_reserve_exact(
            self.mci.devices.len()
                .saturating_add(self.mci.orphan_devices.len())
                .saturating_add(self.mci.active.len().saturating_mul(5))
                .saturating_add(self.mci.pending_cleanup.len().saturating_mul(5))
                .saturating_add(self.mci.completed_yields.len())
                .saturating_add(self.mci.retired_yield_sources.len())
                .saturating_add(usize::from(self.mci.pending_begin.is_some()).saturating_mul(2)),
        ).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact Win16 MCI task device identities before quiescence",
            error,
        ))?;
        request.registrations.try_reserve_exact(
            self.mci.yield_procedures.len()
                .saturating_add(self.mci.active.len().saturating_mul(4))
                // A pending continuation can retain its current and next
                // registrations, a mismatched host yield, and an opened
                // device's registration from the exact cached result.
                .saturating_add(self.mci.pending_cleanup.len().saturating_mul(4))
                .saturating_add(self.mci.retired_yield_sources.len())
                .saturating_add(usize::from(self.mci.pending_begin.is_some())),
        ).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact Win16 MCI yield registrations before quiescence",
                error,
            )
        })?;
        request
            .pending_begins
            .try_reserve_exact(usize::from(self.mci.pending_begin.is_some()))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact pending MCI Begin owner before quiescence",
                    error,
                )
            })?;
        request.active_yields.try_reserve_exact(
            self.mci
                .active
                .len()
                .saturating_mul(3)
                .saturating_add(self.mci.pending_cleanup.len().saturating_mul(3))
                .saturating_add(usize::from(self.mci.pending_begin.is_some())),
        ).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact Win16 MCI active-yield identities before quiescence",
            error,
        ))?;
        let returned_yield_capacity = self
            .mci
            .active
            .iter()
            .map(|continuation| {
                continuation
                    .returned_yields
                    .len()
                    .saturating_add(usize::from(continuation.unexpected_step.is_some()))
            })
            .chain(
                self.mci
                    .pending_cleanup
                    .iter()
                    .map(|pending| {
                        pending
                            .continuation
                            .returned_yields
                            .len()
                            .saturating_add(usize::from(pending.unexpected_step.is_some()))
                    }),
            )
            .fold(self.mci.completed_yields.len(), usize::saturating_add);
        request.returned_yields.try_reserve_exact(returned_yield_capacity).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact returned MCI yield proofs before quiescence",
                error,
            )
        })?;
        request
            .completed_operations
            .try_reserve_exact(
                self.mci
                    .pending_cleanup
                    .len()
                    .saturating_mul(2)
                    .saturating_add(self.mci.active.len().saturating_mul(2))
                    .saturating_add(usize::from(self.mci.pending_begin.is_some()))
                    .saturating_add(self.mci.completed_operations.len()),
            )
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact completed MCI operation proofs before quiescence",
                    error,
                )
            })?;
        let resolved_cause_capacity = self.mci.resolved_finish_causes.len();
        request
            .resolved_causes
            .try_reserve_exact(resolved_cause_capacity)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve cumulative MCI typed cause history before quiescence",
                    error,
                )
            })?;
        request
            .resolved_causes
            .extend(self.mci.resolved_finish_causes.iter().cloned());
        request
            .returned_yields
            .extend(self.mci.completed_yields.iter().copied());
        request
            .completed_operations
            .extend(self.mci.completed_operations.iter().copied());
        for returned in &self.mci.completed_yields {
            if !request.devices.contains(&returned.owner.device) {
                request.devices.push(returned.owner.device);
            }
        }
        for entry in self.mci.devices.values().filter(|entry| !entry.closed) {
            if !request.devices.contains(&entry.host) {
                request.devices.push(entry.host);
            }
        }
        for source in &self.mci.retired_yield_sources {
            if !request.registrations.contains(source) {
                request.registrations.push(*source);
            }
            if !request.devices.contains(&source.device) {
                request.devices.push(source.device);
            }
        }
        for device in &self.mci.orphan_devices {
            if !request.devices.contains(device) {
                request.devices.push(*device);
            }
        }
        for pending in &self.mci.pending_cleanup {
            if let Some(result) = &pending.continuation.completed_result {
                match &result.output {
                    crate::Win16HostMciOutput::Device { device, .. } => {
                        if !request.devices.contains(device) {
                            request.devices.push(*device);
                        }
                    }
                    crate::Win16HostMciOutput::StringCommand { opened, closed, .. } => {
                        if let Some((device, _)) = opened
                            && !request.devices.contains(device)
                        {
                            request.devices.push(*device);
                        }
                        if let Some(device) = closed
                            && !request.devices.contains(device)
                        {
                            request.devices.push(*device);
                        }
                    }
                    _ => {}
                }
                let proof = crate::Win16HostMciOperationCompletion {
                    operation: pending.continuation.operation,
                    native_return_value: result.return_value,
                };
                if !request.completed_operations.contains(&proof) {
                    request.completed_operations.push(proof);
                }
            }
            if let Some(unexpected) = &pending.unexpected_step {
                if !request
                    .returned_yields
                    .contains(&unexpected.returned_yield)
                {
                    request.returned_yields.push(unexpected.returned_yield);
                }
                match &unexpected.step {
                    crate::Win16HostMciStep::Yield(event) => {
                        if !request.devices.contains(&event.device) {
                            request.devices.push(event.device);
                        }
                        let registration = Win16HostMciYieldRegistration {
                            device: event.device,
                            registration: event.registration,
                        };
                        if !request.registrations.contains(&registration) {
                            request.registrations.push(registration);
                        }
                        let active = Win16HostMciActiveYield {
                            operation: event.operation,
                            frame: event.frame,
                            device: event.device,
                        };
                        if !request.active_yields.contains(&active) {
                            request.active_yields.push(active);
                        }
                    }
                    crate::Win16HostMciStep::Complete(result) => {
                        let proof = crate::Win16HostMciOperationCompletion {
                            operation: pending.continuation.operation,
                            native_return_value: result.return_value,
                        };
                        if !request.completed_operations.contains(&proof) {
                            request.completed_operations.push(proof);
                        }
                    }
                }
            }
        }
        for (device, procedure) in &self.mci.yield_procedures {
            request.registrations.push(Win16HostMciYieldRegistration {
                device: *device,
                registration: procedure.registration,
            });
        }
        for continuation in self.mci.active.iter().chain(
            self.mci.pending_cleanup.iter().map(|pending| &pending.continuation),
        ) {
            if !request.devices.contains(&continuation.event.device) {
                request.devices.push(continuation.event.device);
            }
            let registration = Win16HostMciYieldRegistration {
                device: continuation.event.device,
                registration: continuation.event.registration,
            };
            if !request.registrations.contains(&registration) {
                request.registrations.push(registration);
            }
            if let Some(next_event) = continuation.next_event {
                if !request.devices.contains(&next_event.device) {
                    request.devices.push(next_event.device);
                }
                let next_registration = Win16HostMciYieldRegistration {
                    device: next_event.device,
                    registration: next_event.registration,
                };
                if !request.registrations.contains(&next_registration) {
                    request.registrations.push(next_registration);
                }
                let next_owner = Win16HostMciActiveYield {
                    operation: next_event.operation,
                    frame: next_event.frame,
                    device: next_event.device,
                };
                if !request.active_yields.contains(&next_owner) {
                    request.active_yields.push(next_owner);
                }
            }
            if !matches!(
                continuation.finish_phase,
                Win16MciFinishPhase::PreEntryPending
                    | Win16MciFinishPhase::PreEntryAborted
                    | Win16MciFinishPhase::GuestCallback
                    | Win16MciFinishPhase::GuestReturnValidation
                    | Win16MciFinishPhase::RestoreCaller
                    | Win16MciFinishPhase::ResumeNative
                    | Win16MciFinishPhase::EnterNextCallback
                    | Win16MciFinishPhase::UnexpectedHostStep
            ) {
                continue;
            }
            let owner = Win16HostMciActiveYield {
                operation: continuation.event.operation,
                frame: continuation.event.frame,
                device: continuation.event.device,
            };
            if !request.active_yields.contains(&owner) {
                request.active_yields.push(owner);
            }
            for returned in &continuation.returned_yields {
                if !request.returned_yields.contains(returned) {
                    request.returned_yields.push(*returned);
                }
            }
            if let Some(result) = &continuation.completed_result {
                match &result.output {
                    crate::Win16HostMciOutput::Device { device, .. } => {
                        if !request.devices.contains(device) {
                            request.devices.push(*device);
                        }
                    }
                    crate::Win16HostMciOutput::StringCommand { opened, closed, .. } => {
                        if let Some((device, _)) = opened
                            && !request.devices.contains(device)
                        {
                            request.devices.push(*device);
                        }
                        if let Some(device) = closed
                            && !request.devices.contains(device)
                        {
                            request.devices.push(*device);
                        }
                        if let Some((device, _)) = opened {
                            let registration = self
                                .mci
                                .yield_procedures
                                .get(device)
                                .map(|procedure| Win16HostMciYieldRegistration {
                                    device: *device,
                                    registration: procedure.registration,
                                });
                            if let Some(registration) = registration
                                && !request.registrations.contains(&registration)
                            {
                                request.registrations.push(registration);
                            }
                        }
                    }
                    _ => {}
                }
                let proof = crate::Win16HostMciOperationCompletion {
                    operation: continuation.operation,
                    native_return_value: result.return_value,
                };
                if !request.completed_operations.contains(&proof) {
                    request.completed_operations.push(proof);
                }
            }
            if let Some(unexpected) = &continuation.unexpected_step {
                if !request.returned_yields.contains(&unexpected.returned_yield) {
                    request.returned_yields.push(unexpected.returned_yield);
                }
                match &unexpected.step {
                    crate::Win16HostMciStep::Yield(event) => {
                        if !request.devices.contains(&event.device) {
                            request.devices.push(event.device);
                        }
                        let registration = Win16HostMciYieldRegistration {
                            device: event.device,
                            registration: event.registration,
                        };
                        if !request.registrations.contains(&registration) {
                            request.registrations.push(registration);
                        }
                        let active = Win16HostMciActiveYield {
                            operation: event.operation,
                            frame: event.frame,
                            device: event.device,
                        };
                        if !request.active_yields.contains(&active) {
                            request.active_yields.push(active);
                        }
                    }
                    crate::Win16HostMciStep::Complete(result) => {
                        let proof = crate::Win16HostMciOperationCompletion {
                            operation: continuation.operation,
                            native_return_value: result.return_value,
                        };
                        if !request.completed_operations.contains(&proof) {
                            request.completed_operations.push(proof);
                        }
                    }
                }
            }
        }
        if let Some(pending) = &self.mci.pending_begin {
            request.pending_begins.push(pending.operation);
            if let Some(step) = &pending.cached_step {
                match step {
                    crate::Win16HostMciStep::Yield(event) => {
                        if !request.devices.contains(&event.device) {
                            request.devices.push(event.device);
                        }
                        let registration = Win16HostMciYieldRegistration {
                            device: event.device,
                            registration: event.registration,
                        };
                        if !request.registrations.contains(&registration) {
                            request.registrations.push(registration);
                        }
                        let active = Win16HostMciActiveYield {
                            operation: event.operation,
                            frame: event.frame,
                            device: event.device,
                        };
                        if !request.active_yields.contains(&active) {
                            request.active_yields.push(active);
                        }
                    }
                    crate::Win16HostMciStep::Complete(result) => {
                        let proof = crate::Win16HostMciOperationCompletion {
                            operation: pending.operation,
                            native_return_value: result.return_value,
                        };
                        if !request.completed_operations.contains(&proof) {
                            request.completed_operations.push(proof);
                        }
                        match &result.output {
                            crate::Win16HostMciOutput::Device { device, .. } => {
                                if !request.devices.contains(device) {
                                    request.devices.push(*device);
                                }
                            }
                            crate::Win16HostMciOutput::StringCommand {
                                opened, closed, ..
                            } => {
                                if let Some((device, _)) = opened
                                    && !request.devices.contains(device)
                                {
                                    request.devices.push(*device);
                                }
                                if let Some(device) = closed
                                    && !request.devices.contains(device)
                                {
                                    request.devices.push(*device);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok(request)
    }
}
