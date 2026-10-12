//! Owner-specific resource evidence required before terminal ACK.

use super::*;
use guest_core::memory::Memory;

impl Win16State {
    pub(super) fn terminal_user_operation_ack(
        &self,
        frame: &WindowOperationFrame,
        receipt: &crate::Win16WindowAbortReceipt,
    ) -> Result<Option<crate::Win16WindowTerminalAck>, RuntimeError> {
        let state = match frame.lifecycle {
            WindowOperationLifecycle::GuestOnly | WindowOperationLifecycle::NeverStarted => {
                if frame.host_operation.is_some() || frame.worker_generation.is_some()
                    || frame.native_state.is_some() || frame.terminal_started_failure.is_some()
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "guest-only or never-started Win16 operation has a native identity"));
                }
                if frame.lifecycle == WindowOperationLifecycle::NeverStarted
                    && frame.terminal_error.is_none()
                {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "never-started Win16 operation lost its exact begin failure"));
                }
                return Ok(None);
            }
            WindowOperationLifecycle::Started => crate::Win16NativeWindowOperationState::Active,
            WindowOperationLifecycle::ReturnedWithError => crate::Win16NativeWindowOperationState::Returned,
            WindowOperationLifecycle::TerminalModalCancelled => {
                crate::Win16NativeWindowOperationState::Returned
            }
            WindowOperationLifecycle::Returned => {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "normally returned USER operation must consume its source-retirement proof, not a terminal cancel ACK"));
            }
            WindowOperationLifecycle::BeginPending => {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "Win16 USER operation has no real begin outcome or retained operation identity"));
            }
        };
        let operation_id = frame.host_operation.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "started Win16 USER operation lost its exact host operation identity",
        ))?;
        let kind = frame.native_source.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "started Win16 USER operation lost its native API kind",
        ))?;
        let generation = frame.worker_generation.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "started Win16 USER operation lost its worker generation",
        ))?;
        if operation_id.0 == 0 || generation == 0 || generation != receipt.worker_generation
            || frame.native_state != Some(state)
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER operation does not match its cached native worker receipt"));
        }
        let active_count = receipt.active_operations.iter().filter(|proof| {
            proof.operation_id == operation_id && proof.kind == kind
        }).count();
        let active_for_id = receipt.active_operations.iter().filter(|proof| {
            proof.operation_id == operation_id
        }).count();
        match state {
            crate::Win16NativeWindowOperationState::Active
                if active_count == 1 && active_for_id == 1 => {}
            crate::Win16NativeWindowOperationState::Returned
                if active_for_id == 0 && frame.terminal_error.is_some() => {}
            _ => return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 terminal ACK lacks the exact active or returned native operation proof")),
        }
        match (&frame.terminal_started_failure, state) {
            (Some(failure), failure_state)
                if failure.operation.operation_id == operation_id
                    && failure.operation.kind == kind
                    && failure.worker_generation == generation
                    && failure.state == failure_state
                    && frame.terminal_error.as_ref()
                        .is_some_and(|cause| std::sync::Arc::ptr_eq(cause, &failure.cause)) => {}
            (None, crate::Win16NativeWindowOperationState::Active)
                if frame.lifecycle == WindowOperationLifecycle::Started
                    => {}
            (None, crate::Win16NativeWindowOperationState::Returned)
                if frame.lifecycle == WindowOperationLifecycle::TerminalModalCancelled
                    && frame.terminal_modal_error.is_some()
                    && receipt.cancelled_modals.iter().filter(|modal| {
                        modal.operation_id == operation_id.0
                    }).count() == 1
                    && receipt.cancelled_modals.iter().find(|modal| {
                        modal.operation_id == operation_id.0
                    }).is_some_and(|modal| frame.terminal_modal_error.as_ref()
                        .is_some_and(|error| super::modal_error_matches(error, modal))) => {}
            _ => return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 terminal operation lost its exact host-created StartedFailure payload")),
        }
        let mut callbacks = Vec::new();
        callbacks.try_reserve_exact(receipt.cancelled_callbacks.iter().filter(|item| {
            item.operation_id == operation_id
        }).count()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact terminal USER callback ACKs",
            error,
        ))?;
        callbacks.extend(receipt.cancelled_callbacks.iter().copied().filter(|item| {
            item.operation_id == operation_id
        }));
        if callbacks.len() != frame.terminal_retired_callbacks.len() {
            return Err(RuntimeError::new(Kind::HostFailure,
                "native callback receipt lacks one cached guest-frame retirement proof per source"));
        }
        for cancellation in &callbacks {
            let mut proofs = frame.terminal_retired_callbacks.iter().filter(|proof| {
                proof.cancellation == *cancellation
            });
            let Some(proof) = proofs.next() else {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native callback source has no exact cached retirement proof"));
            };
            if proofs.next().is_some()
                || !proof.guest_payload_cleaned
                || !proof.runtime_frame_retired
                || proof.owner_context_restored != frame.terminal_context_restored
                || proof.native_source_acknowledged != frame.terminal_source_acknowledged
            {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "callback terminal proof has an incomplete or mismatched retirement phase"));
            }
        }
        let mut modals = Vec::new();
        modals.try_reserve_exact(receipt.cancelled_modals.iter().filter(|item| {
            item.operation_id == operation_id.0
        }).count()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact terminal USER modal ACKs",
            error,
        ))?;
        modals.extend(receipt.cancelled_modals.iter().filter(|item| {
            item.operation_id == operation_id.0
        }).cloned());
        if callbacks.len() > 1 || modals.len() > 1
            || frame.terminal_modal_responses != modals
            || frame.host_modal_operation.is_some_and(|bound| bound != operation_id)
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 terminal callback or modal slots differ from the exact operation proof"));
        }
        let expected_modal_work = frame.pending_modal_work.as_ref()
            .map(|work| work.terminal_retirement()).transpose()?.flatten();
        if let Some(modal) = modals.first() {
            match expected_modal_work {
                Some(work) if modal.retired_guest_work.as_slice() == [work]
                    && modal.scope_id == Some(work.scope_id) => {}
                None if modal.retired_guest_work.is_empty() => {}
                _ => return Err(RuntimeError::new(Kind::HostFailure,
                    "terminal modal ACK does not retire the exact parked guest-work identity")),
            }
        } else if frame.pending_modal_work.is_some() {
            return Err(RuntimeError::new(Kind::HostFailure,
                "parked Win16 modal work has no native terminal response slot"));
        }
        Ok(Some(crate::Win16WindowTerminalAck {
            worker_generation: generation,
            operation: crate::Win16NativeWindowOperationProof { operation_id, kind },
            state,
            callbacks,
            modals,
        }))
    }

    pub(super) fn retire_terminal_window_operation_resources(
        &mut self,
        frame_id: u64,
        _memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 terminal resource cleanup lost its exact top frame"))?;
        let resource = match frame.continuation() {
            Some(WindowReturn::ShellExecution(continuation)) => {
                continuation.terminal_external_application().map(|(identity, kind)| {
                    TerminalWindowResource::Shell { identity, kind }
                })
            }
            Some(WindowReturn::CommonDialog(continuation)) => continuation
                .terminal_find_replace_request_id()
                .map(TerminalWindowResource::FindReplace),
            Some(WindowReturn::Paint { guest_dc_reserved, .. })
            | Some(WindowReturn::AcquireWindowDc { guest_dc_reserved, .. }) =>
                self.terminal_acquisition_resource(frame, *guest_dc_reserved)?,
            Some(WindowReturn::EndPaint { guest_dc, native_dc })
            | Some(WindowReturn::ReleaseWindowDc { guest_dc, native_dc }) => {
                self.terminal_dc_retirement_resource(frame, *guest_dc, *native_dc)?
            }
            Some(WindowReturn::CleanupPaint { guest_dc_reserved, native_dc, .. })
            | Some(WindowReturn::CleanupWindowDc { guest_dc_reserved, native_dc, .. }) =>
                self.terminal_compensation_resource(
                    frame, *guest_dc_reserved, *native_dc,
                )?,
            _ => None,
        };
        let lifecycle = frame.lifecycle;
        match resource {
            Some(TerminalWindowResource::Shell { identity, kind }) => {
                self.rollback_external_application(identity, kind)
            }
            Some(TerminalWindowResource::FindReplace(request_id)) => {
                self.cancel_find_replace(request_id)
            }
            Some(TerminalWindowResource::ReservedDc(handle)) => {
                self.retire_terminal_reserved_dc(frame_id, handle, lifecycle)
            }
            Some(TerminalWindowResource::CompensationDc { guest, native }) => {
                self.retire_terminal_compensation_dc(frame_id, guest, native)
            }
            None => Ok(()),
        }
    }

    fn retire_terminal_compensation_dc(
        &mut self,
        frame_id: u64,
        expected_guest: u16,
        expected_native: crate::Win16HostDc,
    ) -> Result<(), RuntimeError> {
        let Self { window_operations, guest_gdi, .. } = self;
        let frame = window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 terminal compensation lost its exact top frame"))?;
        let completion = frame.completion.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 terminal compensation lost its exact completion journal",
        ))?;
        match (&completion.continuation, &mut completion.journal.projection) {
            (
                WindowReturn::CleanupPaint {
                    guest_dc_reserved, native_dc, ..
                },
                WindowProjectionJournal::Api(WindowApiProjectionJournal::CleanupPaint(owner)),
            ) if *guest_dc_reserved == expected_guest && *native_dc == expected_native => {
                super::completion_gdi::retire_dc_compensation_resources(
                    *guest_dc_reserved, owner, guest_gdi,
                )
            }
            (
                WindowReturn::CleanupWindowDc {
                    guest_dc_reserved, native_dc, ..
                },
                WindowProjectionJournal::Api(WindowApiProjectionJournal::CleanupWindowDc(owner)),
            ) if *guest_dc_reserved == expected_guest && *native_dc == expected_native => {
                super::completion_gdi::retire_dc_compensation_resources(
                    *guest_dc_reserved, owner, guest_gdi,
                )
            }
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 terminal compensation no longer matches its exact return and journal")),
        }
    }

    fn terminal_acquisition_resource(
        &self,
        frame: &WindowOperationFrame,
        guest_dc: u16,
    ) -> Result<Option<TerminalWindowResource>, RuntimeError> {
        let Some(completion) = frame.completion.as_ref() else {
            return if frame.lifecycle == WindowOperationLifecycle::NeverStarted {
                Ok(Some(TerminalWindowResource::ReservedDc(guest_dc)))
            } else {
                Err(RuntimeError::new(Kind::HostFailure,
                    "terminal Win16 HDC acquisition has no returned native result"))
            };
        };

        match (&completion.continuation, &completion.result, &completion.journal.projection) {
            (
                WindowReturn::Paint { guest_dc_reserved, .. },
                crate::Win16WindowResult::Paint { acquired: None },
                WindowProjectionJournal::Api(WindowApiProjectionJournal::Paint(owner)),
            ) if *guest_dc_reserved == guest_dc => match owner.phase {
                super::operation_frame::PaintProjectionPhase::Ready =>
                    Ok(Some(TerminalWindowResource::ReservedDc(guest_dc))),
                super::operation_frame::PaintProjectionPhase::ReturnReady
                | super::operation_frame::PaintProjectionPhase::Complete
                    if owner.value == Some(0) => Ok(None),
                _ => Err(RuntimeError::new(Kind::InternalInvariant,
                    "BeginPaint no-HDC result has an inconsistent exact projection phase")),
            },
            (
                WindowReturn::AcquireWindowDc { guest_dc_reserved, .. },
                crate::Win16WindowResult::WindowDc(None),
                WindowProjectionJournal::Api(
                    WindowApiProjectionJournal::AcquireWindowDc(owner),
                ),
            ) if *guest_dc_reserved == guest_dc => match owner.phase {
                super::operation_frame::DcAcquisitionProjectionPhase::Ready =>
                    Ok(Some(TerminalWindowResource::ReservedDc(guest_dc))),
                super::operation_frame::DcAcquisitionProjectionPhase::ReturnReady
                | super::operation_frame::DcAcquisitionProjectionPhase::Complete
                    if owner.guest_dc == Some(0) => Ok(None),
                _ => Err(RuntimeError::new(Kind::InternalInvariant,
                    "GetDC no-HDC result has an inconsistent exact projection phase")),
            },
            (
                WindowReturn::Paint { guest_dc_reserved, .. },
                crate::Win16WindowResult::Paint { acquired: Some((native, _)) },
                WindowProjectionJournal::Api(WindowApiProjectionJournal::Paint(owner)),
            ) if *guest_dc_reserved == guest_dc => {
                match owner.phase {
                    super::operation_frame::PaintProjectionPhase::DcLeaseCommitted
                    | super::operation_frame::PaintProjectionPhase::ReturnReady
                    | super::operation_frame::PaintProjectionPhase::Complete
                        if self.guest_gdi.dc(guest_dc) == Some(*native) => {}
                    super::operation_frame::PaintProjectionPhase::Ready
                    | super::operation_frame::PaintProjectionPhase::GuestOutputCommitted
                        if self.guest_gdi.contains_handle(guest_dc)
                            && self.guest_gdi.dc(guest_dc).is_none() => {}
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "BeginPaint native HDC no longer matches its projection and guest owner")),
                }
                Err(RuntimeError::new(Kind::HostFailure,
                    "task ended with a live BeginPaint HDC and no exact EndPaint result"))
            }
            (
                WindowReturn::AcquireWindowDc { guest_dc_reserved, .. },
                crate::Win16WindowResult::WindowDc(Some(native)),
                WindowProjectionJournal::Api(
                    WindowApiProjectionJournal::AcquireWindowDc(owner),
                ),
            ) if *guest_dc_reserved == guest_dc => {
                match owner.phase {
                    super::operation_frame::DcAcquisitionProjectionPhase::NativeDcBound
                    | super::operation_frame::DcAcquisitionProjectionPhase::ReturnReady
                    | super::operation_frame::DcAcquisitionProjectionPhase::Complete
                        if self.guest_gdi.dc(guest_dc) == Some(*native) => {}
                    super::operation_frame::DcAcquisitionProjectionPhase::Ready
                        if self.guest_gdi.contains_handle(guest_dc)
                            && self.guest_gdi.dc(guest_dc).is_none() => {}
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "GetDC native HDC no longer matches its projection and guest owner")),
                }
                Err(RuntimeError::new(Kind::HostFailure,
                    "task ended with a live window HDC and no exact ReleaseDC result"))
            }
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal HDC acquisition lost its exact result or projection journal")),
        }
    }

    fn terminal_dc_retirement_resource(
        &self,
        frame: &WindowOperationFrame,
        guest_dc: u16,
        native_dc: crate::Win16HostDc,
    ) -> Result<Option<TerminalWindowResource>, RuntimeError> {
        let Some(completion) = frame.completion.as_ref() else {
            return Err(RuntimeError::new(Kind::HostFailure,
                "terminal HDC retirement has no exact native result"));
        };
        let retired = match (
            &completion.continuation,
            &completion.result,
            &completion.journal.projection,
        ) {
            (
                WindowReturn::EndPaint { guest_dc: guest, native_dc: native },
                crate::Win16WindowResult::PaintEnded(true),
                WindowProjectionJournal::Api(WindowApiProjectionJournal::EndPaint(owner)),
            ) if *guest == guest_dc && *native == native_dc
                && owner.value == Some(1)
                && matches!(owner.phase,
                    super::operation_frame::DcRetirementProjectionPhase::GuestLeaseRetired
                    | super::operation_frame::DcRetirementProjectionPhase::ReturnReady
                    | super::operation_frame::DcRetirementProjectionPhase::Complete) => true,
            (
                WindowReturn::ReleaseWindowDc { guest_dc: guest, native_dc: native },
                crate::Win16WindowResult::DcReleased(true),
                WindowProjectionJournal::Api(
                    WindowApiProjectionJournal::ReleaseWindowDc(owner),
                ),
            ) if *guest == guest_dc && *native == native_dc
                && owner.value == Some(1)
                && matches!(owner.phase,
                    super::operation_frame::DcRetirementProjectionPhase::GuestLeaseRetired
                    | super::operation_frame::DcRetirementProjectionPhase::ReturnReady
                    | super::operation_frame::DcRetirementProjectionPhase::Complete) => true,
            _ => false,
        };
        if retired { Ok(None) } else {
            Err(RuntimeError::new(Kind::HostFailure,
                "terminal HDC owner has no exact successful EndPaint or ReleaseDC projection"))
        }
    }

    fn terminal_compensation_resource(
        &self,
        frame: &WindowOperationFrame,
        guest_dc: u16,
        native_dc: crate::Win16HostDc,
    ) -> Result<Option<TerminalWindowResource>, RuntimeError> {
        let Some(completion) = frame.completion.as_ref() else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal HDC compensation lost its exact second-stage completion"));
        };
        let phase = match (&completion.continuation, &completion.journal.projection) {
            (
                WindowReturn::CleanupPaint {
                    guest_dc_reserved, native_dc: native, ..
                },
                WindowProjectionJournal::Api(WindowApiProjectionJournal::CleanupPaint(owner)),
            ) if *guest_dc_reserved == guest_dc && *native == native_dc => owner.phase,
            (
                WindowReturn::CleanupWindowDc {
                    guest_dc_reserved, native_dc: native, ..
                },
                WindowProjectionJournal::Api(
                    WindowApiProjectionJournal::CleanupWindowDc(owner),
                ),
            ) if *guest_dc_reserved == guest_dc && *native == native_dc => owner.phase,
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal HDC cleanup owner differs from its exact completion journal")),
        };
        match phase {
            super::operation_frame::CompensationProjectionPhase::NativeCleanupRetired =>
                Ok(Some(TerminalWindowResource::CompensationDc {
                    guest: guest_dc,
                    native: native_dc,
                })),
            super::operation_frame::CompensationProjectionPhase::GuestLeaseRetired
            | super::operation_frame::CompensationProjectionPhase::Complete => Ok(None),
            super::operation_frame::CompensationProjectionPhase::Ready
            | super::operation_frame::CompensationProjectionPhase::NativeCleanupPending =>
                Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "task ended before the exact USER-worker HDC cleanup result was consumed",
                    std::sync::Arc::clone(match &completion.journal.projection {
                        WindowProjectionJournal::Api(
                            WindowApiProjectionJournal::CleanupPaint(owner),
                        ) => &owner.original_cause,
                        WindowProjectionJournal::Api(
                            WindowApiProjectionJournal::CleanupWindowDc(owner),
                        ) => &owner.original_cause,
                        _ => unreachable!(),
                    }),
                )),
        }
    }

    fn retire_terminal_reserved_dc(
        &mut self,
        frame_id: u64,
        guest_dc: u16,
        lifecycle: WindowOperationLifecycle,
    ) -> Result<(), RuntimeError> {
        let Self { window_operations, guest_gdi, .. } = self;
        let frame = window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "terminal reserved HDC lost its exact top frame"))?;
        let Some(completion) = frame.completion.as_mut() else {
            if lifecycle != WindowOperationLifecycle::NeverStarted {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "terminal HDC reservation has no exact no-acquisition result"));
            }
            return if guest_gdi.cancel_dc(guest_dc) {
                Ok(())
            } else {
                Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 terminal USER operation lost its exact reserved HDC"))
            };
        };
        match (
            &completion.continuation,
            &completion.result,
            &mut completion.journal.projection,
        ) {
            (
                WindowReturn::Paint { guest_dc_reserved, .. },
                crate::Win16WindowResult::Paint { acquired: None },
                WindowProjectionJournal::Api(WindowApiProjectionJournal::Paint(owner)),
            ) if *guest_dc_reserved == guest_dc => {
                if owner.phase == super::operation_frame::PaintProjectionPhase::Ready {
                    if !guest_gdi.cancel_dc(guest_dc) {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "terminal BeginPaint cannot retire its exact reserved HDC"));
                    }
                    owner.value = Some(0);
                    owner.phase = super::operation_frame::PaintProjectionPhase::Complete;
                } else if owner.value != Some(0) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "terminal BeginPaint reservation has no exact cancellation phase"));
                }
                Ok(())
            }
            (
                WindowReturn::AcquireWindowDc { guest_dc_reserved, .. },
                crate::Win16WindowResult::WindowDc(None),
                WindowProjectionJournal::Api(
                    WindowApiProjectionJournal::AcquireWindowDc(owner),
                ),
            ) if *guest_dc_reserved == guest_dc => {
                if owner.phase == super::operation_frame::DcAcquisitionProjectionPhase::Ready {
                    if !guest_gdi.cancel_dc(guest_dc) {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "terminal GetDC cannot retire its exact reserved HDC"));
                    }
                    owner.guest_dc = Some(0);
                    owner.phase = super::operation_frame::DcAcquisitionProjectionPhase::Complete;
                } else if owner.guest_dc != Some(0) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "terminal GetDC reservation has no exact cancellation phase"));
                }
                Ok(())
            }
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal reserved HDC has no exact no-native-HDC completion")),
        }
    }

    pub(super) fn retain_operation_failure<T>(
        &mut self,
        frame_id: u64,
        error: RuntimeError,
    ) -> Result<T, RuntimeError> {
        let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 terminal error lost its exact retained top operation"))?;
        let latest = std::sync::Arc::new(error);
        let original = frame.terminal_error.as_ref().or_else(||
            frame.dde_completion.as_ref().and_then(|journal| journal.first_cause.as_ref()));
        let combined = match original {
            Some(original) => RuntimeError::with_source(
                original.kind(),
                "Win16 terminal operation retained its original typed failure",
                std::sync::Arc::clone(original),
            ).with_cleanup(
                "Win16 terminal operation cleanup or acknowledgement remains pending",
                RuntimeError::with_source(
                    latest.kind(),
                    "latest typed Win16 terminal cleanup failure",
                    std::sync::Arc::clone(&latest),
                ),
            ),
            None => RuntimeError::with_source(
                latest.kind(),
                "Win16 terminal operation retained its retryable typed failure",
                std::sync::Arc::clone(&latest),
            ),
        };
        frame.terminal_retained_error = Some(latest);
        Err(combined)
    }

}

enum TerminalWindowResource {
    Shell {
        identity: u16,
        kind: super::super::external_application::ExternalApplicationKind,
    },
    FindReplace(u64),
    ReservedDc(u16),
    CompensationDc {
        guest: u16,
        native: crate::Win16HostDc,
    },
}
