//! Exact guest continuations for host COM operations.
//!
//! This journal records host progress without treating `Running`, a callback
//! frame, or an owned COM result as completion of the guest API. The USER
//! scheduler drives the safe-point methods below and performs final resource
//! reconciliation before it returns to the saved guest caller.

use std::sync::Arc;

use guest_core::{OwnerId, Registers};
use win16_abi::Win16ReturnKind;
use x86_cpu::CpuContext;

use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16ComHostCallbackCall, Win16ComHostCallbackOutcome,
    Win16ComHostCallbackReply, Win16ComHostCallbackRoute, Win16ComHostCallbackStep,
    Win16ComHostOperationIdentity, Win16ComHostOwnerIdentity, Win16ComHostRequest,
    Win16ComHostResume, Win16ComHostShutdownReceipt, Win16ComHostStart, Win16ComHostStep,
};

use super::{exhausted, invariant};
#[path = "win16_com_operation_shutdown.rs"]
mod shutdown;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(in crate::win16_runtime) struct Win16ComGuestOperationId {
    pub(in crate::win16_runtime) host: Win16ComHostOperationIdentity,
}

/// Caller label used by typed terminal conversion. It is metadata only; the
/// exact host operation identity remains the completion key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16ComOperationOrigin {
    Ole1ObjectMethod { proxy_id: u64, slot: u8 },
    Ole1Creation { client_operation: u64 },
}

#[derive(Debug)]
enum Phase {
    Prepared,
    Starting,
    Running,
    Callback(Win16ComHostCallbackStep),
    CallbackResuming {
        frame: crate::Win16ComHostCallbackFrame,
    },
    CallbackFailed {
        failure: crate::Win16ComHostCallbackFailure,
        frame: crate::Win16ComHostCallbackFrame,
    },
    StartFailed(Arc<RuntimeError>),
    Terminal(Win16ComHostStep),
    GuestReturned,
}

struct Entry {
    id: Win16ComGuestOperationId,
    owner: Win16ComHostOwnerIdentity,
    guest_owner: OwnerId,
    legacy_cpu_frame: u64,
    saved_context: CpuContext,
    saved_registers: Registers,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
    callback_route: Win16ComHostCallbackRoute,
    origin: Win16ComOperationOrigin,
    request: Option<Win16ComHostRequest>,
    phase: Phase,
    terminal_acknowledged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerShutdownPhase {
    Open,
    SealRequested,
    Sealed,
    PollRequested,
    Retired(Win16ComHostShutdownReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnerShutdownRecord {
    owner: Win16ComHostOwnerIdentity,
    phase: OwnerShutdownPhase,
}

/// One non-reusing operation sequence shared by all OLE1/COM operations in a
/// `Win16State`. Host operation generations are independent of owner
/// incarnations and increase within this journal so its STA accepts every
/// later operation.
pub(in crate::win16_runtime) struct Win16ComOperationTable {
    next_id: Option<u64>,
    next_host_operation_generation: Option<u64>,
    entries: Vec<Entry>,
    reserved_ids: Vec<Win16ComGuestOperationId>,
    owner_shutdown: Vec<OwnerShutdownRecord>,
}

impl Default for Win16ComOperationTable {
    fn default() -> Self {
        Self {
            next_id: Some(1),
            next_host_operation_generation: Some(1),
            entries: Vec::new(),
            reserved_ids: Vec::new(),
            owner_shutdown: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum StepDisposition {
    Running,
    Callback,
    CallbackFrameComplete,
    Terminal,
    CallbackFailed,
}

pub(super) enum StepRecord {
    Stored(StepDisposition),
    Unowned(Win16ComHostStep),
}

/// Phase-only view of the exact entry selected by its operation ID. Exact
/// owner, operation identity, and callback-frame matching remain in `Entry`
/// and `Phase`; this projection carries only data the safe-point consumes.
#[derive(Clone, Copy, Debug)]
pub(in crate::win16_runtime) enum Progress<'a> {
    Prepared {},
    Starting {},
    Running {},
    Callback {
        step: &'a Win16ComHostCallbackStep,
    },
    CallbackResuming {},
    CallbackFailed {
        failure: &'a crate::Win16ComHostCallbackFailure,
    },
    StartFailed {
        failure: &'a RuntimeError,
    },
    Terminal {
        step: &'a Win16ComHostStep,
    },
    GuestReturned {},
}

/// Borrowed restore data. The saved selector roots remain owned by the exact
/// legacy CPU frame until the scheduler has applied and retired this call.
pub(in crate::win16_runtime) struct GuestContinuation<'a> {
    pub(in crate::win16_runtime) guest_owner: OwnerId,
    pub(in crate::win16_runtime) legacy_cpu_frame: u64,
    pub(in crate::win16_runtime) saved_context: &'a CpuContext,
    pub(in crate::win16_runtime) saved_registers: &'a Registers,
    pub(in crate::win16_runtime) return_to: (u16, u16, u32),
    pub(in crate::win16_runtime) return_kind: Win16ReturnKind,
    pub(in crate::win16_runtime) callback_route: Win16ComHostCallbackRoute,
    pub(in crate::win16_runtime) origin: Win16ComOperationOrigin,
}

impl Win16ComOperationTable {
    /// Burn a host-call identity after ensuring that a subsequently inserted
    /// frame cannot allocate. A failed later CPU capture never makes this ID
    /// available again.
    pub(super) fn reserve_id(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<Win16ComGuestOperationId, RuntimeError> {
        if !owner.is_valid() {
            return Err(invariant("COM operation has an invalid host owner"));
        }
        self.ensure_owner_open(owner)?;
        self.remember_owner(owner)?;
        let required = self
            .entries
            .len()
            .checked_add(self.reserved_ids.len())
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| exhausted("COM operation journal size overflowed"))?;
        let additional = required.saturating_sub(self.entries.len());
        self.entries.try_reserve(additional).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 COM guest-operation continuation",
                error,
            )
        })?;
        self.reserved_ids.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 COM operation identity record",
                error,
            )
        })?;

        let numeric_id = self
            .next_id
            .ok_or_else(|| exhausted("Win16 COM operation identities are exhausted"))?;
        let next = numeric_id.checked_add(1).filter(|value| *value != 0);
        self.next_id = next;
        if numeric_id == 0 {
            return Err(exhausted("Win16 COM operation identities are exhausted"));
        }
        let generation = self
            .next_host_operation_generation
            .ok_or_else(|| exhausted("Win16 COM host operation generations are exhausted"))?;
        self.next_host_operation_generation = generation.checked_add(1).filter(|next| *next != 0);
        let id = Win16ComGuestOperationId {
            host: Win16ComHostOperationIdentity {
                id: numeric_id,
                generation,
            },
        };
        self.reserved_ids.push(id);
        Ok(id)
    }

    /// Release only the reservation record. The numeric identity stays
    /// consumed, so a failed CPU-frame capture cannot make it reusable.
    pub(super) fn cancel_reservation(
        &mut self,
        id: Win16ComGuestOperationId,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self
            .reserved_ids
            .iter()
            .position(|reserved| *reserved == id)
        else {
            return Err(invariant("COM operation reservation is not pending"));
        };
        self.reserved_ids.remove(index);
        Ok(())
    }

    pub(super) fn insert(
        &mut self,
        id: Win16ComGuestOperationId,
        owner: Win16ComHostOwnerIdentity,
        guest_owner: OwnerId,
        legacy_cpu_frame: u64,
        saved_context: CpuContext,
        saved_registers: Registers,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        callback_route: Win16ComHostCallbackRoute,
        origin: Win16ComOperationOrigin,
        request: Win16ComHostRequest,
    ) -> Result<(), RuntimeError> {
        if !id.host.is_valid()
            || !owner.is_valid()
            || legacy_cpu_frame == 0
            || callback_route.0 == 0
            || !self.reserved_ids.contains(&id)
            || self.entries.iter().any(|entry| entry.id == id)
        {
            return Err(invariant(
                "COM operation frame does not match its reserved identity",
            ));
        }
        self.ensure_owner_open(owner)?;
        let position = self
            .reserved_ids
            .iter()
            .position(|reserved| *reserved == id)
            .ok_or_else(|| invariant("COM operation identity reservation disappeared"))?;
        self.reserved_ids.remove(position);
        self.entries.push(Entry {
            id,
            owner,
            guest_owner,
            legacy_cpu_frame,
            saved_context,
            saved_registers,
            return_to,
            return_kind,
            callback_route,
            origin,
            request: Some(request),
            phase: Phase::Prepared,
            terminal_acknowledged: false,
        });
        Ok(())
    }

    pub(super) fn take_start(
        &mut self,
        id: Win16ComGuestOperationId,
    ) -> Result<Win16ComHostStart, RuntimeError> {
        let entry = self.entry_mut(id)?;
        if !matches!(&entry.phase, Phase::Prepared) {
            return Err(invariant("COM host request was started more than once"));
        }
        let request = entry
            .request
            .take()
            .ok_or_else(|| invariant("prepared COM operation lost its owned request"))?;
        entry.phase = Phase::Starting;
        Ok(Win16ComHostStart {
            operation: id.host,
            request,
        })
    }

    pub(super) fn record_start_failure(
        &mut self,
        id: Win16ComGuestOperationId,
        failure: RuntimeError,
    ) -> Result<(), RuntimeError> {
        let entry = self.entry_mut(id)?;
        if !matches!(&entry.phase, Phase::Starting) {
            return Err(invariant(
                "COM start failure has no exact starting operation",
            ));
        }
        entry.phase = Phase::StartFailed(Arc::new(failure));
        Ok(())
    }

    pub(super) fn mark_running_after_unowned_step(
        &mut self,
        id: Win16ComGuestOperationId,
    ) -> Result<(), RuntimeError> {
        let entry = self.entry_mut(id)?;
        if !matches!(&entry.phase, Phase::Starting) {
            return Err(invariant(
                "unowned COM begin step arrived outside the exact starting phase",
            ));
        }
        entry.phase = Phase::Running;
        Ok(())
    }

    pub(super) fn record_step(
        &mut self,
        id: Win16ComGuestOperationId,
        owner: Win16ComHostOwnerIdentity,
        step: Win16ComHostStep,
    ) -> Result<StepDisposition, RuntimeError> {
        let entry = self.entry_mut(id)?;
        if owner != entry.owner {
            return Err(invariant(
                "COM step arrived from a different owner incarnation",
            ));
        }
        let may_advance = matches!(
            &entry.phase,
            Phase::Starting
                | Phase::Running
                | Phase::CallbackResuming { .. }
                | Phase::CallbackFailed { .. }
        );
        match &step {
            Win16ComHostStep::Running(operation) if *operation == id.host && may_advance => {
                entry.phase = Phase::Running;
                Ok(StepDisposition::Running)
            }
            Win16ComHostStep::Callback(callback)
                if callback.parent == Some(id.host)
                    && callback.owner == entry.owner
                    && callback.route == entry.callback_route
                    && callback.has_valid_identity()
                    && may_advance =>
            {
                entry.phase = Phase::Callback(callback.clone());
                Ok(StepDisposition::Callback)
            }
            Win16ComHostStep::Complete(completion)
                if completion.operation == id.host && may_advance =>
            {
                entry.phase = Phase::Terminal(step);
                Ok(StepDisposition::Terminal)
            }
            Win16ComHostStep::OperationFailed { operation, .. }
                if *operation == id.host && may_advance =>
            {
                entry.phase = Phase::Terminal(step);
                Ok(StepDisposition::Terminal)
            }
            Win16ComHostStep::CallbackFailed {
                frame: Some(failed_frame),
                parent: Some(parent),
                owner: failed_owner,
                route,
                failure,
            } if *parent == id.host
                && *failed_owner == entry.owner
                && *route == entry.callback_route
                && match &entry.phase {
                    Phase::Callback(step) => step.frame == *failed_frame,
                    Phase::CallbackResuming { frame } => *frame == *failed_frame,
                    _ => false,
                } =>
            {
                entry.phase = Phase::CallbackFailed {
                    failure: failure.clone(),
                    frame: *failed_frame,
                };
                Ok(StepDisposition::CallbackFailed)
            }
            Win16ComHostStep::CallbackFrameComplete {
                frame,
                owner: completed_owner,
            } if *completed_owner == entry.owner
                && match &entry.phase {
                    Phase::CallbackResuming { frame: expected } => *expected == *frame,
                    Phase::CallbackFailed {
                        frame: expected, ..
                    } => *expected == *frame,
                    _ => false,
                } =>
            {
                entry.phase = Phase::Running;
                Ok(StepDisposition::CallbackFrameComplete)
            }
            _ => Err(invariant(
                "COM host step does not match the pending exact operation phase",
            )),
        }
    }

    pub(super) fn record_step_or_forward(
        &mut self,
        id: Win16ComGuestOperationId,
        owner: Win16ComHostOwnerIdentity,
        step: Win16ComHostStep,
    ) -> Result<StepRecord, RuntimeError> {
        let entry = self.entry(id)?;
        if owner != entry.owner {
            return Err(invariant(
                "COM step arrived from a different owner incarnation",
            ));
        }
        let belongs = match &step {
            Win16ComHostStep::Running(operation) => *operation == id.host,
            Win16ComHostStep::Complete(completion) => completion.operation == id.host,
            Win16ComHostStep::OperationFailed { operation, .. } => *operation == id.host,
            Win16ComHostStep::Callback(callback) => {
                if callback.owner != entry.owner || !callback.has_valid_identity() {
                    return Err(invariant(
                        "COM callback step has an invalid owner or identity",
                    ));
                }
                callback.parent == Some(id.host)
            }
            Win16ComHostStep::CallbackFrameComplete { frame, owner } => {
                if *owner != entry.owner {
                    return Err(invariant("COM callback completion has a different owner"));
                }
                matches!(
                    &entry.phase,
                    Phase::CallbackResuming { frame: expected }
                        if *expected == *frame
                ) || matches!(
                    &entry.phase,
                    Phase::CallbackFailed { frame: expected, .. }
                        if *expected == *frame
                )
            }
            Win16ComHostStep::CallbackFailed {
                frame,
                parent,
                owner,
                route,
                ..
            } => {
                if *owner != entry.owner {
                    return Err(invariant("COM callback failure has a different owner"));
                }
                if *parent == Some(id.host) {
                    if *route != entry.callback_route {
                        return Err(invariant(
                            "COM callback failure has a different exact callback route",
                        ));
                    }
                    if let Some(frame) = frame {
                        matches!(
                            &entry.phase,
                            Phase::Callback(step) if step.frame == *frame
                        ) || matches!(
                            &entry.phase,
                            Phase::CallbackResuming { frame: expected } if *expected == *frame
                        )
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        };
        if !belongs {
            return Ok(StepRecord::Unowned(step));
        }
        self.record_step(id, owner, step).map(StepRecord::Stored)
    }

    pub(super) fn prepare_callback_resume(
        &mut self,
        id: Win16ComGuestOperationId,
        resume: &Win16ComHostResume,
    ) -> Result<(), RuntimeError> {
        let entry = self.entry_mut(id)?;
        let Phase::Callback(step) = &entry.phase else {
            return Err(invariant("COM callback reply has no suspended exact frame"));
        };
        let valid_reply = match (&step.callback, &resume.outcome) {
            (_, Win16ComHostCallbackOutcome::Failed(_)) => true,
            (
                Win16ComHostCallbackCall::ClientSiteSaveObject { .. },
                Win16ComHostCallbackOutcome::Reply(
                    Win16ComHostCallbackReply::ClientSiteSaveObjectHresult(_),
                ),
            ) => true,
            (
                Win16ComHostCallbackCall::AdviseSink { .. },
                Win16ComHostCallbackOutcome::Reply(
                    Win16ComHostCallbackReply::AdviseSinkClientWord(_),
                ),
            ) => true,
            _ => false,
        };
        if resume.parent != Some(id.host)
            || resume.owner != entry.owner
            || resume.frame != step.frame
            || !valid_reply
        {
            return Err(invariant(
                "COM callback reply does not match its parent/frame/owner/result domain",
            ));
        }
        entry.phase = Phase::CallbackResuming { frame: step.frame };
        Ok(())
    }

    pub(super) fn progress(
        &self,
        id: Win16ComGuestOperationId,
    ) -> Result<Progress<'_>, RuntimeError> {
        let entry = self.entry(id)?;
        Ok(match &entry.phase {
            Phase::Prepared => Progress::Prepared {},
            Phase::Starting => Progress::Starting {},
            Phase::Running => Progress::Running {},
            Phase::Callback(step) => Progress::Callback { step },
            Phase::CallbackResuming { .. } => Progress::CallbackResuming {},
            Phase::CallbackFailed { failure, .. } => Progress::CallbackFailed { failure },
            Phase::StartFailed(failure) => Progress::StartFailed { failure },
            Phase::Terminal(step) => Progress::Terminal { step },
            Phase::GuestReturned => Progress::GuestReturned {},
        })
    }

    pub(super) fn continuation(
        &self,
        id: Win16ComGuestOperationId,
    ) -> Result<GuestContinuation<'_>, RuntimeError> {
        let entry = self.entry(id)?;
        Ok(GuestContinuation {
            guest_owner: entry.guest_owner,
            legacy_cpu_frame: entry.legacy_cpu_frame,
            saved_context: &entry.saved_context,
            saved_registers: &entry.saved_registers,
            return_to: entry.return_to,
            return_kind: entry.return_kind,
            callback_route: entry.callback_route,
            origin: entry.origin,
        })
    }

    pub(super) fn mark_guest_returned(
        &mut self,
        id: Win16ComGuestOperationId,
    ) -> Result<(), RuntimeError> {
        let entry = self.entry_mut(id)?;
        let consumed_terminal = matches!(&entry.phase, Phase::Terminal(_))
            && entry.terminal_acknowledged;
        if !consumed_terminal && !matches!(&entry.phase, Phase::StartFailed(_)) {
            return Err(invariant(
                "guest COM call was returned before consuming its exact host terminal",
            ));
        }
        entry.phase = Phase::GuestReturned;
        Ok(())
    }

    pub(super) fn terminal_ack_target(
        &self,
        id: Win16ComGuestOperationId,
    ) -> Result<(Win16ComHostOwnerIdentity, Win16ComHostOperationIdentity), RuntimeError> {
        let entry = self.entry(id)?;
        if entry.terminal_acknowledged {
            return Err(invariant("COM host terminal was acknowledged more than once"));
        }
        let operation = match &entry.phase {
            Phase::Terminal(Win16ComHostStep::Complete(completion))
                if completion.operation == id.host => completion.operation,
            Phase::Terminal(Win16ComHostStep::OperationFailed { operation, .. })
                if *operation == id.host => *operation,
            _ => {
                return Err(invariant(
                    "COM terminal acknowledgement has no exact retained terminal result",
                ));
            }
        };
        Ok((entry.owner, operation))
    }

    pub(super) fn mark_terminal_acknowledged(
        &mut self,
        id: Win16ComGuestOperationId,
    ) -> Result<(), RuntimeError> {
        let entry = self.entry_mut(id)?;
        if entry.terminal_acknowledged
            || !matches!(
                &entry.phase,
                Phase::Terminal(Win16ComHostStep::Complete(completion))
                    if completion.operation == id.host
            ) && !matches!(
                &entry.phase,
                Phase::Terminal(Win16ComHostStep::OperationFailed { operation, .. })
                    if *operation == id.host
            )
        {
            return Err(invariant(
                "COM terminal acknowledgement does not match the retained operation",
            ));
        }
        entry.terminal_acknowledged = true;
        Ok(())
    }

    pub(super) fn terminal_acknowledged(
        &self,
        id: Win16ComGuestOperationId,
    ) -> Result<bool, RuntimeError> {
        let entry = self.entry(id)?;
        Ok(matches!(entry.phase, Phase::Terminal(_)) && entry.terminal_acknowledged)
    }


    pub(super) fn pending_for_owner(&self, owner: Win16ComHostOwnerIdentity) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.owner == owner)
            .count()
    }


    pub(super) fn retire_guest_returned(
        &mut self,
        id: Win16ComGuestOperationId,
        legacy_cpu_frame: u64,
    ) -> Result<(), RuntimeError> {
        let index = self.entry_index(id)?;
        let entry = &self.entries[index];
        if !matches!(&entry.phase, Phase::GuestReturned)
            || entry.legacy_cpu_frame != legacy_cpu_frame
        {
            return Err(invariant(
                "COM caller retirement does not match its returned CPU frame",
            ));
        }
        self.entries.remove(index);
        Ok(())
    }

    /// Retire a completed typed step in a multi-step guest API. Intermediate
    /// COM requests are acknowledged individually but do not return the guest
    /// API's caller until its final step is reconciled.
    pub(super) fn retire_acknowledged_step(
        &mut self,
        id: Win16ComGuestOperationId,
        legacy_cpu_frame: u64,
    ) -> Result<(), RuntimeError> {
        let index = self.entry_index(id)?;
        let entry = &self.entries[index];
        let consumed = matches!(&entry.phase, Phase::Terminal(_))
            && entry.terminal_acknowledged;
        if entry.legacy_cpu_frame != legacy_cpu_frame
            || (!consumed && !matches!(&entry.phase, Phase::StartFailed(_)))
        {
            return Err(invariant(
                "intermediate COM step retirement does not match an acknowledged exact frame",
            ));
        }
        self.entries.remove(index);
        Ok(())
    }

    fn entry(&self, id: Win16ComGuestOperationId) -> Result<&Entry, RuntimeError> {
        let index = self.entry_index(id)?;
        Ok(&self.entries[index])
    }

    fn entry_mut(&mut self, id: Win16ComGuestOperationId) -> Result<&mut Entry, RuntimeError> {
        let index = self.entry_index(id)?;
        Ok(&mut self.entries[index])
    }

    fn entry_index(&self, id: Win16ComGuestOperationId) -> Result<usize, RuntimeError> {
        let mut matches = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.id == id);
        let index = matches
            .next()
            .map(|(index, _)| index)
            .ok_or_else(|| invariant("exact Win16 COM operation is not in the journal"))?;
        if matches.next().is_some() {
            return Err(invariant("Win16 COM operation identity is duplicated"));
        }
        Ok(index)
    }

    pub(super) fn owner(
        &self,
        id: Win16ComGuestOperationId,
    ) -> Result<Win16ComHostOwnerIdentity, RuntimeError> {
        Ok(self.entry(id)?.owner)
    }

    pub(in crate::win16_runtime) fn callback_route(
        &self,
        id: Win16ComGuestOperationId,
    ) -> Result<Win16ComHostCallbackRoute, RuntimeError> {
        Ok(self.entry(id)?.callback_route)
    }

    pub(super) fn guest_operation_for_host(
        &self,
        host: Win16ComHostOperationIdentity,
    ) -> Result<Option<Win16ComGuestOperationId>, RuntimeError> {
        let mut matches = self.entries.iter().filter(|entry| entry.id.host == host);
        let Some(entry) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(invariant(
                "COM host operation identity has duplicate or inconsistent guest ownership",
            ));
        }
        Ok(Some(entry.id))
    }

    pub(super) fn phase_summary(
        &self,
        id: Win16ComGuestOperationId,
    ) -> Result<PhaseSummary, RuntimeError> {
        let entry = self.entry(id)?;
        Ok(match &entry.phase {
            Phase::Prepared => PhaseSummary::Prepared,
            Phase::Starting => PhaseSummary::Starting,
            Phase::Running => PhaseSummary::Running(entry.owner),
            Phase::Callback(_) => PhaseSummary::CallbackPending,
            Phase::CallbackResuming { .. } => PhaseSummary::CallbackResuming,
            Phase::CallbackFailed { .. } => PhaseSummary::CallbackFailed,
            Phase::StartFailed(_) => PhaseSummary::StartFailed,
            Phase::Terminal(_) => PhaseSummary::Terminal,
            Phase::GuestReturned => PhaseSummary::GuestReturned,
        })
    }
}

pub(in crate::win16_runtime) enum SafePointResult<'a> {
    Progress(Progress<'a>),
    UnownedStep(Win16ComHostStep),
}

#[derive(Clone, Copy)]
pub(super) enum PhaseSummary {
    Prepared,
    Starting,
    Running(Win16ComHostOwnerIdentity),
    CallbackPending,
    CallbackResuming,
    CallbackFailed,
    StartFailed,
    Terminal,
    GuestReturned,
}
