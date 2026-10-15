//! Runtime-owned identity and retained completions for one native USER call.

use guest_core::Registers;
use std::{error::Error, fmt, sync::Arc};
use x86_cpu::ControlTransfer;
use x86_cpu::CpuContext;

use super::super::user_services_controls::Win16WindowCreationObservation;
use super::super::window_guest_work::{
    PendingModalGuestWork as ModalGuestWork, PendingWindowGuestWork,
};
use super::WindowReturn;
use crate::{
    RuntimeError, Win16HostWindowOperationId, Win16NativeCallbackCancellation,
    Win16NativeModalCancellation, Win16NativeWindowOperationKind, Win16NativeWindowOperationState,
    Win16WindowResult, Win16WindowSourceRetiredProof,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowOperationLifecycle {
    GuestOnly,
    BeginPending,
    NeverStarted,
    Started,
    Returned,
    ReturnedWithError,
    /// Native modal work ended during USER abort. This is a terminal
    /// cancellation state, never a normal guest API result.
    TerminalModalCancelled,
}

pub(in crate::win16_runtime) struct WindowOperationFrame {
    pub(in crate::win16_runtime) id: u64,
    pub(in crate::win16_runtime) saved: Registers,
    pub(in crate::win16_runtime) return_to: (u16, u16, u32),
    /// The original continuation is present here until the host returns.
    /// After that it moves, without cloning, into `completion.continuation` on
    /// this same exact frame.
    pub(in crate::win16_runtime) result: Option<WindowReturn>,
    /// Native result and original continuation remain owned by this exact
    /// frame while guest projection is pending or retained.
    pub(in crate::win16_runtime) completion: Option<WindowOperationCompletion>,
    /// DDE keeps its native result and typed source receipts inside its own
    /// continuation. This journal records only the central projection and
    /// CPU-return phases while that exact continuation stays in `result`.
    pub(in crate::win16_runtime) dde_completion: Option<DdeWindowCompletionJournal>,
    /// Retain the accepted native callback until a full CPU/DOS entry seam
    /// transfers its exact carrier into the DDE callback owner.
    pub(in crate::win16_runtime) pending_dde_callback: Option<(
        super::super::Win16DdeCallbackOrigin,
        Arc<crate::Win16HostDdeCallbackStep>,
    )>,
    /// Exact host proof that a normal USER source was retired. DDE has its
    /// own continuation proof and never uses this field.
    pub(in crate::win16_runtime) source_retired: Option<Arc<Win16WindowSourceRetiredProof>>,
    /// The exact host tombstone for a normal return is released only after
    /// projection, caller-context restoration, and frame-owner retirement
    /// have all completed. A failed or ambiguous release replays this proof.
    pub(in crate::win16_runtime) source_retirement_consumed: bool,
    /// One earlier native stage whose source retired before this same outer
    /// USER call began its follow-up operation.
    pub(in crate::win16_runtime) prior_source_retirement:
        Option<WindowOperationPriorSourceRetirement>,
    /// Full entry architecture captured at the real service dispatch seam.
    /// Normal callback return continues to use its existing register ABI.
    pub(in crate::win16_runtime) entry_context: CpuContext,
    /// Runtime ledger owner for the checked caller continuation. Guest-only
    /// callback dispatch and teardown compensation frames leave this absent.
    pub(in crate::win16_runtime) cpu_call_owner: Option<u64>,
    /// Latest completed callback and its observed return transfer. One native
    /// operation may invoke several callbacks with different return paths.
    /// Absence means the CPU provider must prove no guest execution.
    pub(in crate::win16_runtime) guest_return_transfer:
        Option<(super::super::CallbackFrameId, ControlTransfer)>,
    pub(in crate::win16_runtime) native_source: Option<Win16NativeWindowOperationKind>,
    pub(in crate::win16_runtime) lifecycle: WindowOperationLifecycle,
    pub(in crate::win16_runtime) native_state: Option<Win16NativeWindowOperationState>,
    pub(in crate::win16_runtime) host_operation: Option<Win16HostWindowOperationId>,
    pub(in crate::win16_runtime) worker_generation: Option<u64>,
    /// Exact host-created failure payload after a real operation began. Its
    /// Arc identity is shared with POST owners and is never reconstructed.
    pub(in crate::win16_runtime) terminal_started_failure:
        Option<std::sync::Arc<crate::Win16WindowOperationStartedFailure>>,
    /// A guest-only dispatch callback has no native begin identity. Its exact
    /// local callback owner still lets terminal LIFO retire this frame.
    pub(in crate::win16_runtime) guest_callback_id: Option<super::super::CallbackFrameId>,
    pub(in crate::win16_runtime) guest_callback_retired: bool,
    pub(in crate::win16_runtime) pending_work: Option<PendingWindowGuestWork>,
    pub(in crate::win16_runtime) pending_modal_work: Option<ModalGuestWork>,
    pub(in crate::win16_runtime) host_wait: Option<Win16HostWindowOperationId>,
    pub(in crate::win16_runtime) host_modal_operation: Option<Win16HostWindowOperationId>,
    /// Terminal native cancellation values remain attached to this exact
    /// suspended modal owner until a completion path consumes them.
    pub(in crate::win16_runtime) terminal_modal_responses: Vec<Win16NativeModalCancellation>,
    /// Typed failure tied to the exact modal response above. It remains
    /// separate from `terminal_error`, which preserves the first earlier
    /// dispatch cause when one already exists.
    pub(in crate::win16_runtime) terminal_modal_error: Option<Arc<RuntimeError>>,
    pub(in crate::win16_runtime) terminal_resources_retired: bool,
    pub(in crate::win16_runtime) terminal_context_restored: bool,
    /// Cache the exact native ACK before crossing the host boundary. A
    /// failed or ambiguous ACK can be retried byte-for-byte while the frame,
    /// modal values, and original context remain on the stack.
    pub(in crate::win16_runtime) terminal_ack: Option<crate::Win16WindowTerminalAck>,
    /// True once the exact cached ACK crossed the host boundary, including an
    /// ambiguous error. A later retry may only replay this same ACK.
    pub(in crate::win16_runtime) terminal_ack_attempted: bool,
    /// Exact native callback sources whose local guest frames and payloads
    /// have already retired. The operation owner keeps these proofs until its
    /// terminal ACK retires the paired native source.
    pub(in crate::win16_runtime) terminal_retired_callbacks: Vec<TerminalWindowCallbackRetirement>,
    pub(in crate::win16_runtime) terminal_source_acknowledged: bool,
    pub(in crate::win16_runtime) terminal_error: Option<Arc<RuntimeError>>,
    /// Most recent retryable terminal-cleanup/ACK failure, kept separate from
    /// the original begin/operation error that established this frame.
    pub(in crate::win16_runtime) terminal_retained_error: Option<Arc<RuntimeError>>,
    pub(in crate::win16_runtime) last_work_generation: u64,
    pub(in crate::win16_runtime) last_modal_work_generation: u64,
}

#[derive(Debug)]
pub(in crate::win16_runtime) struct NativeModalCancellationFailure {
    pub(in crate::win16_runtime) operation_id: u64,
    pub(in crate::win16_runtime) scope_id: Option<u64>,
    pub(in crate::win16_runtime) native_result: Option<i64>,
    pub(in crate::win16_runtime) native_last_error: Option<u32>,
    pub(in crate::win16_runtime) signal: crate::Win16NativeModalCancelSignal,
}

impl NativeModalCancellationFailure {
    pub(in crate::win16_runtime) fn from_response(response: &Win16NativeModalCancellation) -> Self {
        Self {
            operation_id: response.operation_id,
            scope_id: response.scope_id,
            native_result: response.native_result,
            native_last_error: response.native_last_error,
            signal: response.signal,
        }
    }

    pub(in crate::win16_runtime) fn matches(
        &self,
        response: &Win16NativeModalCancellation,
    ) -> bool {
        self.operation_id == response.operation_id
            && self.scope_id == response.scope_id
            && self.native_result == response.native_result
            && self.native_last_error == response.native_last_error
            && self.signal == response.signal
    }
}

impl fmt::Display for NativeModalCancellationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native modal operation {} terminated by {:?} (scope {:?}, result {:?}, last error {:?})",
            self.operation_id,
            self.signal,
            self.scope_id,
            self.native_result,
            self.native_last_error
        )
    }
}

impl Error for NativeModalCancellationFailure {}

pub(in crate::win16_runtime) fn modal_error_matches(
    error: &RuntimeError,
    response: &Win16NativeModalCancellation,
) -> bool {
    error
        .source()
        .and_then(|source| source.downcast_ref::<NativeModalCancellationFailure>())
        .is_some_and(|failure| failure.matches(response))
}

impl WindowOperationFrame {
    pub(in crate::win16_runtime) fn continuation(&self) -> Option<&WindowReturn> {
        self.result.as_ref().or_else(|| {
            self.completion
                .as_ref()
                .map(|completion| &completion.continuation)
        })
    }

    pub(in crate::win16_runtime) fn continuation_mut(&mut self) -> Option<&mut WindowReturn> {
        if self.result.is_some() {
            self.result.as_mut()
        } else {
            self.completion
                .as_mut()
                .map(|completion| &mut completion.continuation)
        }
    }
}

pub(in crate::win16_runtime) struct WindowOperationCompletion {
    pub(in crate::win16_runtime) continuation: WindowReturn,
    pub(in crate::win16_runtime) result: Win16WindowResult,
    pub(in crate::win16_runtime) journal: WindowCompletionJournal,
    /// The source family that owns this exact completion. DDE does not use
    /// the USER normal-source proof/ACK path.
    pub(in crate::win16_runtime) source: WindowOperationCompletionSource,
}

pub(in crate::win16_runtime) struct WindowOperationPriorSourceRetirement {
    pub(in crate::win16_runtime) proof: Arc<Win16WindowSourceRetiredProof>,
    pub(in crate::win16_runtime) consumed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowOperationCompletionSource {
    NativeUser,
    GuestCallback {
        callback_id: Option<super::super::CallbackFrameId>,
    },
}

pub(in crate::win16_runtime) struct DdeWindowCompletionJournal {
    pub(in crate::win16_runtime) phase: DdeWindowCompletionPhase,
    pub(in crate::win16_runtime) value: Option<(u32, win16_abi::Win16ReturnKind)>,
    pub(in crate::win16_runtime) first_cause: Option<Arc<RuntimeError>>,
    /// The DDE owner-local completion effect is invoked once and its typed
    /// outcome stays here until the exact DDE driver advances it. This avoids
    /// re-running result projection after a later CPU/source phase fails.
    pub(in crate::win16_runtime) outcome: Option<super::super::win16_runtime_dde::Win16DdeFinish>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum DdeWindowCompletionPhase {
    SourceProofReceived,
    FinishOutcomeReady,
    FollowUpDispatched,
    CallbackDispatched,
    GuestProjected {
        value: u32,
        return_kind: win16_abi::Win16ReturnKind,
    },
    CallerReturned {
        value: u32,
        return_kind: win16_abi::Win16ReturnKind,
    },
    SourceRetired,
}

pub(in crate::win16_runtime) struct WindowCompletionJournal {
    pub(in crate::win16_runtime) phase: WindowOperationCompletionPhase,
    pub(in crate::win16_runtime) projection: WindowProjectionJournal,
    pub(in crate::win16_runtime) first_cause: Option<Arc<RuntimeError>>,
    pub(in crate::win16_runtime) creation_observation: Option<Win16WindowCreationObservation>,
    /// KERNEL modal choices are queued only after the checked Win16 caller
    /// return. Capacity is reserved during projection; this exact effect is
    /// retained here until the caller boundary commits.
    pub(in crate::win16_runtime) kernel_effect:
        Option<super::super::kernel_diagnostics::Win16KernelDiagnosticEffect>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowOperationCompletionPhase {
    Received,
    GuestProjected {
        value: u32,
        return_kind: win16_abi::Win16ReturnKind,
    },
    CallerReturned {
        value: u32,
        return_kind: win16_abi::Win16ReturnKind,
    },
    SourceRetired,
}

pub(in crate::win16_runtime) enum WindowProjectionJournal {
    Menu {
        phase: MenuProjectionPhase,
        value: Option<(u32, win16_abi::Win16ReturnKind)>,
    },
    MessageCall {
        phase: MessageCallProjectionPhase,
        value: Option<(u32, win16_abi::Win16ReturnKind)>,
    },
    UpdateRegion {
        phase: GuestOutputProjectionPhase,
        value: Option<(u32, win16_abi::Win16ReturnKind)>,
    },
    ScrollBar {
        phase: GuestOutputProjectionPhase,
        value: Option<(u32, win16_abi::Win16ReturnKind)>,
    },
    Api(WindowApiProjectionJournal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum MenuProjectionPhase {
    Ready,
    Invalidated,
    OutputCommitted,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum MessageCallProjectionPhase {
    Ready,
    OwnerBookkeepingCommitted,
    OutputCommitted,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum GuestOutputProjectionPhase {
    Ready,
    OutputCommitted,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum GuestTextProjectionPhase {
    Ready,
    OutputCommitted,
    ValueCaptured,
    Complete,
}

/// Owner-specific progress for the remaining USER returns. A single generic
/// phase cannot say which guest resource, host effect, or output lease has
/// already retired, so every WindowReturn variant has its own journal arm.
pub(in crate::win16_runtime) enum WindowApiProjectionJournal {
    Dde,
    KernelDiagnostics(KernelDiagnosticProjectionPhase),
    Create(CreateWindowProjection),
    Message(MessageProjection),
    DialogItemMessage(DialogItemMessageProjectionPhase),
    Icon(IconProjection),
    SetWindowText(WindowTextSetProjectionPhase),
    GetWindowText(GuestTextProjection),
    GetWindowTextLength(WindowTextLengthProjectionPhase),
    GetMessage(QueuedMessageProjection),
    PeekMessage(QueuedMessageProjection),
    TranslateMessage(SimpleReturnProjectionPhase),
    DispatchMessage(SimpleReturnProjectionPhase),
    GuestDispatch(SimpleReturnProjectionPhase),
    GuestNotificationPost(SimpleReturnProjectionPhase),
    PostQuitMessage(SimpleReturnProjectionPhase),
    GuestTimerDispatch(SimpleReturnProjectionPhase),
    Show(VisibilityProjectionPhase),
    WindowCall(WindowCallProjection),
    WindowData(WindowDataProjection),
    WindowProperties(WindowPropertyProjection),
    QueryProcedure(ProcedureProjection),
    UserMessageBox(SimpleReturnProjectionPhase),
    GrayString(SimpleReturnProjectionPhase),
    UserCursorAccelerator(CursorAcceleratorProjection),
    UserFamily(UserFamilyProjection),
    CommonControls {
        phase: CommonControlsProjectionPhase,
        value: Option<(u32, win16_abi::Win16ReturnKind)>,
    },
    CommonDialog(super::completion_common_dialog::CommonDialogProjection),
    ShellExecution(super::super::compat_shell_execution::ShellExecutionProjection),
    Paint(PaintProjection),
    AcquireWindowDc(DcAcquisitionProjection),
    EndPaint(DcRetirementProjection),
    ReleaseWindowDc(DcRetirementProjection),
    CleanupPaint(CompensationProjection),
    CleanupWindowDc(CompensationProjection),
    GuestProcedureCall(SimpleReturnProjectionPhase),
}

pub(in crate::win16_runtime) struct CreateWindowProjection {
    pub(in crate::win16_runtime) phase: CreateWindowProjectionPhase,
    pub(in crate::win16_runtime) guest_window: Option<u16>,
    /// True when a native callback already created the guest handle and
    /// installed its procedure before the native CreateWindow call returned.
    pub(in crate::win16_runtime) callback_mapped: bool,
}

pub(in crate::win16_runtime) struct MessageProjection {
    pub(in crate::win16_runtime) phase: MessageProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
}

pub(in crate::win16_runtime) struct WindowCallProjection {
    pub(in crate::win16_runtime) phase: WindowCallProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
    pub(in crate::win16_runtime) geometry_result_observed: bool,
}

pub(in crate::win16_runtime) struct WindowPropertyProjection {
    pub(in crate::win16_runtime) phase: WindowPropertyProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
}

pub(in crate::win16_runtime) struct WindowDataProjection {
    pub(in crate::win16_runtime) phase: WindowDataProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
    pub(in crate::win16_runtime) parent_observation: Option<crate::Win16HostWindowParentObservation>,
}

pub(in crate::win16_runtime) struct CursorAcceleratorProjection {
    pub(in crate::win16_runtime) phase: CursorAcceleratorProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u16>,
}

pub(in crate::win16_runtime) struct UserFamilyProjection {
    pub(in crate::win16_runtime) phase: UserFamilyProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
    pub(in crate::win16_runtime) clipboard_sequence_observed: bool,
    pub(in crate::win16_runtime) owned_projection:
        Option<super::completion_native_api::Win16UserOwnedProjection>,
}

pub(in crate::win16_runtime) struct PaintProjection {
    pub(in crate::win16_runtime) phase: PaintProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u16>,
    pub(in crate::win16_runtime) native_dc: Option<crate::Win16HostDc>,
}

pub(in crate::win16_runtime) struct DcAcquisitionProjection {
    pub(in crate::win16_runtime) phase: DcAcquisitionProjectionPhase,
    pub(in crate::win16_runtime) guest_dc: Option<u16>,
}

pub(in crate::win16_runtime) struct DcRetirementProjection {
    pub(in crate::win16_runtime) phase: DcRetirementProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
}

pub(in crate::win16_runtime) struct CompensationProjection {
    pub(in crate::win16_runtime) phase: CompensationProjectionPhase,
    pub(in crate::win16_runtime) original_cause: Arc<RuntimeError>,
}

pub(in crate::win16_runtime) struct GuestTextProjection {
    pub(in crate::win16_runtime) phase: GuestTextProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
}

pub(in crate::win16_runtime) struct IconProjection {
    pub(in crate::win16_runtime) phase: IconProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u16>,
}

pub(in crate::win16_runtime) struct ProcedureProjection {
    pub(in crate::win16_runtime) phase: ProcedureProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
}

pub(in crate::win16_runtime) struct QueuedMessageProjection {
    pub(in crate::win16_runtime) phase: QueuedMessageProjectionPhase,
    pub(in crate::win16_runtime) value: Option<u32>,
    pub(in crate::win16_runtime) owner_bookkeeping_committed: bool,
    pub(in crate::win16_runtime) projected_message: Option<win16_abi::Msg16>,
    pub(in crate::win16_runtime) parent_update: Option<(u16, u16)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum KernelDiagnosticProjectionPhase {
    Ready,
    EffectReserved,
    EffectQueued,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum CreateWindowProjectionPhase {
    Ready,
    HandleMapped,
    WindowDataInitialized,
    ParentLinked,
    ReturnReady,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum MessageProjectionPhase {
    Ready,
    InputsValidated,
    GuestOutputCommitted,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum DialogItemMessageProjectionPhase {
    Ready,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum IconProjectionPhase {
    Ready,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowTextSetProjectionPhase {
    Ready,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowTextLengthProjectionPhase {
    Ready,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum QueuedMessageProjectionPhase {
    Ready,
    QueueOwnerValidated,
    GuestHandlesMapped,
    OutputCommitted,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum SimpleReturnProjectionPhase {
    Ready,
    ValueCaptured,
    ReturnInstalled,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum VisibilityProjectionPhase {
    Ready,
    ValueCaptured,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowCallProjectionPhase {
    Ready,
    OwnerBookkeepingCommitted,
    GuestOutputCommitted,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowDataProjectionPhase {
    Ready,
    ParentObserving,
    ParentGraphRefreshing,
    ParentGraphRefreshed,
    ReturnValueMapped,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowPropertyProjectionPhase {
    Ready,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum ProcedureProjectionPhase {
    Ready,
    ProcedureGateInstalled,
    ReturnReady,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum CursorAcceleratorProjectionPhase {
    Ready,
    HandleAllocated,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum UserFamilyProjectionPhase {
    Ready,
    ControlWindowMapped,
    ControlParentLinked,
    GuestOutputCommitted,
    ValueCaptured,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum CommonControlsProjectionPhase {
    Ready,
    GuestOutputCommitted,
    WindowMapped,
    ParentLinked,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum PaintProjectionPhase {
    Ready,
    GuestOutputCommitted,
    DcLeaseCommitted,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum DcAcquisitionProjectionPhase {
    Ready,
    NativeDcBound,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum DcRetirementProjectionPhase {
    Ready,
    NativeRetired,
    GuestLeaseRetired,
    ReturnReady,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum CompensationProjectionPhase {
    Ready,
    NativeCleanupPending,
    NativeCleanupRetired,
    GuestLeaseRetired,
    Complete,
}
impl WindowApiProjectionJournal {
    pub(in crate::win16_runtime) fn for_return(continuation: &WindowReturn) -> Self {
        use WindowReturn as Return;
        match continuation {
            Return::Dde(_) => Self::Dde,
            Return::KernelDiagnostics(_) => {
                Self::KernelDiagnostics(KernelDiagnosticProjectionPhase::Ready)
            }
            Return::Create { .. } => Self::Create(CreateWindowProjection {
                phase: CreateWindowProjectionPhase::Ready,
                guest_window: None,
                callback_mapped: matches!(
                    continuation,
                    Return::Create {
                        window: Some(_),
                        ..
                    }
                ),
            }),
            Return::Message { .. } => Self::Message(MessageProjection {
                phase: MessageProjectionPhase::Ready,
                value: None,
            }),
            Return::DialogItemMessage { .. } => {
                Self::DialogItemMessage(DialogItemMessageProjectionPhase::Ready)
            }
            Return::Icon { .. } => Self::Icon(IconProjection {
                phase: IconProjectionPhase::Ready,
                value: None,
            }),
            Return::SetWindowText => Self::SetWindowText(WindowTextSetProjectionPhase::Ready),
            Return::GetWindowText { .. } => Self::GetWindowText(GuestTextProjection {
                phase: GuestTextProjectionPhase::Ready,
                value: None,
            }),
            Return::GetWindowTextLength => {
                Self::GetWindowTextLength(WindowTextLengthProjectionPhase::Ready)
            }
            Return::GetMessage { .. } => Self::GetMessage(QueuedMessageProjection {
                phase: QueuedMessageProjectionPhase::Ready,
                value: None,
                owner_bookkeeping_committed: false,
                projected_message: None,
                parent_update: None,
            }),
            Return::PeekMessage { .. } => Self::PeekMessage(QueuedMessageProjection {
                phase: QueuedMessageProjectionPhase::Ready,
                value: None,
                owner_bookkeeping_committed: false,
                projected_message: None,
                parent_update: None,
            }),
            Return::TranslateMessage => Self::TranslateMessage(SimpleReturnProjectionPhase::Ready),
            Return::DispatchMessage { .. } => {
                Self::DispatchMessage(SimpleReturnProjectionPhase::Ready)
            }
            Return::GuestDispatch => Self::GuestDispatch(SimpleReturnProjectionPhase::Ready),
            Return::GuestNotificationPost => {
                Self::GuestNotificationPost(SimpleReturnProjectionPhase::Ready)
            }
            Return::PostQuitMessage => Self::PostQuitMessage(SimpleReturnProjectionPhase::Ready),
            Return::GuestTimerDispatch => {
                Self::GuestTimerDispatch(SimpleReturnProjectionPhase::Ready)
            }
            Return::Show => Self::Show(VisibilityProjectionPhase::Ready),
            Return::Menu(_) => unreachable!("menu projections use their dedicated journal"),
            Return::WindowCall(_) => Self::WindowCall(WindowCallProjection {
                phase: WindowCallProjectionPhase::Ready,
                value: None,
                geometry_result_observed: false,
            }),
            Return::WindowData(_) => Self::WindowData(WindowDataProjection {
                phase: WindowDataProjectionPhase::Ready,
                value: None,
                parent_observation: None,
            }),
            Return::WindowProperties(_) => Self::WindowProperties(WindowPropertyProjection {
                phase: WindowPropertyProjectionPhase::Ready,
                value: None,
            }),
            Return::QueryProcedure { .. }
            | Return::PrepareNativeSubclass { .. }
            | Return::NativeSubclass(_) => Self::QueryProcedure(ProcedureProjection {
                phase: ProcedureProjectionPhase::Ready,
                value: None,
            }),
            Return::MessageCall(_) => {
                unreachable!("message-call projections use their dedicated journal")
            }
            Return::UserMessageBox => Self::UserMessageBox(SimpleReturnProjectionPhase::Ready),
            Return::GrayString { .. } => Self::GrayString(SimpleReturnProjectionPhase::Ready),
            Return::UpdateRegion(_) => {
                unreachable!("update-region projections use their dedicated journal")
            }
            Return::ScrollBar(_) => {
                unreachable!("scroll-bar projections use their dedicated journal")
            }
            Return::UserCursorAccelerator(_) => {
                Self::UserCursorAccelerator(CursorAcceleratorProjection {
                    phase: CursorAcceleratorProjectionPhase::Ready,
                    value: None,
                })
            }
            Return::UserFamily(_) => Self::UserFamily(UserFamilyProjection {
                phase: UserFamilyProjectionPhase::Ready,
                value: None,
                clipboard_sequence_observed: false,
                owned_projection: None,
            }),
            Return::CommonControls(_) => Self::CommonControls {
                phase: CommonControlsProjectionPhase::Ready,
                value: None,
            },
            Return::CommonDialog(_) => {
                Self::CommonDialog(super::completion_common_dialog::CommonDialogProjection::new())
            }
            Return::ShellExecution(_) => Self::ShellExecution(
                super::super::compat_shell_execution::ShellExecutionProjection::new(),
            ),
            Return::Paint { .. } => Self::Paint(PaintProjection {
                phase: PaintProjectionPhase::Ready,
                value: None,
                native_dc: None,
            }),
            Return::AcquireWindowDc { .. } => Self::AcquireWindowDc(DcAcquisitionProjection {
                phase: DcAcquisitionProjectionPhase::Ready,
                guest_dc: None,
            }),
            Return::EndPaint { .. } => Self::EndPaint(DcRetirementProjection {
                phase: DcRetirementProjectionPhase::Ready,
                value: None,
            }),
            Return::ReleaseWindowDc { .. } => Self::ReleaseWindowDc(DcRetirementProjection {
                phase: DcRetirementProjectionPhase::Ready,
                value: None,
            }),
            Return::CleanupPaint { original_error, .. } => {
                Self::CleanupPaint(CompensationProjection {
                    phase: CompensationProjectionPhase::Ready,
                    original_cause: Arc::clone(original_error),
                })
            }
            Return::CleanupWindowDc { original_error, .. } => {
                Self::CleanupWindowDc(CompensationProjection {
                    phase: CompensationProjectionPhase::Ready,
                    original_cause: Arc::clone(original_error),
                })
            }
            Return::GuestProcedureCall { .. } => {
                Self::GuestProcedureCall(SimpleReturnProjectionPhase::Ready)
            }
        }
    }
}

impl WindowCompletionJournal {
    /// Both native result carriers use the same initialization. A prepared
    /// compensation stays Ready until its real EndPaint/ReleaseDC result arrives.
    pub(in crate::win16_runtime) fn for_native_result(
        continuation: &WindowReturn,
        result: &Win16WindowResult,
    ) -> Self {
        let mut journal = Self::new(continuation);
        match (&mut journal.projection, result) {
            (
                WindowProjectionJournal::Api(WindowApiProjectionJournal::CleanupPaint(owner)),
                Win16WindowResult::PaintEnded(_),
            )
            | (
                WindowProjectionJournal::Api(WindowApiProjectionJournal::CleanupWindowDc(owner)),
                Win16WindowResult::DcReleased(_),
            ) => {
                owner.phase = CompensationProjectionPhase::NativeCleanupPending;
            }
            _ => {}
        }
        journal
    }

    pub(in crate::win16_runtime) fn new(continuation: &WindowReturn) -> Self {
        let projection = match continuation {
            WindowReturn::Menu(_) => WindowProjectionJournal::Menu {
                phase: MenuProjectionPhase::Ready,
                value: None,
            },
            WindowReturn::MessageCall(_) => WindowProjectionJournal::MessageCall {
                phase: MessageCallProjectionPhase::Ready,
                value: None,
            },
            WindowReturn::UpdateRegion(_) => WindowProjectionJournal::UpdateRegion {
                phase: GuestOutputProjectionPhase::Ready,
                value: None,
            },
            WindowReturn::ScrollBar(_) => WindowProjectionJournal::ScrollBar {
                phase: GuestOutputProjectionPhase::Ready,
                value: None,
            },
            continuation => {
                WindowProjectionJournal::Api(WindowApiProjectionJournal::for_return(continuation))
            }
        };
        Self {
            phase: WindowOperationCompletionPhase::Received,
            projection,
            first_cause: None,
            creation_observation: None,
            kernel_effect: None,
        }
    }

    pub(in crate::win16_runtime) fn owns_return(&self, continuation: &WindowReturn) -> bool {
        use WindowProjectionJournal as Journal;
        use WindowReturn as Return;

        match (&self.projection, continuation) {
            (Journal::Menu { .. }, Return::Menu(_))
            | (Journal::MessageCall { .. }, Return::MessageCall(_))
            | (Journal::UpdateRegion { .. }, Return::UpdateRegion(_))
            | (Journal::ScrollBar { .. }, Return::ScrollBar(_)) => true,
            (Journal::Api(api), continuation) => api.owns_return(continuation),
            _ => false,
        }
    }
}

impl WindowApiProjectionJournal {
    pub(in crate::win16_runtime) fn owns_return(&self, continuation: &WindowReturn) -> bool {
        use WindowApiProjectionJournal as Journal;
        use WindowReturn as Return;

        matches!(
            (self, continuation),
            (Journal::Dde, Return::Dde(_))
                | (Journal::KernelDiagnostics(_), Return::KernelDiagnostics(_))
                | (Journal::Create(_), Return::Create { .. })
                | (Journal::Message(_), Return::Message { .. })
                | (
                    Journal::DialogItemMessage(_),
                    Return::DialogItemMessage { .. }
                )
                | (Journal::Icon(_), Return::Icon { .. })
                | (Journal::SetWindowText(_), Return::SetWindowText)
                | (Journal::GetWindowText(_), Return::GetWindowText { .. })
                | (Journal::GetWindowTextLength(_), Return::GetWindowTextLength)
                | (Journal::GetMessage(_), Return::GetMessage { .. })
                | (Journal::PeekMessage(_), Return::PeekMessage { .. })
                | (Journal::TranslateMessage(_), Return::TranslateMessage)
                | (Journal::DispatchMessage(_), Return::DispatchMessage { .. })
                | (Journal::GuestDispatch(_), Return::GuestDispatch)
                | (
                    Journal::GuestNotificationPost(_),
                    Return::GuestNotificationPost
                )
                | (Journal::PostQuitMessage(_), Return::PostQuitMessage)
                | (Journal::GuestTimerDispatch(_), Return::GuestTimerDispatch)
                | (Journal::Show(_), Return::Show)
                | (Journal::WindowCall(_), Return::WindowCall(_))
                | (Journal::WindowData(_), Return::WindowData(_))
                | (Journal::WindowProperties(_), Return::WindowProperties(_))
                | (Journal::QueryProcedure(_), Return::QueryProcedure { .. })
                | (Journal::QueryProcedure(_), Return::PrepareNativeSubclass { .. })
                | (Journal::QueryProcedure(_), Return::NativeSubclass(_))
                | (Journal::UserMessageBox(_), Return::UserMessageBox)
                | (Journal::GrayString(_), Return::GrayString { .. })
                | (
                    Journal::UserCursorAccelerator(_),
                    Return::UserCursorAccelerator(_)
                )
                | (Journal::UserFamily(_), Return::UserFamily(_))
                | (Journal::CommonControls { .. }, Return::CommonControls(_))
                | (Journal::CommonDialog(_), Return::CommonDialog(_))
                | (Journal::ShellExecution(_), Return::ShellExecution(_))
                | (Journal::Paint(_), Return::Paint { .. })
                | (Journal::AcquireWindowDc(_), Return::AcquireWindowDc { .. })
                | (Journal::EndPaint(_), Return::EndPaint { .. })
                | (Journal::ReleaseWindowDc(_), Return::ReleaseWindowDc { .. })
                | (Journal::CleanupPaint(_), Return::CleanupPaint { .. })
                | (Journal::CleanupWindowDc(_), Return::CleanupWindowDc { .. })
                | (
                    Journal::GuestProcedureCall(_),
                    Return::GuestProcedureCall { .. }
                )
        )
    }
}

pub(in crate::win16_runtime) struct TerminalWindowCallbackRetirement {
    pub(in crate::win16_runtime) callback_frame_id: super::super::CallbackFrameId,
    pub(in crate::win16_runtime) cancellation: Win16NativeCallbackCancellation,
    pub(in crate::win16_runtime) guest_payload_cleaned: bool,
    pub(in crate::win16_runtime) runtime_frame_retired: bool,
    pub(in crate::win16_runtime) owner_context_restored: bool,
    pub(in crate::win16_runtime) native_source_acknowledged: bool,
}
