//! Owned host boundary for the Win16 KERNEL NetBIOSCall export.
//!
//! Guest selectors, FAR values, and pointer-bearing native NCB records never
//! cross this boundary. The runtime decodes the Win16 NCB and owns all buffers
//! before asking the host to execute a command.

use std::sync::Arc;

/// Host-side identity for one accepted asynchronous NCB. Zero is reserved for
/// hosts that return an immediate protocol status without retaining a source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Win16HostNetbiosId(pub u64);

/// Why the exact asynchronous source is being handed to native cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostNetbiosTeardownReason {
    /// The guest task is ending and cannot consume a later completion.
    TaskTeardown,
    /// The shared USER lane has entered terminal shutdown and cannot publish
    /// this source's terminal wake.
    TerminalWakeUnavailable,
}

/// Actual channel used to publish this source's terminal result to Runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Win16HostNetbiosCompletionPublication {
    /// No successful result-delivery channel has published this completion.
    #[default]
    None,
    /// The terminal result was returned directly from the synchronous submit call.
    InlineReturn,
    /// The shared USER/modal wake was successfully signaled for this result.
    SharedWake,
}

impl Win16HostNetbiosCompletionPublication {
    pub fn did_not_regress_to(self, next: Self) -> bool {
        self == next || self == Self::None
    }
}

/// Last proven phase of the exact native source while it is being retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostNetbiosTeardownPhase {
    NativePending,
    TerminalUnpublished,
    CompletionDeliveredAwaitingGuestAck,
    TeardownRequested,
    /// A native wait failure/unexpected result and missing worker consumer
    /// leave the exact owner quarantined without terminal proof.
    NativeOwnerQuarantined,
    NativeTerminal,
    WorkerJoinPending,
    EventCloseFailed,
    WorkerJoinFailed,
    NativeOwnerRetired,
}

/// One retained representative for an actual teardown phase and its bounded
/// retry count. Repeated failures never build an unbounded RuntimeError chain.
#[derive(Clone, Debug, Default)]
pub struct Win16HostNetbiosFailureTally {
    pub first: Option<Arc<crate::RuntimeError>>,
    pub count: u32,
}

impl Win16HostNetbiosFailureTally {
    pub fn record(&mut self, error: Arc<crate::RuntimeError>) {
        if self.first.is_none() {
            self.first = Some(error);
        }
        self.count = self.count.saturating_add(1);
    }

    fn same_cached_slot(&self, other: &Self) -> bool {
        self.count == other.count
            && match (&self.first, &other.first) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
    }

    fn did_not_regress_to(&self, next: &Self) -> bool {
        next.count >= self.count
            && match (&self.first, &next.first) {
                (None, None) if self.count == 0 => true,
                (None, Some(_)) if self.count == 0 && next.count > 0 => true,
                (Some(previous), Some(current)) if self.count > 0 => {
                    Arc::ptr_eq(previous, current)
                }
                _ => false,
            }
    }

    fn is_well_formed(&self) -> bool {
        (self.count == 0) == self.first.is_none()
    }
}

/// Fixed per-phase history carried by the exact native owner receipt.
#[derive(Clone, Debug, Default)]
pub struct Win16HostNetbiosFailureDiagnostics {
    pub wake_publication: Win16HostNetbiosFailureTally,
    pub native_wait: Win16HostNetbiosFailureTally,
    pub completion_projection: Win16HostNetbiosFailureTally,
    pub no_consumer: Win16HostNetbiosFailureTally,
    pub teardown_handoff: Win16HostNetbiosFailureTally,
    pub native_event_close: Win16HostNetbiosFailureTally,
    pub worker_join: Win16HostNetbiosFailureTally,
}

impl Win16HostNetbiosFailureDiagnostics {
    pub(crate) fn is_well_formed(&self) -> bool {
        self.wake_publication.is_well_formed()
            && self.native_wait.is_well_formed()
            && self.completion_projection.is_well_formed()
            && self.no_consumer.is_well_formed()
            && self.teardown_handoff.is_well_formed()
            && self.native_event_close.is_well_formed()
            && self.worker_join.is_well_formed()
    }

    fn same_cached_history(&self, other: &Self) -> bool {
        self.wake_publication.same_cached_slot(&other.wake_publication)
            && self.native_wait.same_cached_slot(&other.native_wait)
            && self.completion_projection.same_cached_slot(&other.completion_projection)
            && self.no_consumer.same_cached_slot(&other.no_consumer)
            && self.teardown_handoff.same_cached_slot(&other.teardown_handoff)
            && self.native_event_close.same_cached_slot(&other.native_event_close)
            && self.worker_join.same_cached_slot(&other.worker_join)
    }

    pub(crate) fn did_not_regress_to(&self, next: &Self) -> bool {
        self.wake_publication.did_not_regress_to(&next.wake_publication)
            && self.native_wait.did_not_regress_to(&next.native_wait)
            && self.completion_projection.did_not_regress_to(&next.completion_projection)
            && self.no_consumer.did_not_regress_to(&next.no_consumer)
            && self.teardown_handoff.did_not_regress_to(&next.teardown_handoff)
            && self.native_event_close.did_not_regress_to(&next.native_event_close)
            && self.worker_join.did_not_regress_to(&next.worker_join)
    }
}

/// Exact-source teardown progress. `NativeOwnerRetired` is valid only after
/// native terminal completion, exact event close, and the matching worker join.
/// It never reports guest delivery or guest source ACK.
#[derive(Clone, Debug)]
pub struct Win16HostNetbiosTeardownReceipt {
    pub id: Win16HostNetbiosId,
    pub reason: Win16HostNetbiosTeardownReason,
    pub phase: Win16HostNetbiosTeardownPhase,
    /// Delivery-channel fact; InlineReturn is not a shared USER wake signal.
    pub completion_publication: Win16HostNetbiosCompletionPublication,
    pub native_terminal: bool,
    pub event_closed: bool,
    pub worker_joined: bool,
    /// Original typed source cause, retained by the same host request row.
    pub cause: Option<Arc<crate::RuntimeError>>,
    /// A typed teardown or owner-retention failure, separate from the source cause.
    pub cleanup_error: Option<Arc<crate::RuntimeError>>,
    /// Bounded diagnostics for each real producer/teardown phase.
    pub failure_diagnostics: Win16HostNetbiosFailureDiagnostics,
}

impl Win16HostNetbiosTeardownReceipt {
    /// Whether this receipt proves every native-owner retirement step.
    pub fn native_owner_retired(&self) -> bool {
        self.id.0 != 0
            && self.phase == Win16HostNetbiosTeardownPhase::NativeOwnerRetired
            && self.native_terminal
            && self.event_closed
            && self.worker_joined
    }

    /// Match the exact cached receipt, including the identity of its cause Arc.
    pub fn same_cached_receipt(&self, other: &Self) -> bool {
        self.id == other.id
            && self.reason == other.reason
            && self.phase == other.phase
            && self.completion_publication == other.completion_publication
            && self.native_terminal == other.native_terminal
            && self.event_closed == other.event_closed
            && self.worker_joined == other.worker_joined
            && match (&self.cause, &other.cause) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
            && match (&self.cleanup_error, &other.cleanup_error) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
            && self.failure_diagnostics.same_cached_history(&other.failure_diagnostics)
    }
}

/// Direction in which the NCB buffer is used by one command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostNetbiosBufferAccess {
    Read,
    Write,
    ReadWrite,
}

/// Command-specific owned input for a decoded Win16 NCB.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetbiosPayload {
    None,
    Bytes {
        bytes: Vec<u8>,
        access: Win16HostNetbiosBufferAccess,
    },
    FindName {
        capacity: u16,
    },
    LanaEnum {
        capacity: u16,
    },
    AdapterStatus {
        capacity: u16,
    },
    SessionStatus {
        capacity: u16,
    },
}

/// Command-specific output projected into the Win16 wire format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetbiosOutput {
    None,
    Bytes { bytes: Vec<u8> },
    FindName { bytes: Vec<u8> },
    LanaEnum { bytes: Vec<u8> },
    AdapterStatus { bytes: Vec<u8> },
    SessionStatus { bytes: Vec<u8> },
}

/// One NetBIOS operation with all guest memory copied into owned values.
/// Guest POST is intentionally not part of this host record: its Win16
/// callback ABI and continuation behavior remain unverified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostNetbiosCall {
    /// Base NetBIOS command, with the Win16 ASYNCH bit already removed.
    pub command: u8,
    pub asynchronous: bool,
    pub lsn: u8,
    pub num: u8,
    /// Input buffer capacity from the Win16 NCB.
    pub length: u16,
    /// Native flat-buffer extent. Normally identical to `length`; chain-send
    /// projects two guest buffers into one owned native SEND buffer.
    pub native_length: u16,
    pub call_name: [u8; 16],
    pub name: [u8; 16],
    pub receive_timeout: u8,
    pub send_timeout: u8,
    pub lana_num: u8,
    pub payload: Win16HostNetbiosPayload,
}

/// Initial NCB fields and, when the native provider completed inline, its
/// terminal snapshot. A nonzero id remains host-owned until exact ACK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostNetbiosSubmission {
    pub id: Win16HostNetbiosId,
    pub initial: Win16HostNetbiosResult,
    pub completion: Option<Win16HostNetbiosResult>,
    /// The provider observed terminal native NCB fields before submission
    /// returned. Completion projection can still be retried if this is true
    /// while `completion` is absent.
    pub inline_terminal: bool,
}

/// Native completion values and any owned buffer projected back to Win16.
/// For synchronous Netbios calls, the host preserves the API return byte and
/// each NCB completion byte independently so the runtime can verify their
/// target contract before writing guest memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostNetbiosResult {
    pub function_return: u8,
    pub retcode: u8,
    pub lsn: u8,
    pub num: u8,
    pub length: u16,
    pub cmd_cplt: u8,
    /// Updated NCB_CALLNAME for commands whose synchronous protocol returns
    /// the remote caller name (LISTEN and datagram receive variants).
    pub call_name: Option<[u8; 16]>,
    pub payload: Win16HostNetbiosOutput,
}

impl Win16HostNetbiosResult {
    /// A documented guest-visible NCB status from a host with no provider.
    pub fn status(status: u8) -> Self {
        Self {
            function_return: status,
            retcode: status,
            lsn: 0,
            num: 0,
            length: 0,
            cmd_cplt: status,
            call_name: None,
            payload: Win16HostNetbiosOutput::None,
        }
    }
}
