//! Pointer-free host contracts for Win16 MCI calls and continuations.

use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16GuestNotificationSource, Win16HostWindow,
};

/// A decoded command-string token. Quoted tokens preserve their quoted status
/// while doubled quotes are unescaped into owned bytes for alias lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16MciCommandToken {
    pub bytes: Vec<u8>,
    pub quoted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MciCommandSyntaxError {
    NoClosingQuote,
    ExtraCharacters,
}

/// Parse the shared MCI command-string quoting rules before either runtime or
/// host classifies side effects. Native MCI still performs command semantics.
pub fn parse_win16_mci_command(
    command: &[u8],
) -> Result<Result<Vec<Win16MciCommandToken>, Win16MciCommandSyntaxError>, RuntimeError> {
    let mut tokens = Vec::new();
    tokens.try_reserve_exact((command.len() / 2).saturating_add(1)).map_err(
        |error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve parsed Win16 MCI command tokens",
                error,
            )
        },
    )?;
    let mut cursor = 0;
    while cursor < command.len() {
        while command.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if cursor == command.len() {
            break;
        }
        let quoted = command[cursor] == b'"';
        let mut bytes = Vec::new();
        if quoted {
            cursor += 1;
            let mut closed = false;
            while cursor < command.len() {
                if command[cursor] == b'"' {
                    if command.get(cursor + 1) == Some(&b'"') {
                        bytes.try_reserve(1).map_err(|error| {
                            RuntimeError::with_source(
                                Kind::ResourceExhausted,
                                "unescape quoted Win16 MCI command token",
                                error,
                            )
                        })?;
                        bytes.push(b'"');
                        cursor += 2;
                    } else {
                        cursor += 1;
                        closed = true;
                        break;
                    }
                } else {
                    bytes.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "copy quoted Win16 MCI command token",
                            error,
                        )
                    })?;
                    bytes.push(command[cursor]);
                    cursor += 1;
                }
            }
            if !closed {
                return Ok(Err(Win16MciCommandSyntaxError::NoClosingQuote));
            }
            if command
                .get(cursor)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
            {
                return Ok(Err(Win16MciCommandSyntaxError::ExtraCharacters));
            }
        } else {
            let start = cursor;
            while command
                .get(cursor)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
            {
                cursor += 1;
            }
            let raw = &command[start..cursor];
            bytes.try_reserve_exact(raw.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "copy Win16 MCI command token",
                    error,
                )
            })?;
            bytes.extend_from_slice(raw);
        }
        tokens.push(Win16MciCommandToken { bytes, quoted });
    }
    Ok(Ok(tokens))
}

/// Host-owned MCI identity. It is not the native MCIDEVICEID and never enters
/// a Win16 register or parameter block.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciDevice {
    pub token: u64,
    pub generation: u64,
}

/// Exact host-owned identity for one installed native yield source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciYieldRegistrationId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciYieldRegistration {
    pub device: Win16HostMciDevice,
    pub registration: Win16HostMciYieldRegistrationId,
}

/// Native identities for a currently blocked YIELDPROC invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciActiveYield {
    pub operation: Win16HostMciOperationId,
    pub frame: Win16HostMciYieldFrame,
    pub device: Win16HostMciDevice,
}

/// Exact guest WORD accepted for one native YIELDPROC invocation. The host
/// separately proves that this identity reached the native return point.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciYieldReturn {
    pub owner: Win16HostMciActiveYield,
    pub guest_return: u16,
}

/// Exact native completion retained until task-level MCI quiescence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciOperationCompletion {
    pub operation: Win16HostMciOperationId,
    pub native_return_value: u32,
}

/// The host accepted a Begin command, but the caller did not receive its
/// original native step. Runtime may reconcile this operation, but must never
/// submit the Begin command again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMciBeginFailurePhase {
    EnqueuedAwaitingOriginalResult,
    EnqueuedWorkerFailure,
    EnqueuedMalformedResult,
}

#[derive(Debug)]
pub struct Win16HostMciBeginFailure {
    pub operation: Win16HostMciOperationId,
    pub phase: Win16HostMciBeginFailurePhase,
    pub cause: std::sync::Arc<RuntimeError>,
}

impl std::fmt::Display for Win16HostMciBeginFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.phase {
            Win16HostMciBeginFailurePhase::EnqueuedAwaitingOriginalResult => write!(
                formatter,
                "MCI operation {} is enqueued and awaiting its original result: {}",
                self.operation.0, self.cause
            ),
            Win16HostMciBeginFailurePhase::EnqueuedWorkerFailure => write!(
                formatter,
                "MCI operation {} returned a retained native worker failure: {}",
                self.operation.0, self.cause
            ),
            Win16HostMciBeginFailurePhase::EnqueuedMalformedResult => write!(
                formatter,
                "MCI operation {} returned a malformed retained result: {}",
                self.operation.0, self.cause
            ),
        }
    }
}

impl std::error::Error for Win16HostMciBeginFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

/// A native MCI step paired with the exact yield invocation that returned to
/// the worker before that step was produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostMciResumeReceipt {
    pub returned_yield: Win16HostMciYieldReturn,
    pub step: Win16HostMciStep,
}

/// Owned native resources the runtime asks the MCI owner to quiesce.
#[derive(Clone, Debug, Default)]
pub struct Win16HostMciQuiesceRequest {
    pub devices: Vec<Win16HostMciDevice>,
    pub registrations: Vec<Win16HostMciYieldRegistration>,
    /// Begin results which the runtime has not yet consumed. These operations
    /// remain live owners; no yield frame is implied by this identity.
    pub pending_begins: Vec<Win16HostMciOperationId>,
    pub active_yields: Vec<Win16HostMciActiveYield>,
    /// Exact runtime-side return claims to reconcile. Presence here is not
    /// native proof: the worker must match each tuple against its own ACK
    /// tombstone before reporting `ActiveYieldReturned`.
    pub returned_yields: Vec<Win16HostMciYieldReturn>,
    /// Exact runtime-side completion claims to reconcile against worker-owned
    /// native completion tombstones.
    pub completed_operations: Vec<Win16HostMciOperationCompletion>,
    pub resolved_causes: Vec<std::sync::Arc<RuntimeError>>,
}

impl PartialEq for Win16HostMciQuiesceRequest {
    fn eq(&self, other: &Self) -> bool {
        self.devices == other.devices
            && self.registrations == other.registrations
            && self.pending_begins == other.pending_begins
            && self.active_yields == other.active_yields
            && self.returned_yields == other.returned_yields
            && self.completed_operations == other.completed_operations
            && self.resolved_causes.len() == other.resolved_causes.len()
            && self
                .resolved_causes
                .iter()
                .zip(&other.resolved_causes)
                .all(|(left, right)| std::sync::Arc::ptr_eq(left, right))
    }
}

impl Eq for Win16HostMciQuiesceRequest {}

/// Exact runtime owner set presented before the MCI worker closes admission to
/// new MCI/YIELDPROC sources. This first phase deliberately does not close a
/// native device or consume any accepted notification.
#[derive(Clone, Debug)]
pub struct Win16HostMciProducerQuiescenceRequest {
    pub owners: Win16HostMciQuiesceRequest,
}

impl PartialEq for Win16HostMciProducerQuiescenceRequest {
    fn eq(&self, other: &Self) -> bool {
        self.owners == other.owners
    }
}

impl Eq for Win16HostMciProducerQuiescenceRequest {}

/// One accepted native MCI notify route that remains owned by the worker.
/// Native MCIDEVICEID is intentionally not exposed as a guest identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMciNotificationRouteOwner {
    pub notification: Win16HostMciNotificationId,
    pub device: Option<Win16HostMciDevice>,
    pub source_id: Option<u64>,
    pub target: Win16HostWindow,
    pub allow_new_device: bool,
    pub tombstone: bool,
}

/// Real producer barrier evidence. `source_admission_closed` and exact
/// disabled-source readbacks prove only that no new MCI notification route or
/// YIELDPROC registration can be introduced. Active native calls, devices,
/// accepted routes, queued notifications, and typed callback failures remain
/// explicit owners until the later exact source ACK and full quiescence.
#[derive(Clone, Debug)]
pub struct Win16HostMciProducerQuiescenceReceipt {
    pub request: Win16HostMciProducerQuiescenceRequest,
    pub source_admission_closed: bool,
    pub source_disable_evidence: Vec<Win16HostMciQuiescenceEvidence>,
    pub live_yield_sources: Vec<Win16HostMciYieldRegistration>,
    pub active_operations: Vec<Win16HostMciOperationId>,
    pub active_yields: Vec<Win16HostMciActiveYield>,
    pub devices: Vec<Win16HostMciDevice>,
    pub accepted_routes: Vec<Win16HostMciNotificationRouteOwner>,
    pub queued_notifications: Vec<Win16HostMciNotification>,
    pub source_causes: Vec<std::sync::Arc<RuntimeError>>,
    pub barrier_causes: Vec<std::sync::Arc<RuntimeError>>,
    pub resolved_causes: Vec<std::sync::Arc<RuntimeError>>,
}

impl Win16HostMciProducerQuiescenceReceipt {
    /// Existing active yield calls and accepted notifications are not terminal
    /// evidence, but they do not reopen source admission once this is true.
    pub fn producers_stopped(&self) -> bool {
        self.source_admission_closed
            && self.live_yield_sources.is_empty()
            && self.barrier_causes.is_empty()
            && self.request.owners.registrations.iter().all(|owner| {
                self.source_disable_evidence.iter().any(|evidence| matches!(
                    evidence,
                    Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                        owner: recorded,
                        observed_installed: false,
                        ..
                    } if recorded == owner
                ))
            })
    }
}

#[derive(Debug)]
pub struct Win16HostMciProducerQuiescenceFailure {
    pub receipt: std::sync::Arc<Win16HostMciProducerQuiescenceReceipt>,
}

impl std::fmt::Display for Win16HostMciProducerQuiescenceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let owners = &self.receipt.request.owners;
        write!(
            formatter,
            "MCI producer barrier retains {} device(s), {} yield source(s), {} active operation(s), {} accepted route(s), and {} queued notification(s)",
            self.receipt.devices.len(),
            self.receipt.live_yield_sources.len(),
            self.receipt.active_operations.len(),
            self.receipt.accepted_routes.len(),
            self.receipt.queued_notifications.len()
        )?;
        if let Some(cause) = self.receipt.barrier_causes.first() {
            write!(formatter, "; barrier cause: {cause}")?;
        } else if let Some(cause) = self.receipt.source_causes.first() {
            write!(formatter, "; retained source cause: {cause}")?;
        } else if !owners.pending_begins.is_empty() {
            write!(formatter, "; {} Begin operation(s) remain owned", owners.pending_begins.len())?;
        }
        Ok(())
    }
}

impl std::error::Error for Win16HostMciProducerQuiescenceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receipt
            .barrier_causes
            .first()
            .or_else(|| self.receipt.source_causes.first())
            .map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMciQuiescenceStatus {
    /// No native MCI owner or resource was involved in this request.
    NotStarted,
    /// Some requested work remains owned by the native worker.
    Retained,
    /// All requested resources reached their documented native terminal state.
    Quiesced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMciQuiescenceEvidence {
    YieldSourceDisabled {
        owner: Win16HostMciYieldRegistration,
        set_result: u32,
        observed_installed: bool,
    },
    ActiveYieldReturned {
        owner: Win16HostMciActiveYield,
        guest_return: u16,
    },
    OperationCompleted {
        operation: Win16HostMciOperationId,
        native_return_value: u32,
    },
    DeviceClosed {
        device: Win16HostMciDevice,
        native_result: u32,
    },
    NotificationLedgerDrained {
        pending_routes: usize,
        queued_events: usize,
        callback_failures: usize,
        wake_failures: usize,
    },
    NotificationWindowDestroyed,
    NotificationClassUnregistered,
    OwnerLoopReturned,
    OwnerThreadJoined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMciRetainedOwner {
    Device(Win16HostMciDevice),
    Registration(Win16HostMciYieldRegistration),
    PendingBegin(Win16HostMciOperationId),
    ActiveYield(Win16HostMciActiveYield),
    YieldReturn(Win16HostMciYieldReturn),
    Operation(Win16HostMciOperationId),
    CompletedOperation(Win16HostMciOperationCompletion),
    NotificationSink,
    OwnerThread,
}

/// Cumulative native evidence and unresolved owners for one quiescence attempt.
#[derive(Clone, Debug)]
pub struct Win16HostMciQuiescenceReceipt {
    pub request: Win16HostMciQuiesceRequest,
    pub status: Win16HostMciQuiescenceStatus,
    pub confirmed: Vec<Win16HostMciQuiescenceEvidence>,
    pub retained: Vec<Win16HostMciRetainedOwner>,
    pub causes: Vec<std::sync::Arc<RuntimeError>>,
    pub resolved_causes: Vec<std::sync::Arc<RuntimeError>>,
}

#[derive(Debug)]
pub struct Win16HostMciQuiescenceFailure {
    pub receipt: Win16HostMciQuiescenceReceipt,
}

impl std::fmt::Display for Win16HostMciQuiescenceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCI native quiescence retained {} owner(s) after confirming {} phase(s)",
            self.receipt.retained.len(),
            self.receipt.confirmed.len()
        )
    }
}

impl std::error::Error for Win16HostMciQuiescenceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receipt
            .causes
            .first()
            .map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciOperationId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciYieldFrame(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMciNotificationId(pub u64);

/// MCI's 0xffff device id means “all devices”; it is distinct from a missing
/// or invalid runtime alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMciTarget {
    All,
    Device(Win16HostMciDevice),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMciValue {
    Ansi(Vec<u8>),
    ResourceId(u32),
    ElementId(u32),
}

/// Native MCI command parameters after all guest pointers and handles have
/// been copied, checked, or translated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMciParameters {
    Null,
    Generic,
    Open {
        device_type: Option<Win16HostMciValue>,
        element: Option<Win16HostMciValue>,
        alias: Option<Vec<u8>>,
        buffer_seconds: Option<u32>,
        style: Option<u32>,
        parent: Option<Win16HostWindow>,
    },
    Play {
        from: u32,
        to: u32,
        speed: Option<u32>,
    },
    Seek {
        to: u32,
    },
    Status {
        item: u32,
        track: u32,
    },
    Info {
        item_flags: u32,
        capacity: Option<u32>,
    },
    GetDeviceCaps {
        item: u32,
    },
    SystemInfo {
        item_flags: u32,
        number: u32,
        device_type: u16,
        capacity: Option<u32>,
    },
    Set {
        time_format: u32,
        audio: u32,
        extension: Win16HostMciSetExtension,
    },
    Record {
        from: u32,
        to: u32,
    },
    Break {
        virtual_key: u16,
        window: Option<Win16HostWindow>,
    },
    File {
        filename: Vec<u8>,
        rectangle: Option<[i16; 4]>,
    },
    Sound {
        name: Vec<u8>,
    },
    Step {
        frames: u32,
    },
    Escape {
        command: Vec<u8>,
    },
    Window {
        window: Option<Win16HostWindow>,
        show_command: u16,
        text: Option<Vec<u8>>,
    },
    Rectangle {
        rectangle: [i16; 4],
        output: bool,
    },
    Delete {
        from: u32,
        to: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMciSetExtension {
    None,
    Wave {
        input: u16,
        output: u16,
        format_tag: u16,
        channels: u16,
        samples_per_second: u32,
        average_bytes_per_second: u32,
        block_align: u16,
        bits_per_sample: u16,
    },
    Sequencer {
        tempo: u32,
        port: u32,
        slave: u32,
        master: u32,
        offset: u32,
    },
}

/// A single call contains scalars, owned text and opaque host identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMciCall {
    SendCommand {
        target: Win16HostMciTarget,
        message: u16,
        flags: u32,
        parameters: Win16HostMciParameters,
        notify_target: Option<Win16HostWindow>,
    },
    SendString {
        command: Vec<u8>,
        output_capacity: Option<u32>,
        callback_target: Option<Win16HostWindow>,
    },
    GetDeviceId {
        name: Vec<u8>,
    },
    GetDeviceIdFromElement {
        element_id: u32,
        device_type: Vec<u8>,
    },
    GetErrorString {
        error: u32,
        capacity: Option<u32>,
    },
    SetDriverData {
        device: Win16HostMciDevice,
        data: u32,
    },
    GetDriverData {
        device: Win16HostMciDevice,
    },
    DriverYield {
        device: Win16HostMciDevice,
    },
    DriverNotify {
        device: Win16HostMciDevice,
        target: Win16HostWindow,
        status: u16,
    },
    SetYieldProc {
        device: Win16HostMciDevice,
        enabled: bool,
        data: u32,
    },
    GetYieldProc {
        device: Win16HostMciDevice,
    },
    CloseDevice {
        device: Win16HostMciDevice,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMciOutput {
    None,
    /// Native MCIDEVICEID UINT(-1), projected to the Win16 all-devices ID.
    All,
    Device {
        device: Win16HostMciDevice,
        device_type: Option<u32>,
    },
    Scalar(u32),
    Bytes(Vec<u8>),
    StringCommand {
        bytes: Vec<u8>,
        opened: Option<(Win16HostMciDevice, Option<u32>)>,
        closed: Option<Win16HostMciDevice>,
        closed_all: bool,
        /// `open` had no explicit alias, so the native device could not be
        /// tied to a stable host-owned token before dispatch.
        unsupported_owner: bool,
    },
    Rectangle([i16; 4]),
    YieldProc {
        installed: bool,
        data: u32,
        registration: Option<Win16HostMciYieldRegistrationId>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostMciResult {
    /// Exact Win32 MCI/MMRESULT or BOOL/UINT result for the operation.
    pub return_value: u32,
    pub output: Win16HostMciOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMciYieldEvent {
    pub operation: Win16HostMciOperationId,
    pub frame: Win16HostMciYieldFrame,
    pub device: Win16HostMciDevice,
    pub registration: Win16HostMciYieldRegistrationId,
    pub data: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMciStep {
    /// The native owner reached an MCI YIELDPROC call and is waiting for this
    /// exact guest callback frame to return.
    Yield(Win16HostMciYieldEvent),
    Complete(Win16HostMciResult),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMciResume {
    pub operation: Win16HostMciOperationId,
    pub frame: Win16HostMciYieldFrame,
    pub return_value: u16,
}

/// Native MM_MCINOTIFY delivery after the host sink has converted HWND and
/// MCIDEVICEID into owned identities. The runtime separately maps the device
/// back to its live guest alias before posting a Win16 message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMciNotification {
    pub id: Win16HostMciNotificationId,
    pub device: Win16HostMciDevice,
    /// Shared USER notification namespace ID, exact device generation, and
    /// this native event's stable MCI notification sequence.
    pub source: Win16GuestNotificationSource,
    pub status: u16,
    pub target: Win16HostWindow,
}
