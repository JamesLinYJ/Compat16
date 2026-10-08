//! Single-thread MCI executor, hidden notification sink, and yield pump.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::super::multimedia_wake::MultimediaWakeSender;
use super::super::guest_text::GuestTextCodec;
use super::super::win16_windows::allocate_shared_identity;
use super::MciNotificationLedger;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMciCall, Win16HostMciDevice,
    Win16HostMciNotificationId, Win16HostMciOperationId, Win16HostMciResume,
    Win16HostMciResumeReceipt, Win16HostMciStep,
    Win16HostMciQuiesceRequest, Win16HostMciQuiescenceEvidence,
    Win16HostMciQuiescenceFailure, Win16HostMciQuiescenceReceipt,
    Win16HostMciQuiescenceStatus,
    Win16HostMciProducerQuiescenceRequest, Win16HostMciProducerQuiescenceReceipt,
    Win16HostMciActiveYield, Win16HostMciRetainedOwner, Win16HostMciYieldEvent,
    Win16HostMciYieldFrame,
    Win16HostMciYieldRegistration,
    Win16HostMciYieldRegistrationId,
    Win16HostMciYieldReturn, Win16HostMciOperationCompletion,
};
use windows_sys::Win32::Foundation::{
    GetLastError, HANDLE, HINSTANCE, HWND, LPARAM, SetLastError, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentThreadId, SetEvent,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GWLP_USERDATA,
    GetWindowLongPtrW, HWND_MESSAGE, IsWindow, MSG, MsgWaitForMultipleObjects, PM_REMOVE,
    PeekMessageW, QS_ALLINPUT, RegisterClassW, SetWindowLongPtrW, TranslateMessage,
    UnregisterClassW, WM_NCCREATE, WM_NCDESTROY, WNDCLASSW,
};

#[path = "win16_mci_worker_context.rs"]
mod context;
#[path = "win16_mci_native.rs"]
mod native;
#[path = "win16_mci_worker_client.rs"]
mod client;
#[path = "win16_mci_worker_error.rs"]
mod error;
#[path = "win16_mci_worker_quarantine.rs"]
mod quarantine;
#[path = "win16_mci_worker_receipt.rs"]
mod receipt;
#[path = "win16_mci_worker_cleanup.rs"]
mod cleanup;
#[path = "win16_mci_worker_registry.rs"]
mod registry;
// Registry types are shared only inside the worker family, never by its owner.
use registry::NativeDeviceRegistry;

const MM_MCINOTIFY: u32 = 0x03b9;
const RETIRE_RETRY: Duration = Duration::from_millis(250);
// Drop can retain one initial drain failure, two shutdown/wake outcomes, and
// one final drain failure. Reserve this bounded ownership before thread start.
const RETAINED_SHUTDOWN_FAILURE_CAPACITY: usize = 8;

static NEXT_WINDOW_CLASS: AtomicU64 = AtomicU64::new(1);
static NEXT_HOST_TOKEN: AtomicU64 = AtomicU64::new(1);

enum WorkerCommand {
    Begin {
        operation: Win16HostMciOperationId,
        call: Win16HostMciCall,
        response: Sender<Result<MciWorkerStep, RuntimeError>>,
    },
    Resume {
        resume: Win16HostMciResume,
        accepted: Sender<Result<(), RuntimeError>>,
    },
    Quiesce {
        request: Win16HostMciQuiesceRequest,
        response: Sender<Result<Win16HostMciQuiescenceReceipt, RuntimeError>>,
    },
    QuiesceProducers {
        request: Win16HostMciProducerQuiescenceRequest,
        response: Sender<Result<Win16HostMciProducerQuiescenceReceipt, RuntimeError>>,
    },
    Shutdown(Sender<Result<MciWorkerShutdownReceipt, RuntimeError>>),
}

#[derive(Clone, Debug)]
pub(super) struct MciWorkerShutdownReceipt {
    closed_devices: Vec<Win16HostMciDevice>,
    disabled_yield_sources: Vec<Win16HostMciQuiescenceEvidence>,
    yield_source_history_complete: bool,
    device_registry_drained: bool,
    notification_ledger_drained: bool,
    notification_window_destroyed: bool,
    notification_class_unregistered: bool,
    owner_loop_returned: bool,
    owner_thread_joined: bool,
    resolved_causes: Vec<Arc<RuntimeError>>,
}

struct PendingOperation {
    response: Receiver<Result<MciWorkerStep, RuntimeError>>,
    frame: Win16HostMciYieldFrame,
    device: Win16HostMciDevice,
    registration: Win16HostMciYieldRegistrationId,
    resume_in_flight: Option<Win16HostMciYieldFrame>,
}

#[derive(Clone, Debug)]
struct MciWorkerStep {
    step: Win16HostMciStep,
    returned_yield: Option<Win16HostMciYieldReturn>,
}

enum DeferredWorkerReceipt {
    Begin {
        operation: Win16HostMciOperationId,
        response: Receiver<Result<MciWorkerStep, RuntimeError>>,
    },
    Resume {
        operation: Win16HostMciOperationId,
        frame: Win16HostMciYieldFrame,
        expected: Win16HostMciYieldReturn,
        accepted: Receiver<Result<(), RuntimeError>>,
    },
    Quiesce {
        request: Win16HostMciQuiesceRequest,
        response: Receiver<Result<Win16HostMciQuiescenceReceipt, RuntimeError>>,
        first_cause: Option<Arc<RuntimeError>>,
        phase: MciQuiescencePhase,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MciQuiescencePhase {
    Enqueued,
    ReceiptReady,
    PreEffectFailure,
    OutcomeUnknown,
}

struct CompletedMciQuiescence {
    request: Win16HostMciQuiesceRequest,
    result: Result<Win16HostMciQuiescenceReceipt, Arc<RuntimeError>>,
    phase: MciQuiescencePhase,
    first_cause: Option<Arc<RuntimeError>>,
    result_delivered: bool,
}

struct PendingMciProducerQuiescence {
    request: Win16HostMciProducerQuiescenceRequest,
    response: Receiver<Result<Win16HostMciProducerQuiescenceReceipt, RuntimeError>>,
    first_cause: Option<Arc<RuntimeError>>,
    prior_causes: Vec<Arc<RuntimeError>>,
}

struct CompletedMciProducerQuiescence {
    request: Win16HostMciProducerQuiescenceRequest,
    result: Option<Result<Win16HostMciProducerQuiescenceReceipt, Arc<RuntimeError>>>,
    first_cause: Option<Arc<RuntimeError>>,
    prior_causes: Vec<Arc<RuntimeError>>,
    outcome_unknown: bool,
}

struct UnclaimedMciOperation {
    operation: Win16HostMciOperationId,
    source_frame: Option<Win16HostMciYieldFrame>,
    outcome: UnclaimedMciOutcome,
}

enum UnclaimedMciOutcome {
    AwaitingYieldResult { expected: Win16HostMciYieldReturn },
    Step(MciWorkerStep),
    UnexpectedBeginStep {
        actual: MciWorkerStep,
        error: Arc<RuntimeError>,
    },
    UnexpectedStep {
        expected: Win16HostMciYieldReturn,
        actual: MciWorkerStep,
        error: Arc<RuntimeError>,
    },
    // Keep the typed failure beside its operation/frame identity so blockers
    // can report it while worker state remains available for cleanup retry.
    Failure {
        error: Arc<RuntimeError>,
        frame: Option<Win16HostMciYieldFrame>,
        submitted_return: Option<Win16HostMciYieldReturn>,
    },
}

pub(super) struct Win16MciWorkerState {
    sender: Sender<WorkerCommand>,
    wake_event: Arc<OwnedHandle>,
    // Keep the typed notification-failure ledger with any client quarantined
    // after an entered native yield can no longer return to its worker loop.
    notifications: Arc<Mutex<MciNotificationLedger>>,
    thread_id: u32,
    thread: Option<JoinHandle<()>>,
    next_operation: u64,
    pending: HashMap<Win16HostMciOperationId, PendingOperation>,
    deferred_receipts: Vec<DeferredWorkerReceipt>,
    completed_quiescences: Vec<CompletedMciQuiescence>,
    pending_producer_quiescence: Option<PendingMciProducerQuiescence>,
    completed_producer_quiescence: Option<CompletedMciProducerQuiescence>,
    shutdown_receipt: Option<MciWorkerShutdownReceipt>,
    shutdown_progress: Arc<Mutex<Option<MciWorkerShutdownReceipt>>>,
    unclaimed: Vec<UnclaimedMciOperation>,
    shutdown_failures: Vec<Arc<RuntimeError>>,
}

pub(super) struct Win16MciWorker {
    state: Option<Win16MciWorkerState>,
    quarantine_slot: usize,
}

struct MciWorkerQuarantineSlot {
    reserved: bool,
    worker_loop_returned: bool,
    worker_thread_joined: bool,
    worker_shutdown_receipt_valid: bool,
    owner: Option<Win16MciWorkerState>,
}

impl Deref for Win16MciWorker {
    type Target = Win16MciWorkerState;

    fn deref(&self) -> &Self::Target {
        self.state
            .as_ref()
            .expect("MCI worker client state is present until Drop transfers its owner")
    }
}

impl DerefMut for Win16MciWorker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state
            .as_mut()
            .expect("MCI worker client state is present until Drop transfers its owner")
    }
}

struct WorkerThreadState {
    receiver: RefCell<Receiver<WorkerCommand>>,
    wake_event: Arc<OwnedHandle>,
    multimedia_wake: MultimediaWakeSender,
    notifications: Arc<Mutex<MciNotificationLedger>>,
    devices: Arc<Mutex<NativeDeviceRegistry>>,
    identity_source: Arc<AtomicU64>,
    text_codec: GuestTextCodec,
    resumes: RefCell<HashMap<(Win16HostMciOperationId, Win16HostMciYieldFrame), u16>>,
    returned_yields: RefCell<Vec<Win16HostMciYieldReturn>>,
    completed_operations: RefCell<Vec<Win16HostMciOperationCompletion>>,
    yield_source_evidence: RefCell<Vec<Win16HostMciQuiescenceEvidence>>,
    next_frame: AtomicU64,
    shutdown_requested: Cell<bool>,
    producer_admission_closed: Cell<bool>,
    shutdown_response: RefCell<Option<Sender<Result<MciWorkerShutdownReceipt, RuntimeError>>>>,
    shutdown_failure: RefCell<Option<Arc<RuntimeError>>>,
    sink: HWND,
}

struct YieldInvocation {
    state: Arc<WorkerThreadState>,
    operation: Win16HostMciOperationId,
    response: Sender<Result<MciWorkerStep, RuntimeError>>,
    failure_slot: Arc<MciEnteredYieldFailureSlot>,
    active_yield: Option<Win16HostMciActiveYield>,
    last_returned_yield: Option<Win16HostMciYieldReturn>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MciEnteredYieldFailurePhase {
    ResolveNativeDevice,
    ResolveRegistration,
    AllocateFrameIdentity,
    ReserveReturnReceipt,
    DeliverYieldStep,
}

#[derive(Clone, Debug)]
pub(super) enum MciEnteredYieldFailureCause {
    NativeDeviceUnowned,
    RegistrationMissing,
    FrameIdentityExhausted,
    ReturnReceiptAllocation(Arc<RuntimeError>),
    YieldResponseDisconnected(Arc<RuntimeError>),
}

#[derive(Clone, Debug)]
pub(super) struct MciEnteredYieldFailure {
    pub(super) operation: Win16HostMciOperationId,
    pub(super) native_device: u32,
    pub(super) device: Option<Win16HostMciDevice>,
    pub(super) registration: Option<Win16HostMciYieldRegistrationId>,
    pub(super) frame: Option<Win16HostMciYieldFrame>,
    pub(super) data: u32,
    pub(super) phase: MciEnteredYieldFailurePhase,
    cause: MciEnteredYieldFailureCause,
    pub(super) returned_yield: Option<Win16HostMciYieldReturn>,
}

impl MciEnteredYieldFailure {
    pub(super) fn kind(&self) -> Kind {
        match &self.cause {
            MciEnteredYieldFailureCause::NativeDeviceUnowned
            | MciEnteredYieldFailureCause::RegistrationMissing => Kind::InternalInvariant,
            MciEnteredYieldFailureCause::FrameIdentityExhausted => Kind::ResourceExhausted,
            MciEnteredYieldFailureCause::ReturnReceiptAllocation(error)
            | MciEnteredYieldFailureCause::YieldResponseDisconnected(error) => error.kind(),
        }
    }
}

impl fmt::Display for MciEnteredYieldFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            MciEnteredYieldFailurePhase::ResolveNativeDevice => "resolve native device",
            MciEnteredYieldFailurePhase::ResolveRegistration => "resolve yield registration",
            MciEnteredYieldFailurePhase::AllocateFrameIdentity => "allocate yield frame identity",
            MciEnteredYieldFailurePhase::ReserveReturnReceipt => "reserve return receipt",
            MciEnteredYieldFailurePhase::DeliverYieldStep => "deliver yield step",
        };
        let (cause, detail) = match &self.cause {
            MciEnteredYieldFailureCause::NativeDeviceUnowned => ("native device is unowned", None),
            MciEnteredYieldFailureCause::RegistrationMissing => ("yield registration is missing", None),
            MciEnteredYieldFailureCause::FrameIdentityExhausted => {
                ("yield frame identity space is exhausted", None)
            }
            MciEnteredYieldFailureCause::ReturnReceiptAllocation(error) => (
                "return receipt allocation failed",
                Some(error.as_ref()),
            ),
            MciEnteredYieldFailureCause::YieldResponseDisconnected(error) => (
                "yield response channel is disconnected",
                Some(error.as_ref()),
            ),
        };
        write!(
            formatter,
            "MCI operation {} entered YIELDPROC for native device {} during {}: {}",
            self.operation.0, self.native_device, phase, cause
        )?;
        if let Some(device) = self.device {
            write!(formatter, "; host device token {} generation {}", device.token, device.generation)?;
        }
        if let Some(registration) = self.registration {
            write!(formatter, "; yield registration {}", registration.0)?;
        }
        if let Some(frame) = self.frame {
            write!(formatter, "; yield frame {}", frame.0)?;
        }
        write!(formatter, "; callback data 0x{:08X}", self.data)?;
        if let Some(returned) = self.returned_yield {
            write!(
                formatter,
                "; prior returned yield operation {} frame {} with guest WORD 0x{:04X}",
                returned.owner.operation.0, returned.owner.frame.0, returned.guest_return
            )?;
        }
        if let Some(detail) = detail {
            write!(formatter, "; cause: {detail}")?;
        }
        Ok(())
    }
}

impl Error for MciEnteredYieldFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            MciEnteredYieldFailureCause::ReturnReceiptAllocation(error)
            | MciEnteredYieldFailureCause::YieldResponseDisconnected(error) => {
                Some(error.as_ref())
            }
            _ => None,
        }
    }
}

pub(super) fn entered_yield_failure(error: &RuntimeError) -> Option<MciEnteredYieldFailure> {
    let mut current = Some(error as &(dyn Error + 'static));
    while let Some(source) = current {
        if let Some(failure) = source.downcast_ref::<MciEnteredYieldFailure>() {
            return Some(failure.clone());
        }
        current = source.source();
    }
    None
}

// Allocate this fixed first-failure slot before entering WinMM. A failed
// callback must not need to grow a receipt vector before it can be retained.
pub(super) struct MciEnteredYieldFailureSlot(Mutex<Option<MciEnteredYieldFailure>>);

impl MciEnteredYieldFailureSlot {
    pub(super) fn retain_first(&self, failure: MciEnteredYieldFailure) -> MciEnteredYieldFailure {
        let mut first = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if first.is_none() {
            *first = Some(failure);
        }
        first
            .as_ref()
            .expect("the entered-yield first-failure slot was just retained")
            .clone()
    }
}

thread_local! {
    static ACTIVE_YIELDS: RefCell<Vec<YieldInvocation>> = const { RefCell::new(Vec::new()) };
}

struct NotifyWindowContext {
    notifications: Arc<Mutex<MciNotificationLedger>>,
    devices: Arc<Mutex<NativeDeviceRegistry>>,
    multimedia_wake: MultimediaWakeSender,
}

struct MciNativeContext {
    state: Arc<WorkerThreadState>,
}

impl WorkerThreadState {
    pub(super) fn prior_yield_source_evidence(
        &self,
        owner: Win16HostMciYieldRegistration,
    ) -> Option<Win16HostMciQuiescenceEvidence> {
        self.yield_source_evidence
            .borrow()
            .iter()
            .find(|evidence| {
                matches!(
                    evidence,
                    Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                        owner: current,
                        observed_installed: false,
                        ..
                    } if *current == owner
                )
            })
            .cloned()
    }

    pub(super) fn reserve_yield_source_evidence(
        &self,
        owner: Win16HostMciYieldRegistration,
    ) -> Result<bool, RuntimeError> {
        if self.prior_yield_source_evidence(owner).is_some() {
            return Ok(false);
        }
        self.yield_source_evidence
            .borrow_mut()
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact MCI yield-source retirement receipt before native disable",
                    error,
                )
            })?;
        Ok(true)
    }

    pub(super) fn reserve_yield_source_evidence_batch(
        &self,
        owners: &[Win16HostMciYieldRegistration],
    ) -> Result<(), RuntimeError> {
        let mut evidence = self.yield_source_evidence.borrow_mut();
        let needed = owners
            .iter()
            .filter(|owner| {
                !evidence.iter().any(|current| {
                    matches!(
                        current,
                        Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                            owner: recorded,
                            observed_installed: false,
                            ..
                        } if recorded == *owner
                    )
                })
            })
            .count();
        evidence.try_reserve(needed).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact MCI yield-source receipt batch before native disable",
                error,
            )
        })
    }

    pub(super) fn record_yield_source_evidence(
        &self,
        evidence: Win16HostMciQuiescenceEvidence,
    ) {
        self.yield_source_evidence.borrow_mut().push(evidence);
    }

    pub(super) fn reserve_yield_registration(
        &self,
        device: Win16HostMciDevice,
    ) -> Result<Win16HostMciYieldRegistrationId, RuntimeError> {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reserve_yield_registration(device)
    }

    pub(super) fn publish_yield_registration(
        &self,
        device: Win16HostMciDevice,
        registration: Win16HostMciYieldRegistrationId,
    ) {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .publish_yield_registration(device, registration);
    }

    pub(super) fn current_yield_registration(
        &self,
        device: Win16HostMciDevice,
    ) -> Option<Win16HostMciYieldRegistrationId> {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .current_yield_registration(device)
    }

    pub(super) fn retire_yield_registration(
        &self,
        device: Win16HostMciDevice,
        registration: Win16HostMciYieldRegistrationId,
    ) -> Result<(), RuntimeError> {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retire_yield_registration(device, registration)
    }

    pub(super) fn reserve_device_slot(&self) -> Result<u64, RuntimeError> {
        // Allocate before native OPEN can synchronously deliver its first
        // notification. A rejected open may leave a harmless identity gap.
        let source_id = allocate_shared_identity(&self.identity_source)?;
        let mut devices = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
        devices.by_native.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI device identity before open",
                error,
            )
        })?;
        devices.by_identity.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI reverse identity before open",
                error,
            )
        })?;
        devices.generations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI generation before open",
                error,
            )
        })?;
        let retired_identity_capacity = devices.by_identity.len().saturating_add(1);
        devices
            .retired_identities
            .try_reserve(retired_identity_capacity)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve native MCI tombstone before open notification can allocate identity",
                    error,
                )
            })?;
        devices.orphan_aliases.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI orphan-alias owner before open",
                error,
            )
        })?;
        devices.orphan_native_ids.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI orphan-ID owner before open",
                error,
            )
        })?;
        Ok(source_id)
    }

    fn native_id(&self, identity: Win16HostMciDevice) -> Result<(u32, Option<u32>), RuntimeError> {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .resolve(identity)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "MCI request references a retired or foreign host device token",
                )
            })
    }

    fn register_device(
        &self,
        native_id: u32,
        device_type: Option<u32>,
        reserved_source_id: Option<u64>,
    ) -> Result<Win16HostMciDevice, RuntimeError> {
        let existing_source_id = self
            .devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_native
            .get(&native_id)
            .map(|device| device.notification_source_id);
        let source_id = match (reserved_source_id, existing_source_id) {
            (Some(reserved), Some(existing)) if reserved != existing => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native MCI OPEN source reservation changed before device registration",
                ));
            }
            (Some(reserved), _) => reserved,
            (None, Some(existing)) => existing,
            (None, None) => allocate_shared_identity(&self.identity_source)?,
        };
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .identity(native_id, device_type, source_id)
    }

    pub(super) fn notification_source_id(
        &self,
        identity: Win16HostMciDevice,
    ) -> Result<u64, RuntimeError> {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .notification_source_id(identity)
            .filter(|id| *id != 0 && *id != u64::MAX)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "native MCI notification source has no exact live device owner",
                )
            })
    }

    fn retire_device(&self, identity: Win16HostMciDevice) -> Result<(), RuntimeError> {
        let mut devices = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
        if devices.current_yield_registration(identity).is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI device cannot retire while its exact yield-source registration remains live",
            ));
        }
        devices.forget(identity);
        Ok(())
    }

    fn retire_all_devices(&self) -> Result<(), RuntimeError> {
        let mut devices = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
        if !devices.yield_registrations.is_empty() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI close-all cannot retire devices while yield-source registrations remain live",
            ));
        }
        devices.retire_every_live_identity();
        // A successful MCI string `close all` covers rollback aliases and raw
        // IDs retained after earlier bookkeeping failures as well.
        devices.orphan_aliases.clear();
        devices.orphan_native_ids.clear();
        Ok(())
    }

    fn device_type(&self, native_id: u32) -> Option<u32> {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_native
            .get(&native_id)
            .and_then(|entry| entry.device_type)
    }

    pub(super) fn existing_identity(&self, native_id: u32) -> Option<Win16HostMciDevice> {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .existing_identity(native_id)
    }

    pub(super) fn retain_orphan_alias(&self, alias: Vec<u8>) {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain_orphan_alias(alias);
    }

    pub(super) fn retain_orphan_native_id(&self, native_id: u32) {
        self.devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain_orphan_native_id(native_id);
    }
}

#[path = "win16_mci_worker_loop.rs"]
mod worker_loop;
