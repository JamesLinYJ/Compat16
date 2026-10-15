//! Owned message payloads at the WOW/host boundary.
//!
//! Neither a guest address nor a native pointer is represented by these types.
//! Add a distinct variant for messages with handles or nested structures.

use crate::{RuntimeError, Win16HostBrush, Win16HostClass, Win16HostDc, Win16HostMenu, Win16HostWindow};
use std::sync::Arc;

/// The exact guest-facing class spelling used when rebuilding CREATESTRUCT16.
/// An atom remains a WORD atom; a name is copied ANSI data owned by runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostClassName {
    Name(Vec<u8>),
    Atom(u16),
}

/// Standard USER message families with an available pointer-free conversion.
/// Callers must validate conditional fields before constructing one; WM_TIMER,
/// for example, is scalar only when its callback LPARAM is null. Values are
/// the Windows SDK WM_* identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Win16ScalarMessage {
    Null = 0x0000,
    Destroy = 0x0002,
    Move = 0x0003,
    Size = 0x0005,
    Enable = 0x000a,
    SetRedraw = 0x000b,
    Paint = 0x000f,
    Close = 0x0010,
    /// System session query; LPARAM is a modern end-session option bitmask.
    QueryEndSession = 0x0011,
    /// Pointer-free restore query; a zero WndProc result vetoes opening the icon.
    QueryOpen = 0x0013,
    /// SDK WM_SYSCOLORCHANGE carries no pointer or handle parameters.
    SystemColorChange = 0x0015,
    /// End-session result; WPARAM is BOOL and LPARAM carries session options.
    EndSession = 0x0016,
    ShowWindow = 0x0018,
    /// SDK font-pool notification; both parameters are unused.
    FontChange = 0x001d,
    /// SDK system-time notification; both parameters are unused.
    TimeChange = 0x001e,
    CancelMode = 0x001f,
    NcDestroy = 0x0082,
    NcHitTest = 0x0084,
    KeyDown = 0x0100,
    KeyUp = 0x0101,
    Char = 0x0102,
    DeadChar = 0x0103,
    SysKeyDown = 0x0104,
    SysKeyUp = 0x0105,
    SysChar = 0x0106,
    SysDeadChar = 0x0107,
    /// WM_TIMER delivered to a window procedure. Synchronous SendMessage
    /// preserves LPARAM as scalar data. Queued DispatchMessage treats a
    /// non-null LPARAM as a guest FARPROC or private native TIMERPROC through
    /// a separate, source-aware callback path.
    Timer = 0x0113,
    MouseMove = 0x0200,
    LeftButtonDown = 0x0201,
    LeftButtonUp = 0x0202,
    LeftButtonDoubleClick = 0x0203,
    RightButtonDown = 0x0204,
    RightButtonUp = 0x0205,
    RightButtonDoubleClick = 0x0206,
    MiddleButtonDown = 0x0207,
    MiddleButtonUp = 0x0208,
    MiddleButtonDoubleClick = 0x0209,
    DestroyClipboard = 0x0307,
    DrawClipboard = 0x0308,
}

impl Win16ScalarMessage {
    /// Broadcast reaches native windows without a guest procedure identity.
    /// The optional paint HDC and timer FARPROC need a lifetime/provenance
    /// adapter; their nonzero forms are not scalar broadcast parameters.
    pub const fn broadcast_parameters_are_scalar(self, w_param: u16, l_param: u32) -> bool {
        match self {
            Self::Paint => w_param == 0,
            Self::Timer => l_param == 0,
            _ => true,
        }
    }

    pub fn from_raw(message: u16) -> Option<Self> {
        Some(match message {
            0x0000 => Self::Null,
            0x0002 => Self::Destroy,
            0x0003 => Self::Move,
            0x0005 => Self::Size,
            0x000a => Self::Enable,
            0x000b => Self::SetRedraw,
            0x000f => Self::Paint,
            0x0010 => Self::Close,
            0x0011 => Self::QueryEndSession,
            0x0013 => Self::QueryOpen,
            0x0015 => Self::SystemColorChange,
            0x0016 => Self::EndSession,
            0x0018 => Self::ShowWindow,
            0x001d => Self::FontChange,
            0x001e => Self::TimeChange,
            0x001f => Self::CancelMode,
            0x0082 => Self::NcDestroy,
            0x0084 => Self::NcHitTest,
            0x0100 => Self::KeyDown,
            0x0101 => Self::KeyUp,
            0x0102 => Self::Char,
            0x0103 => Self::DeadChar,
            0x0104 => Self::SysKeyDown,
            0x0105 => Self::SysKeyUp,
            0x0106 => Self::SysChar,
            0x0107 => Self::SysDeadChar,
            0x0113 => Self::Timer,
            0x0200 => Self::MouseMove,
            0x0201 => Self::LeftButtonDown,
            0x0202 => Self::LeftButtonUp,
            0x0203 => Self::LeftButtonDoubleClick,
            0x0204 => Self::RightButtonDown,
            0x0205 => Self::RightButtonUp,
            0x0206 => Self::RightButtonDoubleClick,
            0x0207 => Self::MiddleButtonDown,
            0x0208 => Self::MiddleButtonUp,
            0x0209 => Self::MiddleButtonDoubleClick,
            0x0307 => Self::DestroyClipboard,
            0x0308 => Self::DrawClipboard,
            // Multimedia notifications use their source-aware carrier. A
            // WAVEHDR16 FAR or native WAVEHDR cannot be forwarded as scalar.
            _ => return None,
        })
    }
}

#[path = "win16_host_message_payloads.rs"]
mod payloads;
pub use payloads::{
    Win16HostCreationData, Win16HostDialogMessage, Win16HostMdiChildCreation, Win16HostMessage,
    Win16HostMessageOutput, Win16HostMessageResult, Win16HostStaticIconOperation,
    Win16HostStaticIconResult,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostPoint {
    pub x: i32,
    pub y: i32,
}

/// Native WM_DROPFILES data after the worker has copied and released HDROP.
/// Paths are NUL-free strings encoded with this guest's configured ANSI page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDropFiles {
    pub paths: Vec<Vec<u8>>,
    pub point: Win16HostPoint,
    pub in_client_area: bool,
}

/// Exact worker-owned identity for one queued native WM_DROPFILES record.
/// It is never a guest HGLOBAL or an HDROP pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDropFilesLease(pub u64);

/// Copied WM_DROPFILES content paired with its exact native queue lease.
/// `native_removed` transitions monotonically when PM_REMOVE transfers the
/// copied data to the guest; repeated PM_NOREMOVE calls reuse the same lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostQueuedDropFiles {
    pub lease: Win16HostDropFilesLease,
    pub native_removed: bool,
    pub files: Win16HostDropFiles,
}

/// Receipt that native USER no longer owns one exact WM_DROPFILES lease.
/// Receipt acknowledgement is transport bookkeeping; it does not resume a
/// window callback or acknowledge an operation source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDropRetirementReceipt {
    pub lease: Win16HostDropFilesLease,
    pub window: crate::Win16HostWindow,
}

/// One GetMessage/PeekMessage result. Drop data is separate from MSG's scalar
/// fields because Win16 LPARAM is a runtime-owned HGLOBAL, never native HDROP.
#[derive(Clone, Debug)]
pub struct Win16HostQueuedDelivery {
    pub message: Option<Win16HostQueuedMessage>,
    pub drop_files: Option<Win16HostQueuedDropFiles>,
}

impl Win16HostQueuedDelivery {
    pub fn message(message: Win16HostQueuedMessage) -> Self {
        Self { message: Some(message), drop_files: None }
    }

    pub fn empty() -> Self {
        Self { message: None, drop_files: None }
    }
}

/// Copied Win16 USER rectangle coordinates. This is the sole runtime/host
/// rectangle representation; native RECT and Win16 RECT16 stay at adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Pointer-free result of BeginPaint/GetDC-family USER calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostPaintInfo {
    pub erase: bool,
    pub rect: Win16HostRect,
    pub restore: bool,
    pub inc_update: bool,
    pub reserved: [u8; 16],
}

/// Provenance for a message crossing the runtime/host boundary. A native MSG
/// belongs to the worker's USER queue; a guest MSG contains only guest ABI
/// values and must never be interpreted as native pointers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MessageSource {
    NativeQueue,
    GuestMessage,
    GuestNotification,
}

/// Host USER queue incarnation bound to one exact Win16 task identity. This
/// opaque value is not a native thread ID and cannot be constructed from an
/// HTASK word.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostTaskQueue(pub u64);

/// Win16 WM_ACTIVATEAPP refers to an HTASK, while native USER supplies a
/// thread ID. A queue token is usable only for the exact currently bound task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostActivationApp {
    pub active: u16,
    pub other_task_queue: Option<Win16HostTaskQueue>,
}

/// WM_PARENTNOTIFY has two native layouts: child creation/destruction carries
/// an HWND and child ID; button-down notifications carry packed coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostParentNotificationData {
    Child { child: Option<Win16HostWindow>, id: u16 },
    Mouse { coordinates: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostParentNotification {
    pub event: u16,
    pub data: Win16HostParentNotificationData,
}

/// The seven native WM_CTLCOLOR* messages share Win16's WM_CTLCOLOR, with the
/// type carried in LPARAM. HDC/HWND identities stay opaque through runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostControlColor {
    pub kind: u16,
    pub dc: Option<Win16HostDc>,
    pub control: Option<Win16HostWindow>,
}

/// Return data after checking a guest HBRUSH16. Invalid nonzero guest handles
/// are distinct from the valid null HBRUSH and are never sent as host handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostControlColorBrush {
    Null,
    Brush(Win16HostBrush),
    Invalid(u16),
}

/// Stable producer receipt identity. IDs share one source namespace; the
/// maximum u64 value is reserved for runtime-owned PostAppMessage records.
/// Every other producer must use a nonzero counter, compute its next value
/// with checked addition before committing, and issue only the old counter
/// value returned by that checked update. When the stored counter reaches
/// `u64::MAX`, allocation fails and that reserved value is never issued.
/// `sequence` is monotonic within the exact source generation; retries reuse
/// it until a successful native post, and exhaustion must fail instead of
/// wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16GuestNotificationSource {
    pub id: u64,
    pub generation: u64,
    pub sequence: u64,
}

/// Reserved source ID for runtime-owned PostAppMessage receipts. Host source
/// allocators use checked-next-before-issue counters and cannot issue MAX.
pub const WIN16_APP_MESSAGE_NOTIFICATION_SOURCE_ID: u64 = u64::MAX;

/// Exact guest destination for an owned asynchronous notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16GuestNotificationTarget {
    /// `guest_hwnd` is the alias observed for this exact host window token at
    /// enqueue time. Readback must use this alias directly and never remap the
    /// host token to a later guest handle incarnation.
    Window {
        window: Win16HostWindow,
        guest_hwnd: u16,
    },
    /// A task queue can be used only when all four identity fields match the
    /// worker's live binding. HTASK is never a native thread ID.
    Task {
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
        queue: Win16HostTaskQueue,
    },
}

/// Owned, pointer-free guest message data. In particular `l_param` is a
/// numeric Win16 value (possibly a FAR encoding), never a host pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16GuestNotification {
    pub target: Win16GuestNotificationTarget,
    pub source: Win16GuestNotificationSource,
    pub message: u16,
    pub w_param: u16,
    pub l_param: u32,
}

/// Win16 multimedia callback messages whose LPARAM is a guest FAR to a
/// WAVEHDR16 or MIDIHDR16. The values follow the Windows 3.1 SDK
/// `files/include/MMSYSTEM.H`; they must never be passed to native USER.
pub const fn multimedia_notification_has_guest_far_lparam(message: u16) -> bool {
    matches!(message, 0x03bd | 0x03c0 | 0x03c4 | 0x03c6 | 0x03c9)
}

/// The Win16 multimedia callback messages. Messages not listed by
/// `multimedia_notification_has_guest_far_lparam` carry scalar LPARAM data.
pub const fn is_multimedia_notification_message(message: u16) -> bool {
    // Windows 3.1 MMSYSTEM.H defines MM_MCINOTIFY separately from the
    // WAVE/MIDI range. Its LPARAM is a device ID, not a guest pointer.
    const MM_MCINOTIFY: u16 = 0x03b9;
    message == MM_MCINOTIFY || (message >= 0x03bb && message <= 0x03c9)
}

/// Provenance retained by the host sidecar until exact PM_REMOVE consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16GuestNotificationProvenance {
    pub target: Win16GuestNotificationTarget,
    pub source: Win16GuestNotificationSource,
}

/// LPARAM representation for a message operation. `Scalar` is a message
/// family whose LPARAM is numeric. `GuestBits` preserves guest MSG bits for
/// APIs such as TranslateMessage that do not dereference LPARAM; native
/// DispatchMessage must never treat it as a host pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MessageParam {
    WindowInput(crate::Win16WindowInputMessage),
    ActivationApp(Win16HostActivationApp),
    ParentNotification(Win16HostParentNotification),
    ControlColor(Win16HostControlColor),
    Scalar(u32),
    GuestBits(u32),
    /// Exact host-owned notification sidecar. This is separate from GuestBits
    /// so low-numbered multimedia messages do not broaden pointer handling.
    GuestNotification {
        provenance: Win16GuestNotificationProvenance,
        l_param: u32,
    },
    /// WM_COMMAND has a typed control HWND in LPARAM for control
    /// notifications. `None` denotes menu and accelerator notifications.
    Command {
        control: Option<Win16HostWindow>,
        notify: u16,
        /// Actual native parent copied at the source; never infer it from a receiver.
        control_parent: Option<Win16HostWindow>,
    },
    /// WM_CHANGECBCHAIN replaces two native HWNDs with opaque identities.
    ClipboardChainChange {
        removed: Option<Win16HostWindow>,
        next: Option<Win16HostWindow>,
    },
    /// Native WM_TIMER uses a host-sized timer identity in WPARAM. Runtime
    /// maps it back to the registered Win16 timer id and callback FAR value.
    TimerHostId(u64),
    /// A typed MDI queue payload whose native HWND/HMENU fields were copied
    /// into opaque identities by the host adapter.
    Mdi(crate::Win16HostMdiQueuedMessage),
}

/// An owned Win16-compatible view of a native or guest message. The HWND is
/// either a runtime-owned opaque token or null; no native HWND crosses here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostQueuedMessage {
    pub source: Win16MessageSource,
    pub window: Option<Win16HostWindow>,
    pub message: u16,
    pub w_param: u16,
    pub l_param: Win16MessageParam,
    pub time: u32,
    pub point: Win16HostPoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MessageWindow {
    /// Win16 HWND 0: all messages belonging to the current task/thread.
    Any,
    /// Retrieve thread messages only (the native API's thread-only filter).
    ThreadOnly,
    /// A checked host-window token corresponding to a guest HWND16.
    Window(Win16HostWindow),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MessageFilter {
    pub window: Win16MessageWindow,
    pub min_message: u16,
    pub max_message: u16,
    /// Exact task queue incarnation for this Win16 USER call. A worker never
    /// substitutes whichever native queue happens to be current.
    pub task_queue: Option<Win16HostTaskQueue>,
}

/// Copied geometry for WM_GETMINMAXINFO, independent of either ABI's layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMinMaxInfo {
    pub reserved: Win16HostPoint,
    pub max_size: Win16HostPoint,
    pub max_position: Win16HostPoint,
    pub min_track_size: Win16HostPoint,
    pub max_track_size: Win16HostPoint,
}

/// An owned request whose completion may follow synchronous guest callbacks.
#[derive(Debug)]
pub enum Win16WindowOperation {
    /// Pointer-free DDEML call executed on the same owner-thread continuation
    /// pump as USER. Guest handles remain runtime-only tokens.
    Dde(crate::Win16HostDdeCall),
    Thunk(crate::Win16ThunkOperation),
    Create {
        creation: Win16CreationId,
        data: Win16HostCreationData,
    },
    Menu(crate::Win16MenuOperation),
    WindowCall(crate::Win16WindowCall),
    MessageCall(crate::Win16MessageCall),
    UserService(crate::Win16HostUserServiceOperation),
    CommonControls(crate::Win16HostCommonControlsOperation),
    CommonDialog(crate::Win16HostCommonDialogOperation),
    UpdateRegion(crate::Win16HostUpdateOperation),
    ScrollBar(crate::Win16HostScrollBarOperation),
    UserCursorAccelerator(crate::Win16HostUserCursorAcceleratorOperation),
    ShellExecution(crate::Win16HostShellExecutionOperation),
    BeginPaint {
        window: Win16HostWindow,
    },
    EndPaint {
        window: Win16HostWindow,
        dc: Win16HostDc,
        info: Win16HostPaintInfo,
    },
    AcquireWindowDc {
        window: Option<Win16HostWindow>,
        whole_window: bool,
    },
    AcquireWindowDcEx {
        window: Win16HostWindow,
        region: Option<crate::Win16HostGdiObject>,
        flags: u32,
    },
    ReleaseWindowDc {
        window: Option<Win16HostWindow>,
        dc: Win16HostDc,
    },
    Default {
        window: Win16HostWindow,
        callback: Option<Win16HostCallback>,
        message: Win16HostMessage,
    },
    DefFrameProc {
        frame: Win16HostWindow,
        mdi_client: Option<Win16HostWindow>,
        callback: Option<Win16HostCallback>,
        message: Win16HostMessage,
    },
    TranslateMDISysAccel {
        mdi_client: Win16HostWindow,
        message: Win16HostQueuedMessage,
    },
    DefaultMdiChild {
        window: Win16HostWindow,
        callback: Option<Win16HostCallback>,
        message: Win16HostMessage,
    },
    /// Synchronous text delivery with owned buffers and explicit output copyback.
    Send {
        window: Win16HostWindow,
        message: Win16HostMessage,
    },
    StaticIcon {
        window: Win16HostWindow,
        procedure: Option<crate::Win16HostProcedure>,
        operation: Win16HostStaticIconOperation,
    },
    QueryProcedure {
        window: Win16HostWindow,
    },
    QuerySubclassProcedure {
        window: Win16HostWindow,
    },
    /// Installation follows a completed query: the guest already owns its
    /// callable old-procedure gate before the native window changes.
    SetProcedure {
        window: Win16HostWindow,
        previous: crate::Win16HostProcedure,
        restore: bool,
    },
    CallProcedure {
        procedure: crate::Win16HostProcedure,
        window: Win16HostWindow,
        /// Exact suspended native callback, when this forwards the current
        /// message. A new SendMessage does not inherit this capability.
        callback: Option<Win16HostCallback>,
        message: Win16HostMessage,
    },
    Show {
        window: Win16HostWindow,
        command: i16,
    },
    Destroy {
        window: Win16HostWindow,
    },
    SetWindowText {
        window: Win16HostWindow,
        text: Option<Vec<u8>>,
    },
    GetWindowText {
        window: Win16HostWindow,
        buffer: Vec<u8>,
    },
    GetWindowTextLength {
        window: Win16HostWindow,
    },
    GetMessage {
        filter: Win16MessageFilter,
    },
    PeekMessage {
        filter: Win16MessageFilter,
        flags: u16,
    },
    PostGuestNotification(Win16GuestNotification),
    TranslateMessage {
        message: Win16HostQueuedMessage,
    },
    DispatchMessage {
        message: Win16HostQueuedMessage,
    },
    PostQuitMessage {
        exit_code: u16,
    },
}

/// Stable source class retained by the native worker for terminal proof.
/// The operation id remains the unique identity; this tag lets the runtime
/// verify that the proof belongs to the continuation it actually started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16NativeWindowOperationKind {
    DefaultMdiChild,
    DefFrameProc,
    TranslateMDISysAccel,
    Dde,
    Thunk,
    Create,
    Menu,
    WindowCall,
    MessageCall,
    UserService,
    CommonControls,
    CommonDialog,
    UpdateRegion,
    ScrollBar,
    UserCursorAccelerator,
    ShellExecution,
    BeginPaint,
    EndPaint,
    AcquireWindowDc,
    ReleaseWindowDc,
    Default,
    Send,
    StaticIcon,
    QueryProcedure,
    SetProcedure,
    CallProcedure,
    Show,
    Destroy,
    SetWindowText,
    GetWindowText,
    GetWindowTextLength,
    GetMessage,
    PeekMessage,
    PostGuestNotification,
    TranslateMessage,
    DispatchMessage,
    PostQuitMessage,
}

impl Win16WindowOperation {
    pub fn native_operation_kind(&self) -> Win16NativeWindowOperationKind {
        use Win16NativeWindowOperationKind as Kind;
        match self {
            Self::DefFrameProc { .. } => Kind::DefFrameProc,
            Self::DefaultMdiChild { .. } => Kind::DefaultMdiChild,
            Self::TranslateMDISysAccel { .. } => Kind::TranslateMDISysAccel,
            Self::Dde(_) => Kind::Dde,
            Self::Thunk(_) => Kind::Thunk,
            Self::Create { .. } => Kind::Create,
            Self::Menu(_) => Kind::Menu,
            Self::WindowCall(_) => Kind::WindowCall,
            Self::MessageCall(_) => Kind::MessageCall,
            Self::UserService(_) => Kind::UserService,
            Self::CommonControls(_) => Kind::CommonControls,
            Self::CommonDialog(_) => Kind::CommonDialog,
            Self::UpdateRegion(_) => Kind::UpdateRegion,
            Self::ScrollBar(_) => Kind::ScrollBar,
            Self::UserCursorAccelerator(_) => Kind::UserCursorAccelerator,
            Self::ShellExecution(_) => Kind::ShellExecution,
            Self::BeginPaint { .. } => Kind::BeginPaint,
            Self::EndPaint { .. } => Kind::EndPaint,
            Self::AcquireWindowDc { .. } | Self::AcquireWindowDcEx { .. } => Kind::AcquireWindowDc,
            Self::ReleaseWindowDc { .. } => Kind::ReleaseWindowDc,
            Self::Default { .. } => Kind::Default,
            Self::Send { .. } => Kind::Send,
            Self::StaticIcon { .. } => Kind::StaticIcon,
            Self::QueryProcedure { .. } | Self::QuerySubclassProcedure { .. } => Kind::QueryProcedure,
            Self::SetProcedure { .. } => Kind::SetProcedure,
            Self::CallProcedure { .. } => Kind::CallProcedure,
            Self::Show { .. } => Kind::Show,
            Self::Destroy { .. } => Kind::Destroy,
            Self::SetWindowText { .. } => Kind::SetWindowText,
            Self::GetWindowText { .. } => Kind::GetWindowText,
            Self::GetWindowTextLength { .. } => Kind::GetWindowTextLength,
            Self::GetMessage { .. } => Kind::GetMessage,
            Self::PeekMessage { .. } => Kind::PeekMessage,
            Self::PostGuestNotification(_) => Kind::PostGuestNotification,
            Self::TranslateMessage { .. } => Kind::TranslateMessage,
            Self::DispatchMessage { .. } => Kind::DispatchMessage,
            Self::PostQuitMessage { .. } => Kind::PostQuitMessage,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16NativeWindowOperationProof {
    pub operation_id: Win16HostWindowOperationId,
    pub kind: Win16NativeWindowOperationKind,
}

/// The worker has either returned a real Begin operation with an error, or
/// it still owns that operation. This is deliberately separate from a normal
/// Win16 API result; terminal cancellation must never manufacture success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16NativeWindowOperationState {
    Active,
    Returned,
}

/// Proof that one USER operation actually returned and its exact source
/// entry was retired by the host's normal completion path. This is separate
/// from abort ACKs and cannot describe DDE, WAVE, or MIDI owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16WindowSourceRetiredProof {
    pub operation: Win16NativeWindowOperationProof,
    pub worker_generation: u64,
    pub state: Win16NativeWindowOperationState,
}

/// Exact acknowledgement for retiring one runtime USER owner after terminal
/// cleanup. Its callback and modal sources must be the receipt entries for
/// this same host operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16WindowTerminalAck {
    pub worker_generation: u64,
    pub operation: Win16NativeWindowOperationProof,
    pub state: Win16NativeWindowOperationState,
    pub callbacks: Vec<Win16NativeCallbackCancellation>,
    pub modals: Vec<Win16NativeModalCancellation>,
}

/// Exact native producer that entered one guest callback. These values are
/// copied from the worker's live callback owner before abort changes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16NativeCallbackSource {
    WindowMessage {
        window: Win16HostWindow,
        class: Option<Win16HostClass>,
        message: u32,
    },
    Timer {
        window: Option<Win16HostWindow>,
        host_timer_id: Option<u64>,
        guest_w_param: u16,
        guest_l_param: u32,
        time: u32,
    },
    PropertyEnumeration {
        window: Win16HostWindow,
        class: Option<Win16HostClass>,
        atom: u16,
        generation: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16NativeCallbackCancellation {
    pub callback: Win16HostCallback,
    pub operation_id: Win16HostWindowOperationId,
    pub source: Win16NativeCallbackSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16NativeModalGuestWorkRetirement {
    pub operation_id: Win16HostWindowOperationId,
    pub scope_id: u64,
    pub generation: u64,
    pub marker_id: u64,
    pub wake_generation: u64,
}

/// Native owner objects are deliberately not implied by callback quiescence.
/// The abort receipt snapshots them while the worker maps are still alive;
/// later USER teardown retires these resources one class at a time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16NativeWindowResourceSnapshot {
    pub windows: Vec<Win16HostWindow>,
    pub menus: Vec<Win16HostMenu>,
    pub classes: Vec<Win16HostClass>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16NativeResourceRetirement {
    Deferred,
    Retired,
}

/// Identity of one suspended native window-procedure invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostCallback(pub u64);

/// Identity of one pending creation, including its synchronous callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16CreationId(pub u64);

/// Result metadata for an ordinary native USER window-creation call.
/// `native_api_return` records the HWND nullness immediately when the native
/// creation API returns; `live_window` is the separately validated opaque
/// identity retained after the worker's existing checks and cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16NativeWindowApiReturn {
    NotInvoked,
    ReturnedNull,
    ReturnedWindow,
}

/// A known pre-call rejection point. It describes the adapter path that kept
/// the native API from being invoked, not the cause of a native API failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowCreationRejection {
    NullProcedureRejectedByRuntime,
    GuestOwnerUnavailable,
    GuestParentUnavailable,
    GuestMenuUnavailable,
    InvalidGuestCreationData,
    GuestTemplateUnavailable,
    UnsupportedControlCreationData,
    UnsupportedMenuResource,
    UnsupportedControlTitleResource,
    GuestClassUnavailable,
    UnsupportedGuestClassRoute,
    UnsupportedClassMenuResource,
    NativeOwnerUnavailable,
    NativeTemplateUnavailable,
    NativeWindowClassUnavailable,
    NativeParentUnavailable,
    NativeMenuUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWindowCreationResult {
    pub native_api_return: Win16NativeWindowApiReturn,
    pub preflight_rejection: Option<Win16WindowCreationRejection>,
    pub live_window: Option<Win16HostWindow>,
}

impl Win16HostWindowCreationResult {
    pub const fn not_invoked(rejection: Win16WindowCreationRejection) -> Self {
        Self {
            native_api_return: Win16NativeWindowApiReturn::NotInvoked,
            preflight_rejection: Some(rejection),
            live_window: None,
        }
    }

    pub const fn returned_null() -> Self {
        Self {
            native_api_return: Win16NativeWindowApiReturn::ReturnedNull,
            preflight_rejection: None,
            live_window: None,
        }
    }
}

#[derive(Debug)]
pub enum Win16WindowResult {
    /// A terminal native modal cancellation; worker code must place this in
    /// the abort receipt and never dispatch it as a guest API completion.
    NativeModalCancelled(Win16NativeModalCancellation),
    Dde(crate::Win16HostDdeResult),
    StaticIcon(Win16HostStaticIconResult),
    Thunk(crate::Win16ThunkResult),
    Created(Win16HostWindowCreationResult),
    Procedure(Option<crate::Win16HostProcedure>),
    SubclassProcedure {
        procedure: Option<crate::Win16HostProcedure>,
        instance: Option<u16>,
    },
    Menu(crate::Win16MenuResult),
    WindowCall(crate::Win16WindowCallResult),
    MessageCall(crate::Win16MessageCallResult),
    UserService(crate::Win16HostUserServiceResult),
    CommonControls(crate::Win16HostCommonControlsResult),
    CommonDialog(crate::Win16HostCommonDialogResult),
    UpdateRegion(crate::Win16HostUpdateResult),
    ScrollBar(crate::Win16HostScrollBarResult),
    UserCursorAccelerator(crate::Win16HostUserCursorAcceleratorResult),
    ShellExecution(crate::Win16HostShellExecutionResult),
    Paint {
        acquired: Option<(Win16HostDc, Win16HostPaintInfo)>,
    },
    WindowDc(Option<Win16HostDc>),
    PaintEnded(bool),
    DcReleased(bool),
    /// None means the native window is no longer valid. It is an API failure,
    /// not an empty text result, and supplies no bytes to copy to the guest.
    Message(Option<Win16HostMessageResult>),
    Visibility(Option<bool>),
    Destroyed {
        succeeded: bool,
        /// Exact window and menu lifetime effects, independent of the BOOL.
        /// Runtime consumes these without issuing another native destroy.
        retirements: crate::Win16HostWindowRetirementBatch,
    },
    WindowTextSet(bool),
    /// Only the native output prefix, including its NUL, is returned. An
    /// absent native window produces no output bytes.
    WindowText {
        value: i32,
        buffer: Vec<u8>,
    },
    WindowTextLength(i32),
    /// Native GetMessage/PeekMessage result. WM_QUIT is returned as Some and
    /// is distinguished by its message number, not by an absent result.
    QueuedMessage(Win16HostQueuedDelivery),
    /// `true` means the exact owned receipt was accepted by the native USER
    /// queue. It does not mean the guest removed or dispatched the MSG; a
    /// later target retirement can still tombstone the queued carrier.
    NotificationPosted(bool),
    /// Native GetMessage failed (including a window-filter handle that became
    /// invalid while the worker processed sent messages). It is not WM_QUIT.
    MessageError,
    Translated(bool),
    Dispatched(i32),
    /// Native dispatch may retire exact window incarnations and invalidate
    /// menus while processing this message, including MDI descendants.
    DispatchedMdi {
        result: crate::Win16HostMdiMessageResult,
        retirements: crate::Win16HostWindowRetirementBatch,
    },
    QuitPosted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16NativeModalCancelSignal {
    BeforeEntry,
    OwnerThreadQuit,
    DialogEnd,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16NativeModalCancellation {
    pub operation_id: u64,
    /// None is only valid for a terminal request observed before modal scope
    /// creation. An entered native modal always reports its actual scope id.
    pub scope_id: Option<u64>,
    pub native_result: Option<i64>,
    pub native_last_error: Option<u32>,
    pub signal: Win16NativeModalCancelSignal,
    pub retired_guest_work: Vec<Win16NativeModalGuestWorkRetirement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16WindowAbortReceipt {
    pub worker_generation: u64,
    pub request_id: u64,
    pub active_operations: Vec<Win16NativeWindowOperationProof>,
    pub cancelled_callbacks: Vec<Win16NativeCallbackCancellation>,
    pub cancelled_modals: Vec<Win16NativeModalCancellation>,
    pub active_operation_stack_empty: bool,
    pub callback_stack_empty: bool,
    pub modal_scope_stack_empty: bool,
    pub resources: Win16NativeWindowResourceSnapshot,
    pub resource_retirement: Win16NativeResourceRetirement,
}

/// The host's single typed outcome after a real USER operation was enqueued
/// but its first result could not be delivered as a normal completion.
/// Owners retain this exact Arc through terminal cleanup and retry.
#[derive(Clone, Debug)]
pub struct Win16WindowOperationStartedFailure {
    pub operation: Win16NativeWindowOperationProof,
    pub worker_generation: u64,
    pub state: Win16NativeWindowOperationState,
    pub cause: Arc<RuntimeError>,
}

/// Read-only view of the exact top source in the shared USER/DDE ledger after
/// abort. The USER worker receipt alone is a subset and must not be used to
/// guess which nested source can be acknowledged next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowTerminalSourceTop {
    User {
        operation: Win16HostWindowOperationId,
        kind: Win16NativeWindowOperationKind,
        state: Win16NativeWindowOperationState,
        worker_generation: u64,
    },
    Dde {
        operation: crate::Win16HostDdeOperation,
    },
}

#[derive(Debug)]
pub enum Win16WindowStep {
    /// Only the host `begin` boundary constructs this wrapper after it has
    /// allocated and retained the real operation identity. Guest-only and
    /// error paths must never synthesize it.
    Started {
        operation_id: Win16HostWindowOperationId,
        worker_generation: u64,
        kind: Win16NativeWindowOperationKind,
        step: Box<Win16WindowStep>,
    },
    /// The host has already enqueued the real operation and preserves its
    /// identity even though the first step failed. `state` distinguishes an
    /// operation whose worker response returned from one still awaiting its
    /// native owner-thread proof.
    StartedFailure(Arc<Win16WindowOperationStartedFailure>),
    /// A DDE begin was accepted by its own producer but failed before the
    /// callback/normal-step path could bind the operation to this exact DDE
    /// continuation. The DTO is producer-owned; USER never derives a DDE ID
    /// from a window-frame nonce or from the shared source ledger.
    DdeStartedFailure(Arc<crate::Win16DdeOperationStartedFailure>),
    /// Normal USER completion after the host has verified the actual
    /// Returned state and retired this exact USER source. Runtime must cache
    /// the proof on the original frame before projecting guest outputs.
    SourceRetired {
        proof: Arc<Win16WindowSourceRetiredProof>,
        result: Box<Win16WindowStep>,
    },
    /// A DDE-owned source was retired only after its callback payload/frame
    /// cleanup and exact native source-top proof. USER preserves the DDE
    /// continuation and never converts this proof to a USER proof.
    DdeSourceRetired {
        proof: Arc<crate::Win16DdeSourceRetiredProof>,
        result: Box<Win16WindowStep>,
    },
    /// The native USER worker suspended this exact host operation while the
    /// runtime drains typed owner mailboxes. The generation is a wake epoch,
    /// not a guest message or completion acknowledgement.
    PendingGuestWork {
        operation_id: Win16HostWindowOperationId,
        generation: u64,
    },
    /// Native modal ingress yielded while the exact API remains on the
    /// owner-thread stack. Consuming this step does not acknowledge a source
    /// callback or retire a callback frame.
    PendingModalGuestWork {
        operation_id: Win16HostWindowOperationId,
        scope_id: u64,
        generation: u64,
        marker_id: Option<u64>,
        wake_generation: Option<u64>,
        failure: Option<RuntimeError>,
    },
    /// The host retired one native HDROP owner. This sideband receipt is
    /// consumed independently from the suspended USER callback/operation.
    NativeDropRetired(Win16HostDropRetirementReceipt),
    /// Native DDE callback suspended a foreground operation or was received
    /// while the owner thread pumped a window wait.
    DdeCallback(Arc<crate::Win16HostDdeCallbackStep>),
    Callback {
        operation_id: Win16HostWindowOperationId,
        callback: Win16HostCallback,
        creation: Option<Win16CreationId>,
        /// Owned creation provenance is independent of the current message.
        /// USER may call a custom dialog WndProc before its CREATESTRUCT
        /// message is projected to the guest.
        creation_data: Option<Win16HostCreationData>,
        window: Win16HostWindow,
        class: Win16HostClass,
        message: Win16HostMessage,
        source: Win16NativeCallbackSource,
    },
    /// Explicit guest subclass of a native window, without a guest class.
    NativeSubclassCallback {
        operation_id: Win16HostWindowOperationId,
        callback: Win16HostCallback,
        window: Win16HostWindow,
        message: Win16HostMessage,
        source: Win16NativeCallbackSource,
    },
    /// Synchronous dialog-procedure invocation. Its HWND and nested message
    /// data are opaque/copied values; the guest FARPROC remains runtime-only.
    DialogCallback {
        operation_id: Win16HostWindowOperationId,
        callback: Win16HostCallback,
        window: Win16HostWindow,
        message: Win16HostDialogMessage,
        source: Win16NativeCallbackSource,
    },
    /// A host-owned TIMERPROC thunk suspended inside a native USER operation.
    /// Native timer identities remain opaque. Numeric guest bits are present
    /// only for a posted guest message retained by the host's typed sidecar.
    GuestTimerCallback {
        operation_id: Win16HostWindowOperationId,
        callback: Win16HostCallback,
        window: Option<Win16HostWindow>,
        host_timer_id: Option<u64>,
        guest_w_param: u16,
        guest_l_param: u32,
        time: u32,
        source: Win16NativeCallbackSource,
    },
    /// EnumProps suspended in the native property enumerator. The callback
    /// itself stays a guest FARPROC in runtime-only state.
    WindowPropertyCallback {
        operation_id: Win16HostWindowOperationId,
        callback: Win16HostCallback,
        window: Win16HostWindow,
        name: crate::Win16HostPropertyCallbackName,
        data: u16,
        source: Win16NativeCallbackSource,
    },
    /// The host applied native default processing because reverse marshalling
    /// is not implemented. This notice is not a suspended guest callback.
    Untranslated {
        message: u32,
    },
    /// A recoverable host outcome with its precise cause. Unlike Untranslated,
    /// this does not imply that native default processing replaced the call.
    Diagnostic(crate::Diagnostic),
    Complete(Win16WindowResult),
}

/// Host-side identity for one USER operation that yielded pending guest work.
/// It is distinct from the runtime's own operation-frame identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWindowOperationId(pub u64);

#[derive(Debug)]
pub struct Win16WindowReply {
    pub callback: Win16HostCallback,
    pub result: Win16HostMessageResult,
}
