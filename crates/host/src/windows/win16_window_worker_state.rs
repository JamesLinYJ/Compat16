//! Native USER worker state, callback provenance and retained owner records.

use super::super::win16_common_dialog_worker::ShutdownStorageGuard;
use super::super::win16_deferred_native_messages::DeferredNativeMessageQueue;
use super::{ShutdownResult, WorkerCommand};
use crate::windows::win16_gdi::Win16Dcs;
use crate::windows::win16_images::Win16Images;
use runtime::{
    RuntimeError, Win16CreationId, Win16HostCallback, Win16HostClass, Win16HostCreationData,
    Win16HostMenu, Win16HostWindow, Win16WindowStep,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::os::windows::io::OwnedHandle;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{HINSTANCE, HWND};

#[path = "win16_window_worker_drop.rs"]
mod native_drop;
pub(in crate::windows::win16_windows) use native_drop::{
    NativeDropCallbackClaim, NativeDropCallbackResolution, NativeDropFilesQueue, NativeDropOwner,
    NativeDropRetirementQueue, NativeDropRetirementQueueHandle,
};

pub(in crate::windows::win16_windows) struct NativeClass {
    pub(in crate::windows::win16_windows) name: Vec<u8>,
    pub(in crate::windows::win16_windows) instance: HINSTANCE,
    pub(in crate::windows::win16_windows) system_class: bool,
    pub(in crate::windows::win16_windows) system_class_kind: Option<runtime::Win16HostSystemClass>,
    /// Actual native storage capacity, distinct from guest sidecar lengths.
    pub(in crate::windows::win16_windows) native_extras: Option<(i32, i32)>,
}

#[derive(Clone, Copy)]
pub(in crate::windows::win16_windows) struct NativeWindowIdentity {
    pub(in crate::windows::win16_windows) window: Win16HostWindow,
    pub(in crate::windows::win16_windows) class: Option<Win16HostClass>,
    /// Exact guest creation-operation provenance for callbacks from a window
    /// created by CreateWindow/dialog APIs. This is not a per-HWND lifetime
    /// ID; the checked-monotonic Win16HostWindow token identifies that lifetime.
    /// Borrowed aliases have no guest creation operation provenance.
    pub(in crate::windows::win16_windows) creation: Option<Win16CreationId>,
    /// Native owner identity captured when this exact HWND alias was adopted.
    pub(in crate::windows::win16_windows) process_id: u32,
    pub(in crate::windows::win16_windows) thread_id: u32,
    /// A native window created for this Win16 task. Borrowed HWND aliases are
    /// retained for USER calls but never destroyed during host shutdown.
    pub(in crate::windows::win16_windows) owned: bool,
}

pub(in crate::windows::win16_windows) struct PendingCreation {
    pub(in crate::windows::win16_windows) creation: Win16CreationId,
    pub(in crate::windows::win16_windows) window: Win16HostWindow,
    pub(in crate::windows::win16_windows) data: Win16HostCreationData,
    pub(in crate::windows::win16_windows) cookie: usize,
}

#[derive(Clone)]
pub(in crate::windows::win16_windows) struct PendingWindowMenuRetirement {
    pub(in crate::windows::win16_windows) retirement_id: u64,
    pub(in crate::windows::win16_windows) window: Win16HostWindow,
    pub(in crate::windows::win16_windows) hwnd: usize,
    pub(in crate::windows::win16_windows) identity_cookie: Option<usize>,
    pub(in crate::windows::win16_windows) menu_tokens: BTreeMap<Win16HostMenu, usize>,
}

#[repr(C)]
pub(in crate::windows::win16_windows) struct NativeCreateCookie {
    pub(in crate::windows::win16_windows) creation: Win16CreationId,
    pub(in crate::windows::win16_windows) window: Win16HostWindow,
    pub(in crate::windows::win16_windows) class: Win16HostClass,
}

#[derive(Clone)]
pub(in crate::windows::win16_windows) struct ActiveOperation {
    pub(in crate::windows::win16_windows) id: u64,
    /// Typed HFONT mapping for this synchronous request; a nested request
    /// receives its own mapping rather than inheriting its caller's font.
    pub(in crate::windows::win16_windows) native_font: Option<(runtime::Win16HostGdiObject, usize)>,
    pub(in crate::windows::win16_windows) kind: runtime::Win16NativeWindowOperationKind,
    pub(in crate::windows::win16_windows) response: Sender<Result<Win16WindowStep, RuntimeError>>,
    /// Provenance for a native MSG passed to DispatchMessage on this exact
    /// operation frame; nested guest SendMessage calls never inherit it.
    pub(in crate::windows::win16_windows) native_queue_dispatch: bool,
    /// Trusted host-owned modal API message pump on this exact operation.
    /// Dialog/control SendMessage calls do not set this provenance.
    pub(in crate::windows::win16_windows) native_dialog_pump: bool,
}

/// A separately owned classic-DDE command on the USER worker. It is not a
/// USER operation id and it never consumes a GetMessage/WaitMessage proof.
pub(in crate::windows::win16_windows) struct ActiveClassicDdeOperation {
    pub(in crate::windows::win16_windows) identity: runtime::Win16ClassicDdeOperationIdentity,
    /// Exact nested-command ancestry copied from the live worker stack at
    /// operation entry; nearest parent first and same-owner only.
    pub(in crate::windows::win16_windows) causal_parents:
        Vec<runtime::Win16ClassicDdeOperationIdentity>,
    pub(in crate::windows::win16_windows) call: runtime::Win16HostClassicDdeCall,
    pub(in crate::windows::win16_windows) response:
        Sender<Result<runtime::Win16HostClassicDdeStep, RuntimeError>>,
    pub(in crate::windows::win16_windows) callback_receipts:
        Vec<runtime::Win16HostClassicDdeCallbackRetirement>,
    pub(in crate::windows::win16_windows) awaiting:
        Option<std::sync::Arc<runtime::Win16HostClassicDdeCallbackStep>>,
    pub(in crate::windows::win16_windows) callback_retirements:
        Vec<runtime::Win16HostClassicDdeCallbackRetirement>,
    pub(in crate::windows::win16_windows) replied:
        Option<runtime::Win16HostClassicDdeCallbackResult>,
    /// Set only for a callback that arrived while the USER worker was parked
    /// in its outer GetMessage/WaitMessage call. That WndProc must first
    /// return, then an internal endpoint message publishes this operation's
    /// terminal source-retirement proof.
    pub(in crate::windows::win16_windows) external_ingress: Option<(
        runtime::Win16HostClassicDdeEndpoint,
        runtime::Win16ClassicDdeEventId,
        runtime::Win16HostClassicDdeCallbackFrame,
    )>,
}

/// Host-only record for one real Win32 endpoint HWND. The HWND, class and
/// atom/HGLOBAL ownership never cross RuntimeHost; only opaque endpoint and
/// conversation identities do.
pub(in crate::windows::win16_windows) struct NativeClassicDdeEndpoint {
    pub(in crate::windows::win16_windows) owner: guest_core::OwnerId,
    pub(in crate::windows::win16_windows) worker_generation: u64,
    pub(in crate::windows::win16_windows) hwnd: HWND,
    pub(in crate::windows::win16_windows) window_destroyed: bool,
    pub(in crate::windows::win16_windows) parent: Option<runtime::Win16HostClassicDdeEndpoint>,
    pub(in crate::windows::win16_windows) class_name: Vec<u16>,
    pub(in crate::windows::win16_windows) instance: HINSTANCE,
    pub(in crate::windows::win16_windows) events:
        VecDeque<super::classic_dde_worker::NativeQueuedClassicDdeEvent>,
    pub(in crate::windows::win16_windows) conversations: BTreeMap<
        runtime::Win16ClassicDdeConversationId,
        super::classic_dde_worker::NativeClassicDdeConversation,
    >,
    pub(in crate::windows::win16_windows) transfers: BTreeMap<
        runtime::Win16ClassicDdeTransferId,
        super::classic_dde_worker::NativeClassicDdeTransfer,
    >,
    pub(in crate::windows::win16_windows) transactions: BTreeMap<
        runtime::Win16ClassicDdeTransactionId,
        super::classic_dde_worker::NativeClassicDdeTransaction,
    >,
    pub(in crate::windows::win16_windows) synchronous_frames: HashMap<
        (
            runtime::Win16ClassicDdeOperationId,
            runtime::Win16HostClassicDdeCallbackFrame,
        ),
        super::classic_dde_worker::NativeSynchronousClassicDdeFrame,
    >,
}

pub(in crate::windows::win16_windows) struct NativeClassicDdePeer {
    pub(in crate::windows::win16_windows) hwnd: HWND,
    pub(in crate::windows::win16_windows) process_id: u32,
    pub(in crate::windows::win16_windows) thread_id: u32,
}

/// Durable owner shutdown barrier. `id` remains in the worker after the
/// quiescence proof so later API calls for the same task cannot restart DDE
/// producers. All values are host identities; no HWND or guest handle escapes.
pub(in crate::windows::win16_windows) struct NativeClassicDdeQuiescence {
    pub(in crate::windows::win16_windows) id: runtime::Win16ClassicDdeQuiescenceId,
    pub(in crate::windows::win16_windows) worker_generation: u64,
    pub(in crate::windows::win16_windows) quiesced: bool,
}

impl ActiveOperation {
    pub(in crate::windows::win16_windows) fn allows_drag_list_origin(&self) -> bool {
        self.native_queue_dispatch || self.native_dialog_pump
    }
}

#[derive(Clone, Copy)]
pub(in crate::windows::win16_windows) struct Win16GuestTimerPost {
    pub(in crate::windows::win16_windows) guest_w_param: u16,
    pub(in crate::windows::win16_windows) guest_l_param: u32,
}

/// Native USER identity and generation metadata for one Win16 SetTimer call.
/// `host_id` is the only timer identity returned to the runtime; HWND and
/// UINT_PTR remain inside this worker-owned record.
#[derive(Clone, Copy)]
pub(in crate::windows::win16_windows) struct NativeTimerRecord {
    pub(in crate::windows::win16_windows) host_id: u64,
    pub(in crate::windows::win16_windows) window: Option<Win16HostWindow>,
    pub(in crate::windows::win16_windows) guest_timer_id: u16,
    pub(in crate::windows::win16_windows) hwnd: usize,
    pub(in crate::windows::win16_windows) native_id: usize,
    pub(in crate::windows::win16_windows) guest_callback: bool,
    pub(in crate::windows::win16_windows) active: bool,
}

pub(in crate::windows::win16_windows) struct LiveCallback {
    pub(in crate::windows::win16_windows) callback: Win16HostCallback,
    pub(in crate::windows::win16_windows) operation: u64,
    pub(in crate::windows::win16_windows) source: runtime::Win16NativeCallbackSource,
    pub(in crate::windows::win16_windows) creation: Option<Win16CreationId>,
    pub(in crate::windows::win16_windows) identity: Option<NativeWindowIdentity>,
    pub(in crate::windows::win16_windows) message: Option<u32>,
    pub(in crate::windows::win16_windows) hwnd: HWND,
    pub(in crate::windows::win16_windows) w_param: Option<usize>,
    pub(in crate::windows::win16_windows) l_param: Option<isize>,
    /// Native-only message provenance is retained only while the exact
    /// synchronous callback is suspended. In particular, WM_NCPAINT's HRGN
    /// is never copied into a guest handle or detached from this live frame.
    pub(in crate::windows::win16_windows) native_message_context: Option<NativeCallbackContext>,
    pub(in crate::windows::win16_windows) creation_cookie: Option<usize>,
    /// USER's actual MCS copy is live only while this synchronous creation
    /// callback is suspended. The outer guard owns a separate canonical MCS;
    /// neither native address enters guest-visible creation data.
    pub(in crate::windows::win16_windows) mdi_create_struct: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows::win16_windows) enum NativeCallbackContext {
    /// Win32 COMPAREITEM's locale is absent from the Win16 structure. Keep
    /// it only for this exact suspended callback's default/procedure forwarding.
    OwnerDrawCompareLocale { locale: u32 },
    /// Capability for one suspended callback; the owned session is pinned by
    /// that callback's local guard, and this pointer never enters guest data.
    FindReplace {
        request_id: u64,
        native_l_param: isize,
    },
    /// WM_NCACTIVATE's native -1 LPARAM has no HWND16 representation. Reuse
    /// it only when guest default/procedure forwarding matches this input.
    NonClientActivateNoRepaint {
        input: runtime::Win16WindowInputMessage,
    },
    /// Opaque original Win32 WM_NCPAINT WPARAM. It is valid only for the
    /// lifetime of the synchronous callback and is never exposed as a guest
    /// region handle.
    NonClientPaint { native_w_param: usize },
    /// The native DRAGLISTINFO pointer remains valid only while this exact
    /// registered-message callback is suspended inside MakeDragList.
    DragList {
        operation: u64,
        list_box: Win16HostWindow,
        native_list_hwnd: usize,
        native_l_param: isize,
    },
}

#[derive(Clone)]
pub(in crate::windows::win16_windows) struct DragListSidecar {
    pub(in crate::windows::win16_windows) list_box: Win16HostWindow,
    pub(in crate::windows::win16_windows) hwnd: usize,
    pub(in crate::windows::win16_windows) parent: Win16HostWindow,
    pub(in crate::windows::win16_windows) guest_list_box: u16,
    pub(in crate::windows::win16_windows) message: u16,
    pub(in crate::windows::win16_windows) subclass_id: usize,
    pub(in crate::windows::win16_windows) owner_thread: u32,
    pub(in crate::windows::win16_windows) installed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows::win16_windows) struct DragListOrigin {
    pub(in crate::windows::win16_windows) list_box: Win16HostWindow,
    pub(in crate::windows::win16_windows) hwnd: usize,
    pub(in crate::windows::win16_windows) parent: Win16HostWindow,
    pub(in crate::windows::win16_windows) operation: u64,
    pub(in crate::windows::win16_windows) message: u16,
    pub(in crate::windows::win16_windows) owner_thread: u32,
}

pub(in crate::windows::win16_windows) struct PendingDialogRoute {
    pub(in crate::windows::win16_windows) operation: u64,
    pub(in crate::windows::win16_windows) creation: Win16CreationId,
    /// Opaque per-call cookie supplied as WM_INITDIALOG's lParam. It is
    /// compared as an integer only; it is never a CREATESTRUCT16 pointer and
    /// is never dereferenced or exposed as guest data.
    pub(in crate::windows::win16_windows) cookie: usize,
    pub(in crate::windows::win16_windows) guest_instance: u16,
    pub(in crate::windows::win16_windows) init_parameter: u32,
    /// Identity reserved before entering USER so synchronous child/root
    /// callbacks cannot allocate or adopt a different dialog generation.
    pub(in crate::windows::win16_windows) root_token: Win16HostWindow,
    pub(in crate::windows::win16_windows) owner: HWND,
    pub(in crate::windows::win16_windows) root: Option<DialogRootCreationRoute>,
    pub(in crate::windows::win16_windows) root_window: Option<usize>,
    pub(in crate::windows::win16_windows) init_published: bool,
    pub(in crate::windows::win16_windows) controls: Vec<DialogControlCreationRoute>,
    pub(in crate::windows::win16_windows) menu: Option<Win16HostMenu>,
}

pub(in crate::windows::win16_windows) struct DialogRootCreationRoute {
    pub(in crate::windows::win16_windows) data: Win16HostCreationData,
}

pub(in crate::windows::win16_windows) struct DialogControlCreationRoute {
    pub(in crate::windows::win16_windows) size_pointer: usize,
    pub(in crate::windows::win16_windows) data_pointer: usize,
    pub(in crate::windows::win16_windows) window_token: Win16HostWindow,
    pub(in crate::windows::win16_windows) data: Win16HostCreationData,
}

#[derive(Clone, Copy)]
pub(in crate::windows::win16_windows) struct DialogRoute {
    pub(in crate::windows::win16_windows) operation: u64,
    pub(in crate::windows::win16_windows) creation: Win16CreationId,
    pub(in crate::windows::win16_windows) cookie: usize,
    pub(in crate::windows::win16_windows) window: Win16HostWindow,
    pub(in crate::windows::win16_windows) init_parameter: u32,
    pub(in crate::windows::win16_windows) menu: Option<Win16HostMenu>,
    /// Exact nested USER phase used while routing private-class initialization.
    pub(in crate::windows::win16_windows) class_init_in_progress: bool,
    pub(in crate::windows::win16_windows) class_init_default_called: bool,
}

#[derive(Clone, Copy)]
pub(in crate::windows::win16_windows) struct ClipboardViewerRegistration {
    pub(in crate::windows::win16_windows) window: usize,
    pub(in crate::windows::win16_windows) next_viewer: usize,
}

#[derive(Clone, Debug)]
pub(in crate::windows::win16_windows) struct TerminalProofSnapshot {
    pub(in crate::windows::win16_windows) active_operations:
        Vec<runtime::Win16NativeWindowOperationProof>,
    pub(in crate::windows::win16_windows) cancelled_callbacks:
        Vec<runtime::Win16NativeCallbackCancellation>,
    pub(in crate::windows::win16_windows) resources: runtime::Win16NativeWindowResourceSnapshot,
}

pub(in crate::windows) struct WorkerState {
    pub(in crate::windows) text_codec: crate::windows::guest_text::GuestTextCodec,
    pub(in crate::windows) oem_text_codec: crate::windows::guest_text::GuestTextCodec,
    pub(in crate::windows::win16_windows) window_text_contexts:
        super::super::win16_window_text_context::WindowTextContextStack,
    pub(in crate::windows::win16_windows) shutdown_storage: Arc<Mutex<Vec<ShutdownStorageGuard>>>,
    pub(in crate::windows::win16_windows) worker_retirement_id: u64,
    pub(in crate::windows::win16_windows) toolbar_bitmap_retention:
        Arc<Mutex<super::super::win16_common_controls_bitmap_pins::ToolbarBitmapRetention>>,
    pub(in crate::windows::win16_windows) window_properties:
        super::super::win16_window_properties::WindowPropertyStore,
    pub(in crate::windows::win16_windows) native_procedures:
        super::super::win16_native_procedures::NativeProcedures,
    pub(in crate::windows::win16_windows) window_identity_cookies:
        HashMap<Win16HostWindow, super::super::win16_window_identity::WindowCookieBinding>,
    pub(in crate::windows::win16_windows) commands: Arc<Mutex<Receiver<WorkerCommand>>>,
    /// Exact native MSG values removed by a nested COM pump stay owned here
    /// until the normal USER message consumer applies its original filter.
    pub(in crate::windows::win16_windows) deferred_native_messages: DeferredNativeMessageQueue,
    /// COM apartment and canonical interface table are owned by this exact
    /// USER worker thread. Clone only this Rc before a call; never borrow the
    /// outer WorkerState across a COM method that can reenter USER.
    pub(in crate::windows::win16_windows) com: Rc<super::com_sta::Win16ComStaState>,
    pub(in crate::windows::win16_windows) identity_source: Arc<AtomicU64>,
    /// Native classic-DDE endpoint HWNDs and their queued message ownership
    /// remain on this exact USER worker. Endpoint peers are not guest HWNDs.
    pub(in crate::windows::win16_windows) classic_dde_endpoints:
        BTreeMap<runtime::Win16HostClassicDdeEndpoint, NativeClassicDdeEndpoint>,
    pub(in crate::windows::win16_windows) classic_dde_endpoints_by_native:
        HashMap<usize, runtime::Win16HostClassicDdeEndpoint>,
    pub(in crate::windows::win16_windows) classic_dde_quiescing_owners:
        HashMap<guest_core::OwnerId, NativeClassicDdeQuiescence>,
    pub(in crate::windows::win16_windows) active_classic_dde_operations:
        Vec<ActiveClassicDdeOperation>,
    pub(in crate::windows::win16_windows) pending_classic_dde_ingress:
        VecDeque<super::classic_dde_worker::PendingSynchronousClassicDdeIngress>,
    pub(in crate::windows::win16_windows) classic_dde_native_peers:
        HashMap<runtime::Win16HostClassicDdeNativeWindow, NativeClassicDdePeer>,
    /// An inbound synchronous DDE callback may park the exact outer USER
    /// GetMessage/WaitMessage frame while PollOwner dispatches it.
    pub(in crate::windows::win16_windows) active_user_waits: Vec<(u64, super::UserWaitKind)>,
    pub(in crate::windows::win16_windows) wake_event: Arc<OwnedHandle>,
    pub(in crate::windows::win16_windows) multimedia_generation: Arc<AtomicU64>,
    pub(in crate::windows::win16_windows) multimedia_generation_seen: u64,
    pub(in crate::windows::win16_windows) modal_control:
        Arc<super::super::super::win16_modal::ModalWorkerControl>,
    pub(in crate::windows::win16_windows) dcs: Win16Dcs,
    pub(in crate::windows::win16_windows) images: Win16Images,
    /// Retain native process handles until worker teardown. Closing these
    /// leases never terminates the launched processes.
    pub(in crate::windows::win16_windows) shell_processes:
        Vec<super::super::win16_shell_execution::ProcessLease>,
    /// Native HACCEL tables stay on the USER worker and are destroyed when
    /// its WorkerState drops on this same thread after callbacks unwind.
    pub(in crate::windows::win16_windows) accelerator_tables:
        super::super::win16_user_cursor_accelerator::Win16AcceleratorTables,
    pub(in crate::windows::win16_windows) live_find_replace:
        BTreeMap<u64, Rc<super::super::win16_common_dialog_worker::LiveFindReplaceDialog>>,
    pub(in crate::windows::win16_windows) classes: BTreeMap<Win16HostClass, Rc<NativeClass>>,
    pub(in crate::windows::win16_windows) windows: HashMap<Win16HostWindow, HWND>,
    pub(in crate::windows::win16_windows) windows_by_native: HashMap<usize, NativeWindowIdentity>,
    pub(in crate::windows::win16_windows) drop_accepting_windows: HashSet<Win16HostWindow>,
    /// Exact host-token retirement evidence used by read-only liveness
    /// queries. Capacity is reserved when each token is issued, before any
    /// native window can retire.
    pub(in crate::windows::win16_windows) retired_window_tokens: HashSet<Win16HostWindow>,
    pub(in crate::windows::win16_windows) menus:
        BTreeMap<Win16HostMenu, windows_sys::Win32::UI::WindowsAndMessaging::HMENU>,
    pub(in crate::windows::win16_windows) menus_by_native: HashMap<usize, Win16HostMenu>,
    pub(in crate::windows::win16_windows) system_menus: BTreeMap<Win16HostWindow, Win16HostMenu>,
    pub(in crate::windows::win16_windows) window_menus: BTreeMap<Win16HostWindow, Win16HostMenu>,
    /// Menu owners are pinned until a callback-capable DestroyWindow unwinds.
    pub(in crate::windows::win16_windows) pending_window_menu_retirements:
        Vec<PendingWindowMenuRetirement>,
    /// Keep menu trees reachable while callback-capable USER calls change
    /// their attachment or ledger publication.
    pub(in crate::windows::win16_windows) active_menu_call_owners:
        Vec<BTreeMap<Win16HostMenu, usize>>,
    /// Window teardown may finish inside SetMenu/DrawMenuBar guest reentry;
    /// retire only exact native identities after the call owner unwinds.
    pub(in crate::windows::win16_windows) deferred_menu_retirements: Vec<(Win16HostMenu, usize)>,
    /// Prevent an HMENU value being re-interned as its old guest token while a
    /// consuming USER call is in flight and may recycle the native value.
    pub(in crate::windows::win16_windows) retiring_menu_native_handles: Vec<(Win16HostMenu, usize)>,
    pub(in crate::windows::win16_windows) menu_children:
        BTreeMap<Win16HostMenu, BTreeSet<Win16HostMenu>>,
    pub(in crate::windows::win16_windows) owned_menus: BTreeSet<Win16HostMenu>,
    pub(in crate::windows::win16_windows) owned_menu_roots: BTreeSet<Win16HostMenu>,
    /// Native HMENU owners retained when class-menu materialization cleanup
    /// could not allocate a host token. These handles never leave the worker.
    pub(in crate::windows::win16_windows) retained_unmapped_menu_owners:
        Vec<windows_sys::Win32::UI::WindowsAndMessaging::HMENU>,
    pub(in crate::windows::win16_windows) pending_creations: Vec<PendingCreation>,
    pub(in crate::windows::win16_windows) pending_mdi_creations:
        Vec<super::super::win16_mdi_pending_creation::PendingMdiCreation>,
    pub(in crate::windows::win16_windows) active_operations: Vec<ActiveOperation>,
    pub(in crate::windows::win16_windows) live_callbacks: Vec<LiveCallback>,
    /// Runtime operation currently installing a native DLGPROC. This exists
    /// only around CreateDialog*/DialogBox* calls, including their modal pump.
    pub(in crate::windows::win16_windows) pending_dialog_routes: Vec<PendingDialogRoute>,
    pub(in crate::windows::win16_windows) dialog_icon_sidecars: super::super::win16_dialog_icon_controls::IconSidecars,
    /// Native dialog HWND to copied route identity; no guest FAR is stored.
    pub(in crate::windows::win16_windows) dialog_routes_by_native: HashMap<usize, DialogRoute>,
    /// Checked CREATESTRUCT16 source copied for each custom dialog WndProc
    /// HWND. Kept until its exact WM_NCDESTROY identity is retired.
    pub(in crate::windows::win16_windows) dialog_creation_data:
        HashMap<usize, (Win16CreationId, Win16HostCreationData)>,
    /// Borrowed dialog-manager child HWNDs discovered in typed messages.
    /// They are retired with their parent dialog, while private WndProc
    /// children retain their own callback-driven lifetime.
    pub(in crate::windows::win16_windows) dialog_children_by_native:
        HashMap<usize, BTreeMap<usize, Win16HostWindow>>,
    /// Whether this worker thread currently owns an open native clipboard.
    pub(in crate::windows::win16_windows) clipboard_open: bool,
    /// Clipboard viewer registrations created by this guest, for same-thread
    /// ChangeClipboardChain cleanup when a window or worker is retired.
    pub(in crate::windows::win16_windows) clipboard_viewers:
        BTreeMap<Win16HostWindow, ClipboardViewerRegistration>,
    /// Native timers installed by this task, keyed by HWND bits and UINT_PTR.
    pub(in crate::windows::win16_windows) native_timers: BTreeSet<(usize, usize)>,
    /// Retained timer generations. Entries survive KillTimer/replacement so
    /// queued WM_TIMER records and native TIMERPROC calls keep their origin.
    pub(in crate::windows::win16_windows) timer_records: BTreeMap<u64, NativeTimerRecord>,
    /// Native queue identity to the generation captured when the timer was
    /// installed. Old keys remain until shutdown; only same-ID, callback-free
    /// HWND timers may intentionally update this mapping in place.
    pub(in crate::windows::win16_windows) timer_by_native: BTreeMap<(usize, usize), u64>,
    pub(in crate::windows::win16_windows) next_host_timer_id: u64,
    pub(in crate::windows::win16_windows) next_native_callback_timer_id: usize,
    /// Sidecars for guest PostMessage(WM_TIMER). Native LPARAM is our trusted
    /// TIMERPROC thunk, never the guest FARPROC value.
    pub(in crate::windows::win16_windows) guest_timer_posts:
        BTreeMap<(usize, usize), Win16GuestTimerPost>,
    pub(in crate::windows::win16_windows) native_drop_files: NativeDropFilesQueue,
    pub(in crate::windows::win16_windows) native_drop_retirements: NativeDropRetirementQueueHandle,
    /// Exact owner-thread MakeDragList identities and the active dynamic
    /// subclass origin stack used to validate native DRAGLISTINFO pointers.
    pub(in crate::windows::win16_windows) drag_lists: Vec<DragListSidecar>,
    pub(in crate::windows::win16_windows) drag_list_origins: Vec<DragListOrigin>,
    /// Keep the registered pointer-bearing message recognizable after its
    /// last listbox sidecar retires, so stale deliveries stay native-only.
    pub(in crate::windows::win16_windows) drag_list_message: Option<u16>,
    /// Bitmap sources stay pinned to their exact toolbar HWND until its
    /// subclass observes completed WM_NCDESTROY processing.
    pub(in crate::windows::win16_windows) toolbar_bitmap_sidecars:
        Vec<super::super::win16_common_controls_bitmap_pins::ToolbarBitmapSidecar>,
    pub(in crate::windows::win16_windows) pending_toolbar_dc_releases:
        Vec<super::super::win16_common_controls_dc_retention::ToolbarDcReleaseOwner>,
    pub(in crate::windows::win16_windows) pending_toolbar_dc_release_reservations: usize,
    pub(super) next_guest_timer_post_token: usize,
    pub(in crate::windows::win16_windows) callbacks_enabled: bool,
    pub(in crate::windows::win16_windows) aborted: bool,
    pub(in crate::windows::win16_windows) shutdown_requested: bool,
    pub(in crate::windows::win16_windows) abort_waiters: Vec<(u64, Sender<ShutdownResult>)>,
    pub(in crate::windows::win16_windows) shutdown_waiters: Vec<(u64, Sender<ShutdownResult>)>,
    pub(in crate::windows::win16_windows) terminal_wake_requests: BTreeSet<u64>,
    pub(in crate::windows::win16_windows) terminal_failures: Vec<Arc<RuntimeError>>,
    pub(in crate::windows::win16_windows) cancelled_modals:
        Vec<runtime::Win16NativeModalCancellation>,
    /// Immutable source snapshot captured at the first actual terminal
    /// request, before native callback owners are allowed to unwind.
    pub(in crate::windows::win16_windows) terminal_proof: Option<TerminalProofSnapshot>,
    pub(in crate::windows::win16_windows) terminal_proof_error: Option<Arc<RuntimeError>>,
}

impl WorkerState {
    /// Observe the worker's wake cursor without exposing mutable owner fields.
    pub(in crate::windows) fn multimedia_wake_state(&self) -> (u64, bool) {
        let current = self.multimedia_generation.load(Ordering::Acquire);
        (current, current != self.multimedia_generation_seen)
    }
}
