//! Owned commands crossing the native USER worker boundary.

use super::*;
use super::super::HostNativeBrushResult;

pub(in crate::windows::win16_windows) enum WorkerCommand {
    ImeProfile {
        call: runtime::Win16HostImeProfileCall,
        response: Sender<Result<runtime::Win16HostImeProfileResult, RuntimeError>>,
    },
    WindowEnumeration {
        query: runtime::Win16WindowEnumerationQuery,
        response: Sender<Result<runtime::Win16WindowEnumerationReply, RuntimeError>>,
    },
    QueryControlIdentity {
        query: runtime::Win16HostControlQuery,
        response: Sender<Result<runtime::Win16HostControlQueryReply, RuntimeError>>,
    },
    QuerySystemClass {
        kind: runtime::Win16HostSystemClass,
        response: Sender<Result<Option<super::super::win16_system_classes::NativeSystemClassInfo>, RuntimeError>>,
    },
    RegisterClass {
        class: Win16HostClass,
        spec: Win16HostClassSpec,
        icon: usize,
        cursor: usize,
        background: crate::windows::win16_gdi_objects::NativeClassBackground,
        response: Sender<Result<Option<Win16RegisteredClass>, RuntimeError>>,
    },
    UnregisterClass {
        class: Win16HostClass,
        response: Sender<bool>,
    },
    ReplaceClassResource {
        class: Win16HostClass,
        window: runtime::Win16HostWindow,
        resource: NativeClassResource,
        response: Sender<Result<bool, RuntimeError>>,
    },
    Begin {
        id: u64,
        operation: Win16WindowOperation,
        win_exec: Option<Result<crate::windows::win16_program_launch::PreparedLaunch, u16>>,
        control_color_return: Option<ControlColorReturnSlot>,
        native_bitmaps: BTreeMap<Win16HostGdiObject, Option<usize>>,
        native_font: Option<(Win16HostGdiObject, usize)>,
        toolbar_bitmap_leases: BTreeMap<
            Win16HostGdiObject,
            Option<super::super::win16_gdi_bitmap_lease::Win16BitmapLease>,
        >,
        native_regions: BTreeMap<Win16HostGdiObject, Option<Win16RegionLease>>,
        gray_string_brush: Option<super::super::win16_gray_string::BrushLease>,
        metafile: Option<Arc<super::super::metafile_enumeration::MetafileSession>>,
        response: Sender<Result<Win16WindowStep, RuntimeError>>,
    },
    Resume {
        id: u64,
        reply: Win16WindowReply,
        /// Native HBRUSH is host-only callback return data. It never enters
        /// the runtime reply object or the guest ABI.
        native_control_color_result: Option<HostNativeBrushResult>,
    },
    ContinueGetMessage {
        id: u64,
    },
    ContinueWaitMessage {
        id: u64,
    },
    DestroyQuiet {
        window: Win16HostWindow,
        response: Sender<bool>,
    },
    QueryWindowLiveness {
        window: Win16HostWindow,
        response: Sender<Result<Win16HostWindowLiveness, RuntimeError>>,
    },
    QueryWindowParent {
        window: Win16HostWindow,
        response: Sender<Result<runtime::Win16HostWindowParentObservation, RuntimeError>>,
    },
    #[cfg(test)]
    TestWindowData {
        run: fn(&Rc<RefCell<WorkerState>>),
        response: Sender<std::thread::Result<()>>,
    },
    Abort {
        request_id: u64,
        response: Sender<ShutdownResult>,
    },
    ResumeModalGuestWork {
        operation_id: u64,
        scope_id: u64,
        generation: u64,
        marker_id: Option<u64>,
        wake_generation: Option<u64>,
    },
    TerminalWakePosted {
        request_id: u64,
    },
    InitializeQueue {
        response: Sender<Result<(), RuntimeError>>,
    },
    BindTaskQueue {
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
        response: Sender<Result<Option<Win16HostTaskQueue>, RuntimeError>>,
    },
    RetireTaskQueue {
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
        queue: Win16HostTaskQueue,
        response: Sender<bool>,
    },
    GetKeyState {
        key: i32,
        response: Sender<i16>,
    },
    Keyboard {
        call: runtime::Win16HostKeyboardCall,
        response: Sender<Result<runtime::Win16HostKeyboardResult, RuntimeError>>,
    },
    ComShutdown {
        owner: runtime::Win16ComHostOwnerIdentity,
        operation: runtime::Win16ComHostShutdownOperation,
        response: Sender<Result<runtime::Win16ComHostShutdownStep, RuntimeError>>,
    },
    ComBegin {
        owner: runtime::Win16ComHostOwnerIdentity,
        start: super::super::super::win16_com_request_executor::PreparedWin16ComStart,
        accepted: Sender<Result<(), RuntimeError>>,
    },
    ComAcknowledgeTerminal {
        owner: runtime::Win16ComHostOwnerIdentity,
        operation: runtime::Win16ComHostOperationIdentity,
        response: Sender<Result<(), RuntimeError>>,
    },
    ClassicDdeBegin {
        operation: runtime::Win16ClassicDdeOperationIdentity,
        call: runtime::Win16HostClassicDdeCall,
        response: Sender<Result<runtime::Win16HostClassicDdeStep, RuntimeError>>,
    },
    ClassicDdeResume {
        operation: runtime::Win16ClassicDdeOperationIdentity,
        reply: runtime::Win16HostClassicDdeCallbackReply,
    },
    Shutdown {
        request_id: u64,
        response: Sender<ShutdownResult>,
    },
}
