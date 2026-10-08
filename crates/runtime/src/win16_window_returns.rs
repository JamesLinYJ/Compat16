//! Result continuations for suspended native window and service calls.

use super::*;

pub(in crate::win16_runtime) enum WindowReturn {
    Dde(super::super::runtime_dde::Win16DdeContinuation),
    UpdateRegion(super::super::user_services_update_region::Win16UpdateContinuation),
    ScrollBar(super::super::scroll_bar::Win16ScrollBarContinuation),
    UserCursorAccelerator(
        super::super::user_cursor_accelerator::Win16UserCursorAcceleratorContinuation,
    ),
    Create {
        creation: Win16CreationId,
        request: WindowCreateRequest,
        procedure: WindowProcedure,
        window: Option<u16>,
        parent_was_updated: bool,
    },
    Message {
        output: MessageOutput,
    },
    DialogItemMessage {
        dialog: u16,
        native_dialog: Win16HostWindow,
        message: u16,
        w_param: u16,
        l_param: u32,
    },
    Icon {
        window: u16,
        message: u16,
    },
    SetWindowText,
    GetWindowText {
        output: win16_abi::Win16OutputBuffer,
        output_range: super::super::guest_ranges::GuestOutputRange,
    },
    GetWindowTextLength,
    Show,
    Menu(MenuCall),
    WindowCall(Win16WindowCallContinuation),
    WindowData(super::super::window_data::Win16WindowDataContinuation),
    WindowProperties(super::super::window_properties::WindowPropertyReturn),
    QueryProcedure {
        window: u16,
        native_window: Win16HostWindow,
    },
    MessageCall(crate::win16_host_message_calls::Win16MessageCallContinuation),
    UserMessageBox,
    UserFamily(Win16UserFamilyContinuation),
    CommonControls(super::super::commctrl::Win16CommonControlsContinuation),
    CommonDialog(super::super::commdlg::Win16CommonDialogContinuation),
    KernelDiagnostics(super::super::kernel_diagnostics::Win16KernelDiagnosticContinuation),
    ShellExecution(super::super::compat_shell_execution::Win16ShellExecutionContinuation),
    Paint {
        guest_dc_reserved: u16,
        output: super::super::guest_ranges::GuestOutputRange,
        native_window: Win16HostWindow,
    },
    AcquireWindowDc {
        guest_dc_reserved: u16,
        native_window: Win16HostWindow,
    },
    EndPaint {
        guest_dc: u16,
        native_dc: Win16HostDc,
    },
    ReleaseWindowDc {
        guest_dc: u16,
        native_dc: Win16HostDc,
    },
    CleanupPaint {
        guest_dc_reserved: u16,
        native_dc: Win16HostDc,
        native_window: Win16HostWindow,
        paint_info: crate::Win16HostPaintInfo,
        original_error: std::sync::Arc<RuntimeError>,
    },
    CleanupWindowDc {
        guest_dc_reserved: u16,
        native_dc: Win16HostDc,
        native_window: Win16HostWindow,
        original_error: std::sync::Arc<RuntimeError>,
    },
    GetMessage {
        output: super::super::guest_ranges::GuestOutputRange,
    },
    PeekMessage {
        output: super::super::guest_ranges::GuestOutputRange,
    },
    TranslateMessage,
    DispatchMessage {
        mdi_output: Option<super::super::messages_mdi::MdiOutputPlan>,
    },
    GuestDispatch,
    GuestNotificationPost,
    PostQuitMessage,
    GuestTimerDispatch,
    GuestProcedureCall {
        return_kind: Win16ReturnKind,
    },
}
