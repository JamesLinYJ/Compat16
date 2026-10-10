//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserWindowRequest {
    /// Retrieve window or control text using the signed Win16 `INT16` maximum
    /// count. The raw output FAR pointer is passed to runtime-side write checks.
    GetWindowText {
        window: u16,
        output: u32,
        count: i16,
    },

    /// Set window or control text using a nullable checked ANSI string copy.
    SetWindowText {
        window: u16,
        text: Option<Vec<u8>>,
    },

    /// Retrieve the current native window or control text length as a WORD.
    GetWindowTextLength {
        window: u16,
    },

    /// Look up a host window class and retain its packed Win16 output address
    /// for checked runtime conversion only after a successful host lookup.
    GetClassInfo {
        instance: u16,
        class_name: Win16ClassName,
        class_info: u32,
    },

    /// Register a host window class from a checked Win16 structure copy.
    /// Pointer-bearing members are separately copied or retained as typed
    /// integer resource/atom values; the procedure remains guest FARPROC bits.
    RegisterClass {
        window_class: crate::user_abi::WndClass16,
        class_name: Win16ClassName,
        menu_name: Option<Win16ResourceName>,
    },

    /// Remove only the guest registration owned by this module instance.
    UnregisterClass {
        class_name: Win16ClassName,
        instance: u16,
    },

    /// Create a guest window from copied class/title strings and scalar ABI
    /// values. Window/menu/instance handles and creation data remain guest
    /// values for runtime translation; `parameter` is never a host pointer.
    CreateWindow {
        class_name: Win16ClassName,
        window_name: Option<Vec<u8>>,
        ex_style: u32,
        style: u32,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        parent: u16,
        menu: u16,
        instance: u16,
        parameter: u32,
    },

    /// Show or hide a translated guest window. The show command retains its
    /// signed Win16 INT width and the API result reports prior visibility.
    ShowWindow {
        window: u16,
        command: i16,
    },

    /// USER timer callback bits are guest FARPROC values, never host pointers.
    SetTimer {
        window: u16,
        timer_id: u16,
        interval: u16,
        callback: u32,
    },

    KillTimer {
        window: u16,
        timer_id: u16,
    },

    SetCapture {
        window: u16,
    },

    ReleaseCapture,

    SetFocus {
        window: u16,
    },

    GetFocus,

    GetCapture,

    /// Bitmap 0/1 selects a solid/gray caret. Other values remain guest GDI
    /// handles and require a separate lifetime-safe bitmap implementation.
    CreateCaret {
        window: u16,
        bitmap: u16,
        width: i16,
        height: i16,
    },

    DestroyCaret,

    SetCaretPos {
        x: i16,
        y: i16,
    },

    HideCaret {
        window: u16,
    },

    ShowCaret {
        window: u16,
    },

    /// USER.183 writes one checked packed POINT16 and has no return value.
    GetCaretPos {
        point: u32,
    },

    /// USER.39 writes one packed PAINTSTRUCT16 through this raw guest FAR address.
    BeginPaint {
        window: u16,
        paint: u32,
    },

    /// USER.40 reads one packed PAINTSTRUCT16 and has no semantic result.
    EndPaint {
        window: u16,
        paint: u32,
    },

    /// USER.44 restores an iconic window through native OpenIcon, including
    /// WM_QUERYOPEN and its guest veto. The result is a success BOOL.
    OpenIcon {
        window: u16,
    },

    /// Query the native minimized state of a window.
    IsIconic {
        window: u16,
    },

    /// Enable or disable a native window and return its previous state.
    EnableWindow {
        window: u16,
        enable: u16,
    },

    IsWindowEnabled {
        window: u16,
    },

    BringWindowToTop {
        window: u16,
    },

    GetParent {
        window: u16,
    },

    IsWindow {
        window: u16,
    },

    IsWindowVisible {
        window: u16,
    },

    /// Search by an optional class name/atom and optional title string.
    FindWindow {
        class_name: Option<Win16ClassName>,
        window_name: Option<Vec<u8>>,
    },

    /// Destroy a native window; Windows applies native menu/window ownership rules.
    DestroyWindow {
        window: u16,
    },

    /// Preserve the output pointer and signed Win16 INT16 capacity for runtime checks.
    GetClassName {
        window: u16,
        output: u32,
        capacity: i16,
    },

    /// Change the current active window and return the previously active guest HWND.
    SetActiveWindow {
        window: u16,
    },

    GetActiveWindow,

    /// Apply the native GetWindow command selector.
    GetWindow {
        window: u16,
        command: u16,
    },

    /// Return the first child in the USER window list. A null parent retains
    /// the API's desktop-window meaning through the host's native binding.
    GetTopWindow {
        window: u16,
    },

    /// Return the adjacent or preceding window. The SDK supports only
    /// `GW_HWNDNEXT` and `GW_HWNDPREV`; other selectors produce a null HWND.
    GetNextWindow {
        window: u16,
        direction: u16,
    },

    /// Show or hide all owned popups; Win16 USER.265 returns no value.
    ShowOwnedPopups {
        window: u16,
        show: u16,
    },

    IsZoomed {
        window: u16,
    },

    /// Return the signed Win16 INT16 control ID as its raw WORD bit pattern.
    GetDlgCtrlID {
        window: u16,
    },

    GetDesktopWindow,

    GetLastActivePopup {
        window: u16,
    },

    InitApp {
        instance: u16,
    },

    /// Obtain the client-area device context for a translated Win16 window.
    GetDc {
        window: u16,
    },

    /// Obtain the whole-window device context for a translated Win16 window.
    GetWindowDc {
        window: u16,
    },

    /// Release a device context previously acquired for a translated window.
    ReleaseDc {
        window: u16,
        dc: u16,
    },
}
