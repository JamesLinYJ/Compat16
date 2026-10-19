//! Win32 calls whose arguments are handles or integers.
//!
//! Each wrapper is a safe function because the API treats an invalid handle as
//! a failure result and does not dereference a caller pointer. Guest addresses
//! are never accepted here.

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HINSTANCE, HWND, SetLastError, WIN32_ERROR,
};
use windows_sys::Win32::Graphics::Gdi::{
    DeleteDC, DeleteObject, GetObjectType, GetStockObject, GetSysColor, HDC, HGDIOBJ, ReleaseDC,
    UpdateWindow,
};
use windows_sys::Win32::Networking::WinSock::WSAGetLastError;
use windows_sys::Win32::Storage::FileSystem::FindClose;
use windows_sys::Win32::System::Com::CoUninitialize;
use windows_sys::Win32::System::DataExchange::DdeGetLastError;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Ole::OleUninitialize;
use windows_sys::Win32::System::Registry::{HKEY, RegCloseKey};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, SetEvent,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetActiveWindow, GetCapture, GetFocus, IsWindowEnabled, SetActiveWindow, SetFocus,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, CloseWindow, DestroyMenu, DestroyWindow, GetAncestor, GetDesktopWindow,
    GetDlgCtrlID, GetForegroundWindow, GetMenu, GetParent, GetSystemMetrics, GetWindow, HHOOK,
    HMENU, IsChild, IsIconic, IsMenu, IsWindow, IsWindowVisible, IsZoomed, KillTimer, OpenIcon,
    PostQuitMessage, ShowWindow, UnhookWindowsHookEx,
};
use windows_sys::core::BOOL;

pub(crate) fn last_error() -> u32 {
    // SAFETY: GetLastError reads only the calling thread's last-error slot.
    unsafe { GetLastError() }
}

pub(crate) fn set_last_error(code: u32) {
    // SAFETY: SetLastError writes only the calling thread's last-error slot.
    unsafe { SetLastError(code) }
}

pub(crate) fn wsa_last_error() -> i32 {
    // SAFETY: WSAGetLastError reads only the calling thread's Winsock error.
    unsafe { WSAGetLastError() }
}

pub(crate) fn current_thread_id() -> u32 {
    // SAFETY: GetCurrentThreadId takes no pointers and returns this thread's id.
    unsafe { GetCurrentThreadId() }
}

pub(crate) fn current_process_id() -> u32 {
    // SAFETY: GetCurrentProcessId takes no pointers and returns this process id.
    unsafe { GetCurrentProcessId() }
}

pub(crate) fn current_process() -> HANDLE {
    // SAFETY: GetCurrentProcess returns the calling process pseudo-handle.
    unsafe { GetCurrentProcess() }
}

pub(crate) fn current_module() -> HINSTANCE {
    // SAFETY: a null module name requests the executable that created this process.
    unsafe { GetModuleHandleW(std::ptr::null()) }
}

pub(crate) fn system_metrics(index: i32) -> i32 {
    // SAFETY: GetSystemMetrics takes an integer index and returns 0 when it is unknown.
    unsafe { GetSystemMetrics(index) }
}

pub(crate) fn is_window(hwnd: HWND) -> BOOL {
    // SAFETY: IsWindow accepts any HWND bit pattern and returns 0 when it is not a window.
    unsafe { IsWindow(hwnd) }
}

pub(crate) fn is_window_visible(hwnd: HWND) -> BOOL {
    // SAFETY: IsWindowVisible accepts any HWND bit pattern and returns 0 for a non-window.
    unsafe { IsWindowVisible(hwnd) }
}

pub(crate) fn is_iconic(hwnd: HWND) -> BOOL {
    // SAFETY: IsIconic accepts any HWND bit pattern and returns 0 for a non-window.
    unsafe { IsIconic(hwnd) }
}

pub(crate) fn is_zoomed(hwnd: HWND) -> BOOL {
    // SAFETY: IsZoomed accepts any HWND bit pattern and returns 0 for a non-window.
    unsafe { IsZoomed(hwnd) }
}

pub(crate) fn is_window_enabled(hwnd: HWND) -> BOOL {
    // SAFETY: IsWindowEnabled accepts any HWND bit pattern and returns 0 for a non-window.
    unsafe { IsWindowEnabled(hwnd) }
}

pub(crate) fn is_child(parent: HWND, child: HWND) -> BOOL {
    // SAFETY: IsChild accepts any HWND bit patterns and returns 0 when the relation does not hold.
    unsafe { IsChild(parent, child) }
}

pub(crate) fn is_menu(menu: HMENU) -> BOOL {
    // SAFETY: IsMenu accepts any HMENU bit pattern and returns 0 when it is not a menu.
    unsafe { IsMenu(menu) }
}

pub(crate) fn get_parent(hwnd: HWND) -> HWND {
    // SAFETY: GetParent accepts any HWND bit pattern and returns null when there is no parent.
    unsafe { GetParent(hwnd) }
}

pub(crate) fn get_window(hwnd: HWND, command: u32) -> HWND {
    // SAFETY: GetWindow accepts any HWND bit pattern and returns null when the relation is absent.
    unsafe { GetWindow(hwnd, command) }
}

pub(crate) fn get_ancestor(hwnd: HWND, flags: u32) -> HWND {
    // SAFETY: GetAncestor accepts any HWND bit pattern and returns null when the ancestor is absent.
    unsafe { GetAncestor(hwnd, flags) }
}

pub(crate) fn get_menu(hwnd: HWND) -> HMENU {
    // SAFETY: GetMenu accepts any HWND bit pattern and returns null when the window has no menu.
    unsafe { GetMenu(hwnd) }
}

pub(crate) fn get_dlg_ctrl_id(hwnd: HWND) -> i32 {
    // SAFETY: GetDlgCtrlID accepts any HWND bit pattern and returns 0 when it is not a child control.
    unsafe { GetDlgCtrlID(hwnd) }
}

pub(crate) fn destroy_window(hwnd: HWND) -> BOOL {
    // SAFETY: DestroyWindow returns 0 for an HWND that is not a window on this thread.
    unsafe { DestroyWindow(hwnd) }
}

pub(crate) fn destroy_menu(menu: HMENU) -> BOOL {
    // SAFETY: DestroyMenu returns 0 for an HMENU that is not a menu.
    unsafe { DestroyMenu(menu) }
}

pub(crate) fn delete_object(object: HGDIOBJ) -> BOOL {
    // SAFETY: DeleteObject returns 0 for an object that is not a deletable GDI object.
    unsafe { DeleteObject(object) }
}

pub(crate) fn get_object_type(object: HGDIOBJ) -> u32 {
    // SAFETY: GetObjectType returns 0 for a value that is not a GDI object.
    unsafe { GetObjectType(object) }
}

pub(crate) fn close_handle(handle: HANDLE) -> BOOL {
    // SAFETY: CloseHandle returns 0 for a handle that is not open in this process.
    unsafe { CloseHandle(handle) }
}

pub(crate) fn set_event(handle: HANDLE) -> BOOL {
    // SAFETY: SetEvent returns 0 for a handle that is not an event in this process.
    unsafe { SetEvent(handle) }
}

pub(crate) fn kill_timer(hwnd: HWND, id: usize) -> BOOL {
    // SAFETY: KillTimer returns 0 when the window and id are not a live timer.
    unsafe { KillTimer(hwnd, id) }
}

pub(crate) fn release_dc(hwnd: HWND, dc: HDC) -> i32 {
    // SAFETY: ReleaseDC returns 0 when the DC was not obtained from this window.
    unsafe { ReleaseDC(hwnd, dc) }
}

pub(crate) fn delete_dc(dc: HDC) -> BOOL {
    // SAFETY: DeleteDC returns 0 when the value is not a device context this process created.
    unsafe { DeleteDC(dc) }
}

pub(crate) fn reg_close_key(key: HKEY) -> WIN32_ERROR {
    // SAFETY: RegCloseKey returns an error code for a key this process did not open.
    unsafe { RegCloseKey(key) }
}

pub(crate) fn post_quit_message(code: i32) {
    // SAFETY: PostQuitMessage posts a quit message to the calling thread and takes no pointers.
    unsafe { PostQuitMessage(code) }
}

pub(crate) fn show_window(hwnd: HWND, command: i32) -> BOOL {
    // SAFETY: ShowWindow returns 0 when the HWND is not a window on this thread.
    unsafe { ShowWindow(hwnd, command) }
}

pub(crate) fn enable_window(hwnd: HWND, enable: i32) -> BOOL {
    // SAFETY: EnableWindow returns the previous state, or 0 when the HWND is not a window.
    unsafe { EnableWindow(hwnd, enable) }
}

pub(crate) fn system_color(index: i32) -> u32 {
    // SAFETY: GetSysColor takes an integer index and returns 0 when it is unknown.
    unsafe { GetSysColor(index) }
}

pub(crate) fn stock_object(index: i32) -> HGDIOBJ {
    // SAFETY: GetStockObject takes an integer stock index and returns null when it is unknown.
    unsafe { GetStockObject(index) }
}

pub(crate) fn desktop_window() -> HWND {
    // SAFETY: GetDesktopWindow takes no pointers and returns the desktop window.
    unsafe { GetDesktopWindow() }
}

pub(crate) fn foreground_window() -> HWND {
    // SAFETY: GetForegroundWindow takes no pointers.
    unsafe { GetForegroundWindow() }
}

pub(crate) fn active_window() -> HWND {
    // SAFETY: GetActiveWindow takes no pointers and returns null when this thread has none.
    unsafe { GetActiveWindow() }
}

pub(crate) fn focus_window() -> HWND {
    // SAFETY: GetFocus takes no pointers and returns null when this thread has no focus window.
    unsafe { GetFocus() }
}

pub(crate) fn capture_window() -> HWND {
    // SAFETY: GetCapture takes no pointers and returns null when this thread has no capture.
    unsafe { GetCapture() }
}

pub(crate) fn set_focus(hwnd: HWND) -> HWND {
    // SAFETY: SetFocus returns null when the HWND is not a window on this thread.
    unsafe { SetFocus(hwnd) }
}

pub(crate) fn set_active_window(hwnd: HWND) -> HWND {
    // SAFETY: SetActiveWindow returns null when the HWND is not a window on this thread.
    unsafe { SetActiveWindow(hwnd) }
}

pub(crate) fn update_window(hwnd: HWND) -> BOOL {
    // SAFETY: UpdateWindow returns 0 when the HWND is not a window on this thread.
    unsafe { UpdateWindow(hwnd) }
}

pub(crate) fn bring_window_to_top(hwnd: HWND) -> BOOL {
    // SAFETY: BringWindowToTop returns 0 when the HWND is not a window on this thread.
    unsafe { BringWindowToTop(hwnd) }
}

pub(crate) fn open_icon(hwnd: HWND) -> BOOL {
    // SAFETY: OpenIcon returns 0 when the HWND is not a minimized window on this thread.
    unsafe { OpenIcon(hwnd) }
}

pub(crate) fn close_window(hwnd: HWND) -> BOOL {
    // SAFETY: CloseWindow returns 0 when the HWND is not a window on this thread.
    unsafe { CloseWindow(hwnd) }
}

pub(crate) fn ole_uninitialize() {
    // SAFETY: OleUninitialize takes no pointers and balances OleInitialize on this thread.
    unsafe { OleUninitialize() }
}

pub(crate) fn co_uninitialize() {
    // SAFETY: CoUninitialize takes no pointers and balances CoInitialize on this thread.
    unsafe { CoUninitialize() }
}

pub(crate) fn dde_last_error(instance: u32) -> u32 {
    // SAFETY: DdeGetLastError reads the instance's last DDE error and takes no pointers.
    unsafe { DdeGetLastError(instance) }
}

pub(crate) fn find_close(handle: HANDLE) -> BOOL {
    // SAFETY: FindClose returns 0 for a search handle this process did not open.
    unsafe { FindClose(handle) }
}

pub(crate) fn unhook_windows_hook(hook: HHOOK) -> BOOL {
    // SAFETY: UnhookWindowsHookEx returns 0 for a hook this process did not install.
    unsafe { UnhookWindowsHookEx(hook) }
}
