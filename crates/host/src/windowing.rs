//! Windows USER/GDI adapter for the portable graphics model.
//!
//! The adapter owns native HWNDs and translates them to/from guest window
//! handles. Guest class names remain model metadata: all HWNDs use one private
//! host class so a guest cannot select arbitrary native window procedures.

mod context;
mod events;
mod paint;

#[cfg(test)]
mod tests;

use context::{CallbackRecord, WindowContext, window_proc};
use graphics::{HostAction, HostEvent, Rect, Surface, WindowHandle};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use windows_sys::Win32::Foundation::{HINSTANCE, HWND};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DispatchMessageW, GWLP_USERDATA, MSG, MoveWindow,
    PM_REMOVE, PeekMessageW, RegisterClassExW, SW_HIDE, SW_SHOW, SetWindowLongPtrW,
    TranslateMessage, UnregisterClassW, WM_QUIT, WNDCLASSEXW, WS_CHILD, WS_OVERLAPPEDWINDOW,
};

const HOST_CLASS_PREFIX: &str = "VdmDisplayWindow";
static NEXT_CLASS_ID: AtomicU64 = AtomicU64::new(1);

/// Failures from native window operations or checked adapter state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowingError {
    Native {
        operation: &'static str,
        code: Option<u32>,
    },
    InvalidRectangle,
    InvalidTitle,
    DuplicateWindow(WindowHandle),
    UnknownWindow(WindowHandle),
    UnknownParent(WindowHandle),
    AllocationFailed,
    ContextUnavailable,
    SurfaceStatePoisoned,
    IdentifierExhausted,
    CallbackPanic,
}

impl fmt::Display for WindowingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native { operation, code: Some(code) } => write!(
                f,
                "Windows API operation {operation} failed with error code {code} (0x{code:08X})."
            ),
            Self::Native { operation, code: None } => write!(
                f,
                "Windows API operation {operation} failed without reporting an error code."
            ),
            Self::InvalidRectangle => {
                f.write_str("Window rectangle has negative or unrepresentable width or height.")
            }
            Self::InvalidTitle => f.write_str("Window title contains an embedded NUL character."),
            Self::DuplicateWindow(handle) => write!(
                f,
                "Host window handle 0x{:04X} is already registered.",
                handle.raw()
            ),
            Self::UnknownWindow(handle) => write!(
                f,
                "Host window handle 0x{:04X} is not registered.",
                handle.raw()
            ),
            Self::UnknownParent(handle) => write!(
                f,
                "Parent host window handle 0x{:04X} is not registered.",
                handle.raw()
            ),
            Self::AllocationFailed => {
                f.write_str("Could not allocate state for the native window or its frame.")
            }
            Self::ContextUnavailable => f.write_str(
                "Native window callback context is unavailable because the window was destroyed or initialization failed.",
            ),
            Self::SurfaceStatePoisoned => {
                f.write_str("Native window surface state was poisoned by a previous panic.")
            }
            Self::IdentifierExhausted => {
                f.write_str("No unique 64-bit host window class identifiers remain.")
            }
            Self::CallbackPanic => {
                f.write_str("A panic occurred while processing a native window callback.")
            }
        }
    }
}

impl std::error::Error for WindowingError {}

fn native_error(operation: &'static str) -> WindowingError {
    let code = { crate::windows::win32_safe::last_error() };
    WindowingError::Native {
        operation,
        code: (code != 0).then_some(code),
    }
}

struct RegisteredClass {
    instance: HINSTANCE,
    name: Vec<u16>,
    registered: bool,
}

impl RegisteredClass {
    fn register() -> Result<Self, WindowingError> {
        let id = NEXT_CLASS_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| WindowingError::IdentifierExhausted)?;
        let mut name: Vec<u16> = format!("{HOST_CLASS_PREFIX}_{id}").encode_utf16().collect();
        name.push(0);

        {
            crate::windows::win32_safe::set_last_error(0);
        }
        let instance = { crate::windows::win32_safe::current_module() };
        if instance.is_null() {
            return Err(native_error("GetModuleHandleW"));
        }

        let class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: name.as_ptr(),
            ..WNDCLASSEXW::default()
        };
        {
            crate::windows::win32_safe::set_last_error(0);
        }
        // SAFETY: RegisterClassExW reads a caller-owned WNDCLASSEXW whose string pointers stay live for the call.
        let atom = unsafe { RegisterClassExW(&class) };
        if atom == 0 {
            return Err(native_error("RegisterClassExW"));
        }
        Ok(Self {
            instance,
            name,
            registered: true,
        })
    }

    fn name_ptr(&self) -> *const u16 {
        self.name.as_ptr()
    }
}

impl Drop for RegisteredClass {
    fn drop(&mut self) {
        if self.registered {
            // SAFETY: This class was registered by this object and all owned
            // HWNDs are dropped before the class field is dropped.
            if unsafe { UnregisterClassW(self.name.as_ptr(), self.instance) } == 0 {
                // An HWND could still hold this class after failed native
                // teardown. Preserve the name allocation if USER still keeps
                // registration state, and leave the class process-owned.
                let name = std::mem::take(&mut self.name).into_boxed_slice();
                let _ = Box::leak(name);
            }
            self.registered = false;
        }
    }
}

struct NativeWindow {
    hwnd: HWND,
    parent: Option<WindowHandle>,
    context: Option<Box<WindowContext>>,
}

impl NativeWindow {
    fn context(&self) -> Result<&WindowContext, WindowingError> {
        self.context
            .as_deref()
            .ok_or(WindowingError::ContextUnavailable)
    }
}

impl Drop for NativeWindow {
    fn drop(&mut self) {
        let Some(context) = self.context.take() else {
            return;
        };
        if context.is_destroyed() {
            // WM_NCDESTROY has completed. Never pass its numeric HWND back to
            // USER during Drop because the system may already have reused it.
            return;
        }
        // SAFETY: hwnd is an HWND created and retained by this record. DestroyWindow
        // synchronously sends WM_NCDESTROY, which marks the still-owned context.
        let destroyed = { crate::windows::win32_safe::destroy_window(self.hwnd) } != 0;
        if destroyed {
            // A successful DestroyWindow guarantees that no later callback can
            // use this pointer, even if a corrupted WndProc failed to mark it.
            return;
        }
        if !destroyed && !context.is_destroyed() {
            // A failed teardown must not free data still reachable through
            // GWLP_USERDATA. Leaking this tiny context is safer than a callback UAF.
            let _ = Box::leak(context);
        }
    }
}

/// Owns HWNDs on the creating thread and translates native messages to the
/// portable USER event model. It is intentionally `!Send` and `!Sync`.
pub struct Windowing {
    class: RegisteredClass,
    windows: BTreeMap<WindowHandle, NativeWindow>,
    destroyed: BTreeSet<WindowHandle>,
    events_tx: Sender<CallbackRecord>,
    events_rx: Receiver<CallbackRecord>,
    pending_events: VecDeque<HostEvent>,
    pending_failure: Option<WindowingError>,
    quit_code: Option<i32>,
    _thread_affinity: PhantomData<Rc<Cell<()>>>,
}

impl Windowing {
    /// Registers one private host class. The caller must continue pumping its
    /// thread's queue with [`poll_events`](Self::poll_events).
    pub fn new() -> Result<Self, WindowingError> {
        let class = RegisteredClass::register()?;
        let (events_tx, events_rx) = mpsc::channel();
        Ok(Self {
            class,
            windows: BTreeMap::new(),
            destroyed: BTreeSet::new(),
            events_tx,
            events_rx,
            pending_events: VecDeque::new(),
            pending_failure: None,
            quit_code: None,
            _thread_affinity: PhantomData,
        })
    }

    /// Applies one model action. Rectangles used for creation and movement are
    /// outer-window bounds; invalidation rectangles and paint damage are client
    /// coordinates. No host API result is represented as a successful stub.
    pub fn apply_action(&mut self, action: HostAction) -> Result<(), WindowingError> {
        match action {
            HostAction::CreateWindow {
                handle,
                title,
                parent,
                rect,
                ..
            } => self.create_window(handle, &title, parent, rect),
            HostAction::SetWindowVisible { handle, visible } => {
                let hwnd = self.window_handle(handle)?;
                // ShowWindow returns the previous visibility state, not success.
                {
                    crate::windows::win32_safe::show_window(
                        hwnd,
                        if visible { SW_SHOW } else { SW_HIDE },
                    );
                }
                Ok(())
            }
            HostAction::SetWindowEnabled { handle, enabled } => {
                let hwnd = self.window_handle(handle)?;
                // EnableWindow likewise reports the previous enabled state.
                {
                    crate::windows::win32_safe::enable_window(hwnd, if enabled { 1 } else { 0 });
                }
                Ok(())
            }
            HostAction::MoveWindow { handle, rect } => {
                let hwnd = self.window_handle(handle)?;
                let (width, height) = rect_extent(rect)?;
                {
                    crate::windows::win32_safe::set_last_error(0);
                }
                // SAFETY: MoveWindow takes no caller pointer. The HWND is a window on this thread.
                if unsafe { MoveWindow(hwnd, rect.left, rect.top, width, height, 1) } == 0 {
                    return Err(native_error("MoveWindow"));
                }
                Ok(())
            }
            HostAction::DestroyWindow { handle } => self.destroy_window(handle),
            HostAction::InvalidateWindow { handle, rect } => self.invalidate_window(handle, rect),
        }
    }

    /// Replaces the owned software image shown by a native window and requests
    /// a repaint. Pixel bytes are copied into an owned top-down BGRA DIB.
    pub fn update_surface(
        &mut self,
        handle: WindowHandle,
        surface: &Surface,
    ) -> Result<(), WindowingError> {
        let dib = paint::OwnedDib::from_surface(surface)?;
        let hwnd = self.window_handle(handle)?;
        let context = self
            .windows
            .get(&handle)
            .ok_or(WindowingError::UnknownWindow(handle))?
            .context()?;
        *context
            .surface
            .lock()
            .map_err(|_| WindowingError::SurfaceStatePoisoned)? = Some(dib);
        if { paint::invalidate(hwnd, None) } == 0 {
            return Err(native_error("InvalidateRect"));
        }
        Ok(())
    }

    /// Clears a window's software image and invalidates its client area.
    pub fn clear_surface(&mut self, handle: WindowHandle) -> Result<(), WindowingError> {
        let hwnd = self.window_handle(handle)?;
        let context = self
            .windows
            .get(&handle)
            .ok_or(WindowingError::UnknownWindow(handle))?
            .context()?;
        *context
            .surface
            .lock()
            .map_err(|_| WindowingError::SurfaceStatePoisoned)? = None;
        if { paint::invalidate(hwnd, None) } == 0 {
            return Err(native_error("InvalidateRect"));
        }
        Ok(())
    }

    /// Pumps all currently queued native messages and returns translated host
    /// events in FIFO order. `WM_QUIT` is retained for [`take_quit_code`](Self::take_quit_code).
    pub fn poll_events(&mut self) -> Result<Vec<HostEvent>, WindowingError> {
        let mut message = MSG::default();
        // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
        while unsafe { PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
            if message.message == WM_QUIT {
                self.quit_code = Some(message.wParam as i32);
                break;
            }
            // SAFETY: TranslateMessage reads a caller-owned MSG for this call only. DispatchMessageW reads a caller-owned MSG for this call only.
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        self.reap_destroyed_windows();
        while let Ok(record) = self.events_rx.try_recv() {
            match record {
                CallbackRecord::Event(event) => self.pending_events.push_back(event),
                CallbackRecord::Failure(error) => {
                    if self.pending_failure.is_none() {
                        self.pending_failure = Some(error);
                    }
                }
            }
        }
        if let Some(error) = self.pending_failure.take() {
            return Err(error);
        }
        Ok(self.pending_events.drain(..).collect())
    }

    /// Returns and clears the most recently observed `WM_QUIT` exit code.
    pub fn take_quit_code(&mut self) -> Option<i32> {
        self.quit_code.take()
    }

    fn create_window(
        &mut self,
        handle: WindowHandle,
        title: &str,
        parent: Option<WindowHandle>,
        rect: Rect,
    ) -> Result<(), WindowingError> {
        if self.windows.contains_key(&handle) || self.destroyed.contains(&handle) {
            return Err(WindowingError::DuplicateWindow(handle));
        }
        let (width, height) = rect_extent(rect)?;
        if title.encode_utf16().any(|unit| unit == 0) {
            return Err(WindowingError::InvalidTitle);
        }
        let mut wide_title = Vec::new();
        let title_units = title.encode_utf16().count();
        wide_title
            .try_reserve_exact(
                title_units
                    .checked_add(1)
                    .ok_or(WindowingError::AllocationFailed)?,
            )
            .map_err(|_| WindowingError::AllocationFailed)?;
        wide_title.extend(title.encode_utf16());
        wide_title.push(0);
        let (parent_hwnd, style) = match parent {
            Some(parent) => (
                self.window_handle(parent)
                    .map_err(|_| WindowingError::UnknownParent(parent))?,
                WS_CHILD,
            ),
            None => (std::ptr::null_mut(), WS_OVERLAPPEDWINDOW),
        };
        // SAFETY: Class/title strings are valid NUL-terminated UTF-16 for this
        // synchronous call and parent_hwnd is either null or an owned HWND.
        // No Rust pointer is passed through the Windows creation callback.
        let hwnd = unsafe {
            crate::windows::win32_safe::set_last_error(0);
            CreateWindowExW(
                0,
                self.class.name_ptr(),
                wide_title.as_ptr(),
                style,
                rect.left,
                rect.top,
                width,
                height,
                parent_hwnd,
                std::ptr::null_mut(),
                self.class.instance,
                std::ptr::null(),
            )
        };
        if hwnd.is_null() {
            return Err(native_error("CreateWindowExW"));
        }

        let context = Box::new(WindowContext::new(handle, self.events_tx.clone()));
        let context_ptr = (&*context as *const WindowContext).cast::<std::ffi::c_void>();
        // SAFETY: hwnd is the just-created private-class window and userdata is
        // still zero. The stable Box pointer is installed only after native
        // creation has completed, then retained by NativeWindow through
        // WM_NCDESTROY.
        {
            crate::windows::win32_safe::set_last_error(0);
        }
        // windows-sys aliases this API to SetWindowLongW (LONG/i32) on x86;
        // infer the native parameter width so the host-owned pointer keeps
        // every bit on both the 32-bit and pointer-sized API declarations.
        // SAFETY: SetWindowLongPtrW writes one window-long slot owned by this window.
        let previous = unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, context_ptr as _) };
        let error = { crate::windows::win32_safe::last_error() };
        if previous != 0 || error != 0 {
            let error = WindowingError::Native {
                operation: "SetWindowLongPtrW(GWLP_USERDATA)",
                code: (error != 0).then_some(error),
            };
            // Keep context alive until HWND destruction has synchronously
            // delivered WM_NCDESTROY if the pointer was installed.
            let destroyed = { crate::windows::win32_safe::destroy_window(hwnd) } != 0;
            if !destroyed && !context.is_destroyed() {
                let _ = Box::leak(context);
            }
            return Err(error);
        }
        if context.is_destroyed() {
            // A window that was synchronously torn down during creation must
            // never be recorded as a live host object.
            return Err(WindowingError::ContextUnavailable);
        }
        self.windows.insert(
            handle,
            NativeWindow {
                hwnd,
                parent,
                context: Some(context),
            },
        );
        Ok(())
    }

    fn window_handle(&self, handle: WindowHandle) -> Result<HWND, WindowingError> {
        let window = self
            .windows
            .get(&handle)
            .ok_or(WindowingError::UnknownWindow(handle))?;
        let context = window.context()?;
        if context.is_destroyed() || { crate::windows::win32_safe::is_window(window.hwnd) } == 0 {
            return Err(WindowingError::ContextUnavailable);
        }
        Ok(window.hwnd)
    }

    fn invalidate_window(&self, handle: WindowHandle, rect: Rect) -> Result<(), WindowingError> {
        let hwnd = self.window_handle(handle)?;
        rect_extent(rect)?;
        let native_rect = windows_sys::Win32::Foundation::RECT {
            left: rect.left,
            top: rect.top,
            right: rect.right,
            bottom: rect.bottom,
        };
        if { paint::invalidate(hwnd, Some(&native_rect)) } == 0 {
            return Err(native_error("InvalidateRect"));
        }
        Ok(())
    }

    fn destroy_window(&mut self, handle: WindowHandle) -> Result<(), WindowingError> {
        self.reap_destroyed_windows();
        if self.destroyed.contains(&handle) {
            return Ok(());
        }
        let hwnd = self.window_handle(handle)?;
        {
            crate::windows::win32_safe::set_last_error(0);
        }
        if { crate::windows::win32_safe::destroy_window(hwnd) } == 0 {
            return Err(native_error("DestroyWindow"));
        }
        self.reap_destroyed_windows();
        if self.windows.contains_key(&handle) {
            return Err(WindowingError::ContextUnavailable);
        }
        Ok(())
    }

    fn reap_destroyed_windows(&mut self) {
        loop {
            let Some(handle) = self.windows.iter().find_map(|(handle, window)| {
                window
                    .context
                    .as_ref()
                    .filter(|context| context.is_destroyed())
                    .map(|_| *handle)
            }) else {
                break;
            };
            self.windows.remove(&handle);
            self.destroyed.insert(handle);
        }
    }
}

impl Drop for Windowing {
    fn drop(&mut self) {
        // Prefer leaves so native parents do not need to cascade-destroy child
        // windows. NativeWindow remains a final RAII safety net for each HWND.
        while let Some(handle) = self
            .windows
            .iter()
            .rev()
            .find_map(|(candidate, _)| {
                let has_child = self
                    .windows
                    .values()
                    .any(|window| window.parent == Some(*candidate));
                (!has_child).then_some(*candidate)
            })
            .or_else(|| self.windows.keys().next_back().copied())
        {
            self.windows.remove(&handle);
        }
    }
}

fn rect_extent(rect: Rect) -> Result<(i32, i32), WindowingError> {
    let width = i64::from(rect.right) - i64::from(rect.left);
    let height = i64::from(rect.bottom) - i64::from(rect.top);
    if width < 0 || height < 0 {
        return Err(WindowingError::InvalidRectangle);
    }
    let width = i32::try_from(width).map_err(|_| WindowingError::InvalidRectangle)?;
    let height = i32::try_from(height).map_err(|_| WindowingError::InvalidRectangle)?;
    Ok((width, height))
}
