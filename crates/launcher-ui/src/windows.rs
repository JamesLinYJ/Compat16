use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, Receiver, Sender};

use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::{
    Foundation::*,
    Globalization::CompareStringOrdinal,
    Graphics::Gdi::*,
    System::{
        Com::*, Console::FreeConsole, Environment::GetCommandLineW, LibraryLoader::GetModuleHandleW,
    },
    UI::{HiDpi::*, Shell::*, WindowsAndMessaging::*},
};

use crate::{
    model::{Settings, display_path},
    process::Event,
    store,
};

mod actions;
#[cfg(test)]
mod control_tests;
mod controls;
mod layout;
mod theme;

const CLASS: &str = "Compat16.Launcher";
const TIMER: usize = 1;

pub(super) fn is_home_invocation() -> bool {
    let mut arguments = std::env::args_os();
    let Some(first) = arguments.next() else {
        return false;
    };
    if arguments.next().is_some() {
        return false;
    }
    let (Ok(first), Ok(executable)) = (
        resolve_invocation(&first),
        std::env::current_exe().and_then(|path| path.canonicalize()),
    ) else {
        return false;
    };
    let first = wide(first.as_os_str());
    let executable = wide(executable.as_os_str());
    // argv0 from a substituted legacy image is not the public launcher. Compare
    // canonical host paths using Windows' ordinal, case-insensitive semantics.
    if
    // SAFETY: `CompareStringOrdinal` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        CompareStringOrdinal(
            first.as_ptr(),
            (first.len() - 1) as i32,
            executable.as_ptr(),
            (executable.len() - 1) as i32,
            1,
        )
    } != 2
    {
        return false;
    }
    let raw =
        // SAFETY: GetCommandLineW returns this process's command line, or null when the process has none.
        unsafe { GetCommandLineW() };
    if raw.is_null() {
        return false;
    }
    let mut length = 0;
    // CreateProcess bounds command lines to 32,767 UTF-16 units.
    while length < 32_767 &&
        // SAFETY: the index stays below the 32,767-unit command-line bound and this read stops at the first NUL.
        unsafe { *raw.add(length) } != 0
    {
        length += 1;
    }
    if length == 32_767 {
        return false;
    }
    only_executable(
        // SAFETY: the length is the counted prefix before the terminating NUL and does not include that NUL.
        unsafe { std::slice::from_raw_parts(raw, length) },
    )
}

fn resolve_invocation(first: &OsStr) -> std::io::Result<PathBuf> {
    if let Ok(path) = PathBuf::from(first).canonicalize() {
        return Ok(path);
    }
    let mut buffer = vec![0_u16; 32_768];
    let length =
        // SAFETY: `SearchPathW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
        windows_sys::Win32::Storage::FileSystem::SearchPathW(
            null(),
            wide(first).as_ptr(),
            wide(".exe").as_ptr(),
            buffer.len() as u32,
            buffer.as_mut_ptr(),
            null_mut(),
        )
    };
    if length == 0 || length as usize >= buffer.len() {
        return Err(std::io::Error::last_os_error());
    }
    PathBuf::from(OsString::from_wide(&buffer[..length as usize])).canonicalize()
}

fn only_executable(command: &[u16]) -> bool {
    let mut quoted = false;
    for (index, &unit) in command.iter().enumerate() {
        if unit == u16::from(b'"') {
            quoted = !quoted;
        } else if !quoted && matches!(unit, 9 | 32) {
            return command[index..].iter().all(|unit| matches!(unit, 9 | 32));
        }
    }
    !quoted
}

struct State {
    window: HWND,
    controls: controls::Controls,
    fonts: controls::Fonts,
    settings: Settings,
    root: PathBuf,
    installation: PathBuf,
    events: Receiver<Event>,
    sender: Sender<Event>,
    advanced: bool,
    error: bool,
    running: usize,
    log: Option<PathBuf>,
    dpi: u32,
    scroll: i32,
    logs: std::collections::BTreeMap<PathBuf, crate::log_reader::LogReader>,
}

impl State {
    fn status(&mut self, message: &str, error: bool) {
        self.error = error;
        set_text(self.controls.status, message);
        // SAFETY: `InvalidateRect` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            InvalidateRect(self.controls.status, null(), 1);
        }
        if error {
            self.append_log(&format!("{message}\r\n"));
        }
    }

    fn append_log(&self, message: &str) {
        let window = self.controls.log_view;
        let message = message.replace("\r\n", "\n").replace('\n', "\r\n");
        let mut message = wide(&message);
        if message.len() > 48 * 1024 {
            let mut start = message.len() - 48 * 1024;
            if (0xdc00..=0xdfff).contains(&message[start]) {
                start += 1;
            }
            message.drain(..start);
        }
        // SAFETY: `GetWindowTextLengthW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            let length = GetWindowTextLengthW(window).max(0) as usize;
            if length + message.len() > 64 * 1024 {
                let remove = length.saturating_sub(64 * 1024 - message.len());
                SendMessageW(window, 0x00b1, 0, remove as isize); // EM_SETSEL
                SendMessageW(window, 0x00c2, 0, wide("").as_ptr() as isize); // EM_REPLACESEL
            }
            let end = GetWindowTextLengthW(window).max(0) as usize;
            SendMessageW(window, 0x00b1, end, end as isize);
            SendMessageW(window, 0x00c2, 0, message.as_ptr() as isize);
            SendMessageW(window, 0x00b7, 0, 0); // EM_SCROLLCARET
        }
    }

    fn drain_logs(&mut self, finished: Option<&std::path::Path>) {
        let mut chunks = Vec::new();
        for (path, reader) in &mut self.logs {
            chunks.push(reader.read(finished == Some(path.as_path())));
        }
        for chunk in chunks {
            if !chunk.is_empty() {
                self.append_log(&chunk);
            }
        }
        if let Some(path) = finished {
            self.logs.remove(path);
        }
    }
}

struct ComApartment(bool);
impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: `CoUninitialize` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe {
                CoUninitialize();
            }
        }
    }
}

pub(super) fn run() -> Result<(), String> {
    // These process-wide changes occur only on the home path. Guest execution
    // and installed system launches never inherit the UI's DPI context.
    // SAFETY: `FreeConsole` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        FreeConsole();
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let _com = ComApartment(
        // SAFETY: `CoInitializeEx` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32) } >= 0,
    );
    let _theme = theme::Theme::activate()?;
    let instance =
        // SAFETY: `GetModuleHandleW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { GetModuleHandleW(null()) };
    let class = wide(CLASS);
    let icon =
        // SAFETY: `LoadIconW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { LoadIconW(instance, 101_usize as *const u16) };
    let descriptor = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hIcon: icon,
        hCursor:
            // SAFETY: `LoadCursorW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hbrBackground:
            // SAFETY: `GetStockObject` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe { GetStockObject(WHITE_BRUSH) }.cast(),
        lpszClassName: class.as_ptr(),
        ..Default::default()
    };
    if
    // SAFETY: `RegisterClassW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe { RegisterClassW(&descriptor) } == 0 {
        return Err(format!(
            "无法注册启动窗口：{}",
            std::io::Error::last_os_error()
        ));
    }
    let window =
        // SAFETY: `CreateWindowExW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
        CreateWindowExW(
            WS_EX_ACCEPTFILES | WS_EX_CONTROLPARENT,
            class.as_ptr(),
            wide("Compat16").as_ptr(),
            controls::WINDOW_STYLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            700,
            540,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if window.is_null() {
        return Err(format!(
            "无法创建启动窗口：{}",
            std::io::Error::last_os_error()
        ));
    }
    let result = run_window(window);
    if
    // SAFETY: `IsWindow` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe { IsWindow(window) } != 0 {
        // SAFETY: `DestroyWindow` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            DestroyWindow(window);
        }
    }
    // SAFETY: `UnregisterClassW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        UnregisterClassW(class.as_ptr(), instance);
    }
    result
}

fn run_window(window: HWND) -> Result<(), String> {
    let root = store::root();
    let (settings, warning) = match store::load(&root) {
        Ok(settings) => (settings, None),
        Err(error) => (Settings::default(), Some(error)),
    };
    let installation = std::env::current_exe()
        .map_err(|error| error.to_string())?
        .parent()
        .ok_or("无法确定运行时目录。")?
        .to_path_buf();
    let dpi =
        // SAFETY: `GetDpiForWindow` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { GetDpiForWindow(window) }.max(96);
    let fonts = controls::Fonts::new(dpi)?;
    let controls = controls::Controls::new(window, &fonts, &settings)?;
    let (sender, events) = mpsc::channel();
    let state = Box::new(RefCell::new(State {
        window,
        controls,
        fonts,
        settings,
        root,
        installation,
        events,
        sender,
        advanced: false,
        error: false,
        running: 0,
        log: None,
        dpi,
        scroll: 0,
        logs: Default::default(),
    }));
    // SAFETY: `SetWindowLongPtrW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        SetWindowLongPtrW(
            window,
            GWLP_USERDATA,
            (&*state as *const RefCell<State>) as isize,
        );
    }
    state.borrow_mut().layout(true);
    if let Some(warning) = warning {
        state.borrow_mut().status(&warning, true);
    }
    // SAFETY: `DragAcceptFiles` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        DragAcceptFiles(window, 1);
        SetTimer(window, TIMER, 150, None);
        ShowWindow(window, SW_SHOWNORMAL);
        UpdateWindow(window);
        windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus(state.borrow().controls.program);
    }
    let mut message = MSG::default();
    let result = loop {
        let result =
            // SAFETY: `GetMessageW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
        if result == -1 {
            break Err(format!(
                "窗口消息读取失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        if result == 0 {
            break if message.wParam == 0 {
                Ok(())
            } else {
                Err("启动窗口发生内部错误。".into())
            };
        }
        if
        // SAFETY: `IsDialogMessageW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { IsDialogMessageW(window, &message) } == 0 {
            // SAFETY: `TranslateMessage` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    };
    // HWND_USERDATA must never outlive the boxed RefCell, including GetMessage
    // failure and panic paths. Window teardown may still synchronously reenter.
    if
    // SAFETY: `IsWindow` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe { IsWindow(window) } != 0 {
        // SAFETY: `DestroyWindow` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            DestroyWindow(window);
        }
    }
    drop(state);
    result
}

/// # Safety
///
/// Windows calls this with the HWND registered on this thread. For messages
/// that carry a structure, `lp` is either null or a pointer to that structure
/// for the duration of the call.
unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wp: WPARAM,
    lp: LPARAM,
) -> LRESULT {
    std::panic::catch_unwind(||
        // SAFETY: `PostQuitMessage` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { dispatch(window, message, wp, lp) })
    .unwrap_or_else(|_| {
        // SAFETY: `PostQuitMessage` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            PostQuitMessage(125);
        }
        0
    })
}

/// # Safety
///
/// `window` is the HWND Windows passed to this thread's window procedure.
/// `lp` for `WM_DRAWITEM` and `WM_DPICHANGED` is either null or a pointer to
/// the structure Windows allocated for that message.
unsafe fn dispatch(window: HWND, message: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if message == WM_CLOSE {
        // SAFETY: `DestroyWindow` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            DestroyWindow(window);
        }
        return 0;
    }
    if message == WM_DESTROY {
        // SAFETY: `KillTimer` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            KillTimer(window, TIMER);
            PostQuitMessage(0);
        }
        return 0;
    }
    if message == WM_NCDESTROY {
        // SAFETY: `SetWindowLongPtrW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe {
            SetWindowLongPtrW(window, GWLP_USERDATA, 0);
        }
    }
    let pointer =
        // SAFETY: `GetWindowLongPtrW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *const RefCell<State>;
    if !pointer.is_null() {
        // The UI thread owns the box until after DestroyWindow and the loop.
        // Native controls can reenter; nested messages use DefWindowProc.
        if let Ok(mut state) =
            // SAFETY: GWLP_USERDATA holds this thread's State box until DestroyWindow returns, and the pointer was checked non-null.
            unsafe { &*pointer }.try_borrow_mut()
        {
            match message {
                WM_DRAWITEM if wp == usize::from(controls::RUN) => {
                    if lp == 0 {
                        return 0;
                    }
                    // SAFETY: a non-zero WM_DRAWITEM lParam is a DRAWITEMSTRUCT
                    // that stays live for this call and is not retained.
                    state.draw_run(
                        // SAFETY: a non-zero WM_DRAWITEM lParam is a DRAWITEMSTRUCT that stays live for this call and is not retained.
                        unsafe {
                            &*(lp as *const windows_sys::Win32::UI::Controls::DRAWITEMSTRUCT)
                        },
                    );
                    return 1;
                }
                WM_COMMAND => {
                    state.command((wp & 0xffff) as u16, (wp >> 16) as u16);
                    return 0;
                }
                WM_DROPFILES => {
                    state.drop_files(wp as HDROP);
                    return 0;
                }
                WM_TIMER if wp == TIMER => {
                    state.poll();
                    return 0;
                }
                WM_VSCROLL => {
                    state.scroll((wp & 0xffff) as i32, 0);
                    return 0;
                }
                WM_MOUSEWHEEL => {
                    state.scroll(-1, ((wp >> 16) as i16) as i32);
                    return 0;
                }
                WM_DPICHANGED => {
                    let dpi = (wp & 0xffff) as u32;
                    if let Ok(fonts) = controls::Fonts::new(dpi) {
                        state.controls.fonts(&fonts);
                        state.fonts = fonts;
                        state.dpi = dpi;
                        if lp == 0 {
                            state.layout(true);
                            return 0;
                        }
                        // SAFETY: a non-zero WM_DPICHANGED lParam is a suggested
                        // RECT that stays live for this call and is not retained.
                        let rect =
                            // SAFETY: a non-zero WM_DPICHANGED lParam is a RECT that stays live for this call and is not retained.
                            unsafe { &*(lp as *const RECT) };
                        // SAFETY: `SetWindowPos` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
                        unsafe {
                            SetWindowPos(
                                window,
                                null_mut(),
                                rect.left,
                                rect.top,
                                rect.right - rect.left,
                                rect.bottom - rect.top,
                                SWP_NOZORDER | SWP_NOACTIVATE,
                            );
                        }
                        state.layout(true);
                    }
                    return 0;
                }
                WM_CTLCOLORSTATIC => {
                    let dc = wp as HDC;
                    // SAFETY: `SetBkColor` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
                    unsafe {
                        SetBkColor(dc, 0x00ff_ffff);
                        SetTextColor(
                            dc,
                            if lp as HWND == state.controls.status && state.error {
                                0x0030_30b0
                            } else {
                                0x004b_4b4b
                            },
                        );
                        return GetStockObject(WHITE_BRUSH) as LRESULT;
                    }
                }
                // IsDialogMessage supplies keyboard navigation and Enter.
                0x0400 => return (0x534b << 16) | controls::RUN as isize, // DM_GETDEFID
                _ => {}
            }
        }
    }
    // SAFETY: `DefWindowProcW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe { DefWindowProcW(window, message, wp, lp) }
}

pub(super) fn show_error(message: &str) {
    // SAFETY: `MessageBoxW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        MessageBoxW(
            null_mut(),
            wide(message).as_ptr(),
            wide("Compat16").as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain(Some(0)).collect()
}
fn set_text(window: HWND, text: &str) {
    // SAFETY: `SetWindowTextW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
    unsafe {
        SetWindowTextW(window, wide(text).as_ptr());
    }
}
fn text(window: HWND) -> String {
    let length =
        // SAFETY: `GetWindowTextLengthW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { GetWindowTextLengthW(window) }.max(0) as usize;
    let mut buffer = vec![0; length + 1];
    let copied =
        // SAFETY: `GetWindowTextW` uses caller-owned host memory that stays live for this synchronous call. An invalid handle returns the API failure code, and no guest address is passed.
        unsafe { GetWindowTextW(window, buffer.as_mut_ptr(), buffer.len() as i32) }.max(0) as usize;
    String::from_utf16_lossy(&buffer[..copied])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn home_requires_an_empty_native_command_tail() {
        for command in [r#""C:\Tools\compat16w.exe""#, "compat16.exe  \t"] {
            assert!(only_executable(&command.encode_utf16().collect::<Vec<_>>()));
        }
        for command in [
            r#""APP.EXE" --system-module "APP.EXE" --system-command "#,
            "compat16w.exe --guest-child 1 2 3",
            "compat16.exe APP.COM",
            r#""APP --system-module "APP.EXE" --system-command "#,
        ] {
            assert!(!only_executable(
                &command.encode_utf16().collect::<Vec<_>>()
            ));
        }
    }
}
