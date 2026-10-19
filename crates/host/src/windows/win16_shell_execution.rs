//! Native Windows SHELL services executed on the Win16 USER owner thread.

use std::cell::RefCell;
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
use std::rc::Rc;
use std::sync::Arc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostProcess, Win16HostShellActivation,
    Win16HostShellExecutionOperation, Win16HostShellExecutionResult, Win16HostShellFailure,
    Win16HostShellInputEncodingFailure, Win16HostWinExecFailure, Win16NativeModalCancelSignal,
    Win16NativeModalCancellation, Win16WindowResult, Win16WindowTarget,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ELEVATION_REQUIRED, ERROR_FILE_NOT_FOUND, ERROR_NOT_ENOUGH_MEMORY,
    ERROR_OUTOFMEMORY, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, HWND, MAX_PATH,
};
use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, PROCESS_INFORMATION, STARTF_USESHOWWINDOW,
    STARTUPINFOW, WaitForInputIdle,
};
use windows_sys::Win32::UI::Shell::{
    DragAcceptFiles, FindExecutableW, SEE_MASK_CLASSNAME, SEE_MASK_NOASYNC,
    SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellAboutW, ShellExecuteExW,
};

#[path = "win16_shell_execution_paths.rs"]
mod paths;
use paths::{
    AnsiInputConversion, PathEncodingOutcome, lossless_executable_path, resolve_executable_input,
};

use super::super::win16_images::Win16IconLease;
use super::win16_window_worker::WorkerState;
use super::win16_windows_dde::allocate_shared_identity;
use crate::windows::win16_program_launch;
use win16_program_launch::native_error_code as win_exec_error;

pub(super) struct ProcessLease {
    pub(super) token: Win16HostProcess,
    /// None exists only while the owning worker operation is in ShellExecuteEx.
    pub(super) handle: Option<OwnedHandle>,
}

struct ComApartment {
    initialized: bool,
}

impl ComApartment {
    fn initialize_sta() -> Result<Self, i32> {
        // Shell extensions may require STA. Balance both S_OK and S_FALSE;
        // never call CoUninitialize after a failed COM initialization.
        // SAFETY: CoInitializeEx initializes COM on the calling thread.
        let result = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
        if result < 0 {
            return Err(result);
        }
        Ok(Self { initialized: true })
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.initialized {
            (crate::windows::win32_safe::co_uninitialize());
        }
    }
}

struct OwnedAnsi(Vec<u8>);

impl OwnedAnsi {
    fn new(bytes: &[u8], operation: &'static str) -> Result<Self, RuntimeError> {
        if bytes.contains(&0) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "decoded Win16 SHELL string contains an interior NUL",
            ));
        }
        let capacity = bytes.len().checked_add(1).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "Win16 SHELL string size overflow")
        })?;
        let mut value = Vec::new();
        value.try_reserve_exact(capacity).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, operation, error)
        })?;
        value.extend_from_slice(bytes);
        value.push(0);
        Ok(Self(value))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0[..self.0.len() - 1]
    }

    fn into_bytes(mut self) -> Vec<u8> {
        self.0.pop();
        self.0
    }
}

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation_id: u64,
    operation: Win16HostShellExecutionOperation,
    prepared: Option<Result<win16_program_launch::PreparedLaunch, u16>>,
) -> Result<super::super::win16_modal::NativeModalOperationOutcome, RuntimeError> {
    match operation {
        Win16HostShellExecutionOperation::ReleaseProcess { process } => {
            let released = match process {
                None => true,
                Some(process) => {
                    let lease = {
                        let mut worker = state.borrow_mut();
                        worker
                            .shell_processes
                            .iter()
                            .position(|lease| lease.token == process && lease.handle.is_some())
                            .map(|index| worker.shell_processes.remove(index))
                    };
                    let released = lease.is_some();
                    // Dropping the caller's HANDLE retires its lease. The
                    // successfully started application owns its own lifetime.
                    drop(lease);
                    released
                }
            };
            Ok(
                super::super::win16_modal::NativeModalOperationOutcome::Returned(
                    Win16WindowResult::ShellExecution(
                        Win16HostShellExecutionResult::ProcessReleased(released),
                    ),
                ),
            )
        }
        Win16HostShellExecutionOperation::WinExec { show, .. }
        | Win16HostShellExecutionOperation::LoadModule { show, .. } => {
            let prepared = prepared.ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinExec reached USER without an owned executable preparation",
                )
            })?;
            win_exec(state, prepared, show).map(|result| {
                super::super::win16_modal::NativeModalOperationOutcome::Returned(
                    Win16WindowResult::ShellExecution(Win16HostShellExecutionResult::WinExec(
                        result,
                    )),
                )
            })
        }
        Win16HostShellExecutionOperation::DragAcceptFiles { owner, accept } => {
            let Some((token, hwnd)) = resolve_drop_owner(state, owner) else {
                return Ok(
                    super::super::win16_modal::NativeModalOperationOutcome::Returned(
                        Win16WindowResult::ShellExecution(
                            Win16HostShellExecutionResult::DragAcceptFiles(false),
                        ),
                    ),
                );
            };
            if hwnd.is_null() {
                return Ok(
                    super::super::win16_modal::NativeModalOperationOutcome::Returned(
                        Win16WindowResult::ShellExecution(
                            Win16HostShellExecutionResult::DragAcceptFiles(false),
                        ),
                    ),
                );
            }
            if accept {
                state
                    .borrow_mut()
                    .drop_accepting_windows
                    .try_reserve(1)
                    .map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve exact DragAcceptFiles window identity",
                            error,
                        )
                    })?;
            }
            // SAFETY: DragAcceptFiles enables or disables drop on a window this thread owns.
            unsafe {
                DragAcceptFiles(hwnd, if accept { 1 } else { 0 });
            }
            let mut state = state.borrow_mut();
            if accept {
                state.drop_accepting_windows.insert(token);
            } else {
                state.drop_accepting_windows.remove(&token);
            }
            Ok(
                super::super::win16_modal::NativeModalOperationOutcome::Returned(
                    Win16WindowResult::ShellExecution(
                        Win16HostShellExecutionResult::DragAcceptFiles(true),
                    ),
                ),
            )
        }
        Win16HostShellExecutionOperation::Execute {
            owner,
            operation,
            file,
            parameters,
            directory,
            show,
        } => {
            execute_file(state, owner, operation, file, parameters, directory, show).map(|result| {
                super::super::win16_modal::NativeModalOperationOutcome::Returned(
                    Win16WindowResult::ShellExecution(result),
                )
            })
        }
        Win16HostShellExecutionOperation::FindExecutable { file, directory } => {
            let codec = state.borrow().text_codec;
            find_executable(codec, &file, directory.as_deref()).map(|result| {
                super::super::win16_modal::NativeModalOperationOutcome::Returned(
                    Win16WindowResult::ShellExecution(result),
                )
            })
        }
        Win16HostShellExecutionOperation::About {
            owner,
            app,
            other_stuff,
            icon,
        } => about(
            state,
            operation_id,
            owner,
            &app,
            other_stuff.as_deref(),
            icon,
        ),
    }
}

fn win_exec(
    state: &Rc<RefCell<WorkerState>>,
    prepared: Result<win16_program_launch::PreparedLaunch, u16>,
    show: u16,
) -> Result<Result<Win16HostShellActivation, Win16HostWinExecFailure>, RuntimeError> {
    let mut prepared = match prepared {
        Ok(value) => value,
        Err(code) => {
            return Ok(Err(Win16HostWinExecFailure {
                code,
                native_error: None,
            }));
        }
    };
    let token = {
        let source = Arc::clone(&state.borrow().identity_source);
        Win16HostProcess(allocate_shared_identity(&source)?)
    };
    {
        let mut worker = state.borrow_mut();
        worker.shell_processes.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WinExec process lease",
                error,
            )
        })?;
        worker.shell_processes.push(ProcessLease {
            token,
            handle: None,
        });
    }
    if prepared.guest {
        let launched =
            win16_program_launch::launch(&prepared, show, || receive_win_exec_sends(state));
        return match launched {
            Ok(Ok(handle)) => {
                let mut worker = state.borrow_mut();
                let lease = worker
                    .shell_processes
                    .iter_mut()
                    .find(|lease| lease.token == token)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "guest WinExec lost its reserved process identity",
                        )
                    })?;
                lease.handle = Some(handle);
                Ok(Ok(Win16HostShellActivation::ProcessStarted {
                    process: token,
                }))
            }
            Ok(Err(failure)) => {
                retire_process_reservation(state, token);
                Ok(Err(failure))
            }
            Err(error) => {
                retire_process_reservation(state, token);
                Err(error)
            }
        };
    }
    use std::os::windows::ffi::OsStrExt;
    let cwd: Vec<u16> = prepared
        .directory
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let application: Vec<u16> = prepared
        .program
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let environment = prepared
        .native_environment
        .as_ref()
        .map_or(std::ptr::null(), |block| block.as_ptr().cast());
    let flags = if prepared.native_environment.is_some() {
        CREATE_UNICODE_ENVIRONMENT
    } else {
        0
    };
    let command = &mut prepared.native_command;
    let mut startup = STARTUPINFOW::default();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = show;
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: CreateProcessW reads caller-owned strings and writes caller-owned startup and process records.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            environment,
            cwd.as_ptr(),
            &startup,
            &mut process,
        )
    };
    if created == 0 {
        let error = crate::windows::win32_safe::last_error();
        if error == ERROR_ELEVATION_REQUIRED && prepared.native_environment.is_none() {
            let result = shell_execute_for_elevation(state, token, command, &cwd, show);
            if !matches!(&result, Ok(Ok(_))) {
                retire_process_reservation(state, token);
            }
            return result;
        }
        retire_process_reservation(state, token);
        let code = win_exec_error(error);
        return Ok(Err(Win16HostWinExecFailure {
            code,
            native_error: Some(error),
        }));
    }
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let owned = unsafe { OwnedHandle::from_raw_handle(process.hProcess as RawHandle) };
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let thread = unsafe { OwnedHandle::from_raw_handle(process.hThread as RawHandle) };
    drop(thread);
    // SAFETY: WaitForInputIdle waits on a process handle this owner holds.
    let _ = unsafe { WaitForInputIdle(process.hProcess, 10_000) };
    let mut worker = state.borrow_mut();
    let lease = worker
        .shell_processes
        .iter_mut()
        .find(|lease| lease.token == token)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "WinExec process reservation disappeared after native launch",
            )
        })?;
    lease.handle = Some(owned);
    Ok(Ok(Win16HostShellActivation::ProcessStarted {
        process: token,
    }))
}

fn receive_win_exec_sends(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    use super::win16_guest_notifications as notifications;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MSG, PM_NOREMOVE, PM_QS_SENDMESSAGE, PeekMessageW,
    };
    if state.borrow().aborted {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "WinExec startup was canceled",
        ));
    }
    // LibMain may synchronously send to a parent window. Keep the ordinary
    // resumable USER owner active and leave its posted guest messages queued.
    notifications::requeue_deferred()?;
    let queue = notifications::require_bound_queue(notifications::current_queue());
    let _scope = queue
        .map(|queue| notifications::guest_retrieval_scope(queue, PM_NOREMOVE | PM_QS_SENDMESSAGE))
        .transpose()?;
    let mut message = MSG::default();
    // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
    unsafe {
        PeekMessageW(
            &mut message,
            std::ptr::null_mut(),
            0,
            0,
            PM_NOREMOVE | PM_QS_SENDMESSAGE,
        );
    }
    if state.borrow().aborted
        || queue.is_some_and(|queue| notifications::require_bound_queue(Some(queue)) != Some(queue))
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "WinExec lost its USER owner during a synchronous callback",
        ));
    }
    Ok(())
}

fn shell_execute_for_elevation(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostProcess,
    command: &[u16],
    cwd: &[u16],
    show: u16,
) -> Result<Result<Win16HostShellActivation, Win16HostWinExecFailure>, RuntimeError> {
    let Some((file, parameters)) = split_win_exec_command_line(command) else {
        return Ok(Err(Win16HostWinExecFailure {
            code: 31,
            native_error: Some(ERROR_ELEVATION_REQUIRED),
        }));
    };
    let Some(file) = resolve_executable_input(&file, Some(cwd))? else {
        return Ok(Err(Win16HostWinExecFailure {
            code: 31,
            native_error: Some(ERROR_ELEVATION_REQUIRED),
        }));
    };
    let _apartment = match ComApartment::initialize_sta() {
        Ok(apartment) => apartment,
        Err(_) => {
            return Ok(Err(Win16HostWinExecFailure {
                code: 31,
                native_error: None,
            }));
        }
    };
    let verb: [u16; 5] = [b'o' as u16, b'p' as u16, b'e' as u16, b'n' as u16, 0];
    let class: [u16; 8] = [
        b'e' as u16,
        b'x' as u16,
        b'e' as u16,
        b'f' as u16,
        b'i' as u16,
        b'l' as u16,
        b'e' as u16,
        0,
    ];
    let mut info = SHELLEXECUTEINFOW::default();
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    // The shell brokers UAC consent. A verified executable can have a
    // temporary non-.exe suffix, so supply the documented executable class
    // instead of changing its path or registering a file association.
    info.fMask = SEE_MASK_CLASSNAME | SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr());
    info.lpDirectory = cwd.as_ptr();
    info.lpClass = class.as_ptr();
    info.nShow = i32::from(show);
    // SAFETY: `ShellExecuteExW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let called = unsafe { ShellExecuteExW(&mut info) } != 0;
    let native_error = crate::windows::win32_safe::last_error();
    let shell_status = info.hInstApp as usize;
    if called && shell_status > 32 {
        if info.hProcess.is_null() {
            retire_process_reservation(state, token);
            return Ok(Ok(Win16HostShellActivation::NativeActivationReceipt));
        }
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let handle = unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) };
        let mut worker = state.borrow_mut();
        let lease = worker
            .shell_processes
            .iter_mut()
            .find(|lease| lease.token == token)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinExec process reservation disappeared after ShellExecuteEx",
                )
            })?;
        lease.handle = Some(handle);
        return Ok(Ok(Win16HostShellActivation::ProcessStarted {
            process: token,
        }));
    }
    if !info.hProcess.is_null() {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let _unexpected = unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) };
    }
    let code = if shell_status > 0 && shell_status <= 32 {
        shell_status as u16
    } else {
        map_shell_error(native_error)
    };
    Ok(Err(Win16HostWinExecFailure {
        code,
        native_error: Some(native_error),
    }))
}

fn split_win_exec_command_line(command: &[u16]) -> Option<(Vec<u16>, Option<Vec<u16>>)> {
    let text = command.strip_suffix(&[0])?;
    let start = text.iter().position(|unit| !matches!(*unit, 0x20 | 0x09))?;
    let text = &text[start..];
    let (file, tail) = if text.first() == Some(&(b'"' as u16)) {
        let end = text[1..].iter().position(|unit| *unit == b'"' as u16)? + 1;
        (&text[1..end], &text[end + 1..])
    } else {
        let end = text
            .iter()
            .position(|unit| matches!(*unit, 0x20 | 0x09))
            .unwrap_or(text.len());
        (&text[..end], &text[end..])
    };
    if file.is_empty()
        || tail
            .first()
            .is_some_and(|unit| !matches!(*unit, 0x20 | 0x09))
    {
        return None;
    }
    let tail_start = tail
        .iter()
        .position(|unit| !matches!(*unit, 0x20 | 0x09))
        .unwrap_or(tail.len());
    let mut file = file.to_vec();
    file.push(0);
    let parameters = (tail_start < tail.len()).then(|| {
        let mut parameters = tail[tail_start..].to_vec();
        parameters.push(0);
        parameters
    });
    Some((file, parameters))
}

fn execute_file(
    state: &Rc<RefCell<WorkerState>>,
    owner: Win16WindowTarget,
    operation: Option<Vec<u8>>,
    file: Vec<u8>,
    parameters: Option<Vec<u8>>,
    directory: Option<Vec<u8>>,
    show: i16,
) -> Result<Win16HostShellExecutionResult, RuntimeError> {
    let hwnd = match native_owner(state, owner) {
        Some(hwnd) => hwnd,
        None => {
            return Ok(Win16HostShellExecutionResult::Execute(Err(
                Win16HostShellFailure::Api(31),
            )));
        }
    };
    // Win16 ShellExecute's SDK contract makes a NULL operation mean "open".
    // Pass an owned explicit verb because current ShellExecuteEx uses the
    // registered default verb for NULL.
    let prepared = (|| {
        Ok::<_, RuntimeError>((
            OwnedAnsi::new(
                operation.as_deref().unwrap_or(b"open"),
                "reserve Win16 ShellExecute verb",
            )?,
            OwnedAnsi::new(&file, "reserve Win16 ShellExecute file")?,
            parameters
                .as_deref()
                .map(|value| OwnedAnsi::new(value, "reserve Win16 ShellExecute parameters"))
                .transpose()?,
            directory
                .as_deref()
                .map(|value| OwnedAnsi::new(value, "reserve Win16 ShellExecute directory"))
                .transpose()?,
        ))
    })();
    let (operation, file, parameters, directory) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(Win16HostShellExecutionResult::Execute(Err(
                Win16HostShellFailure::Preparation(Arc::new(error)),
            )));
        }
    };

    // The guest retains its ANSI ABI; the shell receives owned UTF-16 decoded
    // with this instance's fixed code page, independent of the host ACP.
    // Complete conversion before reserving a process identity.
    let codec = state.borrow().text_codec;
    let wide = (|| {
        Ok::<_, RuntimeError>((
            codec.to_wide_z(operation.as_bytes())?,
            codec.to_wide_z(file.as_bytes())?,
            parameters
                .as_ref()
                .map(|value| codec.to_wide_z(value.as_bytes()))
                .transpose()?,
            directory
                .as_ref()
                .map(|value| codec.to_wide_z(value.as_bytes()))
                .transpose()?,
        ))
    })();
    let (operation, file, parameters, directory) = match wide {
        Ok(wide) => wide,
        Err(error) => {
            return Ok(Win16HostShellExecutionResult::Execute(Err(
                Win16HostShellFailure::Preparation(Arc::new(error)),
            )));
        }
    };

    let token = {
        let source = Arc::clone(&state.borrow().identity_source);
        match allocate_shared_identity(&source) {
            Ok(token) => Win16HostProcess(token),
            Err(error) => {
                return Ok(Win16HostShellExecutionResult::Execute(Err(
                    Win16HostShellFailure::Preparation(Arc::new(error)),
                )));
            }
        }
    };
    {
        let mut state = state.borrow_mut();
        if let Err(error) = state.shell_processes.try_reserve(1) {
            return Ok(Win16HostShellExecutionResult::Execute(Err(
                Win16HostShellFailure::Preparation(Arc::new(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve native SHELL process lease",
                    error,
                ))),
            )));
        }
        state.shell_processes.push(ProcessLease {
            token,
            handle: None,
        });
    }

    let _apartment = match ComApartment::initialize_sta() {
        Ok(apartment) => apartment,
        Err(hresult) => {
            retire_process_reservation(state, token);
            return Ok(Win16HostShellExecutionResult::Execute(Err(
                Win16HostShellFailure::ComInitialization { hresult },
            )));
        }
    };
    let mut info = SHELLEXECUTEINFOW::default();
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
    info.hwnd = hwnd;
    info.lpVerb = operation.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr());
    info.lpDirectory = directory
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr());
    info.nShow = i32::from(show);

    // Shell association and error UI is owned by the native shell target and
    // is not enrolled in the ShellAbout modal scope; no cancellation guarantee
    // is made for any UI ShellExecuteEx may display.
    // SAFETY: `ShellExecuteExW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let called = unsafe { ShellExecuteExW(&mut info) } != 0;
    let status = info.hInstApp as usize;
    if called && status > 32 {
        if !info.hProcess.is_null() {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let owned = unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) };
            let mut state = state.borrow_mut();
            let Some(lease) = state
                .shell_processes
                .iter_mut()
                .find(|lease| lease.token == token)
            else {
                // The reservation cannot be removed by nested worker calls.
                // Treat violation as damaged worker state, never as a guest
                // ShellExecute failure after an application has started.
                drop(owned);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native process lease reservation disappeared after ShellExecuteEx",
                ));
            };
            lease.handle = Some(owned);
            return Ok(Win16HostShellExecutionResult::Execute(Ok(
                Win16HostShellActivation::ProcessStarted { process: token },
            )));
        }
        retire_process_reservation(state, token);
        return Ok(Win16HostShellExecutionResult::Execute(Ok(
            Win16HostShellActivation::NativeActivationReceipt,
        )));
    }

    let native_error = crate::windows::win32_safe::last_error();
    let shell_error = if status <= 32 && status != 0 {
        status as u16
    } else {
        map_shell_error(native_error)
    };
    if !info.hProcess.is_null() {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let _unexpected = unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) };
    }
    retire_process_reservation(state, token);
    Ok(Win16HostShellExecutionResult::Execute(Err(
        Win16HostShellFailure::Api(shell_error),
    )))
}

fn find_executable(
    codec: crate::windows::guest_text::GuestTextCodec,
    file: &[u8],
    directory: Option<&[u8]>,
) -> Result<Win16HostShellExecutionResult, RuntimeError> {
    let prepared = (|| {
        Ok::<_, RuntimeError>((
            OwnedAnsi::new(file, "reserve FindExecutable file")?,
            directory
                .map(|value| OwnedAnsi::new(value, "reserve FindExecutable directory"))
                .transpose()?,
        ))
    })();
    let (file, directory) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
                Win16HostShellFailure::Preparation(Arc::new(error)),
            )));
        }
    };
    let file_wide = match paths::ansi_path_to_wide(codec, file.as_bytes()) {
        Ok(AnsiInputConversion::Encoded(wide)) => wide,
        Ok(AnsiInputConversion::Unrepresentable(cause)) => {
            return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
                Win16HostShellFailure::ExecutableInputNotRepresentable(
                    Win16HostShellInputEncodingFailure {
                        input: file.into_bytes(),
                        cause,
                    },
                ),
            )));
        }
        Err(error) if error.kind() == Kind::ResourceExhausted => {
            return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
                Win16HostShellFailure::Preparation(Arc::new(error)),
            )));
        }
        Err(error) => return Err(error),
    };
    let directory_wide = match directory {
        Some(directory) => match paths::ansi_path_to_wide(codec, directory.as_bytes()) {
            Ok(AnsiInputConversion::Encoded(wide)) => Some(wide),
            Ok(AnsiInputConversion::Unrepresentable(cause)) => {
                return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
                    Win16HostShellFailure::ExecutableInputNotRepresentable(
                        Win16HostShellInputEncodingFailure {
                            input: directory.into_bytes(),
                            cause,
                        },
                    ),
                )));
            }
            Err(error) if error.kind() == Kind::ResourceExhausted => {
                return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
                    Win16HostShellFailure::Preparation(Arc::new(error)),
                )));
            }
            Err(error) => return Err(error),
        },
        None => None,
    };
    let resolved_executable = match resolve_executable_input(&file_wide, directory_wide.as_deref())
    {
        Ok(path) => path,
        Err(error) if error.kind() == Kind::ResourceExhausted => {
            return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
                Win16HostShellFailure::Preparation(Arc::new(error)),
            )));
        }
        Err(error) => return Err(error),
    };
    if let Some(full_path) = resolved_executable {
        let encoded = match lossless_executable_path(codec, full_path) {
            Ok(result) => result,
            Err(error) if error.kind() == Kind::ResourceExhausted => {
                return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
                    Win16HostShellFailure::Preparation(Arc::new(error)),
                )));
            }
            Err(error) => return Err(error),
        };
        return Ok(Win16HostShellExecutionResult::FindExecutable(
            match encoded {
                PathEncodingOutcome::Encoded(path) => Ok(path),
                PathEncodingOutcome::Unrepresentable(failure) => Err(
                    Win16HostShellFailure::ExecutablePathNotRepresentable(failure),
                ),
            },
        ));
    }
    // MAX_PATH here is the native API's temporary output capacity. The Win16
    // caller has no documented guest-side minimum and is checked against the
    // exact returned path by the runtime.
    let mut output = Vec::new();
    if let Err(error) = output.try_reserve_exact(MAX_PATH as usize) {
        return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
            Win16HostShellFailure::Preparation(Arc::new(RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve FindExecutable native path buffer",
                error,
            ))),
        )));
    }
    // A pre-zeroed tail would make a native success without a terminator look
    // like a valid truncated path.
    output.resize(MAX_PATH as usize, u16::MAX);
    // A positive native GetBinaryTypeW result is handled above by returning
    // that exact executable's resolved path. This API call therefore handles
    // document association; Windows documents that association lookup may
    // start a DDE server.
    // SAFETY: `FindExecutableW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let instance = unsafe {
        FindExecutableW(
            file_wide.as_ptr(),
            directory_wide
                .as_deref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            output.as_mut_ptr(),
        )
    };
    let status = instance as usize;
    if status <= 32 {
        // Preserve the raw small error value, including zero, as permitted by
        // the Win16 SHELL HINSTANCE contract.
        return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
            Win16HostShellFailure::Api(status as u16),
        )));
    }
    let Some(nul) = output.iter().position(|character| *character == 0) else {
        return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
            Win16HostShellFailure::HostContractViolation,
        )));
    };
    if nul == 0 {
        return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
            Win16HostShellFailure::HostContractViolation,
        )));
    }
    output.truncate(nul + 1);
    let encoded = match lossless_executable_path(codec, output) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == Kind::ResourceExhausted => {
            return Ok(Win16HostShellExecutionResult::FindExecutable(Err(
                Win16HostShellFailure::Preparation(Arc::new(error)),
            )));
        }
        Err(error) => return Err(error),
    };
    Ok(Win16HostShellExecutionResult::FindExecutable(
        match encoded {
            PathEncodingOutcome::Encoded(path) => Ok(path),
            PathEncodingOutcome::Unrepresentable(failure) => Err(
                Win16HostShellFailure::ExecutablePathNotRepresentable(failure),
            ),
        },
    ))
}

fn about(
    state: &Rc<RefCell<WorkerState>>,
    operation_id: u64,
    owner: Win16WindowTarget,
    app: &[u8],
    other_stuff: Option<&[u8]>,
    icon: Option<runtime::Win16HostIcon>,
) -> Result<super::super::win16_modal::NativeModalOperationOutcome, RuntimeError> {
    let Some(hwnd) = native_owner(state, owner) else {
        return Ok(returned_about(false));
    };
    if app.contains(&0) || other_stuff.is_some_and(|value| value.contains(&0)) {
        return about_preparation_failure(RuntimeError::new(
            Kind::InvalidInput,
            "decoded Win16 SHELL string contains an interior NUL",
        ));
    }
    let codec = state.borrow().text_codec;
    let app = match codec.to_wide_z(app) {
        Ok(app) => app,
        Err(error) => return about_preparation_failure(error),
    };
    let other = match other_stuff.map(|value| codec.to_wide_z(value)).transpose() {
        Ok(other) => other,
        Err(error) => return about_preparation_failure(error),
    };
    let lease: Option<Win16IconLease> = match icon {
        Some(icon) => match state.borrow().images.lease_icon(icon) {
            Ok(Some(lease)) => Some(lease),
            Ok(None) => return Ok(returned_about(false)),
            Err(error) => return about_preparation_failure(error),
        },
        None => None,
    };
    let native_icon = lease
        .as_ref()
        .map_or(std::ptr::null_mut(), Win16IconLease::native);
    // ShellAboutW is a synchronous native modal loop owned by this worker.
    // Owned UTF-16 strings keep the selected guest page independent of ACP.
    // Its dialog has no private DLGPROC/HWND return, so the scoped modal hook
    // tracks only its real system-dialog activation and waits for API return.
    let call = super::super::win16_modal::with_native_modal(operation_id, || {
        // SAFETY: `ShellAboutW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let shown = unsafe {
            ShellAboutW(
                hwnd,
                app.as_ptr(),
                other.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
                native_icon,
            )
        } != 0;
        let last_error = (!shown).then(|| crate::windows::win32_safe::last_error());
        (shown, last_error)
    })?;
    use super::super::win16_modal::{
        ModalCancellationSignal, ModalDisposition, NativeModalInvocation,
    };
    match call {
        NativeModalInvocation::NotStarted { operation_id } => Ok(
            super::super::win16_modal::NativeModalOperationOutcome::Cancelled {
                receipt: Win16NativeModalCancellation {
                    operation_id,
                    scope_id: None,
                    native_result: None,
                    native_last_error: None,
                    signal: Win16NativeModalCancelSignal::BeforeEntry,
                    retired_guest_work: Vec::new(),
                },
                cleanup_error: None,
            },
        ),
        NativeModalInvocation::Returned(call) => match call.disposition {
            ModalDisposition::Returned => {
                if let Some(error) = call.cleanup_error {
                    return Err(error.with_context("finish Win16 ShellAbout modal scope"));
                }
                Ok(returned_about(call.value.0))
            }
            ModalDisposition::Cancelled { signal, scope_id } => {
                let signal = match signal {
                    ModalCancellationSignal::OwnerThreadPostQuit => {
                        Win16NativeModalCancelSignal::OwnerThreadQuit
                    }
                    ModalCancellationSignal::DialogEndDialog => {
                        Win16NativeModalCancelSignal::DialogEnd
                    }
                };
                Ok(
                    super::super::win16_modal::NativeModalOperationOutcome::Cancelled {
                        receipt: Win16NativeModalCancellation {
                            operation_id,
                            scope_id: Some(scope_id),
                            native_result: Some(i64::from(call.value.0)),
                            native_last_error: call.value.1,
                            signal,
                            retired_guest_work: call.retired_guest_work,
                        },
                        cleanup_error: call.cleanup_error,
                    },
                )
            }
        },
    }
}

fn returned_about(shown: bool) -> super::super::win16_modal::NativeModalOperationOutcome {
    super::super::win16_modal::NativeModalOperationOutcome::Returned(
        Win16WindowResult::ShellExecution(Win16HostShellExecutionResult::About(shown)),
    )
}

fn about_preparation_failure(
    error: RuntimeError,
) -> Result<super::super::win16_modal::NativeModalOperationOutcome, RuntimeError> {
    if error.kind() == Kind::InternalInvariant {
        return Err(error.with_context("prepare Win16 ShellAbout"));
    }
    // Win16 ShellAbout reports native dialog creation failure as -1.
    // Preparation failures therefore remain the target API's ordinary failure.
    eprintln!(
        "runtime: Win16 ShellAbout preparation failed ({}): {}",
        error.kind().as_str(),
        error
    );
    Ok(returned_about(false))
}

fn native_owner(state: &Rc<RefCell<WorkerState>>, owner: Win16WindowTarget) -> Option<HWND> {
    match owner {
        Win16WindowTarget::Null => Some(std::ptr::null_mut()),
        Win16WindowTarget::Invalid => None,
        Win16WindowTarget::Mapped(token) => state.borrow().windows.get(&token).copied(),
    }
}

fn resolve_drop_owner(
    state: &Rc<RefCell<WorkerState>>,
    owner: Win16WindowTarget,
) -> Option<(runtime::Win16HostWindow, HWND)> {
    let Win16WindowTarget::Mapped(token) = owner else {
        return None;
    };
    // Validate the current HWND incarnation, not only the token/reverse-map
    // pair: USER may recycle the same HWND bits before a stale map is retired.
    let hwnd = super::win16_window_identity::resolve_user_window(state, token)?;
    Some((token, hwnd))
}

fn retire_process_reservation(state: &Rc<RefCell<WorkerState>>, token: Win16HostProcess) {
    state
        .borrow_mut()
        .shell_processes
        .retain(|lease| lease.token != token);
}

fn map_shell_error(error: u32) -> u16 {
    match error {
        ERROR_FILE_NOT_FOUND => 2,
        ERROR_PATH_NOT_FOUND => 3,
        ERROR_ACCESS_DENIED => 5,
        ERROR_NOT_ENOUGH_MEMORY | ERROR_OUTOFMEMORY => 8,
        ERROR_SHARING_VIOLATION => 32,
        _ => 31,
    }
}
