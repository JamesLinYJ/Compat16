//! Launch an isolated guest with an explicit native handle inheritance list.

use super::*;
use std::io::{Read, Seek, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
    STARTF_USESHOWWINDOW, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

pub(in crate::windows) fn launch(
    prepared: &PreparedLaunch,
    show: u16,
    mut receive_sends: impl FnMut() -> Result<(), RuntimeError>,
) -> Result<Result<OwnedHandle, runtime::Win16HostWinExecFailure>, RuntimeError> {
    let bytes = serde_json::to_vec(&prepared.request)
        .map_err(|error| failure("encode child launch request", error))?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(invalid("child launch request is too large"));
    }
    // The anonymous file uses the established tempfile lifecycle. No request
    // filename, guest arguments or environment values are published in argv.
    let mut request =
        tempfile::tempfile().map_err(|error| failure("create private child request", error))?;
    request
        .write_all(&bytes)
        .map_err(|error| failure("write child launch request", error))?;
    request
        .rewind()
        .map_err(|error| failure("rewind child launch request", error))?;
    let (mut reply, reply_write) = response_pipe()?;
    let request_child = inherit(request.as_raw_handle(), FILE_GENERIC_READ)?;
    let image_child = inherit(prepared.file.as_raw_handle(), FILE_GENERIC_READ)?;
    let reply_child = inherit(reply_write.as_raw_handle(), FILE_GENERIC_WRITE)?;
    let handles = [
        request_child.as_raw_handle(),
        image_child.as_raw_handle(),
        reply_child.as_raw_handle(),
    ];
    let mut attributes = Attributes::new(&handles)?;
    let current = std::env::current_exe()
        .map_err(|error| failure("locate Compat16 child launcher", error))?;
    let launcher = current
        .parent()
        .ok_or_else(|| invalid("launcher has no parent directory"))?
        .join("compat16w.exe");
    let mut application: Vec<u16> = launcher.as_os_str().encode_wide().collect();
    application.push(0);
    let control = format!(
        " --guest-child {} {} {}",
        handles[0] as usize, handles[1] as usize, handles[2] as usize
    );
    let mut command = vec![0x22];
    command.extend_from_slice(&application[..application.len() - 1]);
    command.push(0x22);
    command.extend(control.encode_utf16());
    command.push(0);
    if command.len() > 32_767 {
        return Err(invalid("child launcher command is too long"));
    }
    let directory: Vec<u16> = prepared
        .directory
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = show;
    startup.lpAttributeList = attributes.pointer();
    let mut process = PROCESS_INFORMATION::default();
    // Only the three read/read/write capabilities are inherited. Guest file,
    // USER, printer and synchronization handles never cross this boundary.
    // SAFETY: CreateProcessW reads caller-owned strings and writes caller-owned startup and process records.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            directory.as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    };
    if created == 0 {
        let error = crate::windows::win32_safe::last_error();
        return Ok(Err(runtime::Win16HostWinExecFailure {
            code: native_error_code(error),
            native_error: Some(error),
        }));
    }
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let owned = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let thread = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
    drop(thread);
    let mut process = StartupProcess(Some(owned));
    drop((
        request_child,
        image_child,
        reply_child,
        reply_write,
        attributes,
        request,
    ));
    let loaded = wait_for_load(
        process.0.as_ref().expect("owned process"),
        &mut reply,
        &mut receive_sends,
    )?;
    match loaded {
        Ok(()) => Ok(Ok(process.0.take().expect("loaded child process"))),
        Err(code) => Ok(Err(runtime::Win16HostWinExecFailure {
            code,
            native_error: None,
        })),
    }
}

fn wait_for_load(
    process: &OwnedHandle,
    reply: &mut File,
    receive_sends: &mut impl FnMut() -> Result<(), RuntimeError>,
) -> Result<Result<(), u16>, RuntimeError> {
    let mut linked_at = None;
    loop {
        receive_sends()?;
        // Keep the existing native startup-wait bound after proven linking.
        // A busy guest that never retrieves messages still has a real loaded
        // image; a child that never completed linking cannot become success.
        if linked_at.is_some_and(|at: std::time::Instant| {
            at.elapsed() >= std::time::Duration::from_secs(10)
        }) {
            return Ok(Ok(()));
        }
        let mut available = 0;
        // SAFETY: `PeekNamedPipe` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        if unsafe {
            PeekNamedPipe(
                reply.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Ok(if linked_at.is_some() { Ok(()) } else { Err(11) });
        }
        if available >= 8 {
            let mut frame = [0_u8; 8];
            reply
                .read_exact(&mut frame)
                .map_err(|error| failure("receive child startup receipt", error))?;
            let status = u16::from_le_bytes([frame[4], frame[5]]);
            let code = u16::from_le_bytes([frame[6], frame[7]]);
            match (&frame[..4], status, code) {
                (b"C16L", 2, 0) if linked_at.is_none() => {
                    linked_at = Some(std::time::Instant::now())
                }
                (b"C16L", 1, 0) if linked_at.is_some() => return Ok(Ok(())),
                (b"C16L", 0, 0..=32) if linked_at.is_none() => return Ok(Err(code)),
                _ => return Err(invalid("child returned an invalid startup receipt")),
            }
            continue;
        }
        // SAFETY: WaitForSingleObject waits on a handle this process owns.
        let wait = unsafe { WaitForSingleObject(process.as_raw_handle(), 10) };
        if wait == WAIT_FAILED {
            return Err(failure(
                "wait for child startup",
                std::io::Error::last_os_error(),
            ));
        }
        if wait == WAIT_OBJECT_0 {
            // Check the pipe once more: a short-lived successfully loaded
            // guest can exit immediately after publishing its receipt.
            let mut available = 0;
            // SAFETY: `PeekNamedPipe` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            if unsafe {
                PeekNamedPipe(
                    reply.as_raw_handle(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            } == 0
                || available < 8
            {
                return Ok(if linked_at.is_some() { Ok(()) } else { Err(11) });
            }
        }
    }
}

struct StartupProcess(Option<OwnedHandle>);

impl Drop for StartupProcess {
    fn drop(&mut self) {
        if let Some(process) = &self.0 {
            // A failed/canceled startup is our newly created child, still
            // unpublished to the guest. A successful child is taken above.
            // SAFETY: TerminateProcess signals a process handle this owner holds.
            unsafe {
                TerminateProcess(process.as_raw_handle(), 125);
            }
            // SAFETY: WaitForSingleObject waits on a handle this process owns.
            unsafe {
                WaitForSingleObject(process.as_raw_handle(), u32::MAX);
            }
        }
    }
}

fn response_pipe() -> Result<(File, OwnedHandle), RuntimeError> {
    let (mut read, mut write) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: `CreatePipe` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        return Err(failure(
            "create private child receipt pipe",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    Ok(unsafe {
        (
            File::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

fn inherit(source: HANDLE, access: u32) -> Result<OwnedHandle, RuntimeError> {
    let process = crate::windows::win32_safe::current_process();
    let mut target = std::ptr::null_mut();
    // SAFETY: DuplicateHandle writes a caller-owned handle slot.
    if unsafe { DuplicateHandle(process, source, process, &mut target, access, 1, 0) } == 0 {
        return Err(failure(
            "create child handle capability",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    Ok(unsafe { OwnedHandle::from_raw_handle(target) })
}

struct Attributes<'a>(Vec<usize>, std::marker::PhantomData<&'a [HANDLE]>);

impl<'a> Attributes<'a> {
    fn pointer(&mut self) -> *mut core::ffi::c_void {
        self.0.as_mut_ptr().cast()
    }

    fn new(handles: &'a [HANDLE]) -> Result<Self, RuntimeError> {
        let mut bytes = 0;
        // SAFETY: `InitializeProcThreadAttributeList` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(failure(
                "size child handle list",
                std::io::Error::last_os_error(),
            ));
        }
        let mut storage = vec![0_usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: `InitializeProcThreadAttributeList` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(failure(
                "initialize child handle list",
                std::io::Error::last_os_error(),
            ));
        }
        let mut attributes = Self(storage, std::marker::PhantomData);
        // SAFETY: `UpdateProcThreadAttribute` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(failure(
                "set exact child handle list",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(attributes)
    }
}

impl Drop for Attributes<'_> {
    fn drop(&mut self) {
        // SAFETY: `DeleteProcThreadAttributeList` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}
