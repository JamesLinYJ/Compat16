//! One-shot startup receipt, separate from guest standard streams.

use super::*;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, FILE_TYPE_PIPE, GetFileType};

#[derive(Clone)]
pub struct ProgramLoadReporter(Arc<Mutex<Reply>>);

struct Reply {
    pipe: Option<File>,
    linked: bool,
}

impl Reply {
    fn report(&mut self, result: Result<(), u16>) -> std::io::Result<()> {
        if self.pipe.is_none() {
            return Ok(());
        }
        if result.is_ok() {
            if self.linked {
                return Ok(());
            }
            self.write_frame(2, 0)?;
            self.linked = true;
            return Ok(());
        }
        if self.linked {
            return self.ready();
        }
        // Fixed eight-byte, little-endian receipt; the status distinguishes
        // successful linking from LibMain's documented failure value zero.
        let code = result.expect_err("handled successful linking");
        let result = self.write_frame(0, code);
        self.pipe = None;
        result
    }

    fn ready(&mut self) -> std::io::Result<()> {
        if !self.linked || self.pipe.is_none() {
            return Ok(());
        }
        let result = self.write_frame(1, 0);
        self.pipe = None;
        result
    }

    fn write_frame(&mut self, status: u16, code: u16) -> std::io::Result<()> {
        let mut frame = *b"C16L\0\0\0\0";
        frame[4..6].copy_from_slice(&status.to_le_bytes());
        frame[6..8].copy_from_slice(&code.to_le_bytes());
        self.pipe
            .as_mut()
            .expect("retained receipt pipe")
            .write_all(&frame)
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        // Parsing, host initialization or execution can fail before a
        // loader callback exists. Such a child must never report success.
        let _ = self.report(Err(11));
    }
}

impl ProgramLoadReporter {
    pub fn report(&self, result: Result<(), u16>) -> Result<(), RuntimeError> {
        self.0
            .lock()
            .map_err(|_| invalid("child startup receipt lock is poisoned"))?
            .report(result)
            .map_err(|error| failure("publish child load result", error))
    }

    /// Publish the first cooperative USER wait/yield after linking completed.
    pub fn ready(&self) -> Result<(), RuntimeError> {
        self.0
            .lock()
            .map_err(|_| invalid("child startup receipt lock is poisoned"))?
            .ready()
            .map_err(|error| failure("publish child startup readiness", error))
    }
}

pub struct GuestChildLaunch {
    pub program: PathBuf,
    pub directory: PathBuf,
    pub image: Vec<u8>,
    pub command_tail: Vec<u8>,
    pub environment: Vec<Vec<u8>>,
    pub dos_code_page: u32,
    pub ansi_code_page: u32,
    pub show: u16,
    pub interpreter: bool,
    pub jit_cache: bool,
    reporter: ProgramLoadReporter,
}

impl GuestChildLaunch {
    pub fn reporter(&self) -> ProgramLoadReporter {
        self.reporter.clone()
    }

    pub fn report_failure(&self, error: &RuntimeError) {
        let code = if error.kind() == Kind::ResourceExhausted {
            8
        } else {
            11
        };
        let _ = self.reporter.report(Err(code));
    }

    pub fn from_process_arguments() -> Result<Option<Self>, RuntimeError> {
        let mut args = std::env::args_os().skip(1);
        if args.next().as_deref() != Some(std::ffi::OsStr::new("--guest-child")) {
            return Ok(None);
        }
        let mut handles = [0_usize; 3];
        for handle in &mut handles {
            *handle = args
                .next()
                .and_then(|value| value.into_string().ok())
                .and_then(|value| value.parse().ok())
                .filter(|value| *value != 0 && *value != usize::MAX)
                .ok_or_else(|| invalid("child launch requires three owned native handles"))?;
        }
        if args.next().is_some()
            || handles[0] == handles[1]
            || handles[0] == handles[2]
            || handles[1] == handles[2]
        {
            return Err(invalid(
                "child launch has extra arguments or duplicate handles",
            ));
        }
        let reply = owned_file(handles[2], FILE_TYPE_PIPE)?;
        let reporter = ProgramLoadReporter(Arc::new(Mutex::new(Reply {
            pipe: Some(reply),
            linked: false,
        })));
        let mut request = owned_file(handles[0], FILE_TYPE_DISK)?;
        let mut image = owned_file(handles[1], FILE_TYPE_DISK)?;
        let request_bytes = read_bounded(&mut request, MAX_REQUEST_BYTES)?;
        let request: LaunchRequest = serde_json::from_slice(&request_bytes)
            .map_err(|error| failure("decode child launch request", error))?;
        if request.version != 1
            || !matches!(request.dos_code_page, 437 | 936)
            || request.command_tail.len() > 126
            || request.program.contains(&0)
            || request.directory.contains(&0)
            || request.environment.iter().any(|entry| {
                entry.contains(&0)
                    || !entry
                        .iter()
                        .position(|byte| *byte == b'=')
                        .is_some_and(|offset| offset > 0)
            })
            || request
                .environment
                .iter()
                .map(|entry| entry.len() + 1)
                .sum::<usize>()
                > 65_535
        {
            return Err(invalid(
                "child launch request violates its bounded guest layout",
            ));
        }
        super::super::guest_text::GuestTextCodec::new(request.ansi_code_page)?;
        let program = PathBuf::from(std::ffi::OsString::from_wide(&request.program));
        let directory = PathBuf::from(std::ffi::OsString::from_wide(&request.directory));
        if !program.is_absolute() || !directory.is_absolute() {
            return Err(invalid("child launch paths must be absolute"));
        }
        let image = read_bounded(&mut image, MAX_IMAGE_BYTES)?;
        Ok(Some(Self {
            program,
            directory,
            image,
            command_tail: request.command_tail,
            environment: request.environment,
            dos_code_page: request.dos_code_page,
            ansi_code_page: request.ansi_code_page,
            show: request.show,
            interpreter: request.execution.interpreter,
            jit_cache: !request.execution.no_jit_cache,
            reporter,
        }))
    }
}

fn owned_file(value: usize, kind: u32) -> Result<File, RuntimeError> {
    let handle = value as HANDLE;
    // These are private inherited native handles, never Win16 handles.
    // SAFETY: `GetFileType` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    if handle == INVALID_HANDLE_VALUE || unsafe { GetFileType(handle) } != kind {
        return Err(invalid(
            "child launch handle has an unexpected native object type",
        ));
    }
    // Retire inheritance before any guest library can launch another child.
    // SAFETY: SetHandleInformation updates flags on a handle this process owns.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(failure(
            "retire child handle inheritance",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

fn read_bounded(file: &mut File, limit: u64) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| failure("read child launch input", error))?;
    if bytes.len() as u64 > limit {
        return Err(invalid("child launch input exceeds its limit"));
    }
    Ok(bytes)
}
