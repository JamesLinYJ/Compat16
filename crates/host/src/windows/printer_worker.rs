//! One-query native printer worker process boundary.

use std::error::Error;
use std::fmt;
use std::io;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16PrinterCapabilities,
    Win16PrinterCapabilitiesResult};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use super::printer_protocol;

/// Run one DeviceCapabilities query in a disposable process. The worker owns
/// all writable native printer-driver storage, so a driver fault cannot
/// corrupt the emulator process's heap.
pub(super) fn capabilities(
    request: Win16PrinterCapabilities,
    code_page: u32,
) -> Result<Win16PrinterCapabilitiesResult, RuntimeError> {
    let executable = worker_executable()?;
    let child = Command::new(&executable)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| RuntimeError::with_source(
            Kind::HostFailure,
            format!("spawn printer worker {}", executable.display()),
            error,
        ))?;
    let mut child = ChildGuard::new(child);

    let mut stdin = child.child_mut().stdin.take().ok_or_else(|| {
        RuntimeError::new(Kind::HostFailure, "printer worker has no private stdin pipe")
    })?;
    let mut stdout = child.child_mut().stdout.take().ok_or_else(|| {
        RuntimeError::new(Kind::HostFailure, "printer worker has no private stdout pipe")
    })?;

    let write_result = printer_protocol::write_request(&mut stdin, &request, code_page);
    drop(stdin);

    // Always drain the worker's single response before waiting. Even a failed
    // request write may have reached the child far enough for it to emit an
    // error frame; draining also prevents a full stdout pipe from deadlocking
    // process exit.
    let response_result = printer_protocol::read_response(
        &mut stdout,
        request.index,
        request.collect_output,
    );
    drop(stdout);

    let status = child.child_mut().wait().map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "wait for printer worker", error))?;
    child.mark_reaped();
    if let Err(error) = write_result {
        if error.kind() == Kind::ResourceExhausted {
            return Err(error);
        }
        if !status.success() {
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "printer worker exited unsuccessfully",
                WorkerExitStatus(status),
            ));
        }
        return Err(error);
    }
    if !status.success() {
        return Err(RuntimeError::with_source(
            Kind::HostFailure,
            "printer worker exited unsuccessfully",
            WorkerExitStatus(status),
        ));
    }
    response_result
}

/// Entry point called by the private `compat16host.exe` binary.
pub(crate) fn run_native_worker() -> Result<(), RuntimeError> {
    let (request, code_page) = {
        let stdin = io::stdin();
        let mut locked = stdin.lock();
        printer_protocol::read_request(&mut locked)?
    };
    let index = request.index;
    let response = super::win16_printer::capabilities_in_worker(request, code_page);
    let stdout = io::stdout();
    let mut locked = stdout.lock();
    printer_protocol::write_response(&mut locked, index, response)
}

fn worker_executable() -> Result<std::path::PathBuf, RuntimeError> {
    let current = std::env::current_exe().map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "locate current launcher executable", error))?;
    let directory = current.parent().ok_or_else(|| RuntimeError::new(
        Kind::HostFailure, "current launcher executable has no parent directory"))?;
    let executable = directory.join("compat16host.exe");
    if !executable.is_absolute() {
        return Err(RuntimeError::new(Kind::HostFailure,
            "printer worker path is not absolute"));
    }
    Ok(executable)
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child, reaped: false }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct WorkerExitStatus(ExitStatus);

impl fmt::Display for WorkerExitStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl fmt::Debug for WorkerExitStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for WorkerExitStatus {}
