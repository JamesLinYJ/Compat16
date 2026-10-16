//! Owned executable launch inputs and the private child-loader boundary.

use runtime::{DiagnosticKind as Kind, RuntimeError};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::PathBuf;

mod child;
mod prepare;
mod spawn;
pub use child::{GuestChildLaunch, ProgramLoadReporter};
pub(super) use prepare::prepare;
pub(super) use spawn::launch;

const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutionOptions {
    pub(super) interpreter: bool,
    pub(super) no_jit_cache: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchRequest {
    version: u16,
    program: Vec<u16>,
    directory: Vec<u16>,
    command_tail: Vec<u8>,
    environment: Vec<Vec<u8>>,
    dos_code_page: u32,
    ansi_code_page: u32,
    show: u16,
    execution: ExecutionOptions,
}

pub(super) struct PreparedLaunch {
    // A read-only, non-share-write/delete file lease stabilizes the exact
    // resolved image until the child reports linking/LibMain completion.
    file: File,
    pub(super) program: PathBuf,
    pub(super) directory: PathBuf,
    pub(super) native_command: Vec<u16>,
    request: LaunchRequest,
    pub(super) guest: bool,
}

impl super::WindowsHost {
    pub fn set_program_load_reporter(&mut self, reporter: ProgramLoadReporter) {
        self.program_load_reporter = Some(reporter);
    }

    pub fn set_child_execution_options(&mut self, interpreter: bool, jit_cache: bool) {
        self.child_execution = ExecutionOptions {
            interpreter,
            no_jit_cache: !jit_cache,
        };
    }
}

fn failure(
    operation: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure, operation, error)
}

fn invalid(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InvalidInput, message)
}

pub(super) fn native_error_code(error: u32) -> u16 {
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_BAD_EXE_FORMAT, ERROR_FILE_NOT_FOUND, ERROR_NOT_ENOUGH_MEMORY,
        ERROR_OUTOFMEMORY, ERROR_PATH_NOT_FOUND,
    };
    match error {
        ERROR_FILE_NOT_FOUND => 2,
        ERROR_PATH_NOT_FOUND => 3,
        ERROR_ACCESS_DENIED => 5,
        ERROR_NOT_ENOUGH_MEMORY | ERROR_OUTOFMEMORY => 8,
        ERROR_BAD_EXE_FORMAT => 11,
        _ => 31,
    }
}
