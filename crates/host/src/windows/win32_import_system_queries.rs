//! Typed volume, environment and system-query adapters.

#[path = "win32_import_system_queries/volume.rs"]
mod volume;
#[path = "win32_import_system_queries/environment.rs"]
mod environment;
#[path = "win32_import_system_queries/system.rs"]
mod system;

use runtime::{RuntimeError, Win32HostImportResult};
use super::super::guest_text::GuestTextCodec;

pub(super) fn volume(call: runtime::Win32HostVolumeCall, codec: GuestTextCodec)
    -> Result<Win32HostImportResult, RuntimeError> { volume::execute(call, codec) }

pub(super) fn environment(call: runtime::Win32HostEnvironmentCall, codec: GuestTextCodec)
    -> Result<Win32HostImportResult, RuntimeError> { environment::execute(call, codec) }

pub(super) fn system(call: runtime::Win32HostSystemCall, codec: GuestTextCodec)
    -> Result<Win32HostImportResult, RuntimeError> { system::execute(call, codec) }
