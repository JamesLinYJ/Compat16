//! Native PE loading and scalar ABI calls. No guest address crosses here.

use std::io;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use super::EngineLoadError;

struct LoadedModule(HMODULE);

impl Drop for LoadedModule {
    fn drop(&mut self) {
        // SAFETY: this module owns one successful LoadLibraryExW reference;
        // all calls have returned before the owner leaves run_engine.
        unsafe { FreeLibrary(self.0); }
    }
}

pub(super) fn run_engine() -> Result<i32, EngineLoadError> {
    let executable = std::env::current_exe().map_err(EngineLoadError::ExecutablePath)?;
    let directory = executable.parent().ok_or(EngineLoadError::MissingParent)?;
    let path = directory.join("compat16.dll");
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: wide is an absolute, terminated path. Dependency lookup is
    // restricted to this module's directory and Windows system libraries.
    let handle = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(),
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if handle.is_null() {
        return Err(EngineLoadError::Load { path, source: io::Error::last_os_error() });
    }
    let module = LoadedModule(handle);
    // SAFETY: the module reference is live; the name is a terminated byte string.
    let version_address = unsafe { GetProcAddress(module.0, c"compat16_abi_version".as_ptr().cast()) }
        .ok_or_else(|| EngineLoadError::MissingExport {
            name: "compat16_abi_version", source: io::Error::last_os_error(),
        })?;
    // SAFETY: this project-owned version export has a scalar-only system ABI.
    let version: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(version_address) };
    // SAFETY: the expected project module remains loaded during this call.
    let found_version = unsafe { version() };
    if found_version != 1 { return Err(EngineLoadError::IncompatibleVersion(found_version)); }
    // SAFETY: the module reference is live and the export name is terminated.
    let entry_address = unsafe { GetProcAddress(module.0, c"compat16_entry_v1".as_ptr().cast()) }
        .ok_or_else(|| EngineLoadError::MissingExport {
            name: "compat16_entry_v1", source: io::Error::last_os_error(),
        })?;
    // SAFETY: ABI version 1 defines this scalar-only system entry signature.
    let entry: unsafe extern "system" fn() -> i32 = unsafe { std::mem::transmute(entry_address) };
    // SAFETY: the core owns and destroys runtime resources before returning.
    // This module reference outlives the full execution and UI-worker callbacks.
    let status = unsafe { entry() };
    Ok(status)
}
