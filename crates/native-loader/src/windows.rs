//! Native PE loading and scalar ABI calls. No guest address crosses here.

use std::io;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleExW, GetProcAddress, LoadLibraryExW,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use super::EngineLoadError;

pub(super) fn command_line() -> io::Result<Vec<u16>> {
    let pointer = unsafe { windows_sys::Win32::System::Environment::GetCommandLineW() };
    if !pointer.is_null() {
        for length in 0..32_767 {
            if unsafe { *pointer.add(length) } == 0 {
                return Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid native command line"))
}

struct LoadedModule(HMODULE);

impl Drop for LoadedModule {
    fn drop(&mut self) {
        // SAFETY: this owner balances one loader reference. A validated engine
        // is pinned separately, so balancing these references cannot unmap
        // code still needed by process/thread-exit callbacks.
        unsafe { FreeLibrary(self.0); }
    }
}

impl LoadedModule {
    fn retain_for_process(&self) -> Result<Self, EngineLoadError> {
        let mut retained = std::ptr::null_mut();
        // SAFETY: the owned HMODULE is a live mapped image base. FROM_ADDRESS
        // makes this argument an address in that image, not a UTF-16 string.
        // PIN retains the image through Windows process teardown, including
        // Rust TLS destructors and system callbacks after the scalar entry
        // returns. Runtime objects and explicitly owned workers still retire
        // normally before that return; only the code image has process scope.
        let ok = unsafe { GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            self.0.cast::<u16>(), &mut retained,
        ) };
        if ok == 0 {
            return Err(EngineLoadError::ProcessLifetime(io::Error::last_os_error()));
        }
        Ok(Self(retained))
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
    // Pin only after validating both exports and the scalar ABI version.
    // Returning from entry is not proof that every OS-owned exit callback
    // has finished with this Rust DLL's code or thread-local storage.
    let _process_lifetime = module.retain_for_process()?;
    // SAFETY: the core owns and destroys runtime resources before returning.
    // This module reference outlives the full execution and UI-worker callbacks.
    let status = unsafe { entry() };
    Ok(status)
}
