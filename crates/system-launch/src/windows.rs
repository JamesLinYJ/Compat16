use std::ffi::c_void;
use std::ptr;

use windows_core::w;
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_DATA, ERROR_INVALID_PARAMETER, ERROR_PROC_NOT_FOUND,
    ERROR_SUCCESS, GetLastError, HANDLE, SetLastError,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
};
use windows_sys::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};

use crate::command::{MAX_COMMAND_UNITS, mapped_command};

// Win32 metadata does not declare this private entry. The native loader's
// export and argument forwarding were inspected on Windows ARM64. It keeps
// the twelve-argument CreateProcessInternalW host ABI; all caller-owned token,
// security, environment, startup and result objects remain Windows objects.
type CreateProcess = unsafe extern "system" fn(
    HANDLE, *const u16, *mut u16, *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES, i32, u32, *const c_void, *const u16,
    *const STARTUPINFOW, *mut PROCESS_INFORMATION, *mut HANDLE,
) -> i32;

/// Substitute a native launcher after Windows classifies a legacy image.
///
/// # Safety
/// Windows supplies valid host pointers for the CreateProcessInternalW ABI.
/// Input strings must remain readable and NUL-terminated for this call; output
/// objects must be writable. This entry never accepts guest addresses.
#[unsafe(export_name = "NtVdm64CreateProcessInternalW")]
pub unsafe extern "system" fn create_legacy_process(
    token: HANDLE,
    application: *const u16,
    original_command: *mut u16,
    process_security: *const SECURITY_ATTRIBUTES,
    thread_security: *const SECURITY_ATTRIBUTES,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u16,
    startup: *const STARTUPINFOW,
    process: *mut PROCESS_INFORMATION,
    new_token: *mut HANDLE,
) -> i32 {
    if application.is_null() || startup.is_null() || process.is_null() {
        return failure(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: The native loader owns the two strings for this call.
    let program = match unsafe { wide_string(application) } {
        Ok(value) => value,
        Err(error) => return failure(error),
    };
    let original = if original_command.is_null() {
        &[]
    } else {
        // SAFETY: Same native input-string contract as application.
        match unsafe { wide_string(original_command) } {
            Ok(value) => value,
            Err(error) => return failure(error),
        }
    };
    let mut launcher = [0u16; MAX_COMMAND_UNITS + 1];
    let launcher_length = match configured_launcher(&mut launcher) {
        Ok(value) => value,
        Err(error) => return failure(error),
    };
    let mut command = match mapped_command(&launcher[..launcher_length], program, original) {
        Ok(value) => value,
        Err(error) => return failure(error),
    };
    // SAFETY: KERNELBASE is an OS module retained for the process lifetime.
    let module = unsafe { GetModuleHandleW(w!("KERNELBASE.dll").as_ptr()) };
    // SAFETY: The export name is a static NUL-terminated ASCII string.
    let Some(entry) = (unsafe { GetProcAddress(module, c"CreateProcessInternalW".as_ptr().cast()) }) else {
        return failure(ERROR_PROC_NOT_FOUND);
    };
    // SAFETY: This exact native export implements the host ABI declared above.
    let create: CreateProcess = unsafe { std::mem::transmute(entry) };
    // SAFETY: Forward all original host objects unchanged. Only the native
    // executable and command line are replaced with owned UTF-16 buffers, which
    // stay alive until Windows has completed process creation.
    let result = unsafe {
        create(token, launcher.as_ptr(), command.as_mut_ptr(), process_security,
            thread_security, inherit_handles, creation_flags, environment,
            current_directory, startup, process, new_token)
    };
    // Preserve a failed Windows call's thread-local error across release of
    // our command buffer; allocator cleanup is outside that API's contract.
    // SAFETY: GetLastError reads only the calling native thread's error.
    let error = unsafe { GetLastError() };
    drop(command);
    if result == 0 { failure(error) } else { result }
}

unsafe fn wide_string<'a>(input: *const u16) -> Result<&'a [u16], u32> {
    for length in 0..MAX_COMMAND_UNITS {
        // SAFETY: The caller guarantees a readable NUL-terminated host string.
        if unsafe { *input.add(length) } == 0 {
            // SAFETY: The prefix was read under the same input-string contract.
            return Ok(unsafe { std::slice::from_raw_parts(input, length) });
        }
    }
    Err(windows_sys::Win32::Foundation::ERROR_FILENAME_EXCED_RANGE)
}

fn configured_launcher(output: &mut [u16]) -> Result<usize, u32> {
    let mut bytes = std::mem::size_of_val(output) as u32;
    // SAFETY: The registry names are static UTF-16 strings; output and bytes
    // provide writable storage of the advertised size. Read the native view.
    let status = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NtVdm64\\Compat16").as_ptr(),
            w!("MappedExeName").as_ptr(), RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            ptr::null_mut(), output.as_mut_ptr().cast(), &mut bytes)
    };
    if status != ERROR_SUCCESS { return Err(status); }
    let units = bytes as usize / std::mem::size_of::<u16>();
    if bytes % 2 != 0 || units == 0 || units > output.len()
        || output[units - 1] != 0 || output[..units - 1].contains(&0)
    {
        return Err(ERROR_INVALID_DATA);
    }
    Ok(units - 1)
}

fn failure(error: u32) -> i32 {
    // SAFETY: SetLastError affects only the calling native thread.
    unsafe { SetLastError(error) };
    0
}
