//! Native Windows memory measurements for the Win16 ToolHelp memory query.

use std::{mem::size_of, io};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16ToolhelpMemoryInfo};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};

pub(super) fn query() -> Result<Win16ToolhelpMemoryInfo, RuntimeError> {
    let mut system = SYSTEM_INFO::default();
    // SAFETY: GetSystemInfo writes one initialized SYSTEM_INFO structure.
    unsafe { GetSystemInfo(&mut system); }

    let mut status = MEMORYSTATUSEX::default();
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: dwLength is initialized and the API receives a writable structure.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return Err(RuntimeError::with_source(
            Kind::HostFailure,
            "query host memory status for Win16 ToolHelp",
            io::Error::last_os_error(),
        ));
    }

    Ok(Win16ToolhelpMemoryInfo {
        page_size: system.dwPageSize,
        total_virtual_bytes: status.ullTotalVirtual,
        available_virtual_bytes: status.ullAvailVirtual,
        total_page_file_bytes: status.ullTotalPageFile,
    })
}
