//! Native execution module. Every runtime object is created and released here.
#![deny(unsafe_op_in_unsafe_fn)]

mod entry;
mod launch_options;
#[cfg(windows)]
mod program_encoding;
#[cfg(windows)]
mod system_launch;

/// Version 1 has scalar-only system-ABI exports and no shared allocations.
const ABI_VERSION: u32 = 1;

#[unsafe(no_mangle)]
pub extern "system" fn compat16_abi_version() -> u32 { ABI_VERSION }

/// Runtime, host services and their workers are dropped before this returns.
#[unsafe(no_mangle)]
pub extern "system" fn compat16_entry_v1() -> i32 {
    match std::panic::catch_unwind(entry::entry) {
        Ok(status) => status,
        Err(_) => {
            use std::io::Write;
            let _ = writeln!(std::io::stderr().lock(),
                "runtime: the execution module encountered an internal panic");
            125
        }
    }
}
