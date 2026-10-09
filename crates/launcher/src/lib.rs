//! Process entry for the console and GUI launchers.
#![forbid(unsafe_code)]

pub fn entry() -> std::process::ExitCode {
    let status = match native_loader::run_engine() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("runtime: {error}");
            125
        }
    };
    // The engine widens the guest's u8 exit status to its scalar i32 ABI;
    // loader failures use 125. Returning through main also runs CRT teardown,
    // including the optional profiler's exit handlers.
    std::process::ExitCode::from(status as u8)
}
