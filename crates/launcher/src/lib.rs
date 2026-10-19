//! Process entry for the console and GUI launchers.
#![forbid(unsafe_code)]

#[cfg(windows)]
mod shell_open;

pub fn entry() -> std::process::ExitCode {
    #[cfg(windows)]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--shell-open")) {
        return match shell_open::run() {
            Ok(code) => code,
            Err(error) => { launcher_ui::show_error(&error); std::process::ExitCode::from(125) }
        };
    }
    if launcher_ui::is_home_invocation() {
        return match launcher_ui::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                launcher_ui::show_error(&error);
                std::process::ExitCode::from(125)
            }
        };
    }
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
