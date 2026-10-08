//! Process entry for the console and GUI launchers.
#![forbid(unsafe_code)]

pub fn entry() -> i32 {
    match native_loader::run_engine() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("runtime: {error}");
            125
        }
    }
}
