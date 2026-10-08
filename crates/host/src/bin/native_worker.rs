//! One native API transaction in an address space owned by the helper.

#[cfg(windows)]
fn main() {
    if let Err(error) = host_services::run_native_worker() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the native API helper requires Windows");
    std::process::exit(2);
}
