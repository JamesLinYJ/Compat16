//! Windows host boundary. Guest tokens never contain OS handle values.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(windows, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!("Windows host adapters support only AMD64 and ARM64 targets");

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub mod windowing;

#[cfg(windows)]
mod filesystem;

#[cfg(windows)]
mod ioctl;

#[cfg(windows)]
pub use windows::WindowsHost;

/// Entry for the separately launched native API helper's private pipe protocol.
#[cfg(windows)]
pub fn run_native_worker() -> Result<(), runtime::RuntimeError> {
    windows::run_native_worker()
}

#[cfg(all(test, windows))]
mod diagnostics_tests;
