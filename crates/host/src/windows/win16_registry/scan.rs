//! Independent native enumeration context for a synchronous alias lookup.
use std::thread;
use windows_sys::Win32::Foundation::ERROR_NOT_ENOUGH_MEMORY;
use windows_sys::Win32::System::Registry::HKEY;

use super::TextConversionError;
use runtime::{DiagnosticKind, RuntimeError};

struct BorrowedParent<'key>(&'key HKEY);

// SAFETY: registry HKEYs can be used across threads. The caller keeps the
// validated parent open throughout this synchronous operation, and the scoped
// worker is joined before the borrow ends. The worker never closes the key.
unsafe impl Send for BorrowedParent<'_> {}

impl BorrowedParent<'_> {
    fn raw(&self) -> HKEY {
        *self.0
    }
}

pub(super) fn run<T: Send>(
    parent: HKEY,
    scan: impl FnOnce(HKEY) -> Result<T, TextConversionError> + Send,
) -> Result<T, TextConversionError> {
    // Rewinding a merged HKCR enumeration on the caller's native thread can
    // stall, including with another handle to the same merged view. A fresh
    // thread scans from zero to completion without disturbing that context.
    // Keep the exact parent HKEY: no alternate hive, path reconstruction or
    // cached name snapshot changes which live keys participate in the lookup.
    thread::scope(|scope| {
        let parent = BorrowedParent(&parent);
        let worker = thread::Builder::new()
            .spawn_scoped(scope, move || scan(parent.raw()))
            .map_err(|error| {
                TextConversionError::GuestStatus(
                    error
                        .raw_os_error()
                        .and_then(|code| u32::try_from(code).ok())
                        .unwrap_or(ERROR_NOT_ENOUGH_MEMORY),
                )
            })?;
        worker.join().map_err(|_| {
            TextConversionError::Runtime(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "native registry alias scan panicked",
            ))
        })?
    })
}
