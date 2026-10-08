use std::error::Error;
use dos_kernel::DosErrorCode;
use runtime::{DiagnosticKind, RuntimeError};

#[test]
fn native_failure_keeps_guest_code_and_os_cause_across_runtime_boundary() {
    for (native_code, guest_code) in [
        (2, DosErrorCode::FileNotFound),
        (5, DosErrorCode::AccessDenied),
        (32, DosErrorCode::SharingViolation),
        (112, DosErrorCode::DiskFull),
        (9999, DosErrorCode::GeneralFailure),
    ] {
        let mapped = crate::windows::os_error(std::io::Error::from_raw_os_error(native_code));
        assert_eq!(mapped.code, guest_code);
        let error = RuntimeError::with_source(DiagnosticKind::HostFailure, "host operation", mapped);
        let native = error.source().unwrap().source().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(native.raw_os_error(), Some(native_code));
    }
}
