use super::{DosError, DosErrorCode, DosHostError};
use guest_core::MemoryError;

#[test]
fn dos_error_code_labels_preserve_numeric_abi_values() {
    let codes: [(DosErrorCode, u16, &str); 24] = [
        (DosErrorCode::InvalidFunction, 1, "invalid function"),
        (DosErrorCode::FileNotFound, 2, "file not found"),
        (DosErrorCode::PathNotFound, 3, "path not found"),
        (DosErrorCode::TooManyOpenFiles, 4, "too many open files"),
        (DosErrorCode::AccessDenied, 5, "access denied"),
        (DosErrorCode::InvalidHandle, 6, "invalid handle"),
        (DosErrorCode::McbDestroyed, 7, "memory control block destroyed"),
        (DosErrorCode::InsufficientMemory, 8, "insufficient memory"),
        (DosErrorCode::InvalidMemoryBlock, 9, "invalid memory block"),
        (DosErrorCode::InvalidEnvironment, 10, "invalid environment"),
        (DosErrorCode::InvalidFormat, 11, "invalid format"),
        (DosErrorCode::InvalidAccess, 12, "invalid access mode"),
        (DosErrorCode::InvalidData, 13, "invalid data"),
        (DosErrorCode::UnknownUnit, 15, "unknown device unit"),
        (DosErrorCode::CannotRemoveCurrentDirectory, 16, "cannot remove the current directory"),
        (DosErrorCode::NotSameDevice, 17, "operation crosses devices"),
        (DosErrorCode::NoMoreFiles, 18, "no more files"),
        (DosErrorCode::WriteProtected, 19, "write protected"),
        (DosErrorCode::DriveNotReady, 21, "drive not ready"),
        (DosErrorCode::SharingViolation, 32, "sharing violation"),
        (DosErrorCode::LockViolation, 33, "lock violation"),
        (DosErrorCode::DiskFull, 39, "disk full"),
        (DosErrorCode::GeneralFailure, 31, "general failure"),
        (DosErrorCode::FileExists, 80, "file already exists"),
    ];

    for (code, number, label) in codes {
        assert_eq!(code as u16, number);
        assert_eq!(code.to_string(), label);
    }
}

#[test]
fn host_error_is_readable_and_keeps_code_and_typed_cause() {
    let error = DosHostError::with_source(
        DosErrorCode::AccessDenied,
        std::io::Error::from_raw_os_error(5),
    );
    let text = error.to_string();

    assert!(text.contains("DOS host operation failed: access denied (DOS error 0x0005)"));
    assert!(text.contains("host cause:"));
    assert!(!text.contains("AccessDenied"));
    assert!(!text.contains('{'));
    assert!(std::error::Error::source(&error).unwrap().is::<std::io::Error>());
}

#[test]
fn dos_memory_and_contract_errors_keep_context_without_debug_dumps() {
    let error = DosError::Memory(MemoryError::OutOfBounds { address: 0x1234, length: 8 });
    let text = error.to_string();
    assert!(text.contains("DOS guest-memory access failed"));
    assert!(text.contains("0x00001234"));
    assert!(text.contains("8 bytes"));
    assert!(!text.contains("OutOfBounds"));
    assert!(!text.contains('{'));
    assert!(std::error::Error::source(&error).unwrap().is::<MemoryError>());

    let error = DosError::MalformedGuestInput("unterminated path");
    assert_eq!(error.to_string(), "malformed DOS guest input: unterminated path");

    let error = DosError::HostContractViolation("file_read exceeded its output buffer");
    assert_eq!(
        error.to_string(),
        "DOS host contract violation: file_read exceeded its output buffer"
    );
}

#[test]
fn mcb_corruption_diagnostic_keeps_chain_position_and_guest_header() {
    let mut header = [0u8; 16];
    header[0] = b'X';
    header[1..3].copy_from_slice(&0x1234u16.to_le_bytes());
    header[3..5].copy_from_slice(&0x5678u16.to_le_bytes());
    let error = DosError::InvalidMcbSignature {
        segment: 0x2345,
        chain_head: 0x1000,
        psp_segment: 0x1001,
        previous: Some((0x2000, 0x0344)),
        header,
    };
    let text = error.to_string();

    assert!(text.contains("segment 0x2345"));
    assert!(text.contains("signature 0x58"));
    assert!(text.contains("chain head 0x1000"));
    assert!(text.contains("PSP 0x1001"));
    assert!(text.contains("owner 0x1234"));
    assert!(text.contains("size 0x5678"));
    assert!(text.contains("previous MCB 0x2000 size 0x0344"));
    assert!(text.contains("header bytes=5834127856"));
    assert!(!text.contains("InvalidMcbSignature"));
    assert!(!text.contains('{'));
}

#[test]
fn host_memory_contract_error_keeps_api_context_range_and_source() {
    let error = DosError::HostMemoryContractViolation {
        detail: "reading the NLS collation table",
        source: MemoryError::ReadOnly { address: 0x0000_fffe, length: 4 },
    };
    let text = error.to_string();

    assert!(text.contains("while reading the NLS collation table"));
    assert!(text.contains("0x0000FFFE"));
    assert!(text.contains("4 bytes"));
    assert!(text.contains("read-only memory"));
    assert!(!text.contains("HostMemoryContractViolation"));
    assert!(!text.contains("ReadOnly"));
    assert!(!text.contains('{'));
    assert!(std::error::Error::source(&error).unwrap().is::<MemoryError>());
}

#[test]
fn dos_host_operation_keeps_the_nested_error_chain() {
    let host = DosHostError::with_source(
        DosErrorCode::DriveNotReady,
        std::io::Error::from_raw_os_error(21),
    );
    let error = DosError::HostOperation(host);
    assert!(error.to_string().contains("DOS error 0x0015"));
    let host_source = std::error::Error::source(&error).unwrap();
    assert!(host_source.is::<DosHostError>());
    assert!(std::error::Error::source(host_source).unwrap().is::<std::io::Error>());
}
