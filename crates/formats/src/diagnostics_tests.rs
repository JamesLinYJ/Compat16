use super::{FormatError, GuestMemoryRollbackFailure};
use guest_core::{MemoryError, PhysAddr};

#[test]
fn truncated_format_error_keeps_context_offset_and_required_range() {
    let error = FormatError::Truncated {
        context: "NE entry table",
        offset: 0x3a,
        needed: 6,
    };

    assert_eq!(
        error.to_string(),
        "truncated NE entry table: file range 0x3A..0x40 requires 6 bytes"
    );
}

#[test]
fn guest_address_failure_keeps_range_and_memory_limit() {
    let error = FormatError::AddressOutOfRange {
        address: 0x000f_fff0,
        length: 64,
        memory_len: 0x0010_0000,
    };

    assert_eq!(
        error.to_string(),
        "guest memory range 0x000FFFF0..0x100030 (64 bytes) exceeds available memory size 0x00100000"
    );
}

#[test]
fn memory_and_rollback_errors_are_readable_and_keep_typed_sources() {
    let memory_error = MemoryError::OutOfBounds { address: 0x1234, length: 8 };
    let error = FormatError::GuestMemory(memory_error.clone());
    let text = error.to_string();
    assert!(text.contains("guest-memory access failed"));
    assert!(text.contains("0x00001234"));
    assert!(text.contains("8 bytes"));
    assert!(!text.contains("OutOfBounds"));
    assert!(!text.contains('{'));
    assert!(std::error::Error::source(&error).unwrap().is::<MemoryError>());

    let rollback = FormatError::GuestMemoryRollback {
        failed_address: PhysAddr(0x0002_0000),
        primary_error: MemoryError::InvalidMapping,
        rollback_failures: vec![GuestMemoryRollbackFailure {
            address: PhysAddr(0x0000_1234),
            error: MemoryError::ReadOnly { address: 0x1234, length: 4 },
        }],
    };
    let text = rollback.to_string();
    assert!(text.contains("physical address 0x00020000"));
    assert!(text.contains("invalid guest memory mapping request"));
    assert!(text.contains("rollback at physical address 0x00001234"));
    assert!(text.contains("0x00001234"));
    assert!(text.contains("4 bytes"));
    assert!(text.contains("read-only memory"));
    assert!(!text.contains("InvalidMapping"));
    assert!(!text.contains("ReadOnly"));
    assert!(!text.contains('{'));
    assert!(std::error::Error::source(&rollback).unwrap().is::<MemoryError>());
}

#[test]
fn unsupported_and_invalid_cases_name_the_format_and_reason() {
    assert_eq!(
        FormatError::UnsupportedExecutable("PE").to_string(),
        "unsupported executable format: PE"
    );
    assert_eq!(
        FormatError::InvalidMzHeader("header exceeds file length").to_string(),
        "invalid MZ header: header exceeds file length"
    );
    assert_eq!(
        FormatError::UnsupportedNeFixup("additive fixup").to_string(),
        "unsupported NE fixup: additive fixup"
    );
}
