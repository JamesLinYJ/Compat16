use std::fmt::Display;

use guest_core::arena::{ArenaError, PhysicalArenaMap, RegionKind};
use guest_core::io::{PortError, PortWidth};
use guest_core::host_refs::HostRefError;
use guest_core::{MemoryError, PhysAddr};

fn readable(error: impl Display) -> String {
    let message = error.to_string();
    assert!(!message.contains('{'), "debug struct leaked into: {message}");
    assert!(!message.contains('}'), "debug struct leaked into: {message}");
    message
}

#[test]
fn memory_errors_describe_ranges_and_read_only_writes() {
    let out_of_bounds = readable(MemoryError::OutOfBounds {
        address: 0x1234,
        length: 3,
    });
    assert!(out_of_bounds.contains("0x00001234"));
    assert!(out_of_bounds.contains("3 bytes"));
    assert!(out_of_bounds.contains("0x3"));

    let read_only = readable(MemoryError::ReadOnly {
        address: 0x000f_0000,
        length: 2,
    });
    assert!(read_only.contains("write"));
    assert!(read_only.contains("0x000F0000"));
    assert!(read_only.contains("2 bytes"));

    for error in [
        MemoryError::AddressOverflow,
        MemoryError::AllocationFailed,
        MemoryError::InvalidMapping,
    ] {
        readable(error);
    }
}

#[test]
fn port_errors_name_operation_width_port_and_detail() {
    let unsupported = readable(PortError::Unsupported {
        port: 0x03c0,
        width: PortWidth::Word,
        write: true,
    });
    assert!(unsupported.contains("word (16-bit) write"));
    assert!(unsupported.contains("0x03C0"));

    let invalid_state = readable(PortError::InvalidState {
        port: 0x0064,
        detail: "controller is not initialized",
    });
    assert!(invalid_state.contains("0x0064"));
    assert!(invalid_state.contains("controller is not initialized"));

    let invariant = readable(PortError::InternalInvariant {
        port: 0x0060,
        detail: "read queue is empty",
    });
    assert!(invariant.contains("internal device invariant"));
    assert!(invariant.contains("read queue is empty"));
}

#[test]
fn arena_errors_explain_invalid_and_conflicting_ranges() {
    for error in [
        ArenaError::InvalidMemorySize,
        ArenaError::InvalidLength,
        ArenaError::InvalidAlignment { alignment: 0 },
        ArenaError::MisalignedRange {
            base: PhysAddr(0x1234),
            length: 0x20,
            alignment: 0x10,
        },
        ArenaError::AddressOverflow {
            base: PhysAddr(0xffff_fff0),
            length: 0x20,
        },
        ArenaError::OutOfBounds {
            base: PhysAddr(0x1000),
            length: 0x2000,
            memory_size: 0x2000,
        },
        ArenaError::ForeignMapId,
        ArenaError::UnknownRegionId,
        ArenaError::IdentityExhausted,
        ArenaError::RegionIdExhausted,
    ] {
        readable(error);
    }

    let mut arena = PhysicalArenaMap::new(0x10000).unwrap();
    arena
        .reserve(RegionKind::Xms, PhysAddr(0x2000), 0x1000, 1)
        .unwrap();
    let overlap = readable(
        arena
            .reserve(RegionKind::VideoMemory, PhysAddr(0x2800), 0x1000, 1)
            .unwrap_err(),
    );
    assert!(overlap.contains("video memory"));
    assert!(overlap.contains("extended memory"));
    assert!(overlap.contains("0x00002800"));
    assert!(overlap.contains("0x00002000"));
}

#[test]
fn host_reference_errors_explain_lookup_and_capacity_failures() {
    for error in [
        HostRefError::InvalidHandle,
        HostRefError::StaleHandle,
        HostRefError::CapacityExhausted,
    ] {
        readable(error);
    }
}
