use super::support::*;
use crate::{MoveRequest, XmsError};
use guest_core::{GuestHandle, GuestMemory, OwnerId, PhysAddr};

#[test]
fn moves_use_far_pointers_and_handle_zero_means_conventional_memory() {
    let (mut service, mut memory) = fixture();
    let handle = service.allocate(OwnerId(2), 1, &mut memory).unwrap();
    let conventional = PhysAddr(0x0002_0010);
    memory
        .write(conventional, &[0x41, 0x42, 0x43, 0x44])
        .unwrap();

    service
        .move_block(
            MoveRequest {
                length: 4,
                source_handle: 0,
                source_offset: far_pointer(0x2000, 0x10),
                destination_handle: handle.0,
                destination_offset: 20,
            },
            &mut memory,
        )
        .unwrap();
    let block = service.lock(handle).unwrap();
    service.unlock(handle).unwrap();
    let mut moved = [0; 4];
    memory.read(PhysAddr(block.0 + 20), &mut moved).unwrap();
    assert_eq!(moved, [0x41, 0x42, 0x43, 0x44]);

    service
        .move_block(
            MoveRequest {
                length: 4,
                source_handle: handle.0,
                source_offset: 20,
                destination_handle: 0,
                destination_offset: far_pointer(0x2000, 0x20),
            },
            &mut memory,
        )
        .unwrap();
    let mut copied_back = [0; 4];
    memory
        .read(PhysAddr(0x0002_0020), &mut copied_back)
        .unwrap();
    assert_eq!(copied_back, moved);
}

#[test]
fn forward_overlap_copies_and_reverse_overlap_is_rejected_without_mutation() {
    let (mut service, mut memory) = fixture();
    let handle = service.allocate(OwnerId(3), 1, &mut memory).unwrap();
    let base = service.lock(handle).unwrap();
    service.unlock(handle).unwrap();
    memory.write(base, &[1, 2, 3, 4, 5, 6]).unwrap();

    service
        .move_block(
            MoveRequest {
                length: 4,
                source_handle: handle.0,
                source_offset: 0,
                destination_handle: handle.0,
                destination_offset: 2,
            },
            &mut memory,
        )
        .unwrap();
    let mut after_forward = [0; 6];
    memory.read(base, &mut after_forward).unwrap();
    assert_eq!(after_forward, [1, 2, 1, 2, 3, 4]);

    assert_eq!(
        service.move_block(
            MoveRequest {
                length: 4,
                source_handle: handle.0,
                source_offset: 2,
                destination_handle: handle.0,
                destination_offset: 0,
            },
            &mut memory,
        ),
        Err(XmsError::InvalidMoveOverlap)
    );
    let mut after_rejected = [0; 6];
    memory.read(base, &mut after_rejected).unwrap();
    assert_eq!(after_rejected, after_forward);
}

#[test]
fn invalid_handles_and_offsets_have_specific_errors() {
    let (mut service, mut memory) = fixture();
    assert_eq!(service.free(GuestHandle(0)), Err(XmsError::InvalidHandle));
    assert_eq!(service.lock(GuestHandle(256)), Err(XmsError::InvalidHandle));
    assert_eq!(service.unlock(GuestHandle(1)), Err(XmsError::InvalidHandle));

    assert_eq!(
        service.move_block(
            MoveRequest {
                length: 2,
                source_handle: 4,
                source_offset: 0,
                destination_handle: 0,
                destination_offset: far_pointer(0x2000, 0),
            },
            &mut memory,
        ),
        Err(XmsError::InvalidSourceHandle)
    );

    let handle = service.allocate(OwnerId(4), 1, &mut memory).unwrap();
    assert_eq!(
        service.move_block(
            MoveRequest {
                length: 2,
                source_handle: handle.0,
                source_offset: KIB,
                destination_handle: 0,
                destination_offset: far_pointer(0x2000, 0),
            },
            &mut memory,
        ),
        Err(XmsError::InvalidSourceOffset)
    );
    assert_eq!(
        service.move_block(
            MoveRequest {
                length: 3,
                source_handle: handle.0,
                source_offset: 0,
                destination_handle: 0,
                destination_offset: far_pointer(0x2000, 0),
            },
            &mut memory,
        ),
        Err(XmsError::InvalidLength)
    );
    assert_eq!(
        service.move_block(
            MoveRequest {
                length: 2,
                source_handle: handle.0,
                source_offset: KIB - 1,
                destination_handle: 0,
                destination_offset: far_pointer(0x2000, 0),
            },
            &mut memory,
        ),
        Err(XmsError::InvalidLength)
    );
}

#[test]
fn zero_sized_handles_and_zero_length_moves_are_supported() {
    let (mut service, mut memory) = fixture();
    let handle = service.allocate(OwnerId(5), 0, &mut memory).unwrap();
    assert_eq!(service.handle_info(handle).unwrap().size_kb, 0);
    service
        .move_block(
            MoveRequest {
                length: 0,
                source_handle: handle.0,
                source_offset: 0,
                destination_handle: 0,
                destination_offset: far_pointer(0xffff, 0xffff),
            },
            &mut memory,
        )
        .unwrap();
    service.free(handle).unwrap();
}

#[test]
fn move_descriptor_is_decoded_from_guest_memory_and_address_overflow_is_reported() {
    let (service, mut memory) = fixture();
    let request = MoveRequest {
        length: 0,
        source_handle: 0,
        source_offset: far_pointer(0x2000, 0),
        destination_handle: 0,
        destination_offset: far_pointer(0x2000, 0),
    };
    memory.write(PhysAddr(0x500), &request.encode()).unwrap();
    service
        .move_from_descriptor(PhysAddr(0x500), &mut memory)
        .unwrap();

    assert_eq!(
        service.move_from_descriptor(PhysAddr(u32::MAX - 7), &mut memory),
        Err(XmsError::Memory(
            guest_core::MemoryError::AddressOverflow
        ))
    );
}
