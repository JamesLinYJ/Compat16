use super::support::*;
use crate::{FreeSpace, XmsError};
use guest_core::{GuestHandle, GuestMemory, OwnerId, PhysAddr};

#[test]
fn allocate_zeroes_bytes_and_reallocate_preserves_then_zeroes_growth() {
    let (mut service, mut memory) = fixture();
    let first = service.allocate(OwnerId(1), 1, &mut memory).unwrap();
    let second = service.allocate(OwnerId(1), 1, &mut memory).unwrap();
    assert_eq!(first, GuestHandle(1));
    assert_eq!(second, GuestHandle(2));

    let base = service.lock(second).unwrap();
    service.unlock(second).unwrap();
    let mut initial = vec![0; KIB as usize];
    memory.read(base, &mut initial).unwrap();
    assert!(initial.iter().all(|byte| *byte == 0));
    initial[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    memory.write(base, &initial).unwrap();

    service.free(first).unwrap();
    service.reallocate(second, 2, &mut memory).unwrap();
    let moved_base = service.lock(second).unwrap();
    service.unlock(second).unwrap();
    assert_eq!(moved_base, PhysAddr(0x0011_0000));
    let mut grown = vec![0xff; (2 * KIB) as usize];
    memory.read(moved_base, &mut grown).unwrap();
    assert_eq!(&grown[..4], &[0x11, 0x22, 0x33, 0x44]);
    assert!(grown[4..].iter().all(|byte| *byte == 0));
}

#[test]
fn failed_reallocation_rolls_back_metadata_and_guest_bytes() {
    let (mut service, mut memory) = fixture();
    let handle = service.allocate(OwnerId(7), 1, &mut memory).unwrap();
    let base = service.lock(handle).unwrap();
    service.unlock(handle).unwrap();
    memory.write(base, &[1, 2, 3, 4]).unwrap();

    memory.fail_writes = true;
    assert!(matches!(
        service.reallocate(handle, 2, &mut memory),
        Err(XmsError::ArenaMemory(
            guest_core::MemoryError::ReadOnly { .. }
        ))
    ));
    assert_eq!(service.handle_info(handle).unwrap().size_kb, 1);
    let mut observed = [0; 4];
    memory.read(base, &mut observed).unwrap();
    assert_eq!(observed, [1, 2, 3, 4]);
}

#[test]
fn locks_prevent_free_and_reallocation_until_balanced() {
    let (mut service, mut memory) = fixture();
    let handle = service.allocate(OwnerId(4), 1, &mut memory).unwrap();
    for _ in 0..u8::MAX {
        service.lock(handle).unwrap();
    }
    assert_eq!(service.lock(handle), Err(XmsError::LockCountOverflow));
    assert_eq!(service.free(handle), Err(XmsError::BlockLocked));
    assert_eq!(
        service.reallocate(handle, 2, &mut memory),
        Err(XmsError::BlockLocked)
    );
    for _ in 0..u8::MAX {
        service.unlock(handle).unwrap();
    }
    assert_eq!(service.unlock(handle), Err(XmsError::BlockNotLocked));
    service.free(handle).unwrap();
}

#[test]
fn free_space_reports_total_and_largest_contiguous_gap() {
    let (mut service, mut memory) = fixture();
    let first = service.allocate(OwnerId(6), 1, &mut memory).unwrap();
    let middle = service.allocate(OwnerId(6), 1, &mut memory).unwrap();
    let _last = service.allocate(OwnerId(6), 1, &mut memory).unwrap();
    service.free(middle).unwrap();
    assert_eq!(
        service.free_space(),
        FreeSpace {
            largest_kb: 1,
            total_kb: 2
        }
    );
    service.free(first).unwrap();
    assert_eq!(
        service.free_space(),
        FreeSpace {
            largest_kb: 2,
            total_kb: 3
        }
    );
}

#[test]
fn owner_cleanup_releases_even_locked_handles() {
    let (mut service, mut memory) = fixture();
    let owned = service.allocate(OwnerId(7), 1, &mut memory).unwrap();
    let _other = service.allocate(OwnerId(8), 1, &mut memory).unwrap();
    service.lock(owned).unwrap();
    assert_eq!(service.cleanup_owner(OwnerId(7)), 1);
    assert_eq!(service.handle_info(owned), Err(XmsError::InvalidHandle));
    assert_eq!(service.free_space().total_kb, 3);
}
