use super::*;
use crate::kernel::state::DosSearchPattern;

fn add(
    registry: &mut Continuations,
    psp: u16,
    caller: DosCallerId,
    serial: u16,
    capacity: usize,
) -> Result<u32, DosHostError> {
    let mut records = Vec::with_capacity(capacity);
    let mut record = [0; 32];
    record[..2].copy_from_slice(&serial.to_le_bytes());
    records.push(record);
    registry.insert(
        psp,
        caller,
        3,
        DosSearchPattern {
            name: [b'?'; 8],
            extension: *b"TXT",
        },
        records,
    )
}

#[test]
fn snapshot_count_quota_preserves_copied_cursors_and_reuses_duplicates() {
    let mut registry = Continuations::default();
    let caller = DosCallerId::REAL_MODE;
    let first = add(&mut registry, 0x1000, caller, 0, 1).unwrap();
    for serial in 1..MAX_OWNER_SNAPSHOTS {
        add(&mut registry, 0x1000, caller, serial as u16, 1).unwrap();
    }
    assert_eq!(
        add(&mut registry, 0x1000, caller, 256, 1).unwrap_err().code,
        DosErrorCode::InsufficientMemory
    );
    assert_eq!(add(&mut registry, 0x1000, caller, 0, 1).unwrap(), first);
    assert!(registry.get(0x1000, caller, first).is_some());
    registry.release_psp(0x1000);
    assert!(registry.get(0x1000, caller, first).is_none());
    assert!(add(&mut registry, 0x1000, caller, 256, 1).is_ok());
}

#[test]
fn snapshot_byte_quota_charges_spare_capacity_and_releases_caller_budget() {
    let mut registry = Continuations::default();
    let caller = DosCallerId::new(1).unwrap();
    add(&mut registry, 0x1000, caller, 0, MAX_OWNER_BYTES / 32).unwrap();
    assert_eq!(
        add(&mut registry, 0x1000, caller, 1, 1).unwrap_err().code,
        DosErrorCode::InsufficientMemory
    );
    registry.release_caller(caller);
    assert!(add(&mut registry, 0x1000, caller, 1, 1).is_ok());
}

#[test]
fn shared_registry_quota_bounds_distinct_processes_and_clear_restores_budget() {
    let mut registry = Continuations::default();
    for caller in 1..=4 {
        add(
            &mut registry,
            0x1000,
            DosCallerId::new(caller).unwrap(),
            0,
            MAX_OWNER_BYTES / 32,
        )
        .unwrap();
    }
    let caller = DosCallerId::new(5).unwrap();
    assert_eq!(
        add(&mut registry, 0x1000, caller, 0, 1).unwrap_err().code,
        DosErrorCode::InsufficientMemory
    );
    registry.clear();
    assert!(add(&mut registry, 0x1000, caller, 0, 1).is_ok());
}
