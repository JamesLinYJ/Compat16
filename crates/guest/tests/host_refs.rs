use std::cell::Cell;
use std::rc::Rc;

use guest_core::host_refs::{HostRefError, HostRefTable};
use guest_core::OwnerId;

#[test]
fn released_handle_becomes_stale_even_when_its_slot_is_reused() {
    let mut refs = HostRefTable::new();
    let old = refs.insert(OwnerId(1), String::from("first")).unwrap();
    assert_eq!(refs.get(old).unwrap(), "first");
    let old_slot = old.slot_index();
    let old_generation = old.generation();

    assert_eq!(refs.remove(old).unwrap(), "first");
    let current = refs.insert(OwnerId(2), String::from("second")).unwrap();
    assert_eq!(current.slot_index(), old_slot);
    assert_ne!(current.generation(), old_generation);
    assert_eq!(refs.get(current).unwrap(), "second");
    assert_eq!(refs.get(old), Err(HostRefError::StaleHandle));
}

#[test]
fn table_identity_prevents_a_handle_from_resolving_in_another_table() {
    let mut left = HostRefTable::new();
    let mut right = HostRefTable::new();
    let reference = left.insert(OwnerId(7), 10_u32).unwrap();
    right.insert(OwnerId(7), 99_u32).unwrap();

    assert_eq!(left.get(reference), Ok(&10));
    assert_eq!(right.get(reference), Err(HostRefError::InvalidHandle));
}

#[test]
fn owner_cleanup_drops_only_that_owners_values_and_invalidates_their_handles() {
    struct DropCount(Rc<Cell<usize>>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let drops = Rc::new(Cell::new(0));
    let mut refs = HostRefTable::new();
    let first_owner = refs
        .insert(OwnerId(1), DropCount(Rc::clone(&drops)))
        .unwrap();
    let other_owner = refs
        .insert(OwnerId(2), DropCount(Rc::clone(&drops)))
        .unwrap();

    assert_eq!(refs.owner_of(first_owner).unwrap(), OwnerId(1));
    assert_eq!(refs.release_owner(OwnerId(1)), 1);
    assert_eq!(drops.get(), 1);
    assert_eq!(refs.len(), 1);
    assert!(matches!(
        refs.get(first_owner),
        Err(HostRefError::StaleHandle)
    ));
    assert!(refs.get(other_owner).is_ok());

    assert_eq!(refs.release_owner(OwnerId(1)), 0);
    assert_eq!(refs.release_owner(OwnerId(2)), 1);
    assert_eq!(drops.get(), 2);
    assert!(refs.is_empty());
}

#[test]
fn mutable_lookup_and_release_transfer_ownership() {
    let mut refs = HostRefTable::new();
    let reference = refs.insert(OwnerId(4), 10_i32).unwrap();
    *refs.get_mut(reference).unwrap() += 5;
    assert_eq!(refs.get(reference), Ok(&15));

    let value = refs.remove(reference).unwrap();
    assert_eq!(value, 15);
    assert_eq!(refs.get(reference), Err(HostRefError::StaleHandle));
    assert!(refs.is_empty());
}
