//! Pure ownership fixtures: fake native handles always use a counted destructor.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn guard(raw: usize, kind: ImageKind, count: &Arc<AtomicUsize>) -> NativeIconGuard {
    let mut guard = NativeIconGuard::new_kind(raw as HICON, kind);
    guard.0.as_mut().unwrap().test_destruction = Some(Arc::clone(count));
    guard
}

fn register(table: &mut ImageTable, guard: &mut NativeIconGuard) -> Result<u64, RuntimeError> {
    let mut collision = None;
    table.register_owned(guard, &mut collision)
}

fn adopt(table: &mut ImageTable, raw: usize, kind: ImageKind) -> Result<u64, RuntimeError> {
    let mut recovered = None;
    table.adopt(raw as HICON, kind, &mut recovered)
}

#[test]
fn released_token_is_republished_with_exact_owner_and_fresh_identity() {
    let count = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let first = register(&mut table, &mut guard(101, ImageKind::Icon, &count)).unwrap();
    let lease = Arc::clone(&table.images[&first]);
    let weak = Arc::downgrade(&lease);
    table.images.remove(&first);
    let second = adopt(&mut table, 101, ImageKind::Icon).unwrap();
    assert_ne!(first, second);
    assert!(!table.images.contains_key(&first));
    assert!(Arc::ptr_eq(&table.images[&second], &lease));
    drop(lease);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(adopt(&mut table, 101, ImageKind::Icon).unwrap(), second);
    table.images.remove(&second);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(weak.upgrade().is_none());
    table.sweep();
    assert!(table.owners.is_empty());
}

#[test]
fn nested_get_recovers_a_different_outer_call_owner() {
    let count_a = Arc::new(AtomicUsize::new(0));
    let count_b = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let a = register(&mut table, &mut guard(102, ImageKind::Icon, &count_a)).unwrap();
    let b = register(&mut table, &mut guard(103, ImageKind::Icon, &count_b)).unwrap();
    let outer = table.images.remove(&a).unwrap();
    let inner = Arc::clone(&table.images[&b]);
    // GET carries no input lease. The registry still recovers outer A, not B.
    let result = adopt(&mut table, 102, ImageKind::Icon).unwrap();
    assert!(Arc::ptr_eq(&table.images[&result], &outer));
    assert!(!Arc::ptr_eq(&table.images[&result], &inner));
    drop(outer);
    drop(inner);
    assert_eq!(count_a.load(Ordering::SeqCst), 0);
    drop(table);
    assert_eq!(count_a.load(Ordering::SeqCst), 1);
    assert_eq!(count_b.load(Ordering::SeqCst), 1);
}

#[test]
fn stale_borrowed_alias_never_wins_over_live_owned_incarnation() {
    let count = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let borrowed = adopt(&mut table, 104, ImageKind::Icon).unwrap();
    let borrowed_owner = Arc::clone(&table.images[&borrowed]);
    let owned = register(&mut table, &mut guard(104, ImageKind::Icon, &count)).unwrap();
    assert_eq!(adopt(&mut table, 104, ImageKind::Icon).unwrap(), owned);
    let lease = table.images.remove(&owned).unwrap();
    let recovered = adopt(&mut table, 104, ImageKind::Icon).unwrap();
    assert_ne!(recovered, borrowed);
    assert_ne!(recovered, owned);
    assert!(Arc::ptr_eq(&table.images[&borrowed], &borrowed_owner));
    assert!(!table.images[&borrowed].image.owned);
    assert!(Arc::ptr_eq(&table.images[&recovered], &lease));
    drop(lease);
    drop(table);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn live_owner_kind_mismatch_does_not_publish_borrowed_alias() {
    let count = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let cursor = register(&mut table, &mut guard(105, ImageKind::Cursor, &count)).unwrap();
    let lease = table.images.remove(&cursor).unwrap();
    assert!(adopt(&mut table, 105, ImageKind::Icon).is_err());
    assert!(table.images.is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let recovered = adopt(&mut table, 105, ImageKind::Cursor).unwrap();
    assert!(Arc::ptr_eq(&table.images[&recovered], &lease));
    drop(lease);
    drop(table);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn duplicate_registration_disarms_only_incoming_destruction_authority() {
    let established = Arc::new(AtomicUsize::new(0));
    let duplicate = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let token = register(&mut table, &mut guard(106, ImageKind::Icon, &established)).unwrap();
    let mut incoming = guard(106, ImageKind::Cursor, &duplicate);
    assert!(register(&mut table, &mut incoming).is_err());
    drop(incoming);
    assert_eq!(duplicate.load(Ordering::SeqCst), 0);
    assert_eq!(established.load(Ordering::SeqCst), 0);
    assert!(table.images.contains_key(&token));
    drop(table);
    assert_eq!(established.load(Ordering::SeqCst), 1);
}

#[test]
fn exhaustion_preserves_live_owner_and_consumes_new_registration_once() {
    let count = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let token = register(&mut table, &mut guard(107, ImageKind::Icon, &count)).unwrap();
    let lease = table.images.remove(&token).unwrap();
    table.next_id = u64::MAX;
    assert!(adopt(&mut table, 107, ImageKind::Icon).is_err());
    assert!(table.images.is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let mut incoming = guard(108, ImageKind::Icon, &failed);
    assert!(register(&mut table, &mut incoming).is_err());
    drop(incoming);
    assert_eq!(failed.load(Ordering::SeqCst), 1);
    drop(lease);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    table.sweep();
    assert!(table.owners.is_empty());
}

#[test]
fn expired_owner_does_not_revive_when_native_bits_are_reused() {
    let old_count = Arc::new(AtomicUsize::new(0));
    let new_count = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let old = register(&mut table, &mut guard(109, ImageKind::Icon, &old_count)).unwrap();
    let weak = Arc::downgrade(&table.images[&old]);
    table.images.remove(&old);
    assert_eq!(old_count.load(Ordering::SeqCst), 1);
    let new = register(&mut table, &mut guard(109, ImageKind::Icon, &new_count)).unwrap();
    assert_ne!(old, new);
    assert!(weak.upgrade().is_none());
    assert_eq!(table.owners.len(), 1);
    assert_eq!(adopt(&mut table, 109, ImageKind::Icon).unwrap(), new);
    drop(table);
    assert_eq!(new_count.load(Ordering::SeqCst), 1);
}

#[test]
fn weak_registry_never_keeps_an_unpublished_owner_alive() {
    let count = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    for raw in 200..264 {
        let token = register(&mut table, &mut guard(raw, ImageKind::Icon, &count)).unwrap();
        table.images.remove(&token);
    }
    assert_eq!(count.load(Ordering::SeqCst), 64);
    assert!(table.owners.len() <= 64);
    table.sweep();
    assert!(table.owners.is_empty());
}

#[test]
fn release_racing_recovery_cannot_resurrect_or_double_destroy_owner() {
    for _ in 0..32 {
        let count = Arc::new(AtomicUsize::new(0));
        let mut table = ImageTable::new();
        let token = register(&mut table, &mut guard(110, ImageKind::Icon, &count)).unwrap();
        let lease = table.images.remove(&token).unwrap();
        let table = Arc::new(Mutex::new(table));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let release_barrier = Arc::clone(&barrier);
        let thread = std::thread::spawn(move || {
            release_barrier.wait();
            drop(lease);
        });
        barrier.wait();
        let mut recovered = None;
        let result = table.lock().unwrap().adopt(110 as HICON, ImageKind::Icon, &mut recovered).unwrap();
        drop(recovered);
        thread.join().unwrap();
        let owned = table.lock().unwrap().images[&result].image.owned;
        assert_eq!(count.load(Ordering::SeqCst), usize::from(!owned));
        drop(table);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

struct TestSlots {
    slots: super::super::NativeIconSlots,
    destroyed: Arc<Mutex<Vec<usize>>>,
}

impl TestSlots {
    fn new(large: &[usize], small: &[usize]) -> Self {
        Self {
            slots: super::super::NativeIconSlots {
                large: large.iter().map(|raw| *raw as HICON).collect(),
                small: small.iter().map(|raw| *raw as HICON).collect(),
            },
            destroyed: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Drop for TestSlots {
    fn drop(&mut self) {
        // Exercise the production cleanup traversal with a counted destructor,
        // then disarm all fake slots before NativeIconSlots reaches USER32.
        super::super::visit_unique_icon_slots(
            &mut self.slots.large, &mut self.slots.small,
            |raw| self.destroyed.lock().unwrap().push(raw as usize),
        );
        self.slots.large.fill(std::ptr::null_mut());
        self.slots.small.fill(std::ptr::null_mut());
    }
}

fn images() -> Win16Images {
    Win16Images::new(GuestTextCodec::new(1252).expect("Windows ANSI code page"))
}

#[test]
fn extracted_aliases_transfer_once_and_preserve_output_slots() {
    let images = images();
    let count = Arc::new(AtomicUsize::new(0));
    let mut slots = TestSlots::new(&[301, 0, 302, 301], &[302, 301]);
    let leftovers = Arc::clone(&slots.destroyed);
    let result = images.retain_extracted_slots_with(&mut slots.slots, 4, true, 2, true,
        |raw| images.insert_owned(guard(raw as usize, ImageKind::Icon, &count))).unwrap();
    assert_eq!(result.0[0], result.0[3]);
    assert_eq!(result.0[0], result.1[1]);
    assert_eq!(result.0[2], result.1[0]);
    assert_eq!(result.0[1], None);
    assert_eq!(images.lock().unwrap().images.len(), 2);
    drop(slots);
    assert!(leftovers.lock().unwrap().is_empty());
    drop(images);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[test]
fn extraction_failure_consumes_failed_slot_rolls_back_and_cleans_remaining_aliases() {
    let images = images();
    let count = Arc::new(AtomicUsize::new(0));
    let mut slots = TestSlots::new(&[303, 304, 305], &[304, 305]);
    let leftovers = Arc::clone(&slots.destroyed);
    let result = images.retain_extracted_slots_with(&mut slots.slots, 3, true, 2, true,
        |raw| {
            if raw as usize == 304 { images.lock().unwrap().next_id = u64::MAX; }
            images.insert_owned(guard(raw as usize, ImageKind::Icon, &count))
        });
    assert!(result.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert!(images.lock().unwrap().images.is_empty());
    drop(slots);
    assert_eq!(*leftovers.lock().unwrap(), vec![305]);
    drop(images);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[test]
fn extraction_owner_collision_disarms_all_aliases_and_preserves_existing_token() {
    let images = images();
    let established = Arc::new(AtomicUsize::new(0));
    let incoming = Arc::new(AtomicUsize::new(0));
    let existing = images.insert_owned(guard(307, ImageKind::Icon, &established)).unwrap();
    let mut slots = TestSlots::new(&[306, 307], &[307]);
    let leftovers = Arc::clone(&slots.destroyed);
    let result = images.retain_extracted_slots_with(&mut slots.slots, 2, true, 1, true,
        |raw| images.insert_owned(guard(raw as usize, ImageKind::Icon, &incoming)));
    assert!(result.is_err());
    assert_eq!(incoming.load(Ordering::SeqCst), 1);
    assert_eq!(established.load(Ordering::SeqCst), 0);
    assert!(images.lock().unwrap().images.contains_key(&existing));
    drop(slots);
    assert!(leftovers.lock().unwrap().is_empty());
    drop(images);
    assert_eq!(established.load(Ordering::SeqCst), 1);
    assert_eq!(incoming.load(Ordering::SeqCst), 1);
}

#[test]
fn untransferred_native_slot_cleanup_deduplicates_both_arrays() {
    let slots = TestSlots::new(&[403, 401, 0, 403], &[402, 401, 0]);
    let destroyed = Arc::clone(&slots.destroyed);
    drop(slots);
    assert_eq!(*destroyed.lock().unwrap(), vec![401, 402, 403]);
}

#[test]
fn null_results_allocate_nothing() {
    let images = images();
    assert_eq!(images.adopt_borrowed_icon(std::ptr::null_mut()).unwrap(), None);
    assert_eq!(images.adopt_borrowed_cursor(std::ptr::null_mut()).unwrap(), None);
    assert!(images.lock().unwrap().images.is_empty());
}

#[test]
fn both_orderings_of_last_release_and_recovery_preserve_incarnation_contract() {
    let count = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let token = register(&mut table, &mut guard(501, ImageKind::Icon, &count)).unwrap();
    let lease = table.images.remove(&token).unwrap();
    let result = adopt(&mut table, 501, ImageKind::Icon).unwrap();
    drop(lease);
    assert!(table.images[&result].image.owned);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    table.images.remove(&result);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    // After destruction, only the caller's borrowed-native validity contract
    // remains; the expired index must never resurrect the old owner.
    let external = adopt(&mut table, 501, ImageKind::Icon).unwrap();
    assert_ne!(external, result);
    assert!(!table.images[&external].image.owned);
    drop(table);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn maintenance_sweeps_are_amortized_and_expired_metadata_eventually_clears() {
    let count = Arc::new(AtomicUsize::new(0));
    let mut table = ImageTable::new();
    let mut tokens = Vec::new();
    for raw in 1000..5096 {
        tokens.push(register(&mut table, &mut guard(raw, ImageKind::Icon, &count)).unwrap());
    }
    // Geometrically spaced full sweeps keep bulk registration linear overall.
    assert!(table.sweep_visits <= tokens.len() * 2);
    assert_eq!(table.owners.len(), tokens.len());
    for token in &tokens {
        table.images.remove(token);
        table.maintain();
    }
    assert_eq!(count.load(Ordering::SeqCst), tokens.len());
    assert!(table.sweep_visits <= tokens.len() * 4);
    let remaining_operations = table.maintenance_left;
    assert!(remaining_operations <= tokens.len().max(64));
    for _ in 0..remaining_operations { table.maintain(); }
    assert!(table.owners.is_empty());
}

fn unlocked_guard(raw: usize, images: &Win16Images, count: &Arc<AtomicUsize>) -> NativeIconGuard {
    let mut guard = guard(raw, ImageKind::Icon, count);
    guard.0.as_mut().unwrap().test_unlocked_table = Some(Arc::downgrade(&images.images));
    guard
}

#[test]
fn consumed_registration_and_release_destroy_only_outside_mutex() {
    let images = images();
    let released = Arc::new(AtomicUsize::new(0));
    let token = images.insert_owned(unlocked_guard(6001, &images, &released)).unwrap();
    images.release_icon(Win16HostIcon(token)).unwrap();
    assert_eq!(released.load(Ordering::SeqCst), 1);
    let exhausted = Arc::new(AtomicUsize::new(0));
    images.lock().unwrap().next_id = u64::MAX;
    assert!(images.insert_owned(unlocked_guard(6002, &images, &exhausted)).is_err());
    assert_eq!(exhausted.load(Ordering::SeqCst), 1);
}

#[test]
fn recovery_error_transfers_last_owner_past_mutex_scope() {
    for exhaust in [false, true] {
        let images = images();
        let count = Arc::new(AtomicUsize::new(0));
        let token = images.insert_owned(unlocked_guard(6003, &images, &count)).unwrap();
        let lease = images.lock().unwrap().images.remove(&token).unwrap();
        let mut recovered = None;
        {
            let mut table = images.lock().unwrap();
            if exhaust { table.next_id = u64::MAX; }
            let kind = if exhaust { ImageKind::Icon } else { ImageKind::Cursor };
            assert!(table.adopt(6003 as HICON, kind, &mut recovered).is_err());
            // Simulate the other call releasing its lease while adoption still
            // holds the table lock. The recovered error owner must escape it.
            drop(lease);
            assert_eq!(count.load(Ordering::SeqCst), 0);
        }
        drop(recovered);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn collision_error_transfers_last_established_owner_past_mutex_scope() {
    let images = images();
    let established = Arc::new(AtomicUsize::new(0));
    let rejected = Arc::new(AtomicUsize::new(0));
    let token = images.insert_owned(unlocked_guard(6004, &images, &established)).unwrap();
    let lease = images.lock().unwrap().images.remove(&token).unwrap();
    let mut incoming = unlocked_guard(6004, &images, &rejected);
    let mut collision = None;
    {
        let mut table = images.lock().unwrap();
        assert!(table.register_owned(&mut incoming, &mut collision).is_err());
        drop(lease);
        assert_eq!(established.load(Ordering::SeqCst), 0);
    }
    drop(incoming);
    assert_eq!(rejected.load(Ordering::SeqCst), 0);
    drop(collision);
    assert_eq!(established.load(Ordering::SeqCst), 1);
}

#[test]
fn get_cursor_borrowed_result_release_never_destroys_native_cursor() {
    use crate::windows::win16_windows::win16_user_cursor_accelerator::get_cursor_with;
    use runtime::Win16HostUserCursorAcceleratorResult as ResultValue;

    let images = images();
    let count = Arc::new(AtomicUsize::new(0));
    let raw = 601usize as HICON;
    let ResultValue::GetCursor(Some(cursor)) = get_cursor_with(&images, || raw).unwrap()
        else { panic!("non-null external cursor must be borrowed"); };
    {
        let mut table = images.lock().unwrap();
        let retained = Arc::get_mut(table.images.get_mut(&cursor.0).unwrap()).unwrap();
        assert!(!retained.image.owned);
        retained.test_destruction = Some(Arc::clone(&count));
    }
    assert_eq!(get_cursor_with(&images, || raw).unwrap(), ResultValue::GetCursor(Some(cursor)));
    assert_eq!(images.native_cursor(cursor).unwrap(), Some(raw));
    images.release_cursor(cursor).unwrap();
    assert_eq!(images.native_cursor(cursor).unwrap(), None);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(images);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn get_cursor_preserves_owned_cursor_identity_and_single_destruction_authority() {
    use crate::windows::win16_windows::win16_user_cursor_accelerator::get_cursor_with;
    use runtime::{Win16HostCursor, Win16HostUserCursorAcceleratorResult as ResultValue};

    let images = images();
    let count = Arc::new(AtomicUsize::new(0));
    let token = images.insert_owned(guard(602, ImageKind::Cursor, &count)).unwrap();
    let cursor = Win16HostCursor(token);
    let lease = Arc::clone(&images.lock().unwrap().images[&token]);
    assert_eq!(get_cursor_with(&images, || 602 as HICON).unwrap(),
        ResultValue::GetCursor(Some(cursor)));
    assert!(Arc::ptr_eq(&images.lock().unwrap().images[&token], &lease));
    images.release_cursor(cursor).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 0);

    // A suspended native call can retain the owner after token retirement.
    let ResultValue::GetCursor(Some(recovered)) = get_cursor_with(&images, || 602 as HICON)
        .unwrap() else { panic!("live cursor owner must be recoverable"); };
    assert_ne!(recovered, cursor);
    assert!(Arc::ptr_eq(&images.lock().unwrap().images[&recovered.0], &lease));
    assert!(images.lock().unwrap().images[&recovered.0].image.owned);
    images.release_cursor(recovered).unwrap();
    drop(images);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(lease);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn get_cursor_propagates_token_exhaustion_without_publishing_native_bits() {
    use crate::windows::win16_windows::win16_user_cursor_accelerator::get_cursor_with;

    let images = images();
    images.lock().unwrap().next_id = u64::MAX;
    let mut calls = 0;
    let result = get_cursor_with(&images, || {
        calls += 1;
        603 as HICON
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
    assert!(images.lock().unwrap().images.is_empty());
}
