//! Pure ownership tests: no native image handles and no native destruction.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Lease(Arc<AtomicUsize>);
impl Drop for Lease {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
}

fn owner(worker_id: u64, dropped: &Arc<AtomicUsize>) -> Arc<IconOwner<Lease>> {
    Arc::new(IconOwner {
        lease: Lease(Arc::clone(dropped)), worker_id, binding: Mutex::new(Binding::Unbound),
    })
}

#[test]
fn process_slot_survives_local_owner_loss_and_wrong_creator_join() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut slots = OwnerSlots::new(MAX_PROCESS_ICON_PINS);
    let local = owner(41, &dropped);
    slots.insert(&local).unwrap();
    assert!(slots.workers[&41].capacity() >= 1);
    local.bind(7usize as HWND).unwrap();
    drop(local);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(slots.take_joined(42).is_none());
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    let joined = slots.take_joined(41).unwrap();
    retire_joined(joined);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn unbound_cancel_is_terminal_and_removes_only_exact_owner() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut slots = OwnerSlots::new(MAX_PROCESS_ICON_PINS);
    let first = owner(3, &dropped);
    let second = owner(3, &dropped);
    slots.insert(&first).unwrap();
    slots.insert(&second).unwrap();
    assert!(first.cancel_unbound());
    assert!(first.bind(7usize as HWND).is_err());
    assert!(!first.cancel_unbound());
    drop(slots.remove(&first));
    assert!(Arc::ptr_eq(&slots.workers[&3][&(Arc::as_ptr(&second) as usize)], &second));
    drop(first);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn live_reused_or_ambiguous_hwnd_retains_owner_until_terminal_proof() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut slots = OwnerSlots::new(MAX_PROCESS_ICON_PINS);
    let local = owner(5, &dropped);
    slots.insert(&local).unwrap();
    assert!(local.bind(std::ptr::null_mut()).is_err());
    local.bind(19usize as HWND).unwrap();
    assert!(local.bind(19usize as HWND).is_err());
    assert!(!local.cancel_unbound());
    // A live value could be either the original or a recycled HWND. Neither is
    // authority to release. No cookie or synthetic message changes this state.
    assert!(!local.retire_if_absent(|hwnd| { assert_eq!(hwnd, 19); true }));
    assert_eq!(slots.count, 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(local.retire_if_absent(|_| false));
    drop(slots.remove(&local));
    // In-flight callback Arc still protects the lease after process retirement.
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(local);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn production_admission_failure_preserves_existing_pin_and_accepts_reclaimed_slot() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut slots = OwnerSlots::new(1);
    let local = owner(8, &dropped);
    slots.insert(&local).unwrap();
    local.bind(21usize as HWND).unwrap();
    drop(local);
    let rejected = owner(9, &dropped);
    assert!(slots.insert(&rejected).is_err());
    assert_eq!(slots.count, 1);
    assert!(!slots.workers.contains_key(&9));
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    retire_joined(slots.take_joined(8).unwrap());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    slots.insert(&rejected).unwrap();
    assert_eq!(slots.count, 1);
    drop(rejected);
    retire_joined(slots.take_joined(9).unwrap());
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
}

#[test]
fn final_owner_drop_occurs_after_registry_unlock() {
    struct LockCheckedLease {
        registry: std::sync::Weak<Mutex<OwnerSlots<LockCheckedLease>>>,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for LockCheckedLease {
        fn drop(&mut self) {
            let registry = self.registry.upgrade().unwrap();
            assert!(registry.try_lock().is_ok());
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(Mutex::new(OwnerSlots::new(MAX_PROCESS_ICON_PINS)));
    let local = Arc::new(IconOwner {
        lease: LockCheckedLease {
            registry: Arc::downgrade(&registry), dropped: Arc::clone(&dropped),
        },
        worker_id: 9,
        binding: Mutex::new(Binding::Unbound),
    });
    registry.lock().unwrap().insert(&local).unwrap();
    drop(local);
    let joined = registry.lock().unwrap().take_joined(9);
    retire_joined(joined.unwrap());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn absence_query_runs_unlocked_and_revalidates_binding() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let local = owner(10, &dropped);
    local.bind(31usize as HWND).unwrap();
    assert!(!local.retire_if_absent(|_| {
        let mut binding = local.binding.try_lock().expect("native query must run unlocked");
        *binding = Binding::Retired;
        false
    }));
    assert_eq!(*local.binding.lock().unwrap(), Binding::Retired);
}

#[test]
fn joined_pool_extraction_leaves_other_worker_owners_untouched() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut slots = OwnerSlots::new(4);
    for id in [1, 2, 1, 3] { slots.insert(&owner(id, &dropped)).unwrap(); }
    let joined = slots.take_joined(1).unwrap();
    assert_eq!(joined.len(), 2);
    assert_eq!(slots.count, 2);
    assert!(slots.workers.contains_key(&2));
    assert!(slots.workers.contains_key(&3));
    retire_joined(joined);
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
}

#[test]
fn duplicate_owner_admission_does_not_replace_or_double_count_pin() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut slots = OwnerSlots::new(2);
    let local = owner(11, &dropped);
    slots.insert(&local).unwrap();
    assert!(slots.insert(&local).is_err());
    assert_eq!(slots.count, 1);
    drop(local);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    retire_joined(slots.take_joined(11).unwrap());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}
