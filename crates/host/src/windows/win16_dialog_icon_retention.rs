//! Process-owned dialog icon pins, independent of HWND maps and worker teardown.
//!
//! Reserve and publish the strong owner here before exposing its HICON to USER.
//! An ambiguous HWND stays pinned until its exact creator JoinHandle returns.
//! Neither a thread ID nor a WM_NCDESTROY notification is a join receipt.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{HICON, IsWindow};

use super::win16_images::Win16IconLease;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Binding {
    Unbound,
    Bound(usize),
    Retired,
}

pub(in crate::windows) struct IconOwner<L> {
    lease: L,
    // This is the monotonic USER-worker retirement identity, never a Win32 TID.
    worker_id: u64,
    binding: Mutex<Binding>,
}

pub(in crate::windows) type DialogIconOwner = IconOwner<Win16IconLease>;

impl<L> IconOwner<L> {
    pub(in crate::windows) fn bind(&self, hwnd: HWND) -> Result<(), RuntimeError> {
        let mut binding = self.binding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if hwnd.is_null() || *binding != Binding::Unbound {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "dialog icon owner must bind exactly once to a non-null HWND"));
        }
        *binding = Binding::Bound(hwnd as usize);
        Ok(())
    }

    fn cancel_unbound(&self) -> bool {
        let mut binding = self.binding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if *binding != Binding::Unbound { return false; }
        *binding = Binding::Retired;
        true
    }

    fn retire_if_absent(&self, is_window: impl FnOnce(usize) -> bool) -> bool {
        let observed = *self.binding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Binding::Bound(hwnd) = observed else { return false; };
        // Even read-only USER queries stay outside owner and registry locks.
        if is_window(hwnd) { return false; }
        let mut binding = self.binding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if *binding != observed { return false; }
        *binding = Binding::Retired;
        true
    }
}

impl DialogIconOwner {
    pub(in crate::windows) fn native(&self) -> HICON { self.lease.native() }
}

// Conservative concurrent process-owned pin budget, not a Win16 ABI restriction.
// This limits owners, not the allocator high-water capacity of each worker map.
// Ambiguous recycled HWNDs can otherwise retain generations until worker join.
const MAX_PROCESS_ICON_PINS: usize = 65_536;

struct OwnerSlots<L> {
    workers: HashMap<u64, HashMap<usize, Arc<IconOwner<L>>>>,
    count: usize,
    limit: usize,
}

impl<L> OwnerSlots<L> {
    fn new(limit: usize) -> Self {
        Self { workers: HashMap::new(), count: 0, limit }
    }

    fn insert(&mut self, owner: &Arc<IconOwner<L>>) -> Result<(), RuntimeError> {
        if self.count >= self.limit {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "process-owned dialog icon pin budget exhausted"));
        }
        // Both index and owner storage are reserved before native exposure.
        // Teardown extracts an entire worker pool without allocation or scans
        // across unrelated workers.
        // Arc allocation identity is an internal key only. The table holds a
        // strong Arc throughout its use; native HWND/HICON values are not keys.
        let key = Arc::as_ptr(owner) as usize;
        if let Some(pool) = self.workers.get_mut(&owner.worker_id) {
            if pool.contains_key(&key) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "dialog icon owner already has a process pin"));
            }
            pool.try_reserve(1).map_err(reservation_error)?;
            pool.insert(key, Arc::clone(owner));
        } else {
            self.workers.try_reserve(1).map_err(reservation_error)?;
            let mut pool = HashMap::new();
            pool.try_reserve(1).map_err(reservation_error)?;
            pool.insert(key, Arc::clone(owner));
            self.workers.insert(owner.worker_id, pool);
        }
        self.count += 1;
        Ok(())
    }

    fn remove(&mut self, owner: &Arc<IconOwner<L>>) -> Option<Arc<IconOwner<L>>> {
        let pool = self.workers.get_mut(&owner.worker_id)?;
        let key = Arc::as_ptr(owner) as usize;
        if !Arc::ptr_eq(pool.get(&key)?, owner) { return None; }
        let removed = pool.remove(&key)?;
        let empty = pool.is_empty();
        self.count -= 1;
        if empty { self.workers.remove(&owner.worker_id); }
        Some(removed)
    }

    fn take_joined(&mut self, worker_id: u64) -> Option<HashMap<usize, Arc<IconOwner<L>>>> {
        let pool = self.workers.remove(&worker_id)?;
        self.count -= pool.len();
        Some(pool)
    }
}

fn reservation_error(error: std::collections::TryReserveError) -> RuntimeError {
    RuntimeError::with_source(Kind::ResourceExhausted,
        "reserve process-owned dialog icon pin", error)
}

fn retire_joined<L>(pool: HashMap<usize, Arc<IconOwner<L>>>) {
    for owner in pool.into_values() {
        *owner.binding.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Binding::Retired;
        drop(owner);
    }
}

static OWNERS: OnceLock<Mutex<OwnerSlots<Win16IconLease>>> = OnceLock::new();

fn owners() -> &'static Mutex<OwnerSlots<Win16IconLease>> {
    OWNERS.get_or_init(|| Mutex::new(OwnerSlots::new(MAX_PROCESS_ICON_PINS)))
}

pub(in crate::windows) fn stage(
    worker_id: u64, lease: Win16IconLease,
) -> Result<Arc<DialogIconOwner>, RuntimeError> {
    let owner = Arc::new(IconOwner { lease, worker_id, binding: Mutex::new(Binding::Unbound) });
    let inserted = owners().lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(&owner);
    // On reservation failure, the lease also drops outside the registry lock.
    inserted?;
    Ok(owner)
}

fn remove(owner: &Arc<DialogIconOwner>) {
    let removed = owners().lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(owner);
    // DestroyIcon (on final lease release) must never run under the registry lock.
    drop(removed);
}

/// Only for rollback before the icon was exposed to a native control.
pub(in crate::windows) fn cancel_unbound(owner: &Arc<DialogIconOwner>) -> bool {
    if !owner.cancel_unbound() { return false; }
    remove(owner);
    true
}

/// Call only after the native USER operation returns, not from destruction
/// callbacks. A reused live HWND is deliberately ambiguous and remains pinned.
pub(in crate::windows) fn retire_if_absent(owner: &Arc<DialogIconOwner>) -> bool {
    if !owner.retire_if_absent(|hwnd| {
        // SAFETY: IsWindow accepts an arbitrary HWND value and does not mutate it.
        unsafe { IsWindow(hwnd as HWND) != 0 }
    }) { return false; }
    remove(owner);
    true
}

/// The caller must have just consumed this exact creator's JoinHandle, including
/// a panic result. is_finished(), TID equality, and shutdown receipts do not suffice.
pub(in crate::windows) fn retire_worker_after_join(worker_id: u64) {
    let pool = owners().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
        .take_joined(worker_id);
    if let Some(pool) = pool { retire_joined(pool); }
}

#[cfg(test)]
#[path = "win16_dialog_icon_retention_tests.rs"]
mod tests;
