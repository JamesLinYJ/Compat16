//! Pre-acquired owner slots for toolbar bitmap lifetime tracking.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::HWND;

use super::super::win16_window_worker::WorkerState;
use super::{ToolbarBitmapOwner, ToolbarBitmapRetention, ToolbarBitmapSidecar};

/// Capacity and exact worker identity reserved before acquiring a toolbar bitmap.
pub(in crate::windows) struct ToolbarBitmapStageSlot {
    worker_retirement_id: u64,
    operation: u64,
    expected_parent: usize,
    control_id: u16,
    subclass_id: usize,
    retention: Arc<Mutex<ToolbarBitmapRetention>>,
    reserved_slots: usize,
}

/// Reserve owner and post-join storage before moving a guest lease or creating an HBITMAP.
pub(in crate::windows) fn reserve_stage_slot(
    state: &RefCell<WorkerState>,
    operation: u64,
    parent: HWND,
    control_id: u16,
) -> Result<ToolbarBitmapStageSlot, RuntimeError> {
    let subclass_id = usize::try_from(operation)
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "encode toolbar bitmap sidecar identity",
            )
        })?;
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar bitmap sidecar state is already borrowed",
        )
    })?;
    if worker.active_operations.last().map(|entry| entry.id) != Some(operation)
        || worker
            .toolbar_bitmap_sidecars
            .iter()
            .any(|entry| entry.operation == operation)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar bitmap pin was staged outside its active USER operation",
        ));
    }
    worker
        .toolbar_bitmap_sidecars
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve toolbar bitmap owner sidecar",
                error,
            )
        })?;
    let worker_retirement_id = worker.worker_retirement_id;
    let retention = Arc::clone(&worker.toolbar_bitmap_retention);
    let mut retained = retention
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Two exact slots cover the sidecar's future worker transfer and the
    // owner-preserving fallback if staging fails. Allocator spare capacity is
    // not counted as a reservation for another still-live owner.
    retained.reserve_slots(2)?;
    drop(retained);
    let slot = ToolbarBitmapStageSlot {
        worker_retirement_id,
        operation,
        expected_parent: parent as usize,
        control_id,
        subclass_id,
        retention,
        reserved_slots: 2,
    };
    Ok(slot)
}

/// Publish the acquired owner before CreateToolbarEx can synchronously reenter guest code.
pub(in crate::windows) fn stage(
    state: &RefCell<WorkerState>,
    slot: &mut ToolbarBitmapStageSlot,
    owner: ToolbarBitmapOwner,
) -> Result<(), (RuntimeError, ToolbarBitmapOwner)> {
    let mut worker = match state.try_borrow_mut() {
        Ok(worker) => worker,
        Err(_) => {
            return Err((
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar bitmap sidecar state is already borrowed",
                ),
                owner,
            ));
        }
    };
    if worker.worker_retirement_id != slot.worker_retirement_id
        || worker.active_operations.last().map(|entry| entry.id) != Some(slot.operation)
        || worker
            .toolbar_bitmap_sidecars
            .iter()
            .any(|entry| entry.operation == slot.operation)
    {
        return Err((
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap pin no longer matches its reserved USER operation",
            ),
            owner,
        ));
    }
    // Release the unused emergency slot before publishing. The remaining
    // reservation belongs to this worker sidecar until it transfers or retires.
    if let Err(error) = slot.cancel_one() {
        return Err((error, owner));
    }
    // The worker vector reservation makes this owner publication allocation-free.
    worker.toolbar_bitmap_sidecars.push(ToolbarBitmapSidecar {
        worker_retirement_id: slot.worker_retirement_id,
        operation: slot.operation,
        window: None,
        hwnd: None,
        expected_parent: slot.expected_parent,
        control_id: slot.control_id,
        subclass_id: slot.subclass_id,
        installed: false,
        owner,
    });
    // The sidecar itself remains represented in ToolbarBitmapRetention's
    // outstanding count; only the separate owner-preserving fallback is now
    // released from this temporary slot.
    slot.reserved_slots = 0;
    Ok(())
}

/// Preserve acquired ownership in the worker's pre-reserved post-join storage.
pub(in crate::windows) fn retain_unbound_owner(
    slot: &mut ToolbarBitmapStageSlot,
    owner: ToolbarBitmapOwner,
) -> Result<(), (RuntimeError, ToolbarBitmapOwner)> {
    if let Err(error) = slot.cancel_one() {
        return Err((error, owner));
    }
    let mut retained = slot
        .retention
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Err((error, sidecar)) = retained.push_reserved(ToolbarBitmapSidecar {
        worker_retirement_id: slot.worker_retirement_id,
        operation: slot.operation,
        window: None,
        hwnd: None,
        expected_parent: slot.expected_parent,
        control_id: slot.control_id,
        subclass_id: slot.subclass_id,
        installed: false,
        owner,
    }) {
        return Err((error, sidecar.owner));
    }
    slot.reserved_slots = 0;
    Ok(())
}

impl ToolbarBitmapStageSlot {
    fn cancel_one(&mut self) -> Result<(), RuntimeError> {
        if self.reserved_slots == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap stage slot has no outstanding reservation",
            ));
        }
        self.retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancel_slots(1)?;
        self.reserved_slots -= 1;
        Ok(())
    }
}

impl Drop for ToolbarBitmapStageSlot {
    fn drop(&mut self) {
        if self.reserved_slots == 0 {
            return;
        }
        let count = self.reserved_slots;
        match self
            .retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancel_slots(count)
        {
            Ok(()) => self.reserved_slots = 0,
            Err(error) => eprintln!("runtime: {error}"),
        }
    }
}
